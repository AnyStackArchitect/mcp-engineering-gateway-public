#!/usr/bin/env python3
"""Authenticated-SSH streamed resumable evidence intake, not an MCP upload API.

This module never opens a network listener or executes evidence. The SSH
operator owns a random .upload-<32hex> name and declares the *full* source
length/hash once. Interrupted append calls leave a private, verifiable prefix;
status reports its digest for explicit client-side prefix comparison. Only
transfer_bridge.finalize may create the final non-overwriting inbox name.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
from pathlib import Path
import stat
import sys
from typing import BinaryIO, Iterator

from casework import CaseStore, CaseError, FREE_RESERVE, MAX_WORKER_ARTIFACT
from capacitywork import admission_lock, new_upload_capacity, verify_committed_reserve, read_session_metadata

CHUNK = 1024 * 1024
APPEND_IDLE_SECONDS = 30
MAX_META = 1024
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


SESSION_TOKEN = re.compile(r"^\.upload-[a-f0-9]{32}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _token(temp: str) -> str:
    if not isinstance(temp, str) or not SESSION_TOKEN.fullmatch(temp):
        raise CaseError("Invalid upload token")
    return temp


def _valid_identity(size: int, sha256: str) -> None:
    if (type(size) is not int or not 0 <= size <= MAX_WORKER_ARTIFACT
            or not isinstance(sha256, str) or not SHA256.fullmatch(sha256)):
        raise CaseError("Declared evidence identity is invalid")


def _names(store: CaseStore, temp: str) -> tuple[Path, Path]:
    _token(temp)
    return store.inbox / temp, store.inbox / (temp + ".session")


def _private(fd: int, *, meta: bool = False) -> os.stat_result:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o077
            or (meta and not 0 < info.st_size <= MAX_META)):
        raise CaseError("Private upload session file is unsafe")
    return info


@contextmanager
def _lock_file(path: Path, *, write: bool = False) -> Iterator[tuple[int, os.stat_result]]:
    flags = (os.O_RDWR if write else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = _private(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CaseError("Upload is busy; retry after the current transfer") from exc
        yield fd, info
    finally:
        os.close(fd)


def read_meta(store: CaseStore, temp: str, *, missing_ok: bool = False) -> dict | None:
    # Shared source-bound parser, already imported before privilege separation.
    return read_session_metadata(store, temp, missing_ok=missing_ok)


def begin(store: CaseStore, temp: str, size: int, sha256: str) -> dict:
    _valid_identity(size, sha256)
    with admission_lock(store):
        return _begin_locked(store, temp, size, sha256)


def _begin_locked(store: CaseStore, temp: str, size: int, sha256: str) -> dict:
    # Invoked only with the shared admission lock: concurrent clients cannot
    # both accept the same currently-uncommitted bytes.
    _valid_identity(size, sha256)
    source, meta = _names(store, temp)
    store._ensure_store()
    if new_upload_capacity(store) < size:
        raise CaseError("Insufficient safe capacity after concurrent reservations")
    verify_committed_reserve(store,extra_bytes=size)
    created: list[Path] = []
    try:
        fd = os.open(source, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        created.append(source)
        with os.fdopen(fd, "wb") as out:
            out.flush()
            os.fsync(out.fileno())
        data = json.dumps({"version": 1, "size": size, "sha256": sha256},
                          sort_keys=True, separators=(",", ":")).encode("ascii")
        fd = os.open(meta, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        created.append(meta)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        return {"status": "SESSION_CREATED", "bytes_staged": 0,
                "declared_size": size, "expected_sha256": sha256,
                "prefix_sha256": EMPTY_SHA256}
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def status(store: CaseStore, temp: str) -> dict:
    store._ensure_store()
    session = read_meta(store, temp)
    assert session is not None
    source, _ = _names(store, temp)
    with _lock_file(source) as (fd, before):
        if before.st_size > session["size"]:
            raise CaseError("Upload exceeds its declared size")
        digest = hashlib.sha256()
        seen = 0
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            seen += len(block)
            if seen > session["size"]:
                raise CaseError("Upload changed during verification")
            digest.update(block)
        after = os.fstat(fd)
        if (seen != before.st_size or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns):
            raise CaseError("Upload changed during verification")
    return {"status": "COMPLETE_UNVERIFIED" if seen == session["size"] else "PARTIAL",
            "bytes_staged": seen, "remaining_bytes": session["size"] - seen,
            "declared_size": session["size"], "expected_sha256": session["sha256"],
            "prefix_sha256": digest.hexdigest(),
            "ready_for_case_import": False}


def _read_stdin() -> bytes:
    # SSH may leave its session pipe open after an abruptly terminated client.
    # Never hold the private upload lock indefinitely. Use the descriptor
    # directly: buffered read(CHUNK) can wait for a full chunk after readiness.
    fd = sys.stdin.buffer.fileno()
    ready, _, _ = select.select([fd], [], [], APPEND_IDLE_SECONDS)
    if not ready:
        raise CaseError("Upload input idle; private prefix retained for resume")
    return os.read(fd, CHUNK)


def append(store: CaseStore, temp: str, offset: int,
           stream: BinaryIO | None = None) -> dict:
    if type(offset) is not int or offset < 0:
        raise CaseError("Upload offset must be nonnegative")
    store._ensure_store()
    session = read_meta(store, temp)
    assert session is not None
    source, _ = _names(store, temp)
    incoming = sys.stdin.buffer if stream is None else stream
    if not hasattr(incoming, "read"):
        raise CaseError("Upload source must be a binary stream")
    with _lock_file(source, write=True) as (fd, before):
        if before.st_size != offset or offset > session["size"]:
            raise CaseError("Upload offset is stale or outside declared size")
        os.lseek(fd, offset, os.SEEK_SET)
        written = 0
        try:
            while True:
                block = _read_stdin() if stream is None else incoming.read(CHUNK)
                if not isinstance(block, bytes):
                    raise CaseError("Upload stream returned invalid bytes")
                if not block:
                    break
                if offset + written + len(block) > session["size"]:
                    raise CaseError("Upload exceeds its declared size")
                with admission_lock(store):
                    # Session reservations are committed before upload. Under
                    # this lock, each physical write replaces its own pending
                    # reservation rather than competing against other clients.
                    verify_committed_reserve(store)
                    if os.fstat(fd).st_size != offset + written:
                        raise CaseError("Upload changed during guarded append")
                    view = memoryview(block)
                    while view:
                        n = os.write(fd, view)
                        if n <= 0:
                            raise CaseError("Evidence append was incomplete")
                        view = view[n:]
                        written += n
        finally:
            os.fsync(fd)
        after = os.fstat(fd)
        if after.st_size != offset + written or after.st_size > session["size"]:
            raise CaseError("Upload offset/length changed")
        return {"status": "COMPLETE_UNVERIFIED" if after.st_size == session["size"] else "PARTIAL",
                "bytes_appended": written, "bytes_staged": after.st_size,
                "remaining_bytes": session["size"] - after.st_size,
                "ready_for_case_import": False}


def remove_meta(store: CaseStore, temp: str) -> None:
    _, path = _names(store, temp)
    if read_meta(store, temp, missing_ok=True) is not None:
        path.unlink()


def clear_orphan_meta(store: CaseStore, temp: str) -> bool:
    # A process may crash after verified finalization removes the source
    # but before it removes the tiny session metadata.
    source, meta = _names(store, temp)
    if source.exists() or source.is_symlink():
        return False
    if read_meta(store, temp, missing_ok=True) is None:
        return False
    meta.unlink()
    return True
