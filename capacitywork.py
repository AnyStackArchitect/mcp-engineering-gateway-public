"""Private, cross-process capacity admission for resumable case evidence.

Each unfinished authenticated-SSH upload session is a durable reservation for
its DECLARED remaining bytes, not merely the bytes already on disk. A single
owned flock serializes admission and every bounded append write, preventing
cooperating transfers from independently consuming the 5 GiB free reserve.
This is not filesystem-level quota enforcement against unrelated local users.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
import sharedcapacity
from typing import Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from casework import CaseStore

MAX_INBOX_ENTRIES = 4096
ADMISSION_WAIT_SECONDS = 90
ADMISSION_POLL_SECONDS = 0.05
MAX_META = 1024
SESSION_TOKEN = re.compile(r"^\.upload-[a-f0-9]{32}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _error(message: str) -> Exception:
    # Late import avoids introducing a top-level circular dependency into
    # CaseStore.register, which also uses admission controls.
    from casework import CaseError
    return CaseError(message)


@contextmanager
def admission_lock(store: CaseStore) -> Iterator[None]:
    store._ensure_store()
    with sharedcapacity.admission(store,_local_outstanding_reservations) as shared:
        if shared:
            yield
        else:
            with _local_admission_lock(store):yield


@contextmanager
def _local_admission_lock(store: CaseStore) -> Iterator[None]:
    """Exclusive local process lock (never a public or network admission API)."""
    store._ensure_store()
    target = store.base / ".capacity.lock"
    flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(target, flags, 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_nlink != 1 or st.st_mode & 0o077):
            raise _error("Private capacity admission lock is unsafe")
        deadline = time.monotonic() + ADMISSION_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise _error("Private storage admission is busy; retry") from exc
                time.sleep(ADMISSION_POLL_SECONDS)
        pathinfo = target.lstat()
        if (not stat.S_ISREG(pathinfo.st_mode) or
                (pathinfo.st_dev, pathinfo.st_ino) != (st.st_dev, st.st_ino)):
            raise _error("Admission lock path changed while waiting")
        yield
    finally:
        os.close(fd)


def read_session_metadata(store: CaseStore, token: str,
                          *, missing_ok: bool = False) -> dict | None:
    """Read metadata without importing an untrusted/inaccessible module.

    This module is preloaded before the process crosses into the gateway or
    worker UID. The read is bounded and rejects replaced, linked or public
    sidecars, preserving the legacy resumable-session schema contract.
    """
    from casework import MAX_WORKER_ARTIFACT
    if not isinstance(token, str) or SESSION_TOKEN.fullmatch(token) is None:
        raise _error("Invalid upload token")
    path = store.inbox / (token + ".session")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        if missing_ok:
            return None
        raise _error("Resumable upload session is missing")
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid() or before.st_nlink != 1
                or before.st_mode & 0o077
                or not 0 < before.st_size <= MAX_META):
            raise _error("Private upload session file is unsafe")
        raw = os.read(fd, MAX_META + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns):
            raise _error("Upload session metadata changed")
        try:
            value = json.loads(raw)
        except (UnicodeError, TypeError, ValueError) as exc:
            raise _error("Upload session metadata is invalid") from exc
        if (not isinstance(value, dict)
                or set(value) != {"version", "size", "sha256"}
                or type(value.get("version")) is not int
                or value["version"] != 1):
            raise _error("Upload session metadata schema invalid")
        size, sha = value["size"], value["sha256"]
        if (type(size) is not int or not 0 <= size <= MAX_WORKER_ARTIFACT
                or not isinstance(sha, str) or SHA256.fullmatch(sha) is None):
            raise _error("Declared evidence identity is invalid")
        return value
    finally:
        os.close(fd)


def _local_outstanding_reservations(store: CaseStore) -> int:
    """Compute remaining commitments from persistent private session state.

    Must be called while holding admission_lock. Only valid .session sidecars
    describe reserved space. Missing partial source conservatively reserves the
    entire declared length until explicit operator-approved orphan cleanup.
    """
    from casework import MAX_WORKER_ARTIFACT
    inbox = store.inbox
    names: list[str] = []
    with os.scandir(inbox) as scan:
        for entry in scan:
            names.append(entry.name)
            if len(names) > MAX_INBOX_ENTRIES:
                raise _error("Private intake inventory exceeds admission bound")
    pending = 0
    for name in names:
        if not name.endswith(".session"):
            continue
        token = name[:-len(".session")]
        if SESSION_TOKEN.fullmatch(token) is None:
            # Other private files with this suffix are not upload sessions.
            continue
        meta = read_session_metadata(store, token)
        if meta is None:
            raise _error("Upload admission session disappeared")
        partial = inbox / token
        try:
            st = partial.lstat()
        except FileNotFoundError:
            st = None
        if st is not None and (
                not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_mode & 0o077 or st.st_nlink != 1):
            raise _error("Upload admission prefix is unsafe")
        size = 0 if st is None else st.st_size
        if size > meta["size"] or meta["size"] > MAX_WORKER_ARTIFACT:
            raise _error("Upload session size invalid for admission")
        pending += meta["size"] - size
    return pending


def outstanding_reservations(store: CaseStore) -> int:
    return sharedcapacity.aggregate(store,_local_outstanding_reservations(store))


def new_upload_capacity(store: CaseStore) -> int:
    """Uncommitted physical bytes after both the reserve and every session."""
    from casework import FREE_RESERVE, MAX_WORKER_ARTIFACT
    remaining = outstanding_reservations(store)
    free = shutil.disk_usage(store.inbox).free
    return max(0, min(MAX_WORKER_ARTIFACT, free - FREE_RESERVE - remaining))


def verify_committed_reserve(store: CaseStore, *, extra_bytes: int = 0) -> int:
    """Refuse writes that would consume other transfers' reserved capacity.

    Caller holds admission_lock. free - reservation >= 5 GiB is the required
    pre-write invariant; a chunk that grows its own session decreases its
    reservation by the same amount it consumes on disk.
    """
    from casework import FREE_RESERVE
    if type(extra_bytes) is not int or extra_bytes < 0:
        raise _error("Invalid extra storage reservation")
    committed = outstanding_reservations(store)
    free = shutil.disk_usage(store.inbox).free
    if free < FREE_RESERVE + committed + extra_bytes:
        raise _error("Insufficient space after reserved concurrent commitments")
    sharedcapacity.reserve_extra(store,_local_outstanding_reservations(store),extra_bytes)
    return committed
