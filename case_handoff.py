#!/usr/bin/env python3
"""Operator-only, metadata-only private case handoff with verified originals.

No raw evidence, filenames, freeform notes, excerpts, credentials or decoded
payloads are copied into the handoff. No MCP export tool, network access,
automatic publication, case deletion or retention policy is created.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any

from capacitywork import admission_lock, verify_committed_reserve
from casework import (CaseError, CaseStore, CASE_ID, MAX_CASE_STORAGE, MAX_MANIFEST,
                      _private_directory, _regular_open)

SHA256 = re.compile(r"^[a-f0-9]{64}$")
KIND = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
MAX_ARTIFACTS = 4096
MAX_OUTPUT_BYTES = 1024 * 1024
CHUNK = 1024 * 1024
OUT_DIR = "handoff-manifests"


def _canonical(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_uid, st.st_nlink,
            stat.S_IMODE(st.st_mode), st.st_mtime_ns, st.st_ctime_ns)


def _hash_registered(path: Path, expected_size: int, expected: str) -> None:
    fd, before = _regular_open(path)
    if before.st_nlink != 1 or before.st_size != expected_size:
        os.close(fd)
        raise CaseError("Handoff original identity is unsafe")
    digest = hashlib.sha256()
    seen = 0
    try:
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                seen += len(block)
                if seen > expected_size:
                    raise CaseError("Handoff original grew during verification")
                digest.update(block)
            after = os.fstat(stream.fileno())
        try:
            current = path.lstat()
        except OSError as exc:
            raise CaseError("Handoff original identity disappeared") from exc
        if (_identity(before) != _identity(after) or
                _identity(before) != _identity(current) or
                not stat.S_ISREG(current.st_mode) or
                seen != expected_size or digest.hexdigest() != expected):
            raise CaseError("Handoff original failed SHA-256 identity verification")
    finally:
        if fd >= 0:
            os.close(fd)


def _private_optional(folder: Path, label: str) -> bool:
    if folder.is_symlink():
        raise CaseError(label + " directory is unsafe")
    try:
        data = folder.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISDIR(data.st_mode) or data.st_uid != os.getuid()
            or data.st_mode & 0o077):
        raise CaseError(label + " directory is unsafe")
    return True


def _snapshot(store: CaseStore, case_id: str) -> dict[str, Any]:
    """Caller holds admission lock then case lock for full verification."""
    with store._locked(case_id) as (folder, manifest):
        artifacts = manifest.get("artifacts")
        if (not isinstance(artifacts, dict) or not 0 < len(artifacts) <= MAX_ARTIFACTS):
            raise CaseError("Handoff requires a bounded case with registered evidence")
        created = manifest.get("created_at")
        if not isinstance(created, str) or len(created) > 64:
            raise CaseError("Case creation identity invalid")
        try:
            parsed = datetime.fromisoformat(created)
            if parsed.tzinfo is None:
                raise ValueError("timezone")
        except (ValueError, TypeError) as exc:
            raise CaseError("Case creation timestamp invalid") from exc

        originals = folder / "originals"
        actual = list(originals.iterdir())
        if len(actual) != len(artifacts) or len(actual) > MAX_ARTIFACTS:
            raise CaseError("Handoff blocked by missing or unregistered originals")
        if set(p.name for p in actual) != set(artifacts):
            raise CaseError("Handoff blocked by missing or unregistered originals")

        scratch = folder / "scratch"
        if _private_optional(scratch, "Case scratch") and any(scratch.iterdir()):
            raise CaseError("Handoff blocked by unfinished case scratch")
        indexes = folder / "indexes"
        if not _private_optional(indexes, "Case indexes"):
            raise CaseError("Case indexes directory missing")
        indexed_entries = list(indexes.iterdir())
        if len(indexed_entries) > MAX_ARTIFACTS:
            raise CaseError("Handoff index inventory too large")
        if any(e.name.startswith(".tmp-") for e in indexed_entries):
            raise CaseError("Handoff blocked by unresolved index recovery")

        results: list[dict[str, Any]] = []
        parents: dict[str, str | None] = {}
        total = 0
        for artifact_id in sorted(artifacts):
            item = artifacts[artifact_id]
            if not isinstance(artifact_id, str) or CASE_ID.fullmatch(artifact_id) is None:
                raise CaseError("Invalid registered artifact ID")
            if not isinstance(item, dict):
                raise CaseError("Invalid registered artifact metadata")
            sha = item.get("sha256")
            size = item.get("bytes")
            kind = item.get("type")
            if (not isinstance(sha, str) or SHA256.fullmatch(sha) is None or
                    type(size) is not int or size < 0 or size > MAX_CASE_STORAGE or
                    not isinstance(kind, str) or KIND.fullmatch(kind) is None):
                raise CaseError("Handoff artifact identity invalid")
            parent = item.get("derived_from")
            if parent is not None and (
                    not isinstance(parent, str) or parent == artifact_id or
                    CASE_ID.fullmatch(parent) is None or parent not in artifacts):
                raise CaseError("Handoff source lineage is incomplete")
            total += size
            if total > MAX_CASE_STORAGE:
                raise CaseError("Handoff exceeds bounded case storage")
            _hash_registered(originals / artifact_id, size, sha)
            record = {"artifact_id": artifact_id, "sha256": sha,
                      "bytes": size, "type": kind}
            if parent is not None:
                record["derived_from"] = parent
            parents[artifact_id] = parent
            results.append(record)

        # A source graph that loops back on itself does not establish
        # meaningful provenance; do not certify a cycle as a valid handoff.
        resolved: set[str] = set()
        for artifact_id in parents:
            cursor = artifact_id
            visiting: set[str] = set()
            while cursor is not None and cursor not in resolved:
                if cursor in visiting:
                    raise CaseError("Handoff source lineage contains a cycle")
                visiting.add(cursor)
                cursor = parents[cursor]
            resolved.update(visiting)

        return {
            "schema": 1,
            "scope": "private_metadata_only_no_raw_evidence",
            "case_id": case_id,
            "created_at": created,
            "artifact_count": len(results),
            "original_bytes_verified": total,
            "artifacts": results,
        }


def _export_directory(store: CaseStore) -> Path:
    store._ensure_store()
    location = store.base / OUT_DIR
    _private_directory(location, strict=True)
    return location


def _sync_directory(folder: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(folder, flags)
    try:
        before = os.fstat(fd)
        after = folder.lstat()
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or
                _identity(before) != _identity(after)):
            raise CaseError("Handoff directory durability boundary unsafe")
        os.fsync(fd)
    finally:
        os.close(fd)


def handoff(store: CaseStore, case_id: str, *,
            confirm: bool = False, plan_sha256: str | None = None) -> dict[str, Any]:
    """Read-only preview, followed by explicit and fully reverified local export."""
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid handoff case identifier")
    if confirm:
        if not isinstance(plan_sha256, str) or SHA256.fullmatch(plan_sha256) is None:
            raise CaseError("Handoff confirmation requires preview SHA-256")
    elif plan_sha256 is not None:
        raise CaseError("Handoff preview cannot accept confirmation")
    with admission_lock(store):
        verify_committed_reserve(store)
        document = _snapshot(store, case_id)
        raw = _canonical(document)
        if len(raw) > MAX_OUTPUT_BYTES:
            raise CaseError("Handoff metadata exceeds fixed output limit")
        digest = hashlib.sha256(raw).hexdigest()
        base_result = {
            "case_id": case_id, "artifact_count": document["artifact_count"],
            "original_bytes_verified": document["original_bytes_verified"],
            "plan_sha256": digest, "scope": "metadata_only",
            "raw_originals_exported": 0,
        }
        if not confirm:
            return {"status": "PREVIEW_ONLY", **base_result,
                    "requires_explicit_confirmation": True}
        if digest != plan_sha256:
            raise CaseError("Handoff plan changed; verify and approve again")
        # Metadata is small, but it must not consume even the last available
        # byte of the locked 5 GiB reserve or a concurrent upload commitment.
        verify_committed_reserve(store, extra_bytes=MAX_OUTPUT_BYTES)
        exports = _export_directory(store)
        name = case_id + "-" + digest[:24] + ".json"
        final = exports / name
        if final.exists() or final.is_symlink():
            raise CaseError("Handoff destination already exists; refuse overwrite")
        if os.statvfs(exports).f_bavail * os.statvfs(exports).f_frsize < MAX_OUTPUT_BYTES:
            raise CaseError("Handoff destination lacks free space")
        # A durable, source-bound private journal MUST be published before
        # any scratch bytes. SIGKILL can then leave inspectable provenance.
        # Recovery is separate, explicit, and never deletes a committed final.
        work_id = secrets.token_hex(16)
        tmp = exports / (".tmp-handoff-" + work_id)
        journal = exports / (".handoff-work-" + work_id + ".json")
        journal_data = _canonical({
            "version": 1, "case_id": case_id, "work_id": work_id,
            "plan_sha256": digest, "temp_name": tmp.name,
            "final_name": name,
        })
        if len(journal_data) > 1024:
            raise CaseError("Handoff publication journal exceeds bound")
        journal_fd = os.open(
            journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(journal_fd, "wb") as stream:
                journal_fd = -1
                stream.write(journal_data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if journal_fd >= 0:
                os.close(journal_fd)
        _sync_directory(exports)

        # Do not unconditionally unlink scratch on failure: the journal must
        # remain able to prove exactly what interrupted work owns the file.
        fd = os.open(
            tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        _sync_directory(exports)
        if final.exists() or final.is_symlink():
            raise CaseError("Handoff destination changed before publication")
        os.link(tmp, final, follow_symlinks=False)
        _sync_directory(exports)
        tmp.unlink()
        _sync_directory(exports)

        info = final.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_size != len(raw)):
            raise CaseError("Published handoff file identity cannot be verified")
        with final.open("rb") as stream:
            copied = stream.read(MAX_OUTPUT_BYTES + 1)
        if len(copied) != len(raw) or hashlib.sha256(copied).hexdigest() != digest:
            raise CaseError("Published handoff digest cannot be verified")
        # Only release crash provenance after the final content is proven.
        journal.unlink()
        _sync_directory(exports)
        return {"status": "PRIVATE_METADATA_EXPORTED", **base_result,
                "export_name": name, "source_verified": True,
                "public_disclosure_approved": False,
                "raw_originals_exported": 0}
