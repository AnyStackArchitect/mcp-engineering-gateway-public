#!/usr/bin/env python3
"""Private, explicit, inspect-then-confirm retention for abandoned SSH uploads.

Never sweeps a case vault, regular staged inbox files, or legacy SCP uploads.
No scheduler or implicit deletion. A plan SHA-256 binds the exact identity and
timestamps of the eligible resumable sessions; confirmation re-scans while
holding exclusive locks and refuses any changed inventory.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from casework import CaseError, CaseStore
from resumable_transfer import _lock_file, read_meta, SESSION_TOKEN

SESSION_FILE = re.compile(r"^(\.upload-[a-f0-9]{32})\.session$")
MAX_INBOX_ENTRIES = 4096
MAX_RECLAIM = 64
MIN_AGE_HOURS = 24
MAX_AGE_HOURS = 365 * 24


def _age_hours(value: int) -> int:
    if type(value) is not int or not MIN_AGE_HOURS <= value <= MAX_AGE_HOURS:
        raise CaseError("Retention age must be 24 through 8760 whole hours")
    return value


def _fingerprint(meta: os.stat_result, source: os.stat_result | None) -> dict:
    def part(st: os.stat_result | None):
        if st is None:
            return None
        return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                st.st_ctime_ns, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink]
    return {"metadata": part(meta), "partial": part(source)}


def _validate_meta_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o077
            or not 0 < info.st_size <= 1024):
        raise CaseError("Untrusted private session metadata blocks retention")
    return info


def _eligible(store: CaseStore, older_hours: int, now_ns: int, stack: ExitStack) -> list[dict]:
    inbox = store.inbox
    entries = []
    with os.scandir(inbox) as iterator:
        for entry in iterator:
            entries.append(entry.name)
            if len(entries) > MAX_INBOX_ENTRIES:
                raise CaseError("Inbox inventory exceeds bounded retention scan")
    boundary = now_ns - older_hours * 3600 * 1_000_000_000
    candidates: list[dict] = []
    for name in sorted(entries):
        match = SESSION_FILE.fullmatch(name)
        if match is None:
            continue
        token = match.group(1)
        if SESSION_TOKEN.fullmatch(token) is None:
            raise CaseError("Retention session token invalid")
        meta_path = inbox / name
        meta = _validate_meta_file(meta_path)
        # Ignore recent sessions *before* requesting their upload locks. A
        # healthy writer should not obstruct stale-session inventory; this
        # check is conservative and all old candidates are revalidated below.
        if meta.st_mtime_ns >= boundary:
            continue
        source_path = inbox / token
        try:
            preliminary = source_path.lstat()
        except FileNotFoundError:
            preliminary = None
        if preliminary is not None and preliminary.st_mtime_ns >= boundary:
            continue
        doc = read_meta(store, token)
        if doc is None:
            raise CaseError("Retention session metadata disappeared")
        source = None
        try:
            # If the source is currently being written, an exclusive lock
            # refuses rather than waiting or racing a live upload.
            fileobj = stack.enter_context(_lock_file(source_path))
            _, source = fileobj
        except FileNotFoundError:
            source = None  # Orphaned metadata after a verified finalize crash.
        if source is not None and source.st_size > doc["size"]:
            raise CaseError("Oversized upload cannot be silently expired")
        recent = max(meta.st_mtime_ns, source.st_mtime_ns if source else 0)
        if recent >= boundary:
            continue
        if len(candidates) >= MAX_RECLAIM:
            raise CaseError("Too many eligible upload sessions; narrow the batch")
        candidates.append({
            "token": token,
            "bytes": source.st_size if source else 0,
            "orphan_metadata_only": source is None,
            "declared_size": doc["size"],
            "expected_sha256": doc["sha256"],
            "identity": _fingerprint(meta, source),
        })
    return candidates


def _plan_digest(older_hours: int, candidates: list[dict]) -> str:
    data = json.dumps({"version": 1, "older_hours": older_hours,
                       "candidates": candidates}, separators=(",", ":"),
                      sort_keys=True).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def inventory(store: CaseStore, *, older_hours: int = 72,
              expected_plan_sha256: str | None = None,
              confirm: bool = False, now_ns: int | None = None) -> dict:
    """Inspect or delete ONLY matching expired resumable sessions.

    Explicit confirmation must provide the hash returned by a prior preview.
    The whole candidate inventory is recalculated under source locks, and if
    any prior session identity changed, nothing is removed. Partial cleanup
    after an I/O failure is not reported as a complete success.
    """
    older_hours = _age_hours(older_hours)
    if confirm and (not isinstance(expected_plan_sha256, str)
                    or re.fullmatch(r"[a-f0-9]{64}", expected_plan_sha256) is None):
        raise CaseError("Explicit retention confirmation requires plan SHA-256")
    if not confirm and expected_plan_sha256 is not None:
        raise CaseError("Plan SHA-256 is accepted only with explicit confirmation")
    now = time.time_ns() if now_ns is None else now_ns
    if type(now) is not int or now < 0:
        raise CaseError("Invalid retention clock")
    store._ensure_store()
    with ExitStack() as locks:
        candidates = _eligible(store, older_hours, now, locks)
        digest = _plan_digest(older_hours, candidates)
        total = sum(item["bytes"] for item in candidates)
        if not confirm:
            return {
                "status": "PREVIEW_ONLY", "older_hours": older_hours,
                "eligible_sessions": len(candidates),
                "reclaimable_bytes": total,
                "orphan_metadata": sum(bool(c["orphan_metadata_only"]) for c in candidates),
                "plan_sha256": digest,
                "tokens": [item["token"] for item in candidates],
                "requires_explicit_confirmation": True,
            }
        if digest != expected_plan_sha256:
            raise CaseError("Retention inventory changed; inspect and approve a new plan")
        deleted = 0
        reclaimed = 0
        for item in candidates:
            token = item["token"]
            source_path = store.inbox / token
            meta_path = store.inbox / (token + ".session")
            current_meta = _validate_meta_file(meta_path)
            try:
                current_source = source_path.lstat()
            except FileNotFoundError:
                current_source = None
            if _fingerprint(current_meta, current_source) != item["identity"]:
                raise CaseError("Retention file identity changed during confirmation")
            if current_source is not None:
                if (not stat.S_ISREG(current_source.st_mode)
                        or current_source.st_nlink != 1
                        or current_source.st_uid != os.getuid()
                        or current_source.st_mode & 0o077):
                    raise CaseError("Unsafe upload blocks retention")
                source_path.unlink()
                reclaimed += current_source.st_size
            # Unlink source first: a crash between these unlinks leaves only
            # orphan metadata, which can be independently re-previewed later.
            meta_path.unlink()
            deleted += 1
        return {"status": "CONFIRMED_REMOVED", "older_hours": older_hours,
                "removed_sessions": deleted, "reclaimed_bytes": reclaimed,
                "plan_sha256": digest,
                "raw_evidence_exposed": False}
