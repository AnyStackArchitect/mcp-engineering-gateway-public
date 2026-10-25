#!/usr/bin/env python3
"""Additive, operator-local preservation declarations for private evidence cases.

No deletion, hold release, automatic expiry, publication, hosted approval,
or legal/policy authority. Each private record strengthens preservation only.
The local UID can still rewrite files: the digest chain detects many accidental
changes, but is NOT an independently trusted or tamper-proof audit log.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any

from capacitywork import admission_lock, verify_committed_reserve
from casework import CaseError, CaseStore, CASE_ID
from case_handoff import SHA256, _canonical, _sync_directory

DIRECTORY = "preservation"
RECORD_NAME = re.compile(r"^([0-9]{4})-([a-f0-9]{32})\.json$")
MAX_RECORDS = 128
MAX_RECORD_BYTES = 2048
MAX_RETENTION_DAYS = 3650
FIRST_SHA256 = "0" * 64
ACTIONS = frozenset({"PRESERVATION_HOLD", "MINIMUM_RETENTION_DAYS"})
HOLD_REASONS = frozenset({
    "investigation", "customer_request", "compliance_review", "external_hold_request",
})


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode),
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _directory(case_folder: Path, *, create: bool) -> Path | None:
    target = case_folder / DIRECTORY
    try:
        st = target.lstat()
    except FileNotFoundError:
        if not create:
            return None
        target.mkdir(mode=0o700)
        # A new child-directory name must be durable BEFORE any record is
        # created. An empty directory after interruption fails closed.
        _sync_directory(case_folder)
        st = target.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or st.st_mode & 0o077):
        raise CaseError("Preservation directory ownership, mode or type unsafe")
    return target


def _read_record(path: Path) -> tuple[dict[str, Any], str]:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_mode & 0o077 or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_RECORD_BYTES):
        raise CaseError("Preservation record identity or size unsafe")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if _identity(opened) != _identity(before):
            raise CaseError("Preservation record changed while opening")
        raw = bytearray()
        while len(raw) <= MAX_RECORD_BYTES:
            block = os.read(fd, min(4096, MAX_RECORD_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        final = path.lstat()
        if (len(raw) != before.st_size or len(raw) > MAX_RECORD_BYTES
                or _identity(before) != _identity(after)
                or _identity(before) != _identity(final)):
            raise CaseError("Preservation record changed during verification")
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CaseError("Preservation record contains invalid JSON") from exc
    if not isinstance(value, dict) or bytes(raw) != _canonical(value):
        raise CaseError("Preservation record is not canonical JSON")
    return value, hashlib.sha256(raw).hexdigest()


def _load_locked(folder: Path, case_id: str) -> dict[str, Any]:
    root = _directory(folder, create=False)
    if root is None:
        return {"record_count": 0, "head_sha256": FIRST_SHA256,
                "active_hold_count": 0, "minimum_retention_days": None,
                "record_directory_exists": False, "source_references": (),
                "record_heads": (), "hold_sequences": ()}
    # Stop inventory collection as soon as the fixed limit is exceeded.
    # Sorting an unbounded case directory before checking its size could
    # exhaust process memory on an invalid or hostile filesystem inventory.
    files: list[Path] = []
    with os.scandir(root) as entries:
        for entry in entries:
            files.append(Path(entry.path))
            if len(files) > MAX_RECORDS:
                raise CaseError("Preservation record inventory exceeds fixed bound")
    if not files:
        raise CaseError("Empty preservation directory needs operator investigation")
    files.sort(key=lambda path: path.name)
    previous = FIRST_SHA256
    floor: int | None = None
    holds = 0
    hold_sequences: list[int] = []
    # Internal only: do not disclose reference digests in operator reports.
    # Each source digest is read from the fully checked preservation chain.
    source_references: list[tuple[int, str]] = []
    # Private in-memory prefix identities for operator-supplied checkpoints.
    record_heads: list[str] = []
    last_recorded: datetime | None = None
    for sequence, path in enumerate(files, 1):
        match = RECORD_NAME.fullmatch(path.name)
        if match is None or int(match.group(1)) != sequence:
            raise CaseError("Preservation record filename or sequence invalid")
        document, digest = _read_record(path)
        base_keys = {"schema", "case_id", "sequence", "record_id", "action",
                     "recorded_at", "source_reference_sha256",
                     "case_manifest_sha256", "previous_sha256"}
        action = document.get("action")
        details = ({"reason_code"} if action == "PRESERVATION_HOLD"
                   else {"minimum_days"} if action == "MINIMUM_RETENTION_DAYS"
                   else set())
        if (not isinstance(action, str) or action not in ACTIONS or set(document) != base_keys | details
                or type(document.get("schema")) is not int or document["schema"] != 1
                or document.get("case_id") != case_id
                or type(document.get("sequence")) is not int
                or document["sequence"] != sequence
                or document.get("record_id") != match.group(2)
                or document.get("previous_sha256") != previous
                or not isinstance(document.get("source_reference_sha256"), str)
                or SHA256.fullmatch(document["source_reference_sha256"]) is None
                or not isinstance(document.get("case_manifest_sha256"), str)
                or SHA256.fullmatch(document["case_manifest_sha256"]) is None):
            raise CaseError("Preservation record schema, case or chain invalid")
        try:
            written = datetime.fromisoformat(document["recorded_at"])
        except (KeyError, ValueError, TypeError) as exc:
            raise CaseError("Preservation record timestamp invalid") from exc
        if written.tzinfo is None or written.utcoffset() != timedelta(0):
            raise CaseError("Preservation record must use UTC")
        if ((last_recorded is not None and written < last_recorded)
                or written > datetime.now(timezone.utc) + timedelta(minutes=5)):
            raise CaseError("Preservation record timestamp chronology invalid")
        last_recorded = written
        if action == "PRESERVATION_HOLD":
            if (not isinstance(document["reason_code"], str)
                    or document["reason_code"] not in HOLD_REASONS):
                raise CaseError("Unknown preservation reason code")
            holds += 1
            hold_sequences.append(sequence)
        else:
            days = document["minimum_days"]
            if (type(days) is not int or not 1 <= days <= MAX_RETENTION_DAYS
                    or (floor is not None and days <= floor)):
                raise CaseError("Non-monotonic or invalid minimum retention declaration")
            floor = days
        source_references.append((sequence, document["source_reference_sha256"]))
        record_heads.append(digest)
        previous = digest
    return {"record_count": len(files), "head_sha256": previous,
            "active_hold_count": holds, "minimum_retention_days": floor,
            "record_directory_exists": True,
            "source_references": tuple(source_references),
            "record_heads": tuple(record_heads),
            "hold_sequences": tuple(hold_sequences)}


def read_controls(store: CaseStore, case_id: str) -> dict[str, Any]:
    """Read one case's additive declarations; caller may hold admission lock."""
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid preservation case ID")
    with store._locked(case_id) as (folder, _):
        values = _load_locked(folder, case_id)
    # The full digest inventory is private implementation data: a normal
    # operator status must not expose potentially correlatable source hashes.
    references = values.pop("source_references")
    heads = values.pop("record_heads")
    holds = values.pop("hold_sequences")
    if (len(references) != values["record_count"]
            or len(heads) != values["record_count"]
            or len(holds) != values["active_hold_count"]):
        raise CaseError("Preservation reference inventory count mismatch")
    return {
        **values,
        "status": "OPERATOR_DECLARATIONS_UNVERIFIED" if values["record_count"] else "NO_DECLARATIONS",
        "source_reference_material_verified": False,
        "legal_hold_authority_verified": False,
        "hold_release_supported": False,
        "automatic_expiry_supported": False,
        "deletion_authorized": False,
    }


def _validate_change(action: str, reference_sha256: str,
                     reason_code: str | None, minimum_days: int | None,
                     confirm: bool, plan_sha256: str | None) -> None:
    if not isinstance(action, str) or action not in ACTIONS:
        raise CaseError("Preservation action is not allowlisted")
    if not isinstance(reference_sha256, str) or SHA256.fullmatch(reference_sha256) is None:
        raise CaseError("Preservation source reference must be a SHA-256 digest")
    if action == "PRESERVATION_HOLD":
        if (not isinstance(reason_code, str) or reason_code not in HOLD_REASONS
                or minimum_days is not None):
            raise CaseError("Preservation hold reason must be allowlisted")
    elif reason_code is not None or type(minimum_days) is not int or not 1 <= minimum_days <= MAX_RETENTION_DAYS:
        raise CaseError("Minimum retention days must be 1 through 3650")
    if confirm:
        if not isinstance(plan_sha256, str) or SHA256.fullmatch(plan_sha256) is None:
            raise CaseError("Preservation confirmation requires exact preview SHA-256")
    elif plan_sha256 is not None:
        raise CaseError("Preservation preview cannot carry confirmation digest")


def propose_or_record(store: CaseStore, case_id: str, *,
                      action: str, reference_sha256: str,
                      reason_code: str | None = None,
                      minimum_days: int | None = None,
                      confirm: bool = False,
                      plan_sha256: str | None = None) -> dict[str, Any]:
    """Review/confirm one additive source-reference-linked protection.

    Preview creates no preservation directory; confirmation does not write
    case originals, source manifests, handoffs, policy authorities or holds
    releases. A late ambiguous write remains inspectable, never auto-removed.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid preservation case ID")
    _validate_change(action, reference_sha256, reason_code,
                     minimum_days, confirm, plan_sha256)
    with admission_lock(store):
        with store._locked(case_id) as (folder, manifest):
            state = _load_locked(folder, case_id)
            if state["record_count"] >= MAX_RECORDS:
                raise CaseError("Preservation record capacity reached")
            if (action == "MINIMUM_RETENTION_DAYS"
                    and state["minimum_retention_days"] is not None
                    and minimum_days <= state["minimum_retention_days"]):
                raise CaseError("Preservation minimum cannot be lowered or re-declared")
            proposal: dict[str, Any] = {
                "schema": 1, "scope": "additive_preservation_only",
                "case_id": case_id, "action": action,
                "source_reference_sha256": reference_sha256,
                "manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
                "record_count_before": state["record_count"],
                "previous_sha256": state["head_sha256"],
            }
            if action == "PRESERVATION_HOLD":
                proposal["reason_code"] = reason_code
            else:
                proposal["minimum_days"] = minimum_days
            digest = hashlib.sha256(_canonical(proposal)).hexdigest()
            base = {"case_id": case_id, "action": action,
                    "plan_sha256": digest,
                    "record_count_before": state["record_count"],
                    "source_reference_material_verified": False,
                    "legal_hold_authority_verified": False,
                    "hold_release_supported": False,
                    "deletion_authorized": False,
                    "originals_removed": 0, "raw_originals_exported": 0}
            if not confirm:
                return {"status": "PREVIEW_ONLY", **base,
                        "requires_explicit_confirmation": True}
            if digest != plan_sha256:
                raise CaseError("Preservation review plan changed; preview again")
            verify_committed_reserve(store, extra_bytes=MAX_RECORD_BYTES + 4096)
            root = _directory(folder, create=True)
            record_id = secrets.token_hex(16)
            event = {
                "schema": 1, "case_id": case_id,
                "sequence": state["record_count"] + 1,
                "record_id": record_id, "action": action,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "source_reference_sha256": reference_sha256,
                "case_manifest_sha256": proposal["manifest_sha256"],
                "previous_sha256": state["head_sha256"],
            }
            if action == "PRESERVATION_HOLD":
                event["reason_code"] = reason_code
            else:
                event["minimum_days"] = minimum_days
            payload = _canonical(event)
            if len(payload) > MAX_RECORD_BYTES:
                raise CaseError("Preservation record exceeds hard output bound")
            target = root / f"{event['sequence']:04d}-{record_id}.json"
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)
            _sync_directory(root)
            # Never report a committed record based only on a write call:
            # verify the whole chain, including the exact newly created tail.
            resulting = _load_locked(folder, case_id)
            tail_digest = hashlib.sha256(payload).hexdigest()
            if (resulting["record_count"] != state["record_count"] + 1
                    or resulting["head_sha256"] != tail_digest):
                raise CaseError("Preservation record readback or chain mismatch")
            return {"status": "PRESERVATION_RECORD_COMMITTED", **base,
                    "record_sha256": tail_digest,
                    "record_count_after": resulting["record_count"],
                    "active_preservation_holds": resulting["active_hold_count"],
                    "declared_minimum_days": resulting["minimum_retention_days"]}
