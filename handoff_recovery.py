#!/usr/bin/env python3
"""Explicit source-bound cleanup of interrupted metadata-only case handoffs.

The local non-root operator must list, preview one journaled transaction aged
24+ hours, and separately confirm its exact SHA-256 plan. A committed private
handoff is NEVER deleted, and case originals are never opened for mutation.
Unknown/legacy unjournaled .tmp-handoff files remain manual-review blockers.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from capacitywork import admission_lock
from casework import CaseStore, CaseError, CASE_ID, _regular_open
from case_handoff import (MAX_OUTPUT_BYTES, MAX_ARTIFACTS, OUT_DIR, SHA256,
                          KIND, _canonical, _export_directory, _identity,
                          _sync_directory)

WORK_ID = re.compile(r"^[a-f0-9]{32}$")
JOURNAL = re.compile(r"^\.handoff-work-([a-f0-9]{32})\.json$")
TEMP = re.compile(r"^\.tmp-handoff-([a-f0-9]{32})$")
MAX_JOURNAL = 1024
MAX_ENTRIES = 512
MAX_AGE_HOURS = 8760


def _owned(path: Path, *, links: tuple[int, ...] = (1,)) -> os.stat_result:
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
            or st.st_mode & 0o077 or st.st_nlink not in links):
        raise CaseError("Handoff recovery file type, ownership or links unsafe")
    return st


def _hashed(path: Path, *, links: tuple[int, ...] = (1,),
            limit: int = MAX_OUTPUT_BYTES) -> tuple[list[int], str, bytes]:
    before = _owned(path, links=links)
    if before.st_size > limit:
        raise CaseError("Handoff recovery file exceeds bounded size")
    fd, opened = _regular_open(path)
    if _identity(opened) != _identity(before):
        os.close(fd)
        raise CaseError("Handoff recovery file changed on open")
    data = bytearray()
    hasher = hashlib.sha256()
    try:
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            while len(data) <= limit:
                block = stream.read(min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
                hasher.update(block)
            after = os.fstat(stream.fileno())
        if (len(data) > limit or len(data) != before.st_size
                or _identity(before) != _identity(after)
                or _identity(before) != _identity(_owned(path, links=links))):
            raise CaseError("Handoff recovery file identity changed while hashing")
    finally:
        if fd >= 0:
            os.close(fd)
    return list(_identity(before)), hasher.hexdigest(), bytes(data)


def _validate_published(raw: bytes, case_id: str, expected_digest: str) -> None:
    """A committed file must be the exact allowlisted canonical v0.24 format."""
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise CaseError("Committed handoff metadata malformed") from exc
    if (not isinstance(doc, dict) or
            set(doc) != {"schema", "scope", "case_id", "created_at",
                         "artifact_count", "original_bytes_verified", "artifacts"} or
            type(doc["schema"]) is not int or doc["schema"] != 1 or
            doc["scope"] != "private_metadata_only_no_raw_evidence" or
            doc["case_id"] != case_id or
            not isinstance(doc["created_at"], str) or len(doc["created_at"]) > 64 or
            type(doc["artifact_count"]) is not int or
            not 0 < doc["artifact_count"] <= MAX_ARTIFACTS or
            not isinstance(doc["artifacts"], list) or
            len(doc["artifacts"]) != doc["artifact_count"] or
            type(doc["original_bytes_verified"]) is not int or
            doc["original_bytes_verified"] < 0):
        raise CaseError("Committed handoff metadata violates private schema")
    seen: set[str] = set()
    byte_sum = 0
    for item in doc["artifacts"]:
        if (not isinstance(item, dict) or
                set(item) not in (
                    {"artifact_id", "sha256", "bytes", "type"},
                    {"artifact_id", "sha256", "bytes", "type", "derived_from"})):
            raise CaseError("Committed handoff artifact metadata not allowlisted")
        aid = item["artifact_id"]
        if (not isinstance(aid, str) or CASE_ID.fullmatch(aid) is None or aid in seen
                or not isinstance(item["sha256"], str)
                or SHA256.fullmatch(item["sha256"]) is None
                or type(item["bytes"]) is not int or item["bytes"] < 0
                or not isinstance(item["type"], str) or KIND.fullmatch(item["type"]) is None):
            raise CaseError("Committed handoff artifact identity invalid")
        if "derived_from" in item and (not isinstance(item["derived_from"], str)
                or CASE_ID.fullmatch(item["derived_from"]) is None):
            raise CaseError("Committed handoff source ID invalid")
        seen.add(aid)
        byte_sum += item["bytes"]
    if (byte_sum != doc["original_bytes_verified"] or
            hashlib.sha256(raw).hexdigest() != expected_digest or
            raw != _canonical(doc)):
        raise CaseError("Committed handoff metadata bytes do not match approved plan")


def _journal(path: Path, work_id: str,
             case_id: str | None = None) -> tuple[dict[str, Any], list[int], str]:
    identity, digest, raw = _hashed(path, limit=MAX_JOURNAL)
    if not 0 < len(raw) <= MAX_JOURNAL:
        raise CaseError("Handoff publication journal length invalid")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise CaseError("Handoff publication journal malformed") from exc
    if (not isinstance(doc, dict) or
            set(doc) != {"version", "case_id", "work_id", "plan_sha256",
                         "temp_name", "final_name"} or
            type(doc["version"]) is not int or doc["version"] != 1 or
            not isinstance(doc["case_id"], str) or
            CASE_ID.fullmatch(doc["case_id"]) is None or
            (case_id is not None and doc["case_id"] != case_id) or
            doc["work_id"] != work_id or
            not isinstance(doc["plan_sha256"], str) or
            SHA256.fullmatch(doc["plan_sha256"]) is None or
            doc["temp_name"] != ".tmp-handoff-" + work_id or
            doc["final_name"] != doc["case_id"] + "-" + doc["plan_sha256"][:24] + ".json" or
            raw != _canonical(doc)):
        raise CaseError("Handoff publication journal identity invalid")
    return doc, identity, digest


def _folder(store: CaseStore) -> Path | None:
    store._ensure_store()
    exports = store.base / OUT_DIR
    try:
        info = exports.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise CaseError("Handoff recovery export directory unsafe")
    return exports


def list_interrupted(store: CaseStore, case_id: str) -> dict[str, Any]:
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid handoff case identifier")
    with admission_lock(store):
        exports = _folder(store)
        if exports is None:
            return {"status": "PASS", "case_id": case_id,
                    "handoff_work_ids": [], "unmatched_temp_entries": 0}
        entries = list(exports.iterdir())
        if len(entries) > MAX_ENTRIES:
            raise CaseError("Handoff recovery inventory too large")
        ids: list[str] = []
        unmatched = 0
        for entry in entries:
            match = JOURNAL.fullmatch(entry.name)
            if match:
                # Shared private handoff directory may contain other cases;
                # validate journals for each case before selecting one.
                journal, _, _ = _journal(entry, match.group(1))
                if journal["case_id"] == case_id:
                    ids.append(match.group(1))
            elif entry.name.startswith(".tmp-handoff-") and (
                    TEMP.fullmatch(entry.name) is None):
                unmatched += 1
            elif TEMP.fullmatch(entry.name):
                token = TEMP.fullmatch(entry.name).group(1)
                if not (exports / (".handoff-work-" + token + ".json")).exists():
                    unmatched += 1
        return {"status": "PARTIAL" if unmatched else "PASS",
                "case_id": case_id, "handoff_work_ids": sorted(ids),
                "unmatched_temp_entries": unmatched}


def _scan(exports: Path, case_id: str, work_id: str,
          older_hours: int, now_ns: int) -> tuple[dict[str, Any], list[tuple[Path, list[int]]]]:
    if not isinstance(work_id, str) or WORK_ID.fullmatch(work_id) is None:
        raise CaseError("Invalid handoff recovery work identifier")
    if type(older_hours) is not int or not 24 <= older_hours <= MAX_AGE_HOURS:
        raise CaseError("Handoff recovery age must be 24 through 8760 hours")
    entries = list(exports.iterdir())
    if len(entries) > MAX_ENTRIES:
        raise CaseError("Handoff recovery inventory too large")
    journal = exports / (".handoff-work-" + work_id + ".json")
    doc, journal_identity, journal_sha = _journal(journal, work_id, case_id)
    tmp = exports / doc["temp_name"]
    final = exports / doc["final_name"]
    if any(p.name.startswith(".tmp-handoff-" + work_id) and
           p.name != tmp.name for p in entries):
        raise CaseError("Unexpected handoff sidecar for this work ID")
    temp_stat = None
    final_stat = None
    try:
        temp_stat = tmp.lstat()
    except FileNotFoundError:
        pass
    try:
        final_stat = final.lstat()
    except FileNotFoundError:
        pass
    if temp_stat and final_stat:
        if (temp_stat.st_dev != final_stat.st_dev or
                temp_stat.st_ino != final_stat.st_ino or
                temp_stat.st_nlink != 2 or final_stat.st_nlink != 2):
            raise CaseError("Handoff published metadata and scratch do not share exact identity")
    observations = [
        {"name": journal.name, "identity": journal_identity, "sha256": journal_sha}]
    clean: list[tuple[Path, list[int]]] = []
    age_ns = journal_identity[6]
    if temp_stat:
        identity, sha, _ = _hashed(tmp, links=(2,) if final_stat else (1,))
        observations.append({"name": tmp.name, "identity": identity, "sha256": sha})
        clean.append((tmp, identity))
        age_ns = max(age_ns, identity[6])
    if final_stat:
        identity, sha, raw = _hashed(final, links=(2,) if temp_stat else (1,))
        if sha != doc["plan_sha256"]:
            raise CaseError("Published handoff has incorrect approved SHA-256")
        _validate_published(raw, case_id, doc["plan_sha256"])
        observations.append({"name": final.name, "identity": identity, "sha256": sha})
        age_ns = max(age_ns, identity[6])
    if now_ns - age_ns < older_hours * 3600 * 1_000_000_000:
        raise CaseError("Handoff recovery files are too recent")
    disposition = "COMMITTED" if final_stat else "INTERRUPTED"
    statement = {
        "case_id": case_id, "work_id": work_id,
        "plan_sha256": doc["plan_sha256"], "disposition": disposition,
        "observed_files": observations,
        "scratch_bytes": temp_stat.st_size if temp_stat else 0,
    }
    digest = hashlib.sha256(_canonical(statement)).hexdigest()
    return {"status": "PREVIEW_ONLY", **statement, "recovery_plan_sha256": digest,
            "requires_explicit_confirmation": True,
            "registered_originals_removed": 0, "committed_handoffs_removed": 0}, clean


def recover(store: CaseStore, case_id: str, work_id: str, *,
            older_hours: int = 24, confirm: bool = False,
            recovery_plan_sha256: str | None = None,
            now_ns: int | None = None) -> dict[str, Any]:
    if confirm and (not isinstance(recovery_plan_sha256, str)
                    or SHA256.fullmatch(recovery_plan_sha256) is None):
        raise CaseError("Handoff recovery confirmation needs a preview plan")
    if not confirm and recovery_plan_sha256 is not None:
        raise CaseError("Handoff recovery preview cannot accept a confirmation hash")
    timestamp = time.time_ns() if now_ns is None else now_ns
    if type(timestamp) is not int or timestamp < 0:
        raise CaseError("Handoff recovery clock invalid")
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid handoff case identifier")
    with admission_lock(store):
        exports = _folder(store)
        if exports is None:
            raise CaseError("No handoff recovery directory exists")
        state, remove = _scan(exports, case_id, work_id, older_hours, timestamp)
        if not confirm:
            return state
        if state["recovery_plan_sha256"] != recovery_plan_sha256:
            raise CaseError("Handoff recovery plan changed; inspect again")
        for target, expected in remove:
            st = _owned(target, links=(2,) if state["disposition"] == "COMMITTED" else (1,))
            if list(_identity(st)) != expected:
                raise CaseError("Handoff recovery scratch identity changed")
            target.unlink()
        if remove:
            _sync_directory(exports)
        if state["disposition"] == "COMMITTED":
            # Removing a second hardlink changes ctime/nlink, but must NOT
            # change final inode, bytes, canonical schema or source digest.
            final = exports / (case_id + "-" + state["plan_sha256"][:24] + ".json")
            original = next(entry["identity"] for entry in state["observed_files"]
                            if entry["name"] == final.name)
            final_now, digest, raw = _hashed(final, links=(1,))
            if final_now[:2] != original[:2] or digest != state["plan_sha256"]:
                raise CaseError("Committed handoff changed during recovery")
            _validate_published(raw, case_id, state["plan_sha256"])
        journal = exports / (".handoff-work-" + work_id + ".json")
        if list(_identity(_owned(journal))) != state["observed_files"][0]["identity"]:
            raise CaseError("Handoff journal changed during recovery")
        journal.unlink()
        _sync_directory(exports)
        return {
            "status": ("COMMITTED_JOURNAL_CLEARED" if state["disposition"] == "COMMITTED"
                       else "INTERRUPTED_SCRATCH_CLEARED"),
            "case_id": case_id, "work_id": work_id,
            "recovery_plan_sha256": recovery_plan_sha256,
            "removed_unpublished_files": len(remove),
            "reclaimed_bytes": state["scratch_bytes"] if state["disposition"] == "INTERRUPTED" else 0,
            "registered_originals_removed": 0,
            "committed_handoffs_removed": 0,
        }
