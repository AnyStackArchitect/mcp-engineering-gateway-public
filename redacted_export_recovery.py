#!/usr/bin/env python3
"""Explicit recovery of one source-bound private redacted-export transaction.

Acquiring the common admission lock excludes a cooperating live publisher.
Preview hashes the complete bounded output inventory and fully rechecks the
original source plan; confirmation repeats both checks. Recovery can retire
only the exact journal and its proven scratch file. It never publishes,
rewrites or deletes a final ZIP, changes originals, or authorizes disclosure.
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
from case_handoff import _canonical, _identity, _private_optional, _sync_directory, SHA256
from casework import CASE_ID, CaseError, CaseStore, _regular_open
from redacted_export import (FINAL_NAME, MAX_JOURNAL, MAX_PACKAGE, OUT_DIR,
                             _bounded_entries, _verified_plan)

WORK_ID = re.compile(r"^[a-f0-9]{32}$")
JOURNAL_NAME = re.compile(r"^[.]review-work-([a-f0-9]{32})[.]json$")
TEMP_NAME = re.compile(r"^[.]tmp-review-([a-f0-9]{32})$")
MAX_MINIMUM_AGE_SECONDS = 365 * 24 * 3600


def _owned(path: Path, *, links: tuple[int, ...] = (1,)) -> os.stat_result:
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
            or value.st_mode & 0o077 or value.st_nlink not in links):
        raise CaseError("Redacted recovery file ownership, type or links unsafe")
    return value


def _hashed(path: Path, *, limit: int,
            links: tuple[int, ...] = (1,)) -> dict[str, Any]:
    before = _owned(path, links=links)
    if before.st_size > limit:
        raise CaseError("Redacted recovery file exceeds bounded size")
    fd, opened = _regular_open(path)
    try:
        if _identity(opened) != _identity(before):
            raise CaseError("Redacted recovery file changed on open")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or len(raw) > limit
                or _identity(before) != _identity(after)
                or _identity(before) != _identity(_owned(path, links=links))):
            raise CaseError("Redacted recovery file changed while reading")
    finally:
        if fd >= 0:
            os.close(fd)
    return {"identity": list(_identity(before)),
            "sha256": hashlib.sha256(raw).hexdigest(), "raw": raw}


def _journal(raw: bytes, work_id: str) -> dict[str, Any]:
    """Parse exact private provenance; schema 1 is recognizable but unbound."""
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise CaseError("Redacted recovery journal malformed; manual review required") from exc
    old_keys = {"schema", "package_name", "package_sha256", "preview_sha256",
                "tmp_name", "transaction_id"}
    new_keys = old_keys | {"case_id", "source_snapshot_sha256", "package_size_bytes"}
    if (not isinstance(doc, dict) or type(doc.get("schema")) is not int
            or doc["schema"] not in (1, 2)
            or set(doc) != (new_keys if doc["schema"] == 2 else old_keys)
            or not isinstance(doc["package_sha256"], str)
            or SHA256.fullmatch(doc["package_sha256"]) is None
            or not isinstance(doc["preview_sha256"], str)
            or SHA256.fullmatch(doc["preview_sha256"]) is None
            or doc["package_name"] != "redacted-" + doc["preview_sha256"][:24] + ".zip"
            or doc["tmp_name"] != ".tmp-review-" + work_id
            or doc["transaction_id"] != work_id
            or raw != _canonical(doc)):
        raise CaseError("Redacted recovery journal identity invalid; manual review required")
    if doc["schema"] == 2 and (
            not isinstance(doc["case_id"], str)
            or CASE_ID.fullmatch(doc["case_id"]) is None
            or not isinstance(doc["source_snapshot_sha256"], str)
            or SHA256.fullmatch(doc["source_snapshot_sha256"]) is None
            or type(doc["package_size_bytes"]) is not int
            or not 0 < doc["package_size_bytes"] <= MAX_PACKAGE):
        raise CaseError("Redacted recovery journal source binding invalid")
    return doc


def _folder(store: CaseStore) -> Path | None:
    result = store.base / OUT_DIR
    return result if _private_optional(result, "Private redacted recovery") else None


def _directory_key(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode))


def _inventory(exports: Path) -> dict[str, Any]:
    if not _private_optional(exports, "Private redacted recovery"):
        raise CaseError("Redacted recovery directory disappeared")
    directory = exports.lstat()
    records: dict[str, dict[str, Any]] = {}
    journals: dict[str, dict[str, Any]] = {}
    legacy = malformed = orphans = 0
    for path in _bounded_entries(exports):
        journal_match = JOURNAL_NAME.fullmatch(path.name)
        temp_match = TEMP_NAME.fullmatch(path.name)
        if journal_match:
            record = _hashed(path, limit=MAX_JOURNAL)
            try:
                doc = _journal(record["raw"], journal_match.group(1))
            except CaseError:
                malformed += 1
            else:
                journals[journal_match.group(1)] = doc
                legacy += int(doc["schema"] == 1)
            record["kind"] = "journal"
        elif temp_match:
            record = _hashed(path, limit=MAX_PACKAGE, links=(1, 2))
            record["kind"] = "scratch"
        elif FINAL_NAME.fullmatch(path.name):
            record = _hashed(path, limit=MAX_PACKAGE, links=(1, 2))
            if not record["raw"]:
                raise CaseError("Redacted recovery final package is empty")
            record["kind"] = "final"
        else:
            raise CaseError("Unexpected redacted recovery entry; manual review required")
        records[path.name] = record

    destinations: set[str] = set()
    permitted_links: set[str] = set()
    for work_id, doc in journals.items():
        if doc["package_name"] in destinations:
            raise CaseError("Ambiguous redacted recovery destination journals")
        destinations.add(doc["package_name"])
        temporary = records.get(doc["tmp_name"])
        final = records.get(doc["package_name"])
        if temporary is not None and final is not None:
            if (temporary["identity"] != final["identity"]
                    or temporary["identity"][4] != 2):
                raise CaseError("Redacted recovery scratch and final identity disagree")
            permitted_links.update((doc["tmp_name"], doc["package_name"]))
    for name, record in records.items():
        match = TEMP_NAME.fullmatch(name)
        if match and match.group(1) not in journals:
            orphans += 1
        if record["identity"][4] != (2 if name in permitted_links else 1):
            raise CaseError("Redacted recovery file has an unexplained hardlink")
    if _identity(directory) != _identity(exports.lstat()):
        raise CaseError("Redacted recovery directory changed during inventory")
    return {"directory_identity": list(_identity(directory)), "records": records,
            "journals": journals, "legacy_journals": legacy,
            "malformed_journals": malformed, "orphan_scratch_files": orphans,
            "manual_review_entries": legacy + malformed + orphans}


def list_interrupted(store: CaseStore, case_id: str) -> dict[str, Any]:
    """Discover opaque work IDs, never source metadata or raw journal bytes."""
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid redacted recovery case identifier")
    with admission_lock(store):
        exports = _folder(store)
        if exports is None:
            return {"status": "PASS", "redacted_export_work_ids": [],
                    "manual_review_entries": 0, "legacy_journals": 0,
                    "malformed_journals": 0, "orphan_scratch_files": 0}
        inventory = _inventory(exports)
        work_ids = sorted(work for work, journal in inventory["journals"].items()
                          if journal["schema"] == 2 and journal["case_id"] == case_id)
        return {"status": "PARTIAL" if inventory["manual_review_entries"] else "PASS",
                "redacted_export_work_ids": work_ids,
                **{key: inventory[key] for key in
                   ("manual_review_entries", "legacy_journals", "malformed_journals",
                    "orphan_scratch_files")}}


def _preview(store: CaseStore, exports: Path, case_id: str, work_id: str,
             minimum_age_seconds: int, now_ns: int) -> tuple[dict[str, Any], dict[str, Any]]:
    inventory = _inventory(exports)
    if inventory["manual_review_entries"]:
        raise CaseError("Unbound redacted recovery entries require manual review")
    doc = inventory["journals"].get(work_id)
    if doc is None or doc["schema"] != 2 or doc["case_id"] != case_id:
        raise CaseError("Redacted recovery journal has no matching source case")
    payload, package_sha, source_plan, source_sha = _verified_plan(store, case_id)
    if (doc["preview_sha256"] != source_plan
            or doc["source_snapshot_sha256"] != source_sha
            or doc["package_sha256"] != package_sha
            or doc["package_size_bytes"] != len(payload)):
        raise CaseError("Redacted recovery source plan changed; manual review required")
    records = inventory["records"]
    temporary = records.get(doc["tmp_name"])
    final = records.get(doc["package_name"])
    if temporary is not None and not payload.startswith(temporary["raw"]):
        raise CaseError("Redacted recovery scratch is not the exact package prefix")
    if final is not None and final["raw"] != payload:
        raise CaseError("Redacted recovery committed package bytes invalid")
    if temporary is not None and final is not None and temporary["raw"] != payload:
        raise CaseError("Redacted recovery linked package is incomplete")
    selected = [records[".review-work-" + work_id + ".json"]]
    selected.extend(item for item in (temporary, final) if item is not None)
    last_write = max(item["identity"][6] for item in selected)
    if minimum_age_seconds and now_ns - last_write < minimum_age_seconds * 1_000_000_000:
        raise CaseError("Redacted recovery files are too recent for the requested minimum age")
    if list(_identity(exports.lstat())) != inventory["directory_identity"]:
        raise CaseError("Redacted recovery inventory changed during source verification")
    disposition = "COMMITTED" if final is not None else "INTERRUPTED"
    statement = {
        "schema": 1, "case_id": case_id, "work_id": work_id,
        "minimum_age_seconds": minimum_age_seconds,
        "source_review_fingerprint_sha256": source_plan,
        "source_snapshot_sha256": source_sha,
        "directory_identity": inventory["directory_identity"],
        "observed_files": [{"name": name, "kind": item["kind"],
                            "identity": item["identity"], "sha256": item["sha256"]}
                           for name, item in sorted(records.items())],
        "disposition": disposition,
    }
    response = {
        "status": "PREVIEW_ONLY", "work_id": work_id,
        "disposition": disposition,
        "recovery_plan_sha256": hashlib.sha256(_canonical(statement)).hexdigest(),
        "minimum_age_seconds": minimum_age_seconds,
        "scratch_bytes": len(temporary["raw"]) if temporary is not None else 0,
        "scratch_files_to_remove": int(temporary is not None),
        "journal_files_to_remove": 1,
        "source_full_sha256_checked": True, "source_snapshot_reverified": True,
        "requires_explicit_confirmation": True,
        "registered_originals_removed": 0, "committed_packages_removed": 0,
        "raw_originals_exported": 0, "network_upload_performed": False,
        "public_disclosure_approved": False,
    }
    return response, inventory


def _assert_directory(exports: Path, directory_fd: int,
                      expected: list[int]) -> None:
    if not _private_optional(exports, "Private redacted recovery"):
        raise CaseError("Redacted recovery directory disappeared")
    opened = os.fstat(directory_fd)
    current = exports.lstat()
    wanted = (expected[0], expected[1], expected[3], expected[5])
    if (_directory_key(opened) != wanted or _directory_key(current) != wanted
            or not stat.S_ISDIR(opened.st_mode)):
        raise CaseError("Redacted recovery directory identity changed")


def _unlink_exact(exports: Path, directory_fd: int, name: str,
                  expected: list[int], directory: list[int]) -> None:
    _assert_directory(exports, directory_fd, directory)
    observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(observed.st_mode) or list(_identity(observed)) != expected:
        raise CaseError("Redacted recovery deletion identity changed")
    # An open, verified directory anchors this exact opaque basename. A
    # replaced parent path cannot redirect cleanup to a different directory.
    os.unlink(name, dir_fd=directory_fd)


def _check_remaining(exports: Path, before: dict[str, Any], doc: dict[str, Any],
                     *, removed_scratch: bool) -> None:
    """Recheck every survivor before retiring the only provenance journal."""
    after = _inventory(exports)
    wanted = set(before["records"])
    if removed_scratch:
        wanted.remove(doc["tmp_name"])
    if set(after["records"]) != wanted or after["manual_review_entries"]:
        raise CaseError("Redacted recovery surviving inventory changed")
    for name in wanted:
        old = before["records"][name]
        new = after["records"][name]
        if new["sha256"] != old["sha256"] or new["raw"] != old["raw"]:
            raise CaseError("Redacted recovery surviving file content changed")
        if name == doc["package_name"] and removed_scratch:
            # Retiring exactly the scratch hardlink changes only nlink/ctime.
            fixed_fields = (0, 1, 2, 3, 5, 6)
            if (any(new["identity"][i] != old["identity"][i] for i in fixed_fields)
                    or new["identity"][4] != 1):
                raise CaseError("Redacted recovery committed package identity changed")
        elif new["identity"] != old["identity"]:
            raise CaseError("Redacted recovery surviving file identity changed")


def recover(store: CaseStore, case_id: str, work_id: str, *,
            confirm: bool = False, recovery_plan_sha256: str | None = None,
            minimum_age_seconds: int = 0, now_ns: int | None = None) -> dict[str, Any]:
    """Preview or explicitly retire ONE verified interrupted transaction.

    Immediate recovery is allowed after acquiring the publisher's admission
    lock. An operator may choose an additional minimum age, which is included
    in the fingerprint. No time override is exposed by the operator CLI.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid redacted recovery case identifier")
    if not isinstance(work_id, str) or WORK_ID.fullmatch(work_id) is None:
        raise CaseError("Invalid redacted recovery work identifier")
    if type(confirm) is not bool:
        raise CaseError("Redacted recovery confirmation must be explicit")
    if confirm and (not isinstance(recovery_plan_sha256, str)
                    or SHA256.fullmatch(recovery_plan_sha256) is None):
        raise CaseError("Redacted recovery confirmation requires a preview fingerprint")
    if not confirm and recovery_plan_sha256 is not None:
        raise CaseError("Redacted recovery preview cannot accept confirmation")
    if (type(minimum_age_seconds) is not int
            or not 0 <= minimum_age_seconds <= MAX_MINIMUM_AGE_SECONDS):
        raise CaseError("Redacted recovery minimum age is outside its bounded range")
    if now_ns is not None and (type(now_ns) is not int or now_ns < 0):
        raise CaseError("Redacted recovery clock invalid")
    with admission_lock(store):
        timestamp = time.time_ns() if now_ns is None else now_ns
        exports = _folder(store)
        if exports is None:
            raise CaseError("No redacted recovery directory exists")
        state, inventory = _preview(store, exports, case_id, work_id,
                                    minimum_age_seconds, timestamp)
        if not confirm:
            return state
        if state["recovery_plan_sha256"] != recovery_plan_sha256:
            raise CaseError("Redacted recovery plan changed; repeat preview")
        doc = inventory["journals"][work_id]
        temporary = inventory["records"].get(doc["tmp_name"])
        directory_fd = os.open(exports, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0))
        try:
            _assert_directory(exports, directory_fd, inventory["directory_identity"])
            if temporary is not None:
                _unlink_exact(exports, directory_fd, doc["tmp_name"],
                              temporary["identity"], inventory["directory_identity"])
                _sync_directory(exports)
            _check_remaining(exports, inventory, doc,
                             removed_scratch=temporary is not None)
            journal_name = ".review-work-" + work_id + ".json"
            _unlink_exact(exports, directory_fd, journal_name,
                          inventory["records"][journal_name]["identity"],
                          inventory["directory_identity"])
            _sync_directory(exports)
        finally:
            os.close(directory_fd)
        return {**state,
                "status": ("COMMITTED_JOURNAL_CLEARED" if state["disposition"] == "COMMITTED"
                           else "INTERRUPTED_SCRATCH_CLEARED"),
                "requires_explicit_confirmation": False,
                "scratch_files_to_remove": 0, "journal_files_to_remove": 0,
                "removed_unpublished_files": int(temporary is not None),
                "removed_journal_files": 1,
                "private_storage_only": True}
