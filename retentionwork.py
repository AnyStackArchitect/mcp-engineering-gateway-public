#!/usr/bin/env python3
"""Non-destructive, operator-only registered-case retention assessment.

The minimum age is an operator-supplied review threshold, NOT a retention
policy or permission to erase evidence. No raw evidence, original filenames,
MCP action, network export, scheduled action, or deletion is provided.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
import re
import stat
from typing import Any

from capacitywork import admission_lock, outstanding_reservations
from casework import CaseError, CaseStore, CASE_ID, INDEX_INVENTORY_LIMIT
from case_handoff import _canonical, _snapshot
from handoff_recovery import (_folder, _journal, _hashed, _validate_published,
                              JOURNAL, TEMP, MAX_ENTRIES)
from preservationwork import read_controls

MIN_DAYS = 1
MAX_DAYS = 3650
FINAL_NAME = re.compile(r"^([a-f0-9]{32})-([a-f0-9]{24})\.json$")


def _index_inventory(store: CaseStore, case_id: str) -> int:
    """Reject unknown, unprivileged, linked or unfinished index files."""
    with store._locked(case_id) as (folder, manifest):
        indexes = list((folder / "indexes").iterdir())
        if len(indexes) > INDEX_INVENTORY_LIMIT:
            raise CaseError("Retention index inventory exceeds safety bound")
        complete = 0
        for item in indexes:
            if (not item.name.endswith(".sqlite3") or
                    item.name[:-8] not in manifest["artifacts"]):
                raise CaseError("Retention blocked by unknown or unfinished index")
            meta = item.lstat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                    or meta.st_nlink != 1 or meta.st_mode & 0o077):
                raise CaseError("Retention index file identity unsafe")
            complete += 1
        return complete


def _handoff_inventory(store: CaseStore, case_id: str) -> tuple[int, int, int]:
    """Count committed metadata and unclosed publication work, without edits.

    The directory is shared among private cases. Unattributable legacy scratch
    blocks every case conservatively. A journal belonging to this case blocks
    review even when the final metadata exists: recovery must happen first.
    """
    exports = _folder(store)
    if exports is None:
        return 0, 0, 0
    entries = list(exports.iterdir())
    if len(entries) > MAX_ENTRIES:
        raise CaseError("Retention handoff inventory exceeds safety bound")
    active = 0
    unknown = 0
    for entry in entries:
        if entry.name.startswith(".handoff-work-") and JOURNAL.fullmatch(entry.name) is None:
            raise CaseError("Retention handoff journal name invalid")
        match = JOURNAL.fullmatch(entry.name)
        if match:
            metadata, _, _ = _journal(entry, match.group(1))
            if metadata["case_id"] == case_id:
                active += 1
        elif entry.name.startswith(".tmp-handoff-"):
            match = TEMP.fullmatch(entry.name)
            if match is None or not (exports / (".handoff-work-" + match.group(1) + ".json")).exists():
                unknown += 1
    if active or unknown:
        # Never bless a potentially ambiguous final/scratch pair while
        # source-linked publication recovery remains outstanding.
        return 0, active, unknown

    complete = 0
    for entry in entries:
        if entry.name.startswith(".handoff-work-") or entry.name.startswith(".tmp-handoff-"):
            continue
        if FINAL_NAME.fullmatch(entry.name) is None:
            raise CaseError("Retention handoff inventory includes unknown file")
        if not entry.name.startswith(case_id + "-"):
            continue
        matched = FINAL_NAME.fullmatch(entry.name)
        if matched is None or matched.group(1) != case_id:
            raise CaseError("Retention unexpected private handoff filename")
        _, digest, content = _hashed(entry)
        if matched.group(2) != digest[:24]:
            raise CaseError("Retention private handoff name/content mismatch")
        _validate_published(content, case_id, digest)
        complete += 1
    return complete, 0, 0


def assess_case(store: CaseStore, case_id: str, *,
                minimum_age_days: int,
                now: datetime | None = None) -> dict[str, Any]:
    """Verify whole registered originals; return an advisory review ONLY.

    The case creation timestamp is metadata, not contractual retention proof.
    A positive age match never creates a destructive operation or authorization.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid retention case identifier")
    if type(minimum_age_days) is not int or not MIN_DAYS <= minimum_age_days <= MAX_DAYS:
        raise CaseError("Retention review threshold must be 1 through 3650 days")
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise CaseError("Retention clock must be timezone-aware")
    current = current.astimezone(timezone.utc)

    with admission_lock(store):
        # A read-only audit must still work on a low-space host. Inventory
        # reservations without requiring free space for a new write.
        pending_bytes = outstanding_reservations(store)
        document = _snapshot(store, case_id)
        indexes = _index_inventory(store, case_id)
        committed, active, unknown = _handoff_inventory(store, case_id)
        controls = read_controls(store, case_id)
        try:
            created = datetime.fromisoformat(document["created_at"]).astimezone(timezone.utc)
        except (ValueError, TypeError, OverflowError) as exc:
            raise CaseError("Retention case creation timestamp invalid") from exc
        if created > current:
            raise CaseError("Retention case creation timestamp is in the future")
        threshold_met = current - created >= timedelta(days=minimum_age_days)
        blockers: list[str] = []
        if pending_bytes:
            blockers.append("GLOBAL_UNFINISHED_INTAKE")
        if active:
            blockers.append("UNRESOLVED_CASE_HANDOFF_JOURNAL")
        if unknown:
            blockers.append("UNATTRIBUTED_HANDOFF_SCRATCH")
        if controls["active_hold_count"]:
            blockers.append("LOCAL_PRESERVATION_HOLD_ACTIVE")
        floor = controls["minimum_retention_days"]
        if floor is not None and current - created < timedelta(days=floor):
            blockers.append("DECLARED_MINIMUM_RETENTION_UNMET")
        # Fingerprint the verified allowlisted metadata, not raw contents,
        # current time, filenames, or any authority to remove data.
        fingerprint = hashlib.sha256(_canonical({
            "schema": 1, "scope": "retention_assessment_only",
            "verified_case": document, "minimum_age_days": minimum_age_days,
            "preservation_record_count": controls["record_count"],
            "preservation_head_sha256": controls["head_sha256"],
        })).hexdigest()
        return {
            "status": "REVIEW_ONLY",
            "case_id": case_id, "minimum_age_days": minimum_age_days,
            "case_age_whole_days": (current - created).days,
            "age_threshold_met": threshold_met,
            "review_candidate": threshold_met and not blockers,
            "blockers": blockers,
            "original_artifacts_sha256_verified": document["artifact_count"],
            "original_bytes_sha256_verified": document["original_bytes_verified"],
            "private_index_files_observed": indexes,
            "private_metadata_handoffs_verified": committed,
            "unclosed_handoff_journals": active,
            "unattributed_handoff_scratch": unknown,
            "pending_global_intake_bytes": pending_bytes,
            "local_preservation_holds_active": controls["active_hold_count"],
            "declared_minimum_retention_days": floor,
            "preservation_record_count": controls["record_count"],
            "preservation_head_sha256": controls["head_sha256"],
            "operator_declarations_checked": True,
            "source_reference_material_verified": False,
            "hold_release_supported": False,
            "assessment_sha256": fingerprint,
            "age_basis": "mutable_case_manifest_created_at_not_retention_authority",
            "source_identity_scope": "case_originals_not_backups",
            "legal_hold_checked": False,
            "deletion_authorized": False,
            "source_originals_removed": 0,
            "raw_originals_exported": 0,
            "public_disclosure_approved": False,
        }
