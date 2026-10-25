#!/usr/bin/env python3
"""v0.31 strictly non-destructive registered-original disposition preflight.

No erase, unlink, journal writes, quarantine, recovery-copy assertion, permit,
MCP mutation, automatic retention, or externally trusted policy is implemented.
All reports are BLOCKED because required external authority and independent
restore/backup proof remain unavailable.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

from capacitywork import admission_lock, outstanding_reservations
from casework import CASE_ID, CaseError, CaseStore
from case_handoff import SHA256, _canonical, _snapshot
from policyreview import _source_material_status
from preservationwork import _load_locked
from retentionwork import _handoff_inventory, _index_inventory, MIN_DAYS, MAX_DAYS

# These are descriptions of hypothetical points, never executable steps.
SCENARIOS = frozenset({
    "BEFORE_INTENT_JOURNAL",
    "AFTER_INTENT_JOURNAL",
    "AFTER_RECOVERY_COPY_ASSERTION",
    "DURING_ORIGINAL_DISPOSITION",
    "AFTER_ORIGINAL_DISPOSITION",
})

# The return value is never a legal hold, release approval, or destructive plan.
IRREDUCIBLE_GATES = (
    "LEGAL_AND_CONTRACTUAL_DISPOSITION_AUTHORITY_UNPROVEN",
    "INDEPENDENT_LATEST_PRESERVATION_CHECKPOINT_UNPROVEN",
    "OFF_HOST_BACKUP_CUSTODY_UNPROVEN",
    "ACTUAL_RESTORE_VERIFICATION_UNPROVEN",
    "DUAL_OPERATOR_DELETION_APPROVAL_UNAVAILABLE",
    "CRASH_SAFE_DELETION_TRANSACTION_NOT_IMPLEMENTED",
)

SCENARIO_REQUIREMENTS: dict[str, str] = {
    "BEFORE_INTENT_JOURNAL": "REVALIDATE_CASE_AND_OPERATOR_AUTHORITY",
    "AFTER_INTENT_JOURNAL": "RECONCILE_DURABLE_INTENT_AND_ABORT_OR_RESUME_SAFELY",
    "AFTER_RECOVERY_COPY_ASSERTION": "PROVE_INDEPENDENT_RESTORE_BEFORE_ANY_MUTATION",
    "DURING_ORIGINAL_DISPOSITION": "QUARANTINE_AMBIGUOUS_TRANSACTION_AND_RESTORE_ORIGINAL",
    "AFTER_ORIGINAL_DISPOSITION": "VERIFY_FINAL_RESTORE_AND_EXTERNAL_COMMIT_HISTORY",
}


def inspect_disposition(
    store: CaseStore,
    case_id: str,
    *,
    minimum_age_days: int,
    scenario: str | None = None,
    expected_preview_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Fully recheck case state and perform a read-only interruption model.

    'expected_preview_sha256' is a preview comparison token, NOT a signature,
    human approval, release grant or executable disposition permit.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Disposition preflight case identifier invalid")
    if type(minimum_age_days) is not int or not MIN_DAYS <= minimum_age_days <= MAX_DAYS:
        raise CaseError("Disposition minimum review age invalid")
    if scenario is None:
        if expected_preview_sha256 is not None:
            raise CaseError("Preview cannot receive disposition simulation token")
    elif (not isinstance(scenario, str) or scenario not in SCENARIOS
          or not isinstance(expected_preview_sha256, str)
          or SHA256.fullmatch(expected_preview_sha256) is None):
        raise CaseError("Disposition simulation requires supported stage and exact preview SHA")
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise CaseError("Disposition preflight requires timezone-aware clock")
    current = current.astimezone(timezone.utc)

    with admission_lock(store):
        # Complete streaming SHA and identity checks of every registered source
        # take place under the existing admission and case locks.
        source = _snapshot(store, case_id)
        pending = outstanding_reservations(store)
        index_count = _index_inventory(store, case_id)
        completed_handoffs, active_handoffs, unknown_handoff = _handoff_inventory(
            store, case_id)
        with store._locked(case_id) as (folder, _):
            local = _load_locked(folder, case_id)
        if (len(local["source_references"]) != local["record_count"]
                or len(local["record_heads"]) != local["record_count"]
                or len(local["hold_sequences"]) != local["active_hold_count"]):
            raise CaseError("Disposition preservation inventory inconsistent")
        try:
            created = datetime.fromisoformat(source["created_at"])
        except (ValueError, TypeError, OverflowError) as exc:
            raise CaseError("Disposition case origin metadata invalid") from exc
        if created.tzinfo is None:
            raise CaseError("Disposition case origin clock is untrusted")
        created = created.astimezone(timezone.utc)
        if created > current:
            raise CaseError("Disposition case origin timestamp is in the future")
        age = current - created
        floor = local["minimum_retention_days"]
        strictest = max(minimum_age_days, floor or 0)
        sources: dict[str, list[dict[str, Any]]] = {}
        for original in source["artifacts"]:
            sources.setdefault(original["sha256"], []).append(original)
        unverified = sum(
            _source_material_status(sources, digest)
            != "REGISTERED_ORIGINAL_BYTES_MATCH_ONLY"
            for _, digest in local["source_references"]
        )
        observed: list[str] = []
        if pending:
            observed.append("GLOBAL_INTAKE_RESERVATION_ACTIVE")
        if active_handoffs:
            observed.append("UNRESOLVED_HANDOFF_JOURNAL")
        if unknown_handoff:
            observed.append("UNKNOWN_UNJOURNALED_HANDOFF_SCRATCH")
        if local["active_hold_count"]:
            observed.append("ACTIVE_LOCAL_PRESERVATION_HOLD")
        if age < timedelta(days=strictest):
            observed.append("MINIMUM_ADVISORY_RETENTION_AGE_UNMET")
        if unverified:
            observed.append("LOCAL_PRESERVATION_SOURCE_BYTES_UNVERIFIED")
        blockers = observed + list(IRREDUCIBLE_GATES)

        # This compact, bounded metadata-only preview token has no authority
        # and cannot ever be consumed by a delete/cleanup API. Reverification
        # under the lock catches changed originals, local holds, reservations,
        # indexes, handoffs and age-based thresholds before modelling a stage.
        identity = {
            "schema": 1,
            "kind": "read_only_disposition_preflight_not_executable",
            "verified_case": source,
            "minimum_age_days": minimum_age_days,
            "case_age_whole_days": age.days,
            "strictest_advisory_days": strictest,
            "pending_intake_bytes": pending,
            "indexed_file_count": index_count,
            "handoff_count": completed_handoffs,
            "active_handoff_journals": active_handoffs,
            "unknown_handoff_scratch": unknown_handoff,
            "preservation_record_count": local["record_count"],
            "preservation_head_sha256": local["head_sha256"],
            "active_local_holds": local["active_hold_count"],
            "unverified_preservation_source_references": unverified,
            "blockers": blockers,
        }
        fingerprint = hashlib.sha256(_canonical(identity)).hexdigest()
        if scenario is not None and fingerprint != expected_preview_sha256:
            raise CaseError("Stale disposition preview: revalidate before simulation")
        model = None
        if scenario is not None:
            model = {
                "scenario": scenario,
                "simulated_interruption_only": True,
                "required_future_recovery_action": SCENARIO_REQUIREMENTS[scenario],
                "real_transaction_journal_exists": False,
                "recovery_proven": False,
                "cleanup_permitted": False,
            }
        return {
            "status": "DISPOSITION_BLOCKED_READ_ONLY_PREFLIGHT",
            "case_id": case_id,
            "preview_sha256": fingerprint,
            "simulation": model,
            "review_minimum_age_days": minimum_age_days,
            "case_age_whole_days_from_mutable_manifest": age.days,
            "advisory_minimum_age_met": age >= timedelta(days=strictest),
            "strictest_advisory_minimum_days": strictest,
            "registered_originals_fully_sha256_verified": source["artifact_count"],
            "registered_original_bytes_verified": source["original_bytes_verified"],
            "active_local_preservation_holds": local["active_hold_count"],
            "preservation_record_count": local["record_count"],
            "preservation_head_sha256": local["head_sha256"],
            "unverified_preservation_source_references": unverified,
            "pending_global_intake_bytes": pending,
            "private_index_files_observed": index_count,
            "committed_metadata_handoffs_observed": completed_handoffs,
            "unresolved_handoff_journals": active_handoffs,
            "unattributed_handoff_scratch": unknown_handoff,
            "blockers": blockers,
            "policy_authority_verified": False,
            "independent_backup_exists_verified": False,
            "off_host_recovery_custody_verified": False,
            "actual_restore_test_passed": False,
            "most_recent_external_checkpoint_verified": False,
            "dual_operator_approval_verified": False,
            "destructive_transaction_implemented": False,
            "transaction_recovery_verified": False,
            "hold_release_authorized": False,
            "deletion_authorized": False,
            "originals_removed": 0,
            "raw_originals_exported": 0,
            "public_disclosure_approved": False,
        }
