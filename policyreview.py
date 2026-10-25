#!/usr/bin/env python3
"""Bounded read-only retention policy and hold-release *review*, never execution.

A caller-supplied policy bundle is an UNTRUSTED proposal. Matching source bytes
only establishes current registered-original identity, not authority, signatures,
applicability, effective dates, external custody or legal retention obligations.
No hold is released, no floor is lowered, and no evidence is removed/exported.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any

from capacitywork import admission_lock
from casework import CASE_ID, CaseError, CaseStore
from case_handoff import SHA256, _canonical, _snapshot
from preservationwork import _load_locked, MAX_RETENTION_DAYS

MAX_POLICY_BYTES = 16384
MAX_RULES = 32
RULE_KINDS = frozenset({"MINIMUM_DAYS", "PRESERVATION_HOLD"})
REVIEW_MODE = "REVIEW_ONLY"
POLICY_FIELDS = frozenset({
    "schema", "mode", "case_id", "policy_id", "rules", "release_review",
})
RULE_BASE = frozenset({"rule_id", "kind", "source_sha256"})
RELEASE_FIELDS = frozenset({"target_hold_sequence", "request_source_sha256"})


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CaseError("Policy review contains duplicate JSON keys")
        value[key] = item
    return value


def _check_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _validate_policy(raw: bytes, case_id: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_POLICY_BYTES:
        raise CaseError("Policy review input exceeds fixed size or is empty")
    try:
        parsed = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise CaseError("Policy review input is not valid bounded JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != POLICY_FIELDS:
        raise CaseError("Policy review top-level schema invalid")
    if (type(parsed["schema"]) is not int or parsed["schema"] != 1
            or parsed["mode"] != REVIEW_MODE
            or parsed["case_id"] != case_id
            or not isinstance(parsed["policy_id"], str)
            or CASE_ID.fullmatch(parsed["policy_id"]) is None
            or not isinstance(parsed["rules"], list)
            or len(parsed["rules"]) > MAX_RULES):
        raise CaseError("Policy review identity, mode or inventory invalid")
    request = parsed["release_review"]
    if not parsed["rules"] and request is None:
        raise CaseError("Policy review must contain at least one proposed rule or review request")
    if request is not None:
        if (not isinstance(request, dict) or set(request) != RELEASE_FIELDS
                or type(request["target_hold_sequence"]) is not int
                or not 1 <= request["target_hold_sequence"] <= 128
                or not _check_sha(request["request_source_sha256"])):
            raise CaseError("Hold-release review request is malformed")
    seen: set[str] = set()
    for rule in parsed["rules"]:
        if not isinstance(rule, dict):
            raise CaseError("Policy review rule must be an object")
        kind = rule.get("kind")
        fields = RULE_BASE | ({"minimum_days"} if kind == "MINIMUM_DAYS" else set())
        if (not isinstance(kind, str) or kind not in RULE_KINDS
                or set(rule) != fields
                or not isinstance(rule.get("rule_id"), str)
                or CASE_ID.fullmatch(rule["rule_id"]) is None
                or not _check_sha(rule.get("source_sha256"))):
            raise CaseError("Policy review rule schema invalid")
        if rule["rule_id"] in seen:
            raise CaseError("Policy review has repeated rule identity")
        seen.add(rule["rule_id"])
        if kind == "MINIMUM_DAYS":
            days = rule["minimum_days"]
            if type(days) is not int or not 1 <= days <= MAX_RETENTION_DAYS:
                raise CaseError("Policy review minimum days outside permitted range")
    if raw.strip() != _canonical(parsed):
        raise CaseError("Policy review input must be canonical JSON")
    return parsed


def _source_material_status(artifacts: dict[str, list[dict[str, Any]]],
                            sha256: str) -> str:
    matches = artifacts.get(sha256, [])
    if not matches:
        return "SOURCE_NOT_REGISTERED"
    if len(matches) != 1:
        return "AMBIGUOUS_REGISTERED_SOURCE"
    item = matches[0]
    if item["bytes"] == 0:
        return "EMPTY_REGISTERED_SOURCE"
    if item.get("derived_from") is not None:
        return "DERIVED_SOURCE_NOT_INDEPENDENT"
    return "REGISTERED_ORIGINAL_BYTES_MATCH_ONLY"


def review_policy(store: CaseStore, case_id: str, raw_policy: bytes, *,
                  now: datetime | None = None) -> dict[str, Any]:
    """Review untrusted proposed rules and hold-release request without mutations.

    Existing case-local holds always take precedence. The strictest proposed
    duration cannot lower an existing local floor. A request for release is
    never an approval or command, including after all age/source checks pass.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Policy review case ID invalid")
    policy = _validate_policy(raw_policy, case_id)
    moment = datetime.now(timezone.utc) if now is None else now
    if not isinstance(moment, datetime) or moment.tzinfo is None:
        raise CaseError("Policy review requires an aware UTC-capable clock")
    moment = moment.astimezone(timezone.utc)

    with admission_lock(store):
        verified = _snapshot(store, case_id)
        with store._locked(case_id) as (folder, _):
            state = _load_locked(folder, case_id)
        if (len(state["source_references"]) != state["record_count"]
                or len(state["record_heads"]) != state["record_count"]
                or len(state["hold_sequences"]) != state["active_hold_count"]):
            raise CaseError("Policy review preservation inventory inconsistent")
        try:
            created = datetime.fromisoformat(verified["created_at"])
        except (TypeError, ValueError, OverflowError) as exc:
            raise CaseError("Policy review case creation date invalid") from exc
        if created.tzinfo is None:
            raise CaseError("Policy review case creation lacks timezone")
        created = created.astimezone(timezone.utc)
        if created > moment:
            raise CaseError("Policy review case creation is in the future")
        age = moment - created
        sources: dict[str, list[dict[str, Any]]] = {}
        for artifact in verified["artifacts"]:
            sources.setdefault(artifact["sha256"], []).append(artifact)

        local_reference_missing = sum(
            _source_material_status(sources, digest) !=
            "REGISTERED_ORIGINAL_BYTES_MATCH_ONLY"
            for _, digest in state["source_references"]
        )
        proposed_holds = 0
        proposed_floor: int | None = None
        unresolved_sources = 0
        policy_statuses: list[dict[str, Any]] = []
        reused_source_terms: dict[str, tuple[str, int | None]] = {}
        conflicting = 0
        for index, rule in enumerate(policy["rules"], 1):
            status = _source_material_status(sources, rule["source_sha256"])
            if status != "REGISTERED_ORIGINAL_BYTES_MATCH_ONLY":
                unresolved_sources += 1
            kind = rule["kind"]
            duration = rule.get("minimum_days")
            if kind == "PRESERVATION_HOLD":
                proposed_holds += 1
            else:
                proposed_floor = max(duration, proposed_floor or 0)
            term = (kind, duration)
            previous = reused_source_terms.setdefault(rule["source_sha256"], term)
            if previous != term:
                conflicting += 1
            policy_statuses.append({
                "rule_index": index, "kind": kind,
                "source_material_status": status,
            })

        local_floor = state["minimum_retention_days"]
        strictest = max(local_floor or 0, proposed_floor or 0) or None
        blocked: list[str] = []
        if state["active_hold_count"]:
            blocked.append("LOCAL_PRESERVATION_HOLD_ACTIVE")
        if proposed_holds:
            blocked.append("PROPOSED_PRESERVATION_HOLD")
        if strictest is not None and age < timedelta(days=strictest):
            blocked.append("STRICTEST_MINIMUM_RETENTION_NOT_REACHED")
        if local_reference_missing:
            blocked.append("LOCAL_PRESERVATION_SOURCE_MATERIAL_UNVERIFIED")
        if unresolved_sources:
            blocked.append("POLICY_SOURCE_MATERIAL_UNVERIFIED")
        if conflicting:
            blocked.append("CONFLICTING_TERMS_FOR_SAME_SOURCE")
        release = policy["release_review"]
        release_source_status = None
        release_target_is_hold = None
        if release is not None:
            blocked.append("RELEASE_REQUIRES_SEPARATE_AUTHORITY_AND_REVIEW")
            release_target_is_hold = (
                release["target_hold_sequence"] in state["hold_sequences"])
            if not release_target_is_hold:
                blocked.append("RELEASE_TARGET_NOT_ACTIVE_LOCAL_HOLD")
            release_source_status = _source_material_status(
                sources, release["request_source_sha256"])
            if release_source_status != "REGISTERED_ORIGINAL_BYTES_MATCH_ONLY":
                blocked.append("RELEASE_REQUEST_SOURCE_MATERIAL_UNVERIFIED")

        # This is a review of untrusted caller declarations. Even with no
        # local holds or age blockers, absence of externally checked policy,
        # human custody and latest checkpoint is an unconditional barrier.
        blocked.append("POLICY_AND_CUSTODY_AUTHORITY_NOT_VERIFIED")
        fingerprint = hashlib.sha256(_canonical({
            "schema": 1, "scope": "policy_review_only",
            "verified_case": verified,
            "preservation_head_sha256": state["head_sha256"],
            "preservation_record_count": state["record_count"],
            "submitted_policy": policy,
            "blockers": blocked,
        })).hexdigest()
        return {
            "status": "POLICY_REVIEW_ONLY",
            "case_id": case_id,
            "policy_sha256": hashlib.sha256(_canonical(policy)).hexdigest(),
            "review_sha256": fingerprint,
            "policy_rule_count": len(policy["rules"]),
            "policy_rule_results": policy_statuses,
            "active_local_holds": state["active_hold_count"],
            "proposed_holds": proposed_holds,
            "local_minimum_days": local_floor,
            "proposed_strictest_minimum_days": proposed_floor,
            "effective_advisory_minimum_days": strictest,
            "case_age_whole_days_from_mutable_manifest": age.days,
            "advisory_minimum_age_met": strictest is None or
                                         age >= timedelta(days=strictest),
            "local_source_references_unverified": local_reference_missing,
            "policy_source_references_unverified": unresolved_sources,
            "conflicting_policy_source_terms": conflicting,
            "hold_release_review_requested": release is not None,
            "hold_release_target_is_active_local_hold": release_target_is_hold,
            "hold_release_source_material_status": release_source_status,
            "blockers": blocked,
            "source_reference_material_verified_scope": "current_case_original_bytes_only",
            "policy_authority_independently_verified": False,
            "document_signer_verified": False,
            "latest_external_checkpoint_verified": False,
            "legal_hold_authority_verified": False,
            "hold_release_authorized": False,
            "hold_release_executed": False,
            "deletion_authorized": False,
            "originals_removed": 0,
            "raw_originals_exported": 0,
            "public_disclosure_approved": False,
        }
