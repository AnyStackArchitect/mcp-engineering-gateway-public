#!/usr/bin/env python3
"""Bounded, read-only byte verification for existing case preservation references.

Matching a recorded SHA-256 to a fully rehashed registered original establishes
case-local material byte identity ONLY. It does NOT authenticate a legal hold,
document provenance, signer, contract, custody, timestamp, or external policy.
No raw evidence, filenames, per-reference SHA, destructive operation, network
output, MCP endpoint, or independent ledger anchor is introduced.
"""
from __future__ import annotations

import hashlib
from typing import Any

from capacitywork import admission_lock
from case_handoff import _snapshot, _canonical
from casework import CaseError, CaseStore, CASE_ID
from preservationwork import _load_locked, MAX_RECORDS

STATUS_VERIFIED = "REGISTERED_NONEMPTY_SOURCE_BYTES_VERIFIED"
STATUS_MISSING = "SOURCE_BYTES_NOT_REGISTERED_IN_CASE"
STATUS_AMBIGUOUS = "AMBIGUOUS_MULTIPLE_REGISTERED_MATCHES"
STATUS_DERIVED = "MATCH_IS_DERIVED_EVIDENCE_ONLY"
STATUS_EMPTY = "MATCH_IS_EMPTY_ORIGINAL"

def verify_references(store: CaseStore, case_id: str) -> dict[str, Any]:
    """Verify up to MAX_RECORDS declarations against current registered originals.

    Cooperating writes serialize on the admission lock; same-UID attackers,
    out-of-band edits and deleted whole local ledgers remain unproven. A source
    digest is a recorded *claim* until a complete original-byte hash is read.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Invalid preservation verification case identifier")
    with admission_lock(store):
        # Existing _snapshot rehashes every registered original end-to-end,
        # checks owner/private/single-link/inode/size/mtime and valid lineage.
        document = _snapshot(store, case_id)
        with store._locked(case_id) as (folder, _):
            controls = _load_locked(folder, case_id)
            references = controls["source_references"]
        if len(references) != controls["record_count"] or len(references) > MAX_RECORDS:
            raise CaseError("Preservation reference chain count mismatch")
        indexed: dict[str, list[dict[str, Any]]] = {}
        for artifact in document["artifacts"]:
            indexed.setdefault(artifact["sha256"], []).append(artifact)
        statuses: list[dict[str, Any]] = []
        counts = {
            STATUS_VERIFIED: 0,
            STATUS_MISSING: 0,
            STATUS_AMBIGUOUS: 0,
            STATUS_DERIVED: 0,
            STATUS_EMPTY: 0,
        }
        for sequence, digest in references:
            matches = indexed.get(digest, ())
            if not matches:
                status = STATUS_MISSING
            elif len(matches) != 1:
                status = STATUS_AMBIGUOUS
            elif matches[0]["bytes"] == 0:
                status = STATUS_EMPTY
            elif matches[0].get("derived_from") is not None:
                status = STATUS_DERIVED
            else:
                status = STATUS_VERIFIED
            counts[status] += 1
            # Sequence is opaque and bounded; never expose record SHA,
            # original filenames, payloads, customer identifiers or file paths.
            statuses.append({"sequence": sequence, "source_material_status": status})
        all_matched = bool(references) and counts[STATUS_VERIFIED] == len(references)
        report_digest = hashlib.sha256(_canonical({
            "schema": 1, "scope": "registered_source_bytes_only",
            "case_id": case_id,
            "verified_case": document,
            "preservation_head_sha256": controls["head_sha256"],
            "preservation_record_count": controls["record_count"],
            "verified_source_statuses": statuses,
        })).hexdigest()
        return {
            "status": "MATERIAL_BYTES_VERIFIED_ONLY" if all_matched else
                      "UNVERIFIED_SOURCE_REFERENCE_MATERIAL",
            "case_id": case_id,
            "registered_originals_sha256_verified": document["artifact_count"],
            "registered_original_bytes_sha256_verified": document["original_bytes_verified"],
            "preservation_record_count": controls["record_count"],
            "preservation_head_sha256": controls["head_sha256"],
            "reference_results": statuses,
            "references_with_verified_nonempty_source_bytes": counts[STATUS_VERIFIED],
            "references_missing_from_case": counts[STATUS_MISSING],
            "references_with_ambiguous_matches": counts[STATUS_AMBIGUOUS],
            "references_matching_only_derived_evidence": counts[STATUS_DERIVED],
            "references_matching_empty_originals": counts[STATUS_EMPTY],
            "source_reference_material_verified": all_matched,
            "source_reference_verification_scope": "current_registered_original_bytes_only",
            "source_reference_material_timestamp_authoritative": False,
            "source_reference_signer_verified": False,
            "source_reference_provenance_verified": False,
            "legal_hold_authority_verified": False,
            "case_ledger_independently_anchored": False,
            "hold_release_supported": False,
            "deletion_authorized": False,
            "raw_originals_exported": 0,
            "originals_removed": 0,
            "public_disclosure_approved": False,
            "verification_sha256": report_digest,
        }
