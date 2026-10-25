#!/usr/bin/env python3
"""Private, two-phase, strictly allowlisted redacted case review ZIP.

Never transforms untrusted evidence text into output: ZIP members contain only
fixed literals and coarse bands derived from verified case structure. The ZIP
is NOT approved for customer/public disclosure, is never transmitted, and
cannot contain raw sources, filenames, artifact hashes, paths or notes.
"""
from __future__ import annotations

from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any
import zipfile

from capacitywork import admission_lock, outstanding_reservations, verify_committed_reserve
from case_handoff import (_canonical, _identity, _private_optional,
                          _snapshot, _sync_directory, SHA256)
from casework import CASE_ID, CaseError, CaseStore, _private_directory, _regular_open
from preservationwork import _load_locked
from retentionwork import _handoff_inventory, _index_inventory

OUT_DIR = "redacted-review-packages"
MAX_PACKAGE = 32768
MAX_ENTRIES = 256
MAX_JOURNAL = 1024
FINAL_NAME = re.compile(r"^redacted-[a-f0-9]{24}[.]zip$")
PENDING_NAME = re.compile(r"^[.](?:review-work-[a-f0-9]{32}[.]json|tmp-review-[a-f0-9]{32})$")
MEMBERS = ("summary.json", "review.json", "README.txt", "manifest.json")
README = (
    "PRIVATE REDACTED REVIEW CANDIDATE - NOT APPROVED FOR DISCLOSURE\n"
    "Source text, original files, customer names, timestamps, filenames,\n"
    "source hashes and per-artifact metadata were not copied.\n"
    "Operator and independent disclosure review are still required.\n"
).encode("ascii")


def _count_band(amount: int) -> str:
    if type(amount) is not int or amount < 0:
        raise CaseError("Redacted count unavailable")
    if amount == 0:
        return "0"
    if amount == 1:
        return "1"
    if amount <= 10:
        return "2-10"
    if amount <= 100:
        return "11-100"
    if amount <= 1000:
        return "101-1000"
    return "1001+"


def _byte_band(amount: int) -> str:
    if type(amount) is not int or amount < 0:
        raise CaseError("Redacted size unavailable")
    if amount == 0:
        return "0"
    if amount < 1024 * 1024:
        return "1B-1MiB"
    if amount < 1024 ** 3:
        return "1MiB-1GiB"
    if amount < 16 * 1024 ** 3:
        return "1GiB-16GiB"
    return "16GiB+"


def _review_content(snapshot: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    # NEVER propagate input-derived strings, including the artifact type.
    artifacts = snapshot["artifacts"]
    derived = sum(1 for a in artifacts if a.get("derived_from") is not None)
    summary = {
        "schema": 1,
        "kind": "REDACTED_CASE_STRUCTURE_ONLY",
        "artifact_count_band": _count_band(snapshot["artifact_count"]),
        "verified_original_bytes_band": _byte_band(snapshot["original_bytes_verified"]),
        "derived_artifact_count_band": _count_band(derived),
        "originals_full_hash_checked_locally": True,
        "raw_evidence_included": False,
        "source_identifiers_included": False,
        "customer_prose_included": False,
    }
    review = {
        "schema": 1,
        "status": "PRIVATE_CANDIDATE_REVIEW_REQUIRED",
        "transformation": "STATIC_ALLOWLIST_ONLY_NO_SOURCE_TEXT",
        "human_disclosure_review_completed": False,
        "independent_privacy_approval_verified": False,
        "legal_policy_authority_verified": False,
        "public_disclosure_approved": False,
        "raw_originals_exported": 0,
        "originals_removed": 0,
        "external_transmission_performed": False,
    }
    return summary, review


def _render(snapshot: dict[str, Any]) -> bytes:
    summary, review = _review_content(snapshot)
    generated: dict[str, bytes] = {
        "summary.json": _canonical(summary),
        "review.json": _canonical(review),
        "README.txt": README,
    }
    digest_table = {
        name: {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
        for name, body in sorted(generated.items())
    }
    generated["manifest.json"] = _canonical({
        "schema": 1, "status": "PRIVATE_REDACTED_PACKAGE_NOT_APPROVED",
        "members": digest_table,
    })
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED,
                         allowZip64=False) as archive:
        for name in MEMBERS:
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_STORED
            item.create_system = 3
            item.external_attr = (0o100600 << 16)
            archive.writestr(item, generated[name])
    result = buf.getvalue()
    if len(result) > MAX_PACKAGE:
        raise CaseError("Redacted package unexpectedly exceeded fixed bound")
    return result


def _bounded_entries(folder: Path) -> list[Path]:
    """Stop at the inventory bound, including unrecognized directory entries."""
    entries: list[Path] = []
    with os.scandir(folder) as iterator:
        for entry in iterator:
            if len(entries) >= MAX_ENTRIES:
                raise CaseError("Private redacted package inventory is over limit")
            entries.append(folder / entry.name)
    return sorted(entries, key=lambda entry: entry.name)


def _private_inventory(store: CaseStore, *, reserve_entries: int = 0) -> Path:
    """Return potential folder without creating it during preview."""
    folder = store.base / OUT_DIR
    if not _private_optional(folder, "Private redacted package"):
        return folder
    entries = _bounded_entries(folder)
    if len(entries) + reserve_entries > MAX_ENTRIES:
        raise CaseError("Private redacted package inventory has no publication reserve")
    for entry in entries:
        if PENDING_NAME.fullmatch(entry.name):
            raise CaseError("Interrupted redacted package publication needs separate review")
        if FINAL_NAME.fullmatch(entry.name) is None:
            raise CaseError("Unexpected file in private redacted package directory")
        info = entry.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= MAX_PACKAGE):
            raise CaseError("Private package inventory file identity unsafe")
    return folder


def _verified_plan(store: CaseStore, case_id: str) -> tuple[bytes, str, str, str]:
    """Reverify the source binding while the caller holds admission_lock.

    Output inventory is checked separately so explicit recovery can verify a
    journaled transaction without mistaking it for a new publication request.
    Only the opaque source digest is stored in the private journal; source
    metadata and evidence bytes never enter the ZIP or recovery response.
    """
    pending = outstanding_reservations(store)
    snapshot = _snapshot(store, case_id)
    index_count = _index_inventory(store, case_id)
    committed, active, unknown = _handoff_inventory(store, case_id)
    if active or unknown:
        raise CaseError("Redacted package blocked by unfinished private handoff work")
    with store._locked(case_id) as (folder, _):
        state = _load_locked(folder, case_id)
    if (len(state["record_heads"]) != state["record_count"]
            or len(state["source_references"]) != state["record_count"]
            or len(state["hold_sequences"]) != state["active_hold_count"]):
        raise CaseError("Redacted package preservation chain inventory inconsistent")
    payload = _render(snapshot)
    digest = hashlib.sha256(payload).hexdigest()
    source_digest = hashlib.sha256(_canonical(snapshot)).hexdigest()
    plan = hashlib.sha256(_canonical({
        "schema": 1, "case_id": case_id,
        "private_verified_case": snapshot,
        "index_count": index_count, "committed_handoffs": committed,
        "pending_intake_bytes": pending,
        "preservation_head_sha256": state["head_sha256"],
        "preservation_count": state["record_count"],
        "package_sha256": digest,
    })).hexdigest()
    return payload, digest, plan, source_digest


def _verified_readback(path: Path, wanted: bytes) -> None:
    fd, before = _regular_open(path)
    try:
        if before.st_nlink != 1 or before.st_size != len(wanted):
            raise CaseError("Redacted package publication identity invalid")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            result = stream.read(MAX_PACKAGE + 1)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        if (_identity(before) != _identity(after)
                or _identity(before) != _identity(final)
                or result != wanted):
            raise CaseError("Redacted package publication SHA identity mismatch")
    finally:
        if fd >= 0:
            os.close(fd)


def review_redacted_export(store: CaseStore, case_id: str, *,
                           prepare: bool = False,
                           preview_sha256: str | None = None) -> dict[str, Any]:
    """Preview, then opt-in create ONLY a local PRIVATE review ZIP.

    The SHA binds the private verified originals and current preservation
    record head, pending storage and metadata work to the exact allowlisted
    package. It is an integrity token, NEVER human disclosure permission.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Redacted review case ID invalid")
    if prepare:
        if not isinstance(preview_sha256, str) or SHA256.fullmatch(preview_sha256) is None:
            raise CaseError("Redacted package preparation requires preview digest")
    elif preview_sha256 is not None:
        raise CaseError("Redacted package preview cannot accept approval")
    with admission_lock(store):
        _private_inventory(store)
        payload, digest, plan, source_digest = _verified_plan(store, case_id)
        reply = {
            "status": "PRIVATE_REDACTED_PREVIEW_ONLY",
            "review_fingerprint_sha256": plan,
            "package_sha256": digest,
            "package_size_bytes": len(payload),
            "contents": list(MEMBERS),
            "source_full_sha256_checked": True,
            "source_identifiers_in_package": False,
            "raw_originals_exported": 0,
            "originals_removed": 0,
            "public_disclosure_approved": False,
            "operator_confirmation_is_disclosure_permission": False,
            "independent_privacy_review_verified": False,
            "network_upload_performed": False,
        }
        if not prepare:
            return reply
        if preview_sha256 != plan:
            raise CaseError("Redacted review snapshot changed; repeat preview")
        verify_committed_reserve(store, extra_bytes=MAX_PACKAGE + MAX_JOURNAL)
        store._ensure_store()
        exports = store.base / OUT_DIR
        _private_directory(exports, strict=True)
        _private_inventory(store, reserve_entries=3)
        # Persist a newly created output directory's parent entry before the
        # first journal. A durable journal inside an unpersisted directory is
        # not a durable recovery point. This also rechecks the owned parent.
        _sync_directory(store.base)
        # Stable name from private plan digest; no external path or user text.
        name = "redacted-" + plan[:24] + ".zip"
        final = exports / name
        if final.exists() or final.is_symlink():
            raise CaseError("Private redacted package already exists; no overwrite")
        transaction = secrets.token_hex(16)
        tmp = exports / (".tmp-review-" + transaction)
        journal = exports / (".review-work-" + transaction + ".json")
        journal_bytes = _canonical({
            "schema": 2, "case_id": case_id, "package_name": name,
            "package_sha256": digest, "preview_sha256": plan,
            "package_size_bytes": len(payload),
            "source_snapshot_sha256": source_digest,
            "tmp_name": tmp.name, "transaction_id": transaction,
        })
        if len(journal_bytes) > MAX_JOURNAL:
            raise CaseError("Private redacted publication journal exceeds bound")
        # Crash-safe provenance first, then scratch; never silently clean
        # ambiguous failure or replace an existing package. No auto-recovery.
        journal_fd = os.open(
            journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(journal_fd, "wb") as stream:
                journal_fd = -1
                stream.write(journal_bytes)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if journal_fd >= 0:
                os.close(journal_fd)
        _sync_directory(exports)

        temp_fd = os.open(
            tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(temp_fd, "wb") as stream:
                temp_fd = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
        _sync_directory(exports)
        if final.exists() or final.is_symlink():
            raise CaseError("Private redacted package destination changed")
        os.link(tmp, final, follow_symlinks=False)
        _sync_directory(exports)
        tmp.unlink()
        _sync_directory(exports)
        _verified_readback(final, payload)
        # Proven committed file: journal can now be retired.
        journal.unlink()
        _sync_directory(exports)
        return {
            **reply,
            "status": "PRIVATE_REDACTED_PACKAGE_PREPARED_NOT_APPROVED",
            "package_name": name,
            "private_storage_only": True,
            "source_snapshot_reverified": True,
        }
