#!/usr/bin/env python3
"""Portable signed preservation-ledger checkpoints; off-host custody required.

This provides source-bound *cryptographic comparison* to a separately retained
operator-signed checkpoint. It does not independently establish external
custody, timestamp authority, signer identity/legal authority, or latest-checkpoint
freshness. No case deletion, hold release, secret/key storage, or MCP endpoint.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Any

from capacitywork import admission_lock
from casework import CaseError, CaseStore, CASE_ID
from case_handoff import _canonical
from preservationwork import _load_locked, MAX_RECORDS

DOMAIN = "rocky-eng:preservation-anchor:v1"
TRUST_DIR = Path("/etc/rocky-eng")
TRUST_KEY_NAME = "preservation_anchor_ed25519_pub.pem"
MAX_ENVELOPE_BYTES = 4096
MAX_PREVIEW_BYTES = 2048
MAX_SKEW_SECONDS = 300
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
PAYLOAD_FIELDS = frozenset({
    "domain", "case_id", "record_count", "head_sha256",
    "issued_at", "nonce",
})


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise CaseError("Preservation checkpoint contains duplicate JSON keys")
        output[key] = value
    return output


def _decode(raw: bytes, *, max_bytes: int) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= max_bytes:
        raise CaseError("Preservation checkpoint size invalid")
    try:
        obj = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, TypeError, ValueError) as exc:
        raise CaseError("Preservation checkpoint JSON invalid") from exc
    if not isinstance(obj, dict):
        raise CaseError("Preservation checkpoint is not a JSON object")
    return obj


def _validate_payload(payload: Any, *, now: int | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        raise CaseError("Preservation checkpoint payload schema invalid")
    if (payload["domain"] != DOMAIN
            or not isinstance(payload["case_id"], str)
            or CASE_ID.fullmatch(payload["case_id"]) is None
            or type(payload["record_count"]) is not int
            or not 1 <= payload["record_count"] <= MAX_RECORDS
            or not isinstance(payload["head_sha256"], str)
            or HEX64.fullmatch(payload["head_sha256"]) is None
            or not isinstance(payload["nonce"], str)
            or HEX32.fullmatch(payload["nonce"]) is None
            or type(payload["issued_at"]) is not int
            or payload["issued_at"] <= 0):
        raise CaseError("Preservation checkpoint payload values invalid")
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 0:
        raise CaseError("Preservation checkpoint verification clock invalid")
    if payload["issued_at"] > current + MAX_SKEW_SECONDS:
        raise CaseError("Preservation checkpoint appears future-dated")
    return payload


def create_unsigned_checkpoint(store: CaseStore, case_id: str) -> dict[str, Any]:
    """Return a bounded UNSIGNED review packet; never modify the case vault."""
    import secrets
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Preservation checkpoint case ID invalid")
    with admission_lock(store):
        with store._locked(case_id) as (folder, _):
            state = _load_locked(folder, case_id)
        # A zero-record checkpoint would bless an empty/destroyed ledger.
        if not state["record_count"] or len(state["record_heads"]) != state["record_count"]:
            raise CaseError("No established preservation records to checkpoint")
        payload = {
            "domain": DOMAIN, "case_id": case_id,
            "record_count": state["record_count"],
            "head_sha256": state["head_sha256"],
            "issued_at": int(time.time()),
            "nonce": secrets.token_hex(16),
        }
        _validate_payload(payload)
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        packet = {
            "status": "UNSIGNED_CHECKPOINT_PREVIEW",
            "payload": payload, "payload_sha256": digest,
        }
        if len(_canonical(packet)) > MAX_PREVIEW_BYTES:
            raise CaseError("Preservation checkpoint preview exceeds hard bound")
        return packet


def validate_unsigned_preview(raw: bytes) -> dict[str, Any]:
    """OFF-HOST operator utility input; no signing performed on gateway."""
    preview = _decode(raw, max_bytes=MAX_PREVIEW_BYTES)
    if set(preview) != {"status", "payload", "payload_sha256"}:
        raise CaseError("Preservation checkpoint preview schema invalid")
    if preview["status"] != "UNSIGNED_CHECKPOINT_PREVIEW":
        raise CaseError("Preservation checkpoint preview status invalid")
    payload = _validate_payload(preview["payload"])
    claimed = preview["payload_sha256"]
    if (not isinstance(claimed, str) or HEX64.fullmatch(claimed) is None
            or claimed != hashlib.sha256(_canonical(payload)).hexdigest()):
        raise CaseError("Preservation checkpoint preview digest mismatch")
    if raw.strip() != _canonical(preview):
        raise CaseError("Preservation checkpoint preview is not canonical")
    return payload


def _trusted_public_key(root: Path, trusted_uid: int) -> Path:
    """Production trust root must be root-managed, separate from grant key."""
    if not isinstance(root, Path) or not root.is_absolute() or root == Path("/"):
        raise CaseError("Preservation verification trust root invalid")
    if type(trusted_uid) is not int or trusted_uid < 0:
        raise CaseError("Preservation verification trusted UID invalid")
    for folder in (*reversed(root.parents), root):
        if folder.is_symlink():
            raise CaseError("Preservation verification trust ancestor is a symlink")
        info = folder.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise CaseError("Preservation verification trust ancestor invalid")
        if trusted_uid == 0 and (info.st_uid != 0 or info.st_mode & 0o022):
            raise CaseError("Preservation verification trust ancestry writable")
    st = root.lstat()
    if st.st_uid != trusted_uid or st.st_mode & 0o022:
        raise CaseError("Preservation verification trust directory unsafe")
    key = root / TRUST_KEY_NAME
    info = key.lstat()
    if (not stat.S_ISREG(info.st_mode) or key.is_symlink()
            or info.st_uid != trusted_uid or info.st_nlink != 1
            or info.st_mode & 0o022 or not 80 <= info.st_size <= 2048):
        raise CaseError("Preservation verification public key identity invalid")
    return key


def _verify_ed25519(payload: dict[str, Any], signature_b64: str,
                    trust_root: Path, trusted_uid: int) -> None:
    if not isinstance(signature_b64, str) or len(signature_b64) != 88:
        raise CaseError("Preservation checkpoint signature encoding invalid")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CaseError("Preservation checkpoint signature Base64 invalid") from exc
    if len(signature) != 64:
        raise CaseError("Preservation checkpoint Ed25519 signature length invalid")
    try:
        key = _trusted_public_key(trust_root, trusted_uid)
        # Enforce the exact RFC 8410 Ed25519 SubjectPublicKeyInfo shape.
        # A valid signature from a different algorithm/key type must never
        # qualify as an Ed25519 preservation checkpoint.
        algorithm = subprocess.run(
            ["/usr/bin/openssl", "pkey", "-pubin", "-in", str(key),
             "-outform", "DER"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=8, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        ed25519_spki = bytes.fromhex("302a300506032b6570032100")
        if (algorithm.returncode != 0 or len(algorithm.stdout) != 44
                or not algorithm.stdout.startswith(ed25519_spki)):
            raise CaseError("Preservation checkpoint trust public key must be Ed25519")
        with tempfile.TemporaryDirectory(prefix="rocky-anchor-") as temp:
            src = Path(temp)
            data_path = src / "checkpoint.bin"
            sig_path = src / "signature.bin"
            for path, data in ((data_path, _canonical(payload)), (sig_path, signature)):
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
            answer = subprocess.run(
                ["/usr/bin/openssl", "pkeyutl", "-verify", "-rawin",
                 "-pubin", "-inkey", str(key), "-in", str(data_path),
                 "-sigfile", str(sig_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=8, check=False,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaseError("Preservation checkpoint cryptographic provider unavailable") from exc
    if answer.returncode != 0:
        raise CaseError("Preservation checkpoint Ed25519 signature did not verify")


def verify_signed_checkpoint(store: CaseStore, case_id: str, signed_raw: bytes,
                             *, trust_root: Path = TRUST_DIR, trusted_uid: int = 0,
                             now: int | None = None) -> dict[str, Any]:
    """Verify signature then compare externally supplied anchored prefix.

    SUCCESS says ONLY that the current valid local journal matches this signed
    checkpoint. Storage outside this UID, trusted signatory and latest-checkpoint
    selection cannot be established from the supplied envelope alone.
    """
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise CaseError("Preservation checkpoint case identity invalid")
    envelope = _decode(signed_raw, max_bytes=MAX_ENVELOPE_BYTES)
    if set(envelope) != {"payload", "signature"}:
        raise CaseError("Preservation signed envelope schema invalid")
    payload = _validate_payload(envelope["payload"], now=now)
    if payload["case_id"] != case_id:
        raise CaseError("Preservation checkpoint is for a different case")
    if signed_raw.strip() != _canonical(envelope):
        raise CaseError("Preservation signed envelope is not canonical")
    _verify_ed25519(payload, envelope["signature"], trust_root, trusted_uid)
    with admission_lock(store):
        with store._locked(case_id) as (folder, _):
            state = _load_locked(folder, case_id)
        count = state["record_count"]
        anchored_count = payload["record_count"]
        if count < anchored_count:
            status = "LEDGER_TRUNCATED_BELOW_SIGNED_CHECKPOINT"
            prefix_matches = False
        elif state["record_heads"][anchored_count - 1] != payload["head_sha256"]:
            status = "LEDGER_PREFIX_DIVERGED_FROM_SIGNED_CHECKPOINT"
            prefix_matches = False
        elif count > anchored_count:
            status = "SIGNED_PREFIX_MATCHES_WITH_UNANCHORED_TAIL"
            prefix_matches = True
        else:
            status = "SIGNED_CHECKPOINT_MATCHES_CURRENT_LEDGER"
            prefix_matches = True
        return {
            "status": status, "case_id": case_id,
            "checkpoint_record_count": anchored_count,
            "current_record_count": count,
            "additional_unanchored_records": max(0, count - anchored_count),
            "checkpoint_signature_verified": True,
            "signed_prefix_matches": prefix_matches,
            "signed_checkpoint_covers_current_ledger": status == "SIGNED_CHECKPOINT_MATCHES_CURRENT_LEDGER",
            "external_custody_independently_verified": False,
            "latest_checkpoint_independently_verified": False,
            "signer_legal_authority_verified": False,
            "checkpoint_timestamp_authoritative": False,
            "ledger_fully_immutable": False,
            "deletion_authorized": False,
            "hold_release_supported": False,
            "originals_removed": 0,
            "raw_originals_exported": 0,
            "public_disclosure_approved": False,
            "signed_payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
        }
