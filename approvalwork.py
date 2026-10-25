#!/usr/bin/env python3
"""Verify an operator-signed Ed25519 execution grant.

Only the PUBLIC key is used here. Production trust anchor:
  /etc/rocky-eng/approval_ed25519_pub.pem (root-owned, not writable by worker).
The private signing key must NEVER be installed on Rocky01, passed through MCP,
or placed in a case bundle. Full authorization also requires OS isolation of
the worker's writable grant/consumption state; see OPERATOR_SANDBOX_V010.md.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

APPROVAL_DIR = Path("/etc/rocky-eng")
KEY_NAME = "approval_ed25519_pub.pem"
DOMAIN = "rocky-eng:execution-grant:v1"
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
FIELDS = {"domain", "execution_id", "case_id", "plan_sha256", "nonce",
          "issued_at", "expires_at", "decision"}
MAX_GRANT_BYTES = 4096
MAX_GRANT_SECONDS = 300
FUTURE_SKEW_SECONDS = 30

class GrantError(Exception):
    """A grant was malformed, expired, untrusted, or mismatched."""

def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GrantError("Duplicate grant key")
        result[key] = value
    return result

def decode(data: bytes) -> dict:
    if not isinstance(data, bytes) or not 2 <= len(data) <= MAX_GRANT_BYTES:
        raise GrantError("Grant size invalid")
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise GrantError("Grant JSON invalid") from exc
    if not isinstance(value, dict):
        raise GrantError("Grant must be an object")
    return value

def _approved_key(root: Path, uid: int) -> Path:
    """No symlink, owner/permission substitution, or ordinary writable key path."""
    if not root.is_absolute() or root == Path("/"):
        raise GrantError("Invalid grant trust root")
    # Root's own ancestors must not be writable by worker or other users.
    for parent in (*reversed(root.parents), root):
        if parent.is_symlink():
            raise GrantError("Grant trust ancestor symlink rejected")
        try:
            info = parent.lstat()
        except OSError as exc:
            raise GrantError("Grant trust root unavailable") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise GrantError("Grant trust ancestor not a directory")
        # /tmp with sticky bit is allowed only in explicitly injected test mode.
        if uid == 0 and (info.st_uid != 0 or info.st_mode & 0o022):
            raise GrantError("Grant trust root is not administrator-controlled")
    if root.is_symlink():
        raise GrantError("Grant trust root symlink rejected")
    directory = root.lstat()
    if directory.st_uid != uid or directory.st_mode & 0o022:
        raise GrantError("Grant trust directory is writable by an untrusted identity")
    target = root / KEY_NAME
    if target.is_symlink():
        raise GrantError("Grant signing key symlink rejected")
    try:
        info = target.lstat()
    except OSError as exc:
        raise GrantError("Grant verification key unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_mode & 0o022 or info.st_nlink != 1
            or info.st_size < 80 or info.st_size > 2048):
        raise GrantError("Grant verification key ownership or type unsafe")
    return target

def verify(envelope: dict, *, trust_dir: Path = APPROVAL_DIR,
           trusted_uid: int = 0, now: int | None = None) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise GrantError("Signed grant envelope invalid")
    payload, signature = envelope["payload"], envelope["signature"]
    if not isinstance(payload, dict) or set(payload) != FIELDS:
        raise GrantError("Signed grant payload fields invalid")
    if (payload["domain"] != DOMAIN
            or payload["decision"] not in ("APPROVE", "DENY")
            or not isinstance(payload["execution_id"], str)
            or not HEX32.fullmatch(payload["execution_id"])
            or not isinstance(payload["case_id"], str)
            or not HEX32.fullmatch(payload["case_id"])
            or not isinstance(payload["plan_sha256"], str)
            or not HEX64.fullmatch(payload["plan_sha256"])
            or not isinstance(payload["nonce"], str)
            or not HEX32.fullmatch(payload["nonce"])
            or type(payload["issued_at"]) is not int
            or type(payload["expires_at"]) is not int):
        raise GrantError("Signed grant payload values invalid")
    current = int(time.time()) if now is None else now
    if (payload["issued_at"] > current + FUTURE_SKEW_SECONDS
            or current >= payload["expires_at"]
            or payload["expires_at"] <= payload["issued_at"]
            or payload["expires_at"] - payload["issued_at"] > MAX_GRANT_SECONDS):
        raise GrantError("Signed grant time bounds invalid")
    if not isinstance(signature, str) or len(signature) != 88:
        raise GrantError("Signed grant signature encoding invalid")
    try:
        signed = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GrantError("Signed grant signature invalid") from exc
    if len(signed) != 64:
        raise GrantError("Signed grant signature length invalid")
    public_key = _approved_key(Path(trust_dir), trusted_uid)
    # Use fixed arguments, no shell, no inherited environment secrets.
    with tempfile.TemporaryDirectory(prefix="rocky-approval-") as temporary:
        path = Path(temporary) / "signature.bin"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(signed)
        message = Path(temporary) / "grant-payload.bin"
        mfd = os.open(message, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(mfd, "wb") as out:
            out.write(canonical(payload))
        try:
            result = subprocess.run(
                ["/usr/bin/openssl", "pkeyutl", "-verify", "-rawin",
                 "-pubin", "-inkey", str(public_key), "-in", str(message),
                 "-sigfile", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=6, check=False,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GrantError("Grant signature provider unavailable") from exc
    if result.returncode != 0:
        raise GrantError("Signed grant did not verify")
    return payload
