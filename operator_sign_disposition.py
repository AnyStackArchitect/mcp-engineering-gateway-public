#!/usr/bin/env python3
"""OFF-ROCKY operator signer; distribute with disposition_grants.py only.

Each role keeps a different dedicated private key outside Rocky. This tool does
not generate keys or independently verify the human's external attestations.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from disposition_grants import (DOMAIN, ROLES, ATTESTATIONS, MAX_SECONDS, canonical,
    decode, private_read, validate_plan, validate_payload, DispositionGrantError)


def sign_plan(raw: bytes, key: Path, role: str, attestations: dict, executable: str) -> dict:
    if os.name != "posix":
        raise DispositionGrantError("Signing requires separately qualified POSIX private-key custody")
    packet = decode(raw)
    if (set(packet) != {"status", "plan", "plan_sha256", "deletion_authorized"}
            or packet["status"] != "UNSIGNED_DISPOSITION_PLAN" or packet["deletion_authorized"] is not False):
        raise DispositionGrantError("Unsigned disposition preview invalid")
    plan = validate_plan(packet["plan"])
    if packet["plan_sha256"] != hashlib.sha256(canonical(plan)).hexdigest():
        raise DispositionGrantError("Unsigned disposition preview digest mismatch")
    now = int(time.time())
    payload = {"domain": DOMAIN, "role": role, "decision": "APPROVE", "plan": plan,
               "plan_sha256": packet["plan_sha256"], "nonce": secrets.token_hex(16),
               "issued_at": now, "expires_at": now + MAX_SECONDS, "attestations": attestations}
    validate_payload(payload)
    # Copy verified private key bytes to a private temporary file so a path
    # substitution between validation and OpenSSL cannot switch the signer key.
    material = private_read(key, 16384)
    with tempfile.TemporaryDirectory(prefix="rocky-disposition-sign-") as name:
        folder = Path(name)
        for leaf, value in (("key.pem", material), ("message", canonical(payload))):
            fd = os.open(folder / leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(value)
        fd = os.open(folder / "signature", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            result = subprocess.run([executable, "pkeyutl", "-sign", "-rawin", "-inkey",
                str(folder / "key.pem"), "-in", str(folder / "message"), "-out",
                str(folder / "signature")], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError) as exc:
            raise DispositionGrantError("Off-host disposition signing provider unavailable") from exc
        if result.returncode:
            raise DispositionGrantError("Off-host disposition signing failed")
        signature = private_read(folder / "signature", 1024)
        if len(signature) != 64:
            raise DispositionGrantError("Disposition signer requires an Ed25519 key")
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="OFF-ROCKY independent case-disposition signer")
    parser.add_argument("preview", type=Path)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--attestations", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() == 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        print("A nonroot POSIX operator terminal with independent key custody is required", file=sys.stderr)
        return 2
    try:
        raw = private_read(args.preview)
        packet = decode(raw)
        plan = validate_plan(packet.get("plan"))
        attest = decode(private_read(args.attestations))
        if set(attest) != ATTESTATIONS:
            raise DispositionGrantError("All four external attestation references required")
        print("Action:", plan["action"], "Case:", plan["case_id"], "Role:", args.role)
        print("Registered original count:", plan["original_count"], "Original bytes:", plan["original_bytes"])
        print("Retention start (human declaration):", plan["retention_start_utc"])
        print("You attest the authority, backup, restore and latest-checkpoint records are valid for this exact case.")
        print("The software has NOT independently verified those external facts.")
        if plan["action"] == "FINAL_DELETE":
            print("FINAL_DELETE permanently unlinks the listed case evidence and indexes. Metadata remains.")
        for name in sorted(attest):
            print(name + ":", attest[name])
        digest = hashlib.sha256(canonical(plan)).hexdigest()
        print("Exact plan SHA256:", digest)
        if input("Type this full plan SHA256 to sign, or Enter to cancel: ").strip() != digest:
            return 1
        signed = sign_plan(raw, args.private_key, args.role, attest, shutil.which("openssl") or "")
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(canonical(signed) + b"\n")
            out.flush()
            os.fsync(out.fileno())
        print("One five-minute grant written. The other role must independently sign the same preview and attestations.")
        return 0
    except (OSError, ValueError, DispositionGrantError) as exc:
        print("Disposition signing refused: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
