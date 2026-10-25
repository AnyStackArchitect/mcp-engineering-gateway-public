#!/usr/bin/env python3
"""OFF-ROCKY human signing tool for an exported Rocky engineering review bundle.

Copy this script and approvalwork.py to the operator-controlled workstation.
Use a dedicated Ed25519 private key protected by that workstation; NEVER copy
the key, SSH agent, password, or token onto Rocky01 or into an MCP case.
This tool does not contact Rocky01, GitHub, ChatGPT or any other service.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from approvalwork import DOMAIN, canonical

def _read_review(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > 24000:
        raise ValueError("Invalid review bundle")
    data = json.loads(path.read_text(encoding="ascii"))
    if not isinstance(data, dict) or set(data) != {"plan", "digest", "state", "created", "script"}:
        raise ValueError("Invalid review bundle structure")
    if data["state"] != "PREPARED":
        raise ValueError("Plan no longer eligible for approval")
    plan = data["plan"]
    if not isinstance(plan, dict) or not isinstance(data["script"], str):
        raise ValueError("Review payload invalid")
    digest = hashlib.sha256(canonical(plan)).hexdigest()
    if digest != data["digest"]:
        raise ValueError("Review plan digest mismatch")
    if (hashlib.sha256(data["script"].encode("utf-8")).hexdigest() != plan["script_sha256"]
            or len(data["script"].encode("utf-8")) > 16384
            or not isinstance(data["created"], int)):
        raise ValueError("Review script or creation time invalid")
    if (not isinstance(plan["case_id"], str) or not isinstance(plan["id"], str)
            or len(plan["id"]) != 32 or len(plan["case_id"]) != 32):
        raise ValueError("Review plan identity invalid")
    return data, digest

def _sign_bytes(key: Path, data: bytes, executable: str) -> bytes:
    info = key.lstat()
    if (key.is_symlink() or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or (os.name != "nt"
            and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
        raise ValueError("Signing private key is not protected")
    if not executable:
        raise ValueError("OpenSSL is not available on this operator workstation")
    with tempfile.TemporaryDirectory(prefix="rocky-sign-") as directory:
        signature = Path(directory) / "signature.bin"
        message = Path(directory) / "grant-payload.bin"
        message.write_bytes(data)
        result = subprocess.run(
            [executable, "pkeyutl", "-sign", "-rawin",
             "-inkey", str(key), "-in", str(message), "-out", str(signature)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=12, check=False)
        if result.returncode:
            raise ValueError("Ed25519 signing failed")
        raw = signature.read_bytes()
        if len(raw) != 64:
            raise ValueError("Unexpected signing algorithm or signature length")
        return raw

def main() -> int:
    parser = argparse.ArgumentParser(description="OFF-HOST human authorization of one sandbox plan")
    parser.add_argument("review_bundle", type=Path)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Human interactive terminal required", file=sys.stderr)
        return 2
    try:
        bundle, digest = _read_review(args.review_bundle)
        now = int(time.time())
        expiry = min(now + 300, bundle["created"] + 1800)
        if expiry <= now or now + 30 < bundle["created"]:
            raise ValueError("Review bundle expired or workstation clock disagrees")
        print("Operator review: source is UNTRUSTED and will run in a constrained lab.")
        print("PLAN:", json.dumps(bundle["plan"], sort_keys=True))
        print("PLAN SHA256:", digest)
        print("SCRIPT (escaped so control characters cannot alter the terminal):")
        print(ascii(bundle["script"]))
        print("Type full plan SHA256 to APPROVE; DENY to reject; blank to abort:")
        decision_input = input("> ").strip()
        if decision_input not in (digest, "DENY"):
            print("No grant generated")
            return 1
        payload = {
            "domain": DOMAIN, "execution_id": bundle["plan"]["id"],
            "case_id": bundle["plan"]["case_id"], "plan_sha256": digest,
            "nonce": secrets.token_hex(16), "issued_at": now,
            "expires_at": expiry,
            "decision": "DENY" if decision_input == "DENY" else "APPROVE",
        }
        signature = _sign_bytes(args.private_key, canonical(payload), shutil.which("openssl") or "")
        envelope = {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
        data = canonical(envelope) + b"\n"
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
        print("Signed decision:", payload["decision"], "for", payload["execution_id"])
        print("Move the signed grant only (never the signing key) to the Rocky operator import step.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("Signing refused: " + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
