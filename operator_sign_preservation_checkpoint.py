#!/usr/bin/env python3
"""OFF-ROCKY dedicated Ed25519 checkpoint signer.

Copy this standalone tool to a separate operator workstation. NEVER copy an
Ed25519 private key or signing agent onto Rocky01 or into a gateway case.
The exported preview contains metadata identities only, never original bytes.
Signing proves key possession, not legal authority or trustworthy custody.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

DOMAIN = "rocky-eng:preservation-anchor:v1"
PAYLOAD_FIELDS = {"domain", "case_id", "record_count", "head_sha256",
                  "issued_at", "nonce"}
HEX32 = re.compile(r"^[a-f0-9]{32}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
MAX_PREVIEW = 2048
MAX_ENVELOPE = 4096


def canonical(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def _no_duplicates(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate checkpoint key")
        output[key] = value
    return output


def _source_identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid,
            stat.S_IMODE(st.st_mode), st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def _read_source(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("Untrusted checkpoint source symlink")
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
            or not 0 < st.st_size <= MAX_PREVIEW
            or (os.name != "nt" and (st.st_uid != os.getuid()
                                    or st.st_mode & 0o077))):
        raise ValueError("Checkpoint source identity or privacy invalid")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if _source_identity(st) != _source_identity(opened):
            raise ValueError("Checkpoint source changed while opening")
        data = os.read(fd, MAX_PREVIEW + 1)
        after = os.fstat(fd)
        final = path.lstat()
        if (len(data) != opened.st_size
                or _source_identity(st) != _source_identity(after)
                or _source_identity(st) != _source_identity(final)):
            raise ValueError("Checkpoint source changed during read")
    finally:
        os.close(fd)
    return data


def validate_preview(raw: bytes) -> tuple[dict[str, Any], str]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_PREVIEW:
        raise ValueError("Checkpoint preview size invalid")
    try:
        packet = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Checkpoint preview JSON invalid") from exc
    if (not isinstance(packet, dict)
            or set(packet) != {"status", "payload", "payload_sha256"}
            or packet["status"] != "UNSIGNED_CHECKPOINT_PREVIEW"
            or not isinstance(packet["payload"], dict)
            or set(packet["payload"]) != PAYLOAD_FIELDS):
        raise ValueError("Checkpoint preview schema invalid")
    data = packet["payload"]
    if (data["domain"] != DOMAIN
            or not isinstance(data["case_id"], str)
            or HEX32.fullmatch(data["case_id"]) is None
            or type(data["record_count"]) is not int
            or not 1 <= data["record_count"] <= 128
            or not isinstance(data["head_sha256"], str)
            or HEX64.fullmatch(data["head_sha256"]) is None
            or not isinstance(data["nonce"], str)
            or HEX32.fullmatch(data["nonce"]) is None
            or type(data["issued_at"]) is not int
            or data["issued_at"] <= 0
            or data["issued_at"] > int(time.time()) + 300):
        raise ValueError("Checkpoint preview payload invalid")
    digest = hashlib.sha256(canonical(data)).hexdigest()
    if (not isinstance(packet["payload_sha256"], str)
            or packet["payload_sha256"] != digest
            or raw.strip() != canonical(packet)):
        raise ValueError("Checkpoint preview digest or canonical encoding invalid")
    return data, digest


def sign_preview(raw: bytes, key: Path, executable: str) -> dict[str, Any]:
    # Native Windows private-key ACL validation is not implemented in this
    # slice. Fail closed rather than claiming POSIX mode checks cover NTFS.
    if os.name == "nt":
        raise ValueError("Native Windows signing-key ACL qualification unavailable")
    payload, _ = validate_preview(raw)
    if not executable:
        raise ValueError("OpenSSL is not present on operator workstation")
    if key.is_symlink():
        raise ValueError("Signing key symlink refused")
    st = key.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
            or (os.name != "nt" and (st.st_uid != os.getuid()
                                    or st.st_mode & 0o077))):
        raise ValueError("Operator signing key is not private")
    with tempfile.TemporaryDirectory(prefix="rocky-anchor-sign-") as directory:
        temp = Path(directory)
        message = temp / "message.bin"
        signature = temp / "signature.bin"
        message.write_bytes(canonical(payload))
        output = subprocess.run(
            [executable, "pkeyutl", "-sign", "-rawin",
             "-inkey", str(key), "-in", str(message), "-out", str(signature)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=12, check=False)
        if output.returncode != 0:
            raise ValueError("Off-host Ed25519 signing failed")
        signed = signature.read_bytes()
        if len(signed) != 64:
            raise ValueError("Checkpoint signature must be Ed25519")
    envelope = {
        "payload": payload,
        "signature": base64.b64encode(signed).decode("ascii"),
    }
    if len(canonical(envelope)) > MAX_ENVELOPE:
        raise ValueError("Signed checkpoint output exceeds limit")
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(description="OFF-ROCKY checkpoint signing")
    parser.add_argument("unsigned_checkpoint", type=Path)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.name == "nt":
        print("Native Windows signing requires a separately qualified ACL-aware signer",
              file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Interactive operator terminal required for checkpoint signing",
              file=sys.stderr)
        return 2
    try:
        preview = _read_source(args.unsigned_checkpoint)
        payload, digest = validate_preview(preview)
        print("This signs checkpoint bytes, NOT legal authority or release permission.")
        print("The signing key MUST be dedicated and remain outside Rocky01.")
        print("Case ID:", payload["case_id"], "Record count:", payload["record_count"])
        print("Last preserved record SHA256:", payload["head_sha256"])
        print("Checkpoint payload SHA256:", digest)
        print("Type the entire payload SHA256 to sign, or press Enter to cancel:")
        if input("> ").strip() != digest:
            print("No signed checkpoint produced")
            return 1
        envelope = sign_preview(preview, args.private_key, shutil.which("openssl") or "")
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(canonical(envelope) + b"\n")
            target.flush()
            os.fsync(target.fileno())
        print("Signed checkpoint written. Retain this file and provenance off Rocky01.")
        print("Do not reuse the execution-grant signing key for checkpoint custody.")
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print("Checkpoint signing refused: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
