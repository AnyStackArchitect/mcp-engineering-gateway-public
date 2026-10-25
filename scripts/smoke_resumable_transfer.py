#!/usr/bin/env python3
"""Unprivileged cross-process resumable SSH-stream intake -> managed case import.

Uses only synthetic bytes, fresh HOME and local subprocesses, no network, no
Rocky01 installation and no fabricated Windows interoperability claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from smoke_evidence import call, job

ROOT = Path(__file__).resolve().parents[1]


def bridge(home: Path, args: list[str], *, data: bytes = b"",
           expect_success: bool = True) -> dict | None:
    result = subprocess.run(
        [sys.executable, "-u", str(ROOT / "transfer_bridge.py"), *args],
        input=data, env={**os.environ, "HOME": str(home)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=25, check=False)
    if not expect_success:
        if result.returncode == 0:
            raise RuntimeError("Expected SSH-style transfer command to be rejected")
        return None
    if result.returncode:
        raise RuntimeError("Private stream transfer subprocess failed")
    if result.stderr:
        raise RuntimeError("Unexpected transfer helper stderr")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("Malformed transfer helper result")
    return value


def main() -> int:
    if os.geteuid() == 0:
        print("Run off-host smoke as an unprivileged CI account", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="rocky-resume-smoke-") as directory:
        home = Path(directory)
        case = call(home, "case_open", {})["case_id"]
        data = (b"2026-10-16T23:44:00Z synthetic capture egress failed\n"
                b"retry timeout observed; test-only case bytes\n") * 12
        sha = hashlib.sha256(data).hexdigest()
        token = ".upload-" + "d" * 32
        prep = bridge(home, ["prepare", "--size", str(len(data))])
        if prep["status"] != "READY" or prep["safe_available_bytes"] < len(data):
            raise RuntimeError("Insufficient free-space preflight was not enforced")
        bridge(home, ["begin", "--temp", token, "--size", str(len(data)),
                      "--sha256", sha])
        first = data[:81]
        bridge(home, ["append", "--temp", token, "--offset", "0"], data=first)
        # The next process is a distinct SSH connection; it has no in-memory
        # transfer state and must derive its recovery offset/hash from storage.
        progress = bridge(home, ["status", "--temp", token])
        if (progress["bytes_staged"] != len(first)
                or progress["prefix_sha256"] != hashlib.sha256(first).hexdigest()):
            raise RuntimeError("Recovery prefix was not independently verified")
        bridge(home, ["append", "--temp", token, "--offset", "0"],
               data=b"wrong-offset", expect_success=False)
        bridge(home, ["append", "--temp", token, "--offset", str(len(first))],
               data=data[len(first):])
        pre_final = bridge(home, ["status", "--temp", token])
        if pre_final["status"] != "COMPLETE_UNVERIFIED":
            raise RuntimeError("Upload incorrectly marked staged before full-hash verification")
        stage = bridge(home, ["finalize", "--temp", token, "--filename",
                              "support.log", "--size", str(len(data)), "--sha256", sha])
        if stage["status"] != "STAGED":
            raise RuntimeError("Final full-content SHA-256 proof failed")
        outcome = job(home, "import_staged", case, filename="support.log")
        if (outcome["status"] != "REGISTERED" or outcome["sha256"] != sha
                or outcome["bytes"] != len(data)):
            raise RuntimeError("Managed case intake did not preserve the transferred identity")
        check = job(home, "verify_case", case)
        if check["status"] != "PASS" or check["verified_count"] != 1:
            raise RuntimeError("Case verification rejected the transferred artifact")
        if (home / ".local/share/rocky-mcp-gateway/inbox" / (token + ".session")).exists():
            raise RuntimeError("Resumable upload metadata was not cleaned up")
        summary = json.dumps({"case": case, "result": outcome, "check": check})
        if "timeout observed" in summary or data[:20].decode() in summary:
            raise RuntimeError("Raw case contents exposed in metadata")
    print("PASS: cross-process binary SSH-style resumed upload, hash prefix, offset refusal, finalize, worker import and vault verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
