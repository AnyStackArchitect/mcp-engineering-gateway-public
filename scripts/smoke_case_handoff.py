#!/usr/bin/env python3
"""Non-root end-to-end synthetic private metadata-only case handoff.

No cloud transfer, customer content, real Rocky installation, or raw evidence
package. This smoke explicitly invokes the operator CLI in separate processes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from archivework import verify_case
from casework import CaseStore

CLI = Path(__file__).resolve().parent / "case_handoff_cli.py"


def call(home: Path, *options: str, expect_success: bool = True) -> dict | None:
    command = [sys.executable, "-u", str(CLI), *options]
    done = subprocess.run(command, env={**os.environ, "HOME": str(home)},
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=35, check=False)
    if not expect_success:
        if done.returncode == 0:
            raise RuntimeError("Unapproved handoff operation succeeded")
        return None
    if done.returncode != 0:
        raise RuntimeError("Private case handoff CLI unexpectedly refused")
    if len(done.stdout) > 8192:
        raise RuntimeError("Handoff CLI emitted excessive metadata")
    return json.loads(done.stdout)


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Operator handoff smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-private-handoff-") as directory:
        home = Path(directory)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        raw = b"2026-10-17 ERROR synthetic customer-secret=do-not-publish\n" * 1024
        staged = store.inbox / "sensitive-hostname.log"
        staged.write_bytes(raw)
        staged.chmod(0o600)
        registered = store.register(case, staged.name, worker=True)
        expected = hashlib.sha256(raw).hexdigest()
        if registered["sha256"] != expected:
            raise RuntimeError("Original synthetic log failed registration")
        if verify_case(store, case)["status"] != "PASS":
            raise RuntimeError("Original private case integrity incomplete")

        preview = call(home, "--case-id", case, "--preview")
        if (preview["status"] != "PREVIEW_ONLY" or
                preview["artifact_count"] != 1 or
                preview["raw_originals_exported"] != 0):
            raise RuntimeError("Handoff preview contained unexpected scope")
        call(home, "--case-id", case, "--confirm", expect_success=False)
        confirmed = call(home, "--case-id", case, "--confirm",
                         "--plan-sha256", preview["plan_sha256"])
        target = store.base / "handoff-manifests" / confirmed["export_name"]
        if (confirmed["status"] != "PRIVATE_METADATA_EXPORTED" or
                confirmed["plan_sha256"] != preview["plan_sha256"] or
                hashlib.sha256(target.read_bytes()).hexdigest() != preview["plan_sha256"]):
            raise RuntimeError("Private metadata handoff cannot be verified")
        output = target.read_bytes()
        for secret in (b"sensitive-hostname", b"do-not-publish", b"customer-secret",
                       b"intake_name", raw[:100]):
            if secret in output:
                raise RuntimeError("Handoff disclosed raw synthetic evidence or file name")
        if not output or target.stat().st_mode & 0o077:
            raise RuntimeError("Metadata-only package is not owner-private")
        call(home, "--case-id", case, "--confirm",
             "--plan-sha256", preview["plan_sha256"], expect_success=False)
        if verify_case(store, case)["status"] != "PASS":
            raise RuntimeError("Handoff altered original evidence")
        print(json.dumps({
            "qualification": "OFF_HOST_PRIVATE_METADATA_HANDOFF",
            "status": "PASS", "registered_originals_verified": 1,
            "export_sha256": preview["plan_sha256"],
            "raw_originals_exported": 0,
            "public_disclosure_approved": False,
            "actual_rocky10_qualified": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
