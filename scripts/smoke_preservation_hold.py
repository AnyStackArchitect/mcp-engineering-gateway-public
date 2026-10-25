#!/usr/bin/env python3
"""Independent local process test of additive, non-destructive preservation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseStore, _write_json_atomic
from retentionwork import assess_case

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "case_preservation_cli.py"


def call(home: Path, case_id: str, source_sha: str, *args: str,
         expect_success: bool = True) -> dict | None:
    result = subprocess.run(
        [sys.executable, "-u", str(CLI), "--case-id", case_id,
         "--source-reference-sha256", source_sha, *args],
        env={**os.environ, "HOME": str(home)}, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if not expect_success:
        if result.returncode == 0:
            raise RuntimeError("Invalid preservation operation was accepted")
        return None
    if result.returncode or len(result.stdout) > 8192:
        raise RuntimeError("Bounded nonroot preservation CLI refused")
    return json.loads(result.stdout)


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Off-host preservation smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-preserve-") as root:
        home = Path(root)
        store = CaseStore(home)
        case_id = store.open_case()["case_id"]
        evidence = b"2026-10-17 ERROR synthetic password=keep-private\n" * 4096
        staged = store.inbox / "private-system.log"
        staged.write_bytes(evidence)
        staged.chmod(0o600)
        artifact = store.register(case_id, staged.name)
        source = store.cases / case_id / "originals" / artifact["artifact_id"]
        initial = hashlib.sha256(source.read_bytes()).hexdigest()
        with store._locked(case_id) as (folder, manifest):
            manifest["created_at"] = (datetime.now(timezone.utc) -
                                      timedelta(days=42)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        reference = hashlib.sha256(b"unverified local supporting-reference").hexdigest()
        base = ["--hold-reason", "investigation"]
        call(home, case_id, reference, *base, "--confirm", expect_success=False)
        call(home, case_id, reference, *base, "--preview", "--delete",
             expect_success=False)
        preview = call(home, case_id, reference, *base, "--preview")
        if preview["status"] != "PREVIEW_ONLY":
            raise RuntimeError("Preservation preview did not require confirmation")
        if (store.cases / case_id / "preservation").exists():
            raise RuntimeError("Preservation preview unexpectedly wrote case")
        confirmed = call(home, case_id, reference, *base, "--confirm",
                         "--plan-sha256", preview["plan_sha256"])
        if (confirmed["status"] != "PRESERVATION_RECORD_COMMITTED" or
                confirmed["active_preservation_holds"] != 1 or
                confirmed["deletion_authorized"]):
            raise RuntimeError("Committed hold or destructive boundary incorrect")
        report = assess_case(store, case_id, minimum_age_days=30)
        if (report["age_threshold_met"] is not True or
                report["review_candidate"] or
                "LOCAL_PRESERVATION_HOLD_ACTIVE" not in report["blockers"] or
                report["local_preservation_holds_active"] != 1):
            raise RuntimeError("Local active hold did not block age-only review")
        if hashlib.sha256(source.read_bytes()).hexdigest() != initial:
            raise RuntimeError("Retention controls changed original evidence")
        output = json.dumps({"preview": preview, "confirmed": confirmed,
                             "review": report}).encode()
        for private in (b"password=keep-private", b"private-system.log", evidence[:100]):
            if private in output:
                raise RuntimeError("Preservation emitted raw evidence or original name")
        print(json.dumps({
            "qualification": "OFF_HOST_ADDITIVE_PRESERVATION_HOLD",
            "status": "PASS", "originals_removed": 0,
            "active_holds": 1, "age_only_review_blocked": True,
            "legal_hold_authority_verified": False,
            "rocky10_host_validated": False,
            "disclosure_approved": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
