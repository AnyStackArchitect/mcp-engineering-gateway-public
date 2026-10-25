#!/usr/bin/env python3
"""Independent nonroot policy review smoke using disposable synthetic cases."""
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
from case_handoff import _canonical
from preservationwork import propose_or_record, read_controls

CLI = Path(__file__).resolve().parent / "case_policy_review_cli.py"


def run_cli(home: Path, case_id: str, raw: bytes, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-u", str(CLI), "--case-id", case_id, "--review",
         "--policy-stdin", *extra],
        input=raw, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=50, check=False,
        env={**os.environ, "HOME": str(home)})


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Policy review smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-policy-review-") as temp:
        home = Path(temp)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        raw = b"synthetic private customer password=DO_NOT_EXPORT\n"
        stage = store.inbox / "sensitive-original.log"
        stage.write_bytes(raw)
        stage.chmod(0o600)
        identity = store.register(case, stage.name)
        with store._locked(case) as (folder, manifest):
            manifest["created_at"] = (datetime.now(timezone.utc) -
                                      timedelta(days=90)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        hold = {"action": "PRESERVATION_HOLD",
                "reference_sha256": identity["sha256"],
                "reason_code": "investigation"}
        view = propose_or_record(store, case, **hold)
        propose_or_record(store, case, **hold, confirm=True,
                          plan_sha256=view["plan_sha256"])
        policy = {
            "schema": 1, "mode": "REVIEW_ONLY", "case_id": case,
            "policy_id": "a" * 32,
            "rules": [
                {"rule_id": "b"*32, "kind": "MINIMUM_DAYS",
                 "minimum_days": 180, "source_sha256": identity["sha256"]}],
            "release_review": {
                "target_hold_sequence": 1,
                "request_source_sha256": identity["sha256"],
            },
        }
        result = run_cli(home, case, _canonical(policy))
        if result.returncode != 0:
            raise RuntimeError("Valid review-only policy assessment refused")
        doc = json.loads(result.stdout)
        if (doc["status"] != "POLICY_REVIEW_ONLY"
                or doc["effective_advisory_minimum_days"] != 180
                or "LOCAL_PRESERVATION_HOLD_ACTIVE" not in doc["blockers"]
                or "STRICTEST_MINIMUM_RETENTION_NOT_REACHED" not in doc["blockers"]
                or doc["hold_release_authorized"]
                or doc["hold_release_executed"] or doc["deletion_authorized"]
                or doc["originals_removed"] or doc["raw_originals_exported"]):
            raise RuntimeError("Policy precedence or non-execution contract broken")
        if read_controls(store, case)["active_hold_count"] != 1:
            raise RuntimeError("Read-only policy assessment changed the hold")
        for forbidden in [b"password=DO_NOT_EXPORT", b"sensitive-original.log",
                          identity["sha256"].encode()]:
            if forbidden in result.stdout:
                raise RuntimeError("Review-only report revealed protected evidence")
        denied = run_cli(home, case, _canonical(policy), "--execute")
        if denied.returncode == 0:
            raise RuntimeError("Unapproved action flag accepted")
        original = store.cases / case / "originals" / identity["artifact_id"]
        if hashlib.sha256(original.read_bytes()).hexdigest() != identity["sha256"]:
            raise RuntimeError("Policy review altered original evidence")
        print(json.dumps({
            "qualification": "OFF_HOST_POLICY_HOLD_REVIEW",
            "status": "PASS",
            "case_originals_removed": 0,
            "hold_release_executed": False,
            "trusted_policy_authority_proven": False,
            "rocky10_host_validated": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
