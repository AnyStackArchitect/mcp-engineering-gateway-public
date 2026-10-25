#!/usr/bin/env python3
"""Independent nonroot process proof of read-only case retention readiness.

Synthetic disposable files only. No case deletion, Rocky01 access, real
retention policy, customer data, network transfer or publication approval.
"""
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

CLI = Path(__file__).resolve().parent / "case_retention_cli.py"


def invoke(home: Path, case_id: str, *args: str, allowed: bool) -> dict | None:
    result = subprocess.run(
        [sys.executable, "-u", str(CLI), "--case-id", case_id, *args],
        env={**os.environ, "HOME": str(home)}, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35, check=False)
    if not allowed:
        if result.returncode == 0:
            raise RuntimeError("An unapproved or malformed retention request succeeded")
        return None
    if result.returncode or len(result.stdout) > 8192:
        raise RuntimeError("Expected bounded read-only retention preview refused")
    return json.loads(result.stdout)


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Nonroot retention smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-retention-smoke-") as temp:
        home = Path(temp)
        store = CaseStore(home)
        case_id = store.open_case()["case_id"]
        raw = b"synthetic-case-original password=local-only\n" * 200
        stage = store.inbox / "client-identity-redacted.log"
        stage.write_bytes(raw)
        stage.chmod(0o600)
        record = store.register(case_id, stage.name, worker=True)
        with store._locked(case_id) as (folder, manifest):
            manifest["created_at"] = (datetime.now(timezone.utc) -
                                      timedelta(days=45)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        original = store.cases / case_id / "originals" / record["artifact_id"]
        expected = hashlib.sha256(original.read_bytes()).hexdigest()
        invoke(home, case_id, "--minimum-age-days", "30", allowed=False)
        invoke(home, case_id, "--preview", "--minimum-age-days", "30", "--delete",
               allowed=False)
        preview = invoke(home, case_id, "--preview", "--minimum-age-days", "30",
                         allowed=True)
        if (preview["status"] != "REVIEW_ONLY" or not preview["age_threshold_met"] or
                not preview["review_candidate"] or
                preview["deletion_authorized"] or
                preview["original_artifacts_sha256_verified"] != 1 or
                preview["original_bytes_sha256_verified"] != len(raw)):
            raise RuntimeError("Retention preview source or authority boundaries wrong")
        if b"password=" in json.dumps(preview).encode() or b"client-identity" in json.dumps(preview).encode():
            raise RuntimeError("Retention preview leaked original content/name")
        if hashlib.sha256(original.read_bytes()).hexdigest() != expected:
            raise RuntimeError("Read-only retention preview altered registered evidence")
        original.write_bytes(b"X" * len(raw))
        invoke(home, case_id, "--preview", "--minimum-age-days", "30",
               allowed=False)
        if not original.exists():
            raise RuntimeError("Invalid evidence was deleted during failed preview")
        print(json.dumps({
            "qualification": "OFF_HOST_REGISTERED_ORIGINAL_REVIEW",
            "status": "PASS", "read_only": True,
            "originals_removed": 0, "raw_exported": 0,
            "rocky10_host_validated": False, "retention_authority_established": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
