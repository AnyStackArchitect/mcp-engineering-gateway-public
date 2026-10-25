#!/usr/bin/env python3
"""Off-host nonroot subprocess smoke: disposition eligibility and interruption model.

All data is synthetic and disposable. No actual destructive code is called.
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
from preservationwork import propose_or_record, read_controls

CLI = Path(__file__).resolve().parent / "disposition_preflight_cli.py"


def run_cli(home: Path, case_id: str, *args: str, expected: int = 0) -> dict | None:
    cmd = [sys.executable, "-u", str(CLI), "--case-id", case_id,
           "--minimum-age-days", "30", *args]
    v = subprocess.run(cmd, env={**os.environ, "HOME": str(home)},
                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=50, check=False)
    if v.returncode != expected or len(v.stdout) > 16384:
        raise RuntimeError("Disposition preflight CLI returned wrong bounded state")
    return json.loads(v.stdout) if v.stdout else None


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Off-host disposition preflight smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-disposition-smoke-") as tmp:
        home = Path(tmp)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        source = b"private exported customer password=NEVER_ECHO\n" * 1024
        staged = store.inbox / "protected-original.log"
        staged.write_bytes(source)
        staged.chmod(0o600)
        item = store.register(case, staged.name)
        original = store.cases / case / "originals" / item["artifact_id"]
        hash_before = hashlib.sha256(original.read_bytes()).hexdigest()
        with store._locked(case) as (folder, manifest):
            manifest["created_at"] = (datetime.now(timezone.utc) -
                                      timedelta(days=365)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        preview = run_cli(home, case, "--preview")
        if (preview["status"] != "DISPOSITION_BLOCKED_READ_ONLY_PREFLIGHT"
                or not preview["advisory_minimum_age_met"]
                or preview["deletion_authorized"]
                or preview["independent_backup_exists_verified"]):
            raise RuntimeError("Disposition review did not refuse authority")
        stages = [
            "BEFORE_INTENT_JOURNAL",
            "AFTER_INTENT_JOURNAL",
            "AFTER_RECOVERY_COPY_ASSERTION",
            "DURING_ORIGINAL_DISPOSITION",
            "AFTER_ORIGINAL_DISPOSITION",
        ]
        for stage in stages:
            hypothetical = run_cli(home, case, "--simulate", stage,
                                   "--preview-sha256", preview["preview_sha256"])
            if (not hypothetical["simulation"]["simulated_interruption_only"]
                    or hypothetical["simulation"]["recovery_proven"]
                    or hypothetical["deletion_authorized"]):
                raise RuntimeError("Hypothetical interruption was treated as execution")
        hold = dict(action="PRESERVATION_HOLD", reference_sha256=item["sha256"],
                    reason_code="investigation")
        planned = propose_or_record(store, case, **hold)
        propose_or_record(store, case, **hold, confirm=True,
                          plan_sha256=planned["plan_sha256"])
        run_cli(home, case, "--simulate", "AFTER_INTENT_JOURNAL",
                "--preview-sha256", preview["preview_sha256"], expected=2)
        blocked = run_cli(home, case, "--preview")
        if (blocked["active_local_preservation_holds"] != 1
                or "ACTIVE_LOCAL_PRESERVATION_HOLD" not in blocked["blockers"]
                or blocked["deletion_authorized"]
                or read_controls(store, case)["active_hold_count"] != 1):
            raise RuntimeError("Adding a local hold did not invalidate preflight")
        run_cli(home, case, "--preview", "--delete", expected=2)
        if hashlib.sha256(original.read_bytes()).hexdigest() != hash_before:
            raise RuntimeError("Disposition preflight modified source original")
        output = json.dumps({"preview": preview, "blocked": blocked}).encode()
        for secret in (b"NEVER_ECHO", b"protected-original.log", source[:80],
                       item["sha256"].encode()):
            if secret in output:
                raise RuntimeError("Disposition preflight leaked synthetic original")
        print(json.dumps({
            "qualification": "OFF_HOST_DISPOSITION_READ_ONLY_PREFLIGHT",
            "status": "PASS",
            "scenarios_modeled": len(stages),
            "stale_preview_refused": True,
            "registered_originals_removed": 0,
            "actual_restore_proven": False,
            "deletion_authorized": False,
            "rocky10_host_validated": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
