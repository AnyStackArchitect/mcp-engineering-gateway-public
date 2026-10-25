#!/usr/bin/env python3
"""Actual SIGKILL of fixed archive worker during promotion, then operator repair.

Disposable off-host synthetic evidence only. Does not prove Rocky10 power-loss
durability, human operator authorization or independent release readiness.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from archive_recovery import list_workdirs, recover
from archivework import verify_case
from casework import CaseStore
from jobwork import JobStore

HOUR_NS = 3600 * 1_000_000_000
CHILD = r"""
import os,signal,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import archivework
from jobwork import JobStore
original = archivework.os.replace
def after_first_move(src,dst):
    if Path(src).parent.name.startswith('expand-') and Path(dst).parent.name == 'originals':
        original(src,dst)
        os.kill(os.getpid(),signal.SIGKILL)
    return original(src,dst)
archivework.os.replace=after_first_move
JobStore(Path(sys.argv[2])).work_once()
raise RuntimeError('Expected SIGKILL was not triggered')
"""


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Archive crash smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-archive-crash-ci-") as dirname:
        home = Path(dirname)
        cases = CaseStore(home)
        case = cases.open_case()["case_id"]
        payload = b"2026-10-17T12:03:00Z ERROR synthetic-only node timeout\n"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("logs/node-a.log", payload)
            zipped.writestr("logs/node-b.log", payload + b"retry\n")
        inbox = cases.inbox / "case-support.zip"
        inbox.write_bytes(archive.getvalue())
        inbox.chmod(0o600)
        parent = cases.register(case, inbox.name)
        jobs = JobStore(home)
        queued = jobs.submit("unpack_archive", case, parent["artifact_id"])
        process = subprocess.run(
            [sys.executable, "-c", CHILD, str(Path(__file__).resolve().parents[1]), str(home)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
        if process.returncode != -signal.SIGKILL:
            raise RuntimeError("Real archive worker was not SIGKILLed while promoting files")
        if jobs.status(queued["job_id"])["state"] != "RUNNING":
            raise RuntimeError("Worker did not persist interrupted RUNNING state")
        if jobs.work_once()["worker"] != "IDLE":
            raise RuntimeError("Restart did not reach idle state")
        if jobs.status(queued["job_id"])["state"] != "INTERRUPTED":
            raise RuntimeError("Worker restart did not classify interrupted archive job")
        if verify_case(cases, case)["status"] != "PARTIAL":
            raise RuntimeError("Orphaned archive evidence was incorrectly reported healthy")
        pending = list_workdirs(cases, case)["work_ids"]
        if len(pending) != 1:
            raise RuntimeError("Stale archive work identifier not found")
        aged_clock = time.time_ns() + 72 * HOUR_NS
        plan = recover(cases, case, pending[0], now_ns=aged_clock)
        if plan["disposition"] != "INTERRUPTED" or plan["unregistered_originals"] != 1:
            raise RuntimeError("Crash recovery cannot identify the moved orphan precisely")
        accepted = recover(cases, case, pending[0], now_ns=aged_clock,
                           confirm=True, plan_sha256=plan["plan_sha256"])
        if accepted["removed_registered_originals"] != 0:
            raise RuntimeError("Recovery deleted registered evidence")
        if verify_case(cases, case)["status"] != "PASS":
            raise RuntimeError("Vault remains inconsistent after explicit archive recovery")
        next_job = jobs.submit("unpack_archive", case, parent["artifact_id"])
        if jobs.work_once()["state"] != "SUCCEEDED":
            raise RuntimeError("Fixed archive job could not run after orphan cleanup")
        finished = jobs.result(next_job["job_id"])
        if finished["state"] != "SUCCEEDED" or finished["result"]["derived_artifact_count"] != 2:
            raise RuntimeError("Recovered archive was not re-expanded correctly")
        if verify_case(cases, case)["verified_count"] != 3:
            raise RuntimeError("Recovered case vault cannot independently verify source and outputs")
        with cases._locked(case) as (folder, manifest):
            derived = {k:v for k,v in manifest["artifacts"].items()
                       if v.get("derived_from") == parent["artifact_id"]}
            if len(derived) != 2 or any(
                    not (folder / "originals" / aid).is_file()
                    for aid in derived):
                raise RuntimeError("Archive recovery created incomplete derived files")
        print(json.dumps({
            "status": "OFF_HOST_ARCHIVE_SIGKILL_RECOVERY_PASS",
            "actual_signal": "SIGKILL", "first_job": "INTERRUPTED",
            "private_journal_preview_required": True,
            "registered_originals_deleted": 0,
            "case_audit": "PASS", "replayed_job": "SUCCEEDED",
            "derived_artifacts": len(derived),
            "rocky_host_poweroff_qualified": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
