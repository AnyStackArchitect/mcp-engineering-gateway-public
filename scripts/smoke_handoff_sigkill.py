#!/usr/bin/env python3
"""Actual SIGKILL before/after private metadata handoff publication, then recovery.

Disposable unprivileged Linux subprocesses and synthetic evidence only.
No public file, Rocky01 operation, network, real power loss, or raw export.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from archivework import verify_case
from case_handoff import handoff, OUT_DIR
from casework import CaseStore

ROOT = Path(__file__).resolve().parents[1]
RECOVERY = ROOT / "scripts" / "handoff_recovery_cli.py"
KILL = r"""
import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import case_handoff
from casework import CaseStore
real = case_handoff._sync_directory
calls = 0
threshold = int(sys.argv[4])
def interrupt_after_sync(folder):
    global calls
    calls += 1
    if calls == threshold:
        os.kill(os.getpid(), signal.SIGKILL)
    return real(folder)
case_handoff._sync_directory = interrupt_after_sync
case_handoff.handoff(CaseStore(Path(sys.argv[2])), sys.argv[3],
                     confirm=True, plan_sha256=sys.argv[5])
raise RuntimeError("Real SIGKILL test never interrupted worker")
"""


def call(home: Path, *args: str) -> dict:
    process = subprocess.run(
        [sys.executable, "-u", str(RECOVERY), *args],
        env={**os.environ, "HOME": str(home)}, input=b"",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=20, check=False)
    if process.returncode:
        raise RuntimeError("Local private recovery command refused synthetic fixture")
    value = json.loads(process.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("Recovery command emitted malformed result")
    return value


def case_fixture(home: Path, suffix: int) -> tuple[CaseStore, str, str, bytes]:
    store = CaseStore(home)
    case = store.open_case()["case_id"]
    raw = (f"2026-10-17 CRITICAL private-customer-{suffix} never-publish\n").encode() * 2048
    src = store.inbox / ("private-original-" + str(suffix) + ".log")
    src.write_bytes(raw)
    src.chmod(0o600)
    registered = store.register(case, src.name)
    if registered["sha256"] != hashlib.sha256(raw).hexdigest():
        raise RuntimeError("Original synthetic evidence has unexpected identity")
    approval = handoff(store, case)
    return store, case, approval["plan_sha256"], raw


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Handoff SIGKILL fixture refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-handoff-kill-") as temporary:
        home = Path(temporary)
        for index, stage in enumerate((2, 3), 1):
            store, case, digest, raw = case_fixture(home, index)
            crash = subprocess.run(
                [sys.executable, "-u", "-c", KILL, str(ROOT),
                 str(home), case, str(stage), digest],
                env={**os.environ, "HOME": str(home)}, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if crash.returncode != -signal.SIGKILL:
                raise RuntimeError("Handoff publication process was not SIGKILLed")
            exports = store.base / OUT_DIR
            journals = list(exports.glob(".handoff-work-*.json"))
            if len(journals) != 1:
                raise RuntimeError("Killed publication lost its private source journal")
            journal = journals[0]
            work_id = journal.name[len(".handoff-work-"):-len(".json")]
            temp = exports / (".tmp-handoff-" + work_id)
            final = exports / (case + "-" + digest[:24] + ".json")
            if not temp.exists() or final.exists() != (stage == 3):
                raise RuntimeError("Crash fixture did not reach expected commit boundary")
            # Age only the synthetic fixture; no clock manipulation or actual
            # customer metadata is involved in this off-host test.
            old = time.time() - 48 * 3600
            for p in [journal, temp, final]:
                if p.exists():
                    os.utime(p, (old, old))
            listing = call(home, "--case-id", case, "--list")
            if listing["handoff_work_ids"] != [work_id]:
                raise RuntimeError("Journaled crash was not independently listed")
            planned = call(home, "--case-id", case, "--work-id", work_id)
            if planned["disposition"] != ("COMMITTED" if stage == 3 else "INTERRUPTED"):
                raise RuntimeError("Recovery described wrong publication state")
            proof = planned["recovery_plan_sha256"]
            completed = call(
                home, "--case-id", case, "--work-id", work_id,
                "--confirm", "--recovery-plan-sha256", proof)
            if (completed["registered_originals_removed"] != 0
                    or completed["committed_handoffs_removed"] != 0
                    or journal.exists() or temp.exists()):
                raise RuntimeError("Recovery deleted source or left owned scratch")
            if final.exists() != (stage == 3):
                raise RuntimeError("Recovery removed a committed private handoff")
            if final.exists():
                content = final.read_bytes()
                if (hashlib.sha256(content).hexdigest() != digest
                        or raw[:120] in content
                        or b"never-publish" in content):
                    raise RuntimeError("Private handoff output altered or disclosed raw contents")
            if verify_case(store, case)["status"] != "PASS":
                raise RuntimeError("Handoff recovery mutated registered original integrity")
        print(json.dumps({
            "status": "OFF_HOST_HANDOFF_REAL_SIGKILL_RECOVERY_PASS",
            "kill_stages": ["BEFORE_PUBLICATION", "AFTER_LINK"],
            "metadata_only": True,
            "registered_originals_removed": 0,
            "committed_handoffs_removed": 0,
            "physical_power_failure_proven": False,
            "rocky10_enforcing_selinux_proven": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
