#!/usr/bin/env python3
"""Real killed publisher/recoverer processes plus non-root operator CLI proof.

Synthetic, disposable off-host cases only. Process termination is exercised;
this does not claim hardware power-loss durability or Rocky qualification.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseStore
from redacted_export import OUT_DIR, review_redacted_export

ROOT = Path(__file__).resolve().parents[1]
PHASES = ("journal", "partial_scratch", "scratch", "linked",
          "retired_scratch", "retired_journal", "cancelled")

# This instrumentation lives only in the qualification harness. No runtime
# hook or environment variable lets a gateway client interrupt publication.
PUBLICATION_CHILD = r"""
import os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import redacted_export
from casework import CaseStore
home,case,phase=sys.argv[2:5]
store=CaseStore(Path(home))
preview=redacted_export.review_redacted_export(store,case)
real_sync=redacted_export._sync_directory
count=0
stages={'journal':1,'scratch':2,'linked':3,'retired_scratch':4,'retired_journal':5,
        'cancelled':2,'wait_for_kill':2}
def boundary(folder):
    global count
    real_sync(folder)
    if Path(folder).name==redacted_export.OUT_DIR:
        count+=1
        if count==stages.get(phase):
            if phase=='wait_for_kill':
                os.write(1,b'READY\n')
                os.kill(os.getpid(),signal.SIGSTOP)
            os.kill(os.getpid(),signal.SIGTERM if phase=='cancelled' else signal.SIGKILL)
redacted_export._sync_directory=boundary
real_fdopen=redacted_export.os.fdopen
class Partial:
    def __init__(self,stream): self.stream=stream
    def __enter__(self): return self
    def __exit__(self,*args): return self.stream.__exit__(*args)
    def __getattr__(self,name): return getattr(self.stream,name)
    def write(self,data):
        if data.startswith(b'PK\x03\x04'):
            self.stream.write(data[:len(data)//2])
            self.stream.flush()
            os.fsync(self.stream.fileno())
            os.kill(os.getpid(),signal.SIGKILL)
        return self.stream.write(data)
def partial_fdopen(fd,mode,*args,**kwargs):
    stream=real_fdopen(fd,mode,*args,**kwargs)
    return Partial(stream) if phase=='partial_scratch' and mode=='wb' else stream
redacted_export.os.fdopen=partial_fdopen
redacted_export.review_redacted_export(store,case,prepare=True,
    preview_sha256=preview['review_fingerprint_sha256'])
raise RuntimeError('Expected process termination did not occur')
"""

RECOVERY_CHILD = r"""
import os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import redacted_export_recovery as recovery
from casework import CaseStore
home,case,work,plan=sys.argv[2:6]
real_sync=recovery._sync_directory
def after_scratch_unlink(folder):
    real_sync(folder)
    os.kill(os.getpid(),signal.SIGKILL)
recovery._sync_directory=after_scratch_unlink
recovery.recover(CaseStore(Path(home)),case,work,confirm=True,recovery_plan_sha256=plan)
raise RuntimeError('Expected recovery process termination did not occur')
"""


def _call(home: Path, case: str, *args: str, expected: int = 0) -> dict:
    result = subprocess.run(
        [sys.executable, "-u", str(ROOT / "scripts/redacted_export_recovery_cli.py"),
         "--case-id", case, *args], stdin=subprocess.DEVNULL,
        env={**os.environ, "HOME": str(home)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode != expected:
        raise RuntimeError("Redacted recovery CLI returned an unexpected status")
    if expected:
        if result.stdout:
            raise RuntimeError("Refused recovery unexpectedly returned output")
        return {}
    return json.loads(result.stdout)


def _fixture(home: Path) -> tuple[CaseStore, str, Path, bytes]:
    store = CaseStore(home)
    case = store.open_case()["case_id"]
    raw = b"Synthetic customer=NEVER_EXPORT token=PRIVATE_ONLY\n" * 31
    staged = store.inbox / "customer-private-source.log"
    staged.write_bytes(raw)
    staged.chmod(0o600)
    item = store.register(case, staged.name)
    return store, case, store.cases / case / "originals" / item["artifact_id"], raw


def _kill_publisher(home: Path, case: str, phase: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", PUBLICATION_CHILD, str(ROOT), str(home), case, phase],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)
    wanted = -signal.SIGTERM if phase == "cancelled" else -signal.SIGKILL
    if result.returncode != wanted:
        raise RuntimeError("Export publisher did not stop at the requested real signal")


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Redacted export recovery smoke refuses root")
    for phase in PHASES:
        with tempfile.TemporaryDirectory(prefix="rocky-redacted-recovery-ci-") as name:
            home = Path(name)
            store, case, original, raw = _fixture(home)
            preview = review_redacted_export(store, case)
            _kill_publisher(home, case, phase)
            listed = _call(home, case, "--list")
            work_ids = listed["redacted_export_work_ids"]
            final = store.base / OUT_DIR / (
                "redacted-" + preview["review_fingerprint_sha256"][:24] + ".zip")
            committed = phase in ("linked", "retired_scratch", "retired_journal")
            if phase == "retired_journal":
                if work_ids or not final.is_file():
                    raise RuntimeError("Completed publication cannot be recognized after lost reply")
            else:
                if len(work_ids) != 1 or listed["manual_review_entries"]:
                    raise RuntimeError("Interrupted export did not retain source-bound provenance")
                work = work_ids[0]
                plan = _call(home, case, "--work-id", work)
                if plan["minimum_age_seconds"] != 0:
                    raise RuntimeError("Immediate verified recovery unexpectedly requires a delay")
                _call(home, case, "--work-id", work, "--confirm", expected=2)
                complete = _call(home, case, "--work-id", work, "--confirm",
                                 "--recovery-plan-sha256", plan["recovery_plan_sha256"])
                if (complete["registered_originals_removed"]
                        or complete["committed_packages_removed"]
                        or complete["public_disclosure_approved"]):
                    raise RuntimeError("Recovery crossed its private scratch-only authority")
            if final.exists() != committed or original.read_bytes() != raw:
                raise RuntimeError("Interrupted recovery changed a final package or original")
            if committed and hashlib.sha256(final.read_bytes()).hexdigest() != preview["package_sha256"]:
                raise RuntimeError("Retained package no longer matches its reviewed bytes")
            if any(item.name.startswith(".") for item in (store.base / OUT_DIR).iterdir()):
                raise RuntimeError("Recovery left unexplained private publication scratch")

    with tempfile.TemporaryDirectory(prefix="rocky-redacted-recoverer-kill-ci-") as name:
        home = Path(name)
        store, case, original, raw = _fixture(home)
        _kill_publisher(home, case, "linked")
        work = _call(home, case, "--list")["redacted_export_work_ids"][0]
        first = _call(home, case, "--work-id", work)
        killed = subprocess.run(
            [sys.executable, "-c", RECOVERY_CHILD, str(ROOT), str(home), case, work,
             first["recovery_plan_sha256"]], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if killed.returncode != -signal.SIGKILL:
            raise RuntimeError("Recovery process was not actually SIGKILLed")
        fresh = _call(home, case, "--work-id", work)
        if fresh["recovery_plan_sha256"] == first["recovery_plan_sha256"]:
            raise RuntimeError("A changed crash-recovery state retained a stale approval")
        _call(home, case, "--work-id", work, "--confirm", "--recovery-plan-sha256",
              first["recovery_plan_sha256"], expected=2)
        _call(home, case, "--work-id", work, "--confirm", "--recovery-plan-sha256",
              fresh["recovery_plan_sha256"])
        if original.read_bytes() != raw:
            raise RuntimeError("Recoverer termination changed original evidence")
    print(json.dumps({
        "status": "OFF_HOST_REDACTED_EXPORT_SIGKILL_RECOVERY_PASS",
        "publisher_sigkill_phases": 6, "publisher_sigterm_cancellation_phases": 1,
        "recoverer_sigkill_phases": 1, "nonroot_operator_cli_verified": True,
        "source_bound_preview_confirmation": True,
        "registered_originals_removed": 0, "committed_packages_removed": 0,
        "network_upload_performed": False, "public_disclosure_approved": False,
        "rocky_host_power_loss_qualified": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
