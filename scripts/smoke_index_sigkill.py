#!/usr/bin/env python3
"""Real SIGKILL during SQLite indexing -> explicit recovery -> clean reindex.

Disposable off-host synthetic input only. No host power-cut claim, Rocky01
installation, credentials, client data, network access, or automatic cleanup.
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
from casework import CaseStore
from index_recovery import JOURNAL_NAME

LINE = b"2026-10-17T10:15:00Z ERROR SYNTHETIC_INDEX_RECOVERY password=test-only"
LINE += b"." * (512 - len(LINE) - 1) + b"\n"
LINES = 16384
ROOT = Path(__file__).resolve().parents[1]


def recovery_cli(home: Path, *args: str, expect_ok: bool = True) -> dict | None:
    proc = subprocess.run(
        [sys.executable, "-u", str(ROOT / "scripts" / "index_recovery_cli.py"), *args],
        env={**os.environ, "HOME": str(home)}, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=25, check=False)
    if not expect_ok:
        if proc.returncode == 0:
            raise RuntimeError("Unsafe missing-confirmation index cleanup succeeded")
        return None
    if proc.returncode:
        raise RuntimeError("Local operator index recovery refused controlled fixture")
    payload = json.loads(proc.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("Index recovery did not return a bounded metadata record")
    return payload


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Off-host index SIGKILL test must run without root")
    with tempfile.TemporaryDirectory(prefix="rocky-index-recover-smoke-") as root:
        home = Path(root)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        staged = store.inbox / "synthetic.log"
        with staged.open("xb") as out:
            os.chmod(staged, 0o600)
            sha = hashlib.sha256()
            for _ in range(LINES):
                out.write(LINE)
                sha.update(LINE)
            out.flush()
            os.fsync(out.fileno())
        artifact = store.register(case, staged.name, worker=True)
        aid = artifact["artifact_id"]
        if artifact["sha256"] != sha.hexdigest():
            raise RuntimeError("Original source identity wrong before index")

        # Inject a genuine SIGKILL in the worker callback after thousands of
        # SQLite rows exist. This kills Python without running a finally block.
        child_code = """
import os,signal,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from casework import CaseStore
store=CaseStore(Path.home())
counter=[0]
def kill_during_index():
    counter[0]+=1
    if counter[0] == 7:
        os.kill(os.getpid(), signal.SIGKILL)
store.index_log(sys.argv[2], sys.argv[3], worker=True,
                should_cancel=kill_during_index)
"""
        p = subprocess.run(
            [sys.executable, "-u", "-c", child_code, str(ROOT), case, aid],
            env={**os.environ, "HOME": str(home)},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=45, check=False)
        if p.returncode != -signal.SIGKILL:
            raise RuntimeError("Index writer did not undergo real SIGKILL")
        indexes = store.cases / case / "indexes"
        journals = list(indexes.glob(".tmp-*.index.json"))
        if len(journals) != 1:
            raise RuntimeError("SIGKILL index did not preserve one source-linked journal")
        match = JOURNAL_NAME.fullmatch(journals[0].name)
        if not match:
            raise RuntimeError("Interrupted journal identity invalid")
        index_id = match.group(1)
        temp = indexes / (".tmp-" + index_id + ".sqlite3")
        if not temp.is_file() or temp.stat().st_size == 0:
            raise RuntimeError("SIGKILL failed to leave real SQLite work")
        original = store.cases / case / "originals" / aid
        if not original.is_file() or original.stat().st_size != LINES * len(LINE):
            raise RuntimeError("Registered source original missing")

        # Production requires >=24h; backdate *synthetic fixture metadata*
        # only to exercise CLI acceptance without real waiting or clock changes.
        old = time.time_ns() - 26 * 3600 * 1_000_000_000
        sidecar = indexes / (temp.name + "-journal")
        for path in (journals[0], temp, sidecar):
            if path.exists():
                os.utime(path, ns=(old, old))

        listing = recovery_cli(home, "--case-id", case, "--list")
        if listing["index_work_ids"] != [index_id]:
            raise RuntimeError("Operator index listing missed SIGKILL orphan")
        request = ["--case-id", case, "--work-id", index_id, "--older-hours", "24"]
        view = recovery_cli(home, *request)
        if (view["disposition"] != "INTERRUPTED" or
                view["source_sha256"] != artifact["sha256"] or
                not view["requires_explicit_confirmation"]):
            raise RuntimeError("SIGKILL cleanup preview not source-bound")
        recovery_cli(home, *request, "--confirm", expect_ok=False)
        if not temp.exists() or not journals[0].exists():
            raise RuntimeError("Unapproved cleanup modified abandoned evidence")
        fixed = recovery_cli(home, *request, "--confirm",
                             "--plan-sha256", view["plan_sha256"])
        if (fixed["status"] != "INTERRUPTED_TEMP_CLEARED" or
                fixed["registered_originals_removed"] != 0):
            raise RuntimeError("Explicit approved index cleanup did not prove safe")
        if temp.exists() or journals[0].exists() or sidecar.exists():
            raise RuntimeError("Recovered index scratch still occupying case storage")

        clean = store.index_log(case, aid, worker=True)
        matches = store.search_log(case, aid, "SYNTHETIC_INDEX_RECOVERY")
        if (clean["status"] != "PASS" or clean["lines_indexed"] != LINES or
                matches["matches"][0]["line"] != 1 or
                "test-only" in json.dumps(matches)):
            raise RuntimeError("Clean reindex after SIGKILL lacks source/protected search proof")
        if original.stat().st_size != LINES * len(LINE):
            raise RuntimeError("Original source changed during recovery")
        print(json.dumps({
            "status": "OFF_HOST_INDEX_SIGKILL_RECOVERY_PASS",
            "signal": "SIGKILL",
            "synthetic_source_bytes": len(LINE) * LINES,
            "indexed_lines_after_recovery": clean["lines_indexed"],
            "operator_preview_and_confirmation_required": True,
            "source_sha256_preserved": True,
            "registered_originals_removed": 0,
            "index_search_redaction_verified": True,
            "real_rocky_powerloss_proven": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
