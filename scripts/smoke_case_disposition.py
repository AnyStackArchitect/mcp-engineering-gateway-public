#!/usr/bin/env python3
"""Real SIGKILL recovery of disposable synthetic disposition transactions.

This test never enrolls /etc policy or keys. The harness injects only its trust
source and enable gate; real signatures, hashes, locks, rename, journal and
unlink code execute. It does not prove separate human custody or host rollout.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import case_disposition as cd
import disposition_grants as dg
from casework import CaseError, CaseStore, _write_json_atomic
from operator_sign_disposition import sign_plan

ROOT = Path(__file__).resolve().parents[1]
PHASES = (
    ("RETIRE", "AFTER_INITIALIZATION_DIRECTORY"),
    ("RETIRE", "AFTER_INITIALIZATION_INVENTORY"),
    ("RETIRE", "AFTER_INITIALIZATION_PUBLISH"),
    ("RETIRE", "AFTER_JOURNAL_LINK"),
    ("RETIRE", "AFTER_DURABLE_AUTHORIZATION"),
    ("RETIRE", "AFTER_RETIRE_RENAME"),
    ("RESTORE", "AFTER_RESTORE_RENAME"),
    ("FINAL_DELETE", "BEFORE_EVIDENCE_UNLINK"),
    ("FINAL_DELETE", "AFTER_EVIDENCE_UNLINK"),
)

# Fault injection is confined to this qualification harness. No product CLI or
# environment variable can provide a trust override, arbitrary case path or kill.
CHILD = r"""
import os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import case_disposition as cd
import disposition_grants as dg
from casework import CaseStore
fixture,case,phase=Path(sys.argv[2]),sys.argv[3],sys.argv[4]
dg.production_gate=lambda: None
dg._public_key=lambda role: (fixture/(role+'.pub')).read_bytes()
def killed(name):
    if name==phase:
        os.kill(os.getpid(),signal.SIGKILL)
cd._checkpoint=killed
cd.execute(CaseStore(fixture/'case-owner'),(fixture/'grants.json').read_bytes())
raise RuntimeError('Expected process death did not occur')
"""


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix="rocky-disposition-sigkill-ci-") as name:
        root = Path(name)
        home = root / "case-owner"
        home.mkdir(mode=0o700)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        for i in range(2):
            source = store.inbox / f"synthetic-{i}.log"
            source.write_bytes((f"Synthetic fixture {i} token=DO_NOT_EXPORT\n" * 23).encode())
            source.chmod(0o600)
            store.register(case, source.name)
        old = datetime.now(timezone.utc) - timedelta(days=90)
        with store._locked(case) as (folder, manifest):
            manifest["created_at"] = old.isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        for role in dg.ROLES:
            for args in (("genpkey", "-algorithm", "ED25519", "-out", str(root / (role + ".pem"))),
                         ("pkey", "-in", str(root / (role + ".pem")), "-pubout", "-out", str(root / (role + ".pub")))):
                result = subprocess.run(["/usr/bin/openssl", *args], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10, check=False)
                if result.returncode:
                    raise RuntimeError("Synthetic Ed25519 fixture generation failed")
            (root / (role + ".pem")).chmod(0o600)
        with patch.object(dg, "production_gate", return_value=None), \
                patch.object(dg, "_public_key", side_effect=lambda role: (root / (role + ".pub")).read_bytes()):
            yield root, home, store, case, old.strftime("%Y-%m-%dT%H:%M:%SZ")


def approved(root, store, case, start, action):
    preview = cd.preview(store, case, action=action, minimum_age_days=30, retention_start_utc=start)
    attest = {key: hashlib.sha256(("SYNTHETIC ONLY " + key).encode()).hexdigest() for key in dg.ATTESTATIONS}
    grants = [sign_plan(dg.canonical(preview), root / (role + ".pem"), role,
                       attest, "/usr/bin/openssl") for role in dg.ROLES]
    return dg.canonical({"grants": grants})


def main() -> int:
    if os.name != "posix":
        raise RuntimeError("Disposition SIGKILL qualification requires POSIX")
    if dg.POLICY_PATH.exists() or dg.POLICY_PATH.is_symlink():
        raise RuntimeError("Disposition smoke requires a disposable host without production enrollment")
    # Check actual default production refusal before the harness injects trust.
    try:
        dg.production_gate()
    except dg.DispositionGrantError:
        pass
    else:
        raise RuntimeError("Unenrolled production gate unexpectedly permitted execution")
    cli_preview = False
    for action, phase in PHASES:
        with fixture() as (root, home, store, case, start):
            originals = store.cases / case / "originals"
            before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in originals.iterdir()}
            if os.geteuid() != 0 and not cli_preview:
                result = subprocess.run([sys.executable, str(ROOT / "scripts/case_disposition_cli.py"),
                    "preview", "--case-id", case, "--action", "RETIRE", "--minimum-age-days", "30",
                    "--retention-start-utc", start], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=30, env={**os.environ, "HOME": str(home)}, check=False)
                if result.returncode or json.loads(result.stdout)["deletion_authorized"] is not False:
                    raise RuntimeError("Nonroot disposition CLI preview failed")
                result = subprocess.run([sys.executable, str(ROOT / "scripts/case_disposition_cli.py"), "execute"],
                    input=approved(root, store, case, start, "RETIRE"), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=30, env={**os.environ, "HOME": str(home)}, check=False)
                if result.returncode != 2 or result.stdout:
                    raise RuntimeError("Unenrolled operator CLI did not refuse signed synthetic grants")
                cli_preview = True
            if action != "RETIRE":
                cd.execute(store, approved(root, store, case, start, "RETIRE"))
            raw = approved(root, store, case, start, action)
            grants_file = root / "grants.json"
            grants_file.write_bytes(raw)
            grants_file.chmod(0o600)
            result = subprocess.run([sys.executable, "-c", CHILD, str(ROOT), str(root), case, phase],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30, check=False)
            if result.returncode != -signal.SIGKILL:
                raise RuntimeError("Disposition child did not stop at expected SIGKILL durability boundary")
            if phase in ("AFTER_INITIALIZATION_DIRECTORY", "AFTER_INITIALIZATION_INVENTORY"):
                cleanup = cd.abort_initialization(store, case)
                if cleanup["metadata_initializations_removed"] != 1 or cleanup["originals_removed"] != 0:
                    raise RuntimeError("Unpublished metadata recovery failed")
            outcome = cd.execute(store, approved(root, store, case, start, action))
            if action == "FINAL_DELETE":
                quarantine = store.base / cd.OUT_DIR / case / "quarantine"
                if (list((quarantine / "originals").iterdir())
                        or not (quarantine / "manifest.json").is_file()
                        or outcome["originals_removed"] != 2):
                    raise RuntimeError("Final deletion recovery or metadata retention failed")
            else:
                if action == "RETIRE":
                    cd.execute(store, approved(root, store, case, start, "RESTORE"))
                after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in originals.iterdir()}
                if after != before:
                    raise RuntimeError("Retirement/restore did not preserve exact originals")
            for flag in ("legal_authority_independently_verified", "backup_custody_independently_verified",
                         "restore_test_independently_verified", "latest_external_checkpoint_independently_verified",
                         "hostile_same_uid_rollback_resistance_verified", "secure_erase_verified"):
                if outcome[flag] is not False:
                    raise RuntimeError("Disposition incorrectly claims external or adversarial proof")
    with fixture() as (root, home, store, case, start):
        first = approved(root, store, case, start, "RETIRE")
        cd.execute(store, first)
        cd.execute(store, approved(root, store, case, start, "RESTORE"))
        for phase in ("AFTER_CYCLE_ARCHIVE", "AFTER_INITIALIZATION_PUBLISH"):
            grants_file = root / "grants.json"
            grants_file.write_bytes(approved(root, store, case, start, "RETIRE"))
            grants_file.chmod(0o600)
            result = subprocess.run([sys.executable, "-c", CHILD, str(ROOT), str(root), case, phase],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30, check=False)
            if result.returncode != -signal.SIGKILL:
                raise RuntimeError("New-cycle child did not stop at expected SIGKILL boundary")
            try:
                cd.execute(store, first)
            except CaseError:
                pass
            else:
                raise RuntimeError("Consumed earlier-cycle grant was replayed across initialization crash")
            if not (store.cases / case).is_dir():
                raise RuntimeError("Replay refusal did not leave the active restored case intact")
        cd.execute(store, approved(root, store, case, start, "RETIRE"))
        cd.execute(store, approved(root, store, case, start, "RESTORE"))
    print(json.dumps({"status": "DISPOSABLE_DISPOSITION_SIGKILL_SMOKE_PASS",
        "real_sigkill_durability_boundaries": len(PHASES) + 2, "real_ed25519_signatures": True,
        "synthetic_test_trust_injection": True, "production_enrollment_created": False,
        "nonroot_operator_preview_and_unenrolled_refusal_verified": cli_preview,
        "hardware_power_loss_qualified": False, "independent_human_custody_qualified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
