#!/usr/bin/env python3
"""Disposable CI proof of the actual administrator-owned disposition boundary.

Only the GitHub-hosted Linux test job may run this root fixture. It creates a
previously absent fixed trust directory, uses a genuine nonroot child and real
Ed25519 signatures, then removes its own enrollment. No trust/clock/product
function is patched. This proves machine enforcement, not human/legal custody.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import case_disposition as cd
import disposition_grants as dg
# The disposable UID cannot traverse the hosted runner's private checkout.
# Preload this real lazy dependency before fork; no gate or verifier is replaced.
import redacted_export  # noqa: F401
from casework import CaseStore, _write_json_atomic
from operator_sign_disposition import sign_plan

CASE_UID = 32011


def nonroot(home: Path, operation: str, case_id: str | None = None,
            raw: bytes | None = None) -> dict:
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        try:
            signal.alarm(40)
            os.setgroups([])
            os.setgid(CASE_UID)
            os.setuid(CASE_UID)
            if os.geteuid() != CASE_UID:
                raise RuntimeError("Synthetic case owner did not drop privileges")
            store = CaseStore(home)
            if operation == "create":
                case_id = store.open_case()["case_id"]
                source = store.inbox / "synthetic-trust.log"
                source.write_bytes(b"Synthetic trust-boundary fixture only\n")
                source.chmod(0o600)
                store.register(case_id, source.name)
                old = datetime.now(timezone.utc) - timedelta(days=90)
                with store._locked(case_id) as (folder, manifest):
                    manifest["created_at"] = old.isoformat()
                    _write_json_atomic(folder / "manifest.json", manifest)
                value = {"case_id": case_id, "start": old.strftime("%Y-%m-%dT%H:%M:%SZ")}
            elif operation == "gate":
                dg.production_gate()
                value = {"uid": os.geteuid()}
            elif operation == "verify":
                payloads, fingerprints = dg.verify_grants(raw)
                value = {"roles": len(payloads), "distinct_keys": len(set(fingerprints))}
            elif operation == "execute":
                value = cd.execute(store, raw)
            elif operation == "preview":
                options = json.loads(raw)
                value = cd.preview(store, case_id, action=options["action"],
                    minimum_age_days=30, retention_start_utc=options["start"])
            elif operation == "source":
                with store._locked(case_id) as (folder, manifest):
                    contents = [(folder / "originals" / aid).read_bytes()
                                for aid in manifest["artifacts"]]
                if contents != [b"Synthetic trust-boundary fixture only\n"]:
                    raise RuntimeError("Retire/restore changed the synthetic original")
                value = {"original_intact": True}
            else:
                raise RuntimeError("Unknown trust fixture operation")
            result = {"ok": True, "value": value}
        except Exception as exc:
            result = {"ok": False, "error_type": type(exc).__name__}
        try:
            data = dg.canonical(result)
            if len(data) > 32768:
                raise RuntimeError("Trust fixture result exceeded bound")
            while data:
                data = data[os.write(writer, data):]
        finally:
            os.close(writer)
        os._exit(0)
    os.close(writer)
    data = bytearray()
    deadline = time.monotonic() + 45
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([reader], [], [], remaining)[0]:
                raise RuntimeError("Nonroot trust fixture timed out")
            part = os.read(reader, 32769 - len(data))
            if not part:
                break
            data.extend(part)
            if len(data) > 32768:
                raise RuntimeError("Nonroot trust fixture result too large")
        _, status = os.waitpid(pid, 0)
        pid = None
        if status != 0:
            raise RuntimeError("Nonroot trust fixture process failed")
        return json.loads(data)
    finally:
        os.close(reader)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def require(result: dict, *, refusal=False) -> dict:
    if refusal:
        if result != {"ok": False, "error_type": "DispositionGrantError"}:
            raise RuntimeError("Administrator boundary did not fail closed")
        return {}
    if result.get("ok") is not True:
        raise RuntimeError("Expected nonroot trust operation failed: " + str(result))
    return result["value"]


def main() -> int:
    if (os.name != "posix" or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("This root fixture requires a disposable GitHub-hosted Linux runner")
    trust = dg.TRUST_ROOT
    if trust.exists() or trust.is_symlink():
        raise RuntimeError("Refusing to alter pre-existing disposition enrollment")
    os.umask(0o077)
    created = False
    with tempfile.TemporaryDirectory(prefix="rocky-disposition-trust-ci-") as temporary:
        root = Path(temporary)
        root.chmod(0o711)
        home = root / "case-owner"
        home.mkdir(mode=0o700)
        os.chown(home, CASE_UID, CASE_UID)
        keys, public = {}, {}
        for role in dg.ROLES:
            key = root / (role + ".pem")
            pub = root / (role + ".pub")
            for args in (("genpkey", "-algorithm", "ED25519", "-out", str(key)),
                         ("pkey", "-in", str(key), "-pubout", "-out", str(pub))):
                subprocess.run(["/usr/bin/openssl", *args], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)
            key.chmod(0o600)
            keys[role], public[role] = key, pub.read_bytes()
        case = require(nonroot(home, "create"))
        options = lambda action: dg.canonical({"action": action, "start": case["start"]})
        def signed(action):
            packet = require(nonroot(home, "preview", case["case_id"], options(action)))
            attest = {name: hashlib.sha256(("SYNTHETIC CI " + name).encode()).hexdigest()
                      for name in dg.ATTESTATIONS}
            return dg.canonical({"grants": [sign_plan(dg.canonical(packet), keys[role],
                role, attest, "/usr/bin/openssl") for role in dg.ROLES]})
        raw = signed("RETIRE")
        checks = []
        require(nonroot(home, "execute", case["case_id"], raw), refusal=True)
        checks.append("unenrolled_execute_refused")
        try:
            trust.mkdir(mode=0o755)
            created = True
            trust.chmod(0o755)
            policy = {"schema": 1, "enabled": True, "case_owner_uid": CASE_UID,
                      "same_uid_risk_accepted": True}
            def write_policy(value):
                dg.POLICY_PATH.write_bytes(dg.canonical(value))
                dg.POLICY_PATH.chmod(0o644)
            write_policy(policy)
            for role in dg.ROLES:
                path = trust / dg.KEY_NAMES[role]
                path.write_bytes(public[role])
                path.chmod(0o644)
            require(nonroot(home, "gate"))
            verified = require(nonroot(home, "verify", raw=raw))
            if verified != {"roles": 2, "distinct_keys": 2}:
                raise RuntimeError("Independent fixed trust keys were not verified")
            checks.append("root_owned_policy_and_two_real_ed25519_keys_accepted")
            try:
                dg.production_gate()
            except dg.DispositionGrantError:
                checks.append("root_execution_refused")
            else:
                raise RuntimeError("Root operator was accepted")
            for name, value in (("disabled", dict(policy, enabled=False)),
                                ("wrong_owner", dict(policy, case_owner_uid=CASE_UID + 1)),
                                ("unaccepted_same_uid_risk", dict(policy, same_uid_risk_accepted=False))):
                write_policy(value)
                require(nonroot(home, "execute", case["case_id"], raw), refusal=True)
                checks.append(name + "_policy_refused")
            write_policy(policy)
            dg.POLICY_PATH.chmod(0o666)
            require(nonroot(home, "execute", case["case_id"], raw), refusal=True)
            dg.POLICY_PATH.chmod(0o644)
            checks.append("writable_policy_refused")
            os.chown(dg.POLICY_PATH, CASE_UID, CASE_UID)
            require(nonroot(home, "execute", case["case_id"], raw), refusal=True)
            os.chown(dg.POLICY_PATH, 0, 0)
            checks.append("nonadministrator_policy_owner_refused")
            first_key = trust / dg.KEY_NAMES[dg.ROLES[0]]
            first_key.chmod(0o666)
            require(nonroot(home, "execute", case["case_id"], raw), refusal=True)
            first_key.chmod(0o644)
            checks.append("writable_trust_key_refused")
            first_key.unlink()
            require(nonroot(home, "execute", case["case_id"], raw), refusal=True)
            first_key.write_bytes(public[dg.ROLES[0]])
            first_key.chmod(0o644)
            checks.append("missing_trust_key_refused")
            if require(nonroot(home, "execute", case["case_id"], raw))["status"] != "CASE_RETIRED_RECOVERABLE":
                raise RuntimeError("Actual enabled nonroot retirement did not complete")
            if require(nonroot(home, "execute", case["case_id"], signed("RESTORE")))["status"] != "CASE_RESTORED":
                raise RuntimeError("Actual enabled nonroot restore did not complete")
            require(nonroot(home, "source", case["case_id"]))
            checks.append("unpatched_nonroot_retire_restore_and_original_integrity")
        finally:
            if created:
                for leaf in (dg.POLICY_PATH, *(trust / name for name in dg.KEY_NAMES.values())):
                    leaf.unlink(missing_ok=True)
                trust.rmdir()
        if trust.exists() or trust.is_symlink():
            raise RuntimeError("Disposable enrollment cleanup failed")
        print(json.dumps({"status": "DISPOSITION_TRUST_BOUNDARY_PASS", "checks": checks,
            "actual_nonroot_uid": CASE_UID, "production_functions_patched": False,
            "ephemeral_enrollment_removed": True, "human_custody_proven": False,
            "rocky_host_qualified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
