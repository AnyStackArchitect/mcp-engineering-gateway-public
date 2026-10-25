"""Regression cases for off-host v0.10 one-job approval and execution boundary."""
from __future__ import annotations
import hashlib
import base64
import json
import secrets
import subprocess
import time
import approvalwork
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sandboxwork
import gateway
import jobwork

PINNED = "localhost/rocky-sandbox@sha256:" + "a" * 64

class ExecutionBoundaryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        config = self.home / ".config" / "rocky-mcp-gateway"
        config.mkdir(mode=0o700, parents=True)
        (config / "sandbox-image.txt").write_text(PINNED + "\n")
        (config / "sandbox-image.txt").chmod(0o600)
        trust = self.home / "operator-trust"
        trust.mkdir(mode=0o700)
        self.private = self.home / "offline-signing-private.pem"
        subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(self.private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public = trust / approvalwork.KEY_NAME
        subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(self.private),
                        "-pubout", "-out", str(public)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.private.chmod(0o600)
        public.chmod(0o600)
        self.store = sandboxwork.ExecutionStore(
            self.home, approval_dir=trust, trusted_approval_uid=os.getuid())
        self.case = self.store.cases.open_case()["case_id"]
        self.gateway = gateway.Gateway(gateway.Config({}, (), self.home))

    def plan(self, script="print('analysis')\n", outputs=None, **kwargs):
        return self.store.prepare(self.case, script, [], outputs or ["result.json"], **kwargs)

    def signed(self, plan, *, decision="APPROVE", **changes):
        now = int(time.time())
        payload = {"domain": approvalwork.DOMAIN,
                   "execution_id": plan["execution_id"],
                   "case_id": self.case, "plan_sha256": plan["plan_sha256"],
                   "nonce": secrets.token_hex(16), "issued_at": now,
                   "expires_at": now + 120, "decision": decision}
        payload.update(changes)
        datafile = self.home / ("grant-payload-" + secrets.token_hex(8))
        datafile.write_bytes(approvalwork.canonical(payload))
        try:
            p = subprocess.run(["/usr/bin/openssl", "pkeyutl", "-sign", "-rawin",
                                "-inkey", str(self.private), "-in", str(datafile)],
                               check=True, capture_output=True)
        finally:
            datafile.unlink(missing_ok=True)
        return {"payload": payload,
                "signature": base64.b64encode(p.stdout).decode("ascii")}

    def approve(self, plan, *, decision="APPROVE"):
        return self.store.import_signed_grant(self.signed(plan, decision=decision))

    def test_plan_is_unapproved_and_mcp_cannot_grant(self):
        p = self.plan()
        self.assertEqual(self.store.status(p["execution_id"])["state"], "PREPARED")
        names = {x["name"] for x in self.gateway.tools()}
        self.assertEqual(len(names), 44)
        self.assertTrue({"execution_prepare","execution_status","execution_result","execution_cancel"} <= names)
        self.assertNotIn("execution_approve", names)
        with self.assertRaises(gateway.GatewayError):
            self.gateway.call("execution_approve", {"execution_id": p["execution_id"]})
        self.assertEqual(self.store.work_once()["processed"], 0)

    def test_one_use_grant_and_replay_denied(self):
        p = self.plan()
        accepted = self.approve(p)
        self.assertEqual(accepted["state"], "QUEUED")
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant(self.signed(p))

    def test_wrong_digest_cannot_approve(self):
        p = self.plan()
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant(self.signed(p, plan_sha256="0" * 64))
        self.assertEqual(self.store.status(p["execution_id"])["state"], "PREPARED")

    def test_tampered_plan_cannot_approve_or_run(self):
        p = self.plan()
        with self.store._db() as conn:
            conn.execute("UPDATE plans SET script=? WHERE id=?", ("print('tampered')\n", p["execution_id"]))
            conn.commit()
        with self.assertRaises(sandboxwork.ExecutionError):
            self.approve(p)

    def test_expired_prepared_plan(self):
        p = self.plan()
        with self.store._db() as conn:
            conn.execute("UPDATE plans SET created=? WHERE id=?",
                         (int(sandboxwork.time.time()) - sandboxwork.PLAN_TTL - 10, p["execution_id"]))
            conn.commit()
        with self.assertRaisesRegex(sandboxwork.ExecutionError, "expired"):
            self.approve(p)

    def test_expired_grant_rejected_before_claim(self):
        p = self.plan()
        self.approve(p)
        with self.store._db() as conn:
            conn.execute("UPDATE plans SET approved_until=? WHERE id=?", (0, p["execution_id"]))
            conn.commit()
        self.assertEqual(self.store.work_once()["processed"], 0)
        self.assertEqual(self.store.status(p["execution_id"])["state"], "EXPIRED")

    def test_deny_cannot_transition_to_execution(self):
        p = self.plan()
        self.approve(p, decision="DENY")
        self.assertEqual(self.store.work_once()["processed"], 0)
        self.assertEqual(self.store.status(p["execution_id"])["state"], "DENIED")

    def test_cancel_prepared_and_queued(self):
        p = self.plan()
        self.store.cancel(p["execution_id"])
        self.assertEqual(self.store.status(p["execution_id"])["state"], "CANCELLED")
        with self.assertRaises(sandboxwork.ExecutionError):
            self.approve(p)
        q = self.plan()
        self.approve(q)
        self.store.cancel(q["execution_id"])
        self.assertEqual(self.store.work_once()["processed"], 0)

    def test_bad_policy_and_missing_pinned_config(self):
        for kwargs in ({"timeout_seconds": 0}, {"memory_mib": 2049},
                       {"disk_mib": 2048}, {"output_names": ["../secret"]},
                       {"artifact_ids": ["b" * 32]}, {"script": "def broken("}):
            p = dict(script="print('hi')\n", artifact_ids=[], output_names=["out"])
            p.update(kwargs)
            with self.assertRaises((sandboxwork.ExecutionError, sandboxwork.CaseError)):
                self.store.prepare(self.case, **p)
        maximum=self.store.prepare(self.case,"print('bounded memory fixture')\n",[],['out'],memory_mib=2048)
        self.assertEqual(maximum['state'],'PREPARED')
        (self.home / ".config/rocky-mcp-gateway/sandbox-image.txt").unlink()
        with self.assertRaises(sandboxwork.ExecutionError):
            self.plan()

    def test_missing_podman_fails_no_false_pass(self):
        p = self.plan()
        self.approve(p)
        with patch.object(self.store, "_stage", side_effect=sandboxwork.ExecutionError("sandbox_runtime_unavailable")):
            outcome = self.store.work_once()
        self.assertEqual(outcome["state"], "FAILED")
        self.assertEqual(self.store.status(p["execution_id"], include_result=True)["failure_code"],
                         "sandbox_runtime_unavailable")

    def test_nonzero_script_exit_not_success(self):
        p = self.plan(script="raise SystemExit(2)\n")
        self.approve(p)
        with patch.object(self.store, "_run", side_effect=sandboxwork.ExecutionError("script_nonzero_exit")):
            outcome = self.store.work_once()
        self.assertEqual(outcome["state"], "FAILED")
        self.assertEqual(self.store.status(p["execution_id"], include_result=True)["failure_code"],
                         "script_nonzero_exit")

    def test_uncertain_launch_blocks_same_boot_cleanup_and_new_claim(self):
        p = self.plan()
        self.approve(p)
        row = self.store._claim()
        grant = self.store._verified_grant(row)
        with patch.object(self.store, "_verified_grant", return_value=grant), \
             patch("sandboxwork.subprocess.run", side_effect=subprocess.TimeoutExpired("podman", 30)):
            with self.assertRaisesRegex(sandboxwork.ExecutionError, "cleanup not verified"):
                self.store._run(row)
        self.assertEqual(self.store.status(p["execution_id"])["state"], "RUNNING")
        self.assertTrue(self.store._launch_marker(p["execution_id"]).exists())
        with patch("sandboxwork.subprocess.run") as commands:
            with self.assertRaisesRegex(sandboxwork.ExecutionError, "cleanup not verified"):
                self.store.recover_orphans()
            commands.assert_not_called()
        with self.assertRaisesRegex(sandboxwork.ExecutionError, "cleanup not verified"):
            self.store._claim()

    def test_marker_io_failure_never_terminalizes_running_execution(self):
        import errno
        for failure in (PermissionError('synthetic denied'), OSError(errno.EIO, 'synthetic I/O')):
            p = self.plan()
            self.approve(p)
            self.store._claim()
            def uncertain_cleanup(*args):
                with patch.object(Path, 'lstat', side_effect=failure):
                    self.store._cleanup_container(p["execution_id"])
            with patch.object(self.store, '_claim') as claim:
                with self.store._db() as conn:
                    row = self.store._row(conn, p['execution_id'])
                claim.return_value = row
                with patch.object(self.store, '_run', side_effect=uncertain_cleanup), \
                     patch('sandboxwork.subprocess.run') as commands:
                    with self.assertRaisesRegex(sandboxwork.ExecutionError, 'cleanup not verified'):
                        self.store.work_once()
                    commands.assert_not_called()
            self.assertEqual(self.store.status(p['execution_id'])['state'], 'RUNNING')
            # The second subcase uses its own independent store fixture.
            if isinstance(failure, PermissionError):
                self.setUp()

    def test_workspace_metadata_io_error_is_unverified_cleanup(self):
        p = self.plan()
        with patch.object(Path, 'lstat', side_effect=OSError('synthetic storage failure')):
            with self.assertRaisesRegex(sandboxwork.ExecutionError, 'cleanup not verified'):
                self.store._cleanup_workspace(p['execution_id'])

    def test_previous_boot_marker_requires_verified_container_absence(self):
        p = self.plan()
        root = self.store.workroot / p["execution_id"]
        root.mkdir(mode=0o700, parents=True)
        marker = self.store._launch_marker(p["execution_id"])
        sandboxwork._private_write(marker, sandboxwork._canonical({
            "execution_id": p["execution_id"], "boot_id": "00000000-0000-0000-0000-000000000000"}))
        for exists_code in (0, 125):
            with patch("sandboxwork.subprocess.run", side_effect=[
                    subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], exists_code)]):
                with self.assertRaisesRegex(sandboxwork.ExecutionError, "cleanup not verified"):
                    self.store._cleanup_container(p["execution_id"])
            self.assertTrue(marker.exists())
        with patch("sandboxwork.subprocess.run", side_effect=[
                subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 1)]) as commands:
            self.store._cleanup_container(p["execution_id"])
        self.assertEqual(commands.call_args_list[-1].args[0],
                         ["/usr/bin/podman", "container", "exists", "rocky-gw-job-" + p["execution_id"]])

    def test_malformed_or_linked_uncertainty_marker_fails_closed(self):
        p = self.plan()
        root = self.store.workroot / p["execution_id"]
        root.mkdir(mode=0o700, parents=True)
        marker = self.store._launch_marker(p["execution_id"])
        sandboxwork._private_write(marker, b'{"boot_id":"invalid"}')
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store._check_launch_quiescence(p["execution_id"])
        marker.unlink()
        marker.symlink_to(self.home / 'never-touch')
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store._check_launch_quiescence(p["execution_id"])

    def test_detached_delayed_creator_does_not_clear_same_boot_barrier(self):
        # Reproduce the process behavior without Podman or privileged operations.
        import sys
        p = self.plan()
        root = self.store.workroot / p["execution_id"]
        root.mkdir(mode=0o700, parents=True)
        sandboxwork._private_write(self.store._launch_marker(p["execution_id"]),
            sandboxwork._canonical({"execution_id": p["execution_id"],
                                   "boot_id": self.store._boot_identity()}))
        result = self.home / 'delayed-synthetic-creation'
        child = "import time,pathlib;time.sleep(.25);pathlib.Path(" + repr(str(result)) + ").write_text('synthetic')"
        parent = ("import subprocess,sys,time;subprocess.Popen([sys.executable,'-c'," + repr(child) +
                  "],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);time.sleep(5)")
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run([sys.executable, '-c', parent], timeout=.15)
        with patch("sandboxwork.subprocess.run") as commands:
            with self.assertRaises(sandboxwork.ExecutionError):
                self.store._cleanup_container(p["execution_id"])
            commands.assert_not_called()
        deadline = time.monotonic() + 3
        while not result.exists() and time.monotonic() < deadline:
            time.sleep(.03)
        self.assertEqual(result.read_text(), 'synthetic')
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store._check_launch_quiescence(p["execution_id"])

    def test_crash_recovery_blocks_on_cleanup_failure(self):
        p = self.plan()
        self.approve(p)
        self.store._claim()
        with patch.object(self.store, "_cleanup_container", side_effect=sandboxwork.ExecutionError("Sandbox cleanup not verified")):
            with self.assertRaises(sandboxwork.ExecutionError):
                self.store.recover_orphans()
        self.assertEqual(self.store.status(p["execution_id"])["state"], "RUNNING")

    def test_cleanup_failure_does_not_finalize_running_state(self):
        p = self.plan()
        self.approve(p)
        with patch.object(self.store, "_run", side_effect=sandboxwork.ExecutionError("Sandbox cleanup not verified")):
            with self.assertRaises(sandboxwork.ExecutionError):
                self.store.work_once()
        self.assertEqual(self.store.status(p["execution_id"])["state"], "RUNNING")

    def test_interrupted_worker_cannot_finalize_with_unsafe_partial_original(self):
        p = self.plan()
        self.approve(p)
        self.store._claim()
        with self.store.cases._locked(self.case) as (folder, manifest):
            unsafe = folder / "originals" / ("e" * 32)
            unsafe.symlink_to(folder / "manifest.json")
        with patch.object(self.store, "_cleanup_container"):
            with self.assertRaises(sandboxwork.OutputError):
                self.store.recover_orphans()
        self.assertEqual(self.store.status(p["execution_id"])["state"], "RUNNING")
        self.assertTrue(unsafe.is_symlink())

    def test_output_directory_failure_cleans_approved_input_workspace(self):
        p = self.plan()
        self.approve(p)
        row = self.store._claim()
        root = self.store.workroot / p["execution_id"]
        root.mkdir(mode=0o700, parents=True)
        ro = root / "readonly"
        ro.mkdir(mode=0o700)
        (ro / "copy").write_bytes(b"untrusted synthetic source")
        with patch.object(self.store, "_stage", return_value=(root, ro)) as staged, \
             patch("sandboxwork._private_dir",
                   side_effect=sandboxwork.ExecutionError("Execution directory permissions are unsafe")):
            with self.assertRaisesRegex(sandboxwork.ExecutionError,
                                        "Execution directory permissions are unsafe"):
                self.store._run(row)
        staged.assert_called_once()
        self.assertFalse(root.exists())
        self.assertEqual(self.store.status(p["execution_id"])["state"], "RUNNING")

    def test_verified_cleanup_removes_complete_private_execution_workspace(self):
        p = self.plan()
        root = self.store.workroot / p["execution_id"]
        root.mkdir(mode=0o700, parents=True)
        (root / "copied-evidence").write_bytes(b"synthetic private copy")
        self.store._cleanup_workspace(p["execution_id"])
        self.assertFalse(root.exists())

    def test_workspace_symlink_blocks_cleanup_without_touching_target(self):
        p = self.plan()
        original = self.home / "leave-alone"
        original.mkdir(mode=0o700)
        (original / "evidence").write_bytes(b"original")
        self.store.workroot.mkdir(mode=0o700, parents=True, exist_ok=True)
        pointer = self.store.workroot / p["execution_id"]
        pointer.symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(sandboxwork.ExecutionError, "cleanup not verified"):
            self.store._cleanup_workspace(p["execution_id"])
        self.assertEqual((original / "evidence").read_bytes(), b"original")

    def test_orphan_cleanup_failure_keeps_running_and_does_not_drop_lineage(self):
        p = self.plan()
        self.approve(p)
        self.store._claim()
        with patch.object(self.store, "_cleanup_container"), \
             patch.object(self.store, "_cleanup_workspace",
                          side_effect=sandboxwork.ExecutionError("Sandbox cleanup not verified")):
            with self.assertRaises(sandboxwork.ExecutionError):
                self.store.recover_orphans()
        self.assertEqual(self.store.status(p["execution_id"])["state"], "RUNNING")

    def test_crash_recovery_marks_interrupted_after_cleanup(self):
        p = self.plan()
        self.approve(p)
        self.store._claim()
        with patch.object(self.store, "_cleanup_container") as cleanup:
            self.store.recover_orphans()
        cleanup.assert_called_once_with(p["execution_id"])
        self.assertEqual(self.store.status(p["execution_id"])["state"], "INTERRUPTED")

    def test_direct_database_approval_flag_cannot_forge_authorization(self):
        p = self.plan()
        with self.store._db() as conn:
            conn.execute("""UPDATE plans SET state='QUEUED',approved_digest=?,
                            approved_until=? WHERE id=?""",
                         (p["plan_sha256"], int(time.time()) + 120, p["execution_id"]))
            conn.commit()
        self.assertEqual(self.store.work_once()["processed"], 0)
        self.assertEqual(self.store.status(p["execution_id"])["state"], "FAILED")
        self.assertFalse(hasattr(self.store, "approve_local"))

    def test_signed_payload_tampering_after_database_import_is_rejected(self):
        p = self.plan()
        self.approve(p)
        with self.store._db() as conn:
            row = self.store._row(conn, p["execution_id"])
            envelope = json.loads(row["grant_json"])
            envelope["payload"]["plan_sha256"] = "f" * 64
            conn.execute("UPDATE plans SET grant_json=? WHERE id=?",
                         (json.dumps(envelope), p["execution_id"]))
            conn.commit()
        self.assertEqual(self.store.work_once()["processed"], 0)
        self.assertEqual(self.store.status(p["execution_id"])["state"], "FAILED")

    def test_cross_plan_signed_grant_rejected(self):
        p = self.plan()
        q = self.plan()
        grant = self.signed(p)
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant({
                "payload": {**grant["payload"], "execution_id": q["execution_id"]},
                "signature": grant["signature"]})
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant(self.signed(p, case_id="f" * 32))

    def test_invalid_signature_and_wrong_pubkey_rejected(self):
        p = self.plan()
        envelope = self.signed(p)
        envelope["signature"] = "A" * 88
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant(envelope)
        pub = self.store.approval_dir / approvalwork.KEY_NAME
        pub.chmod(0o666)
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant(self.signed(p))

    def test_expired_signed_grant_rejected(self):
        p = self.plan()
        moment = int(time.time())
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant(
                self.signed(p, issued_at=moment - 120, expires_at=moment - 1))

    def test_same_nonce_cannot_grant_two_distinct_plans(self):
        first = self.plan()
        second = self.plan()
        envelope = self.signed(first)
        self.store.import_signed_grant(envelope)
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store.import_signed_grant(
                self.signed(second, nonce=envelope["payload"]["nonce"]))

    def test_duplicate_json_fields_rejected_before_signature(self):
        with self.assertRaises(approvalwork.GrantError):
            approvalwork.decode(b'{"payload":{},"signature":"x","signature":"y"}')

    def test_signature_identity_checked_again_before_running(self):
        p = self.plan()
        self.approve(p)
        row = self.store._claim()
        with self.store._db() as conn:
            conn.execute("UPDATE grant_nonces SET consumed=0 WHERE execution_id=?",
                         (p["execution_id"],))
            conn.commit()
        with self.assertRaises(sandboxwork.ExecutionError):
            self.store._run(row)

    def test_mcp_result_never_returns_script(self):
        p = self.plan("secret_internal_lab_data = 'confidential'\n")
        with patch.object(self.gateway.execution, "status", return_value=self.store.status(p["execution_id"], include_result=True)):
            public = self.gateway.call("execution_result", {"execution_id": p["execution_id"]})
        self.assertNotIn("secret_internal_lab_data", json.dumps(public))
        self.assertEqual(public["state"], "PREPARED")

if __name__ == "__main__":
    unittest.main()
