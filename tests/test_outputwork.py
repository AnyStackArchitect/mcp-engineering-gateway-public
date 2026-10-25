"""Derived-evidence persistence, quota, tamper and rollback regressions."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from casework import CaseStore, CaseError
from outputwork import OutputError, register_outputs, recover_interrupted_outputs


class DurableOutputTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.cases = CaseStore(self.home)
        self.case = self.cases.open_case()["case_id"]
        self.src = self.cases.inbox / "sample.log"
        self.src.write_text("2026-10-16T23:00:00Z synthetic backup failure\n")
        self.src.chmod(0o600)
        self.input = self.cases.register(self.case, "sample.log")
        self.out = self.home / "sandbox-outputs"
        self.out.mkdir(mode=0o700)
        self.payload = b'{"finding":"synthetic","confidence":"test-only"}\n'
        self.target = self.out / "result.json"
        self.target.write_bytes(self.payload)
        self.target.chmod(0o644)
        self.execid = "a" * 32
        self.plan = "b" * 64

    def register(self, names=None, disk=32):
        return register_outputs(
            self.cases, self.case, self.execid, self.plan,
            [{"artifact_id": self.input["artifact_id"],
              "sha256": self.input["sha256"]}], self.out,
            ["result.json"] if names is None else names, disk)

    def test_output_is_registered_privately_with_source_lineage(self):
        result = self.register()
        self.assertEqual(len(result), 1)
        artifact = result[0]
        self.assertEqual(artifact["name"], "result.json")
        self.assertEqual(artifact["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        with self.cases._locked(self.case) as (folder, manifest):
            rec = manifest["execution_derivatives"][self.execid]
            self.assertEqual(rec["plan_sha256"], self.plan)
            self.assertEqual(rec["input_artifacts"][0]["sha256"], self.input["sha256"])
            self.assertEqual(rec["outputs"][0]["artifact_id"], artifact["artifact_id"])
            stored = folder / "originals" / artifact["artifact_id"]
            self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
            self.assertEqual(stored.read_bytes(), self.payload)
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 2)
        self.assertEqual(list(self.cases.inbox.iterdir()), [self.src])

    def test_signed_worker_output_can_exceed_sync_intake_without_bypassing_worker_cap(self):
        ordinary=self.cases.inbox/'ordinary.json';ordinary.write_bytes(self.payload);ordinary.chmod(0o600)
        with patch('casework.MAX_ARTIFACT',4):
            with self.assertRaises(CaseError):self.cases.register(self.case,ordinary.name)
            result=self.register(disk=512)
        self.assertEqual(result[0]['bytes'],len(self.payload))
        with self.cases._locked(self.case) as (folder,manifest):
            lineage=manifest['execution_derivatives'][self.execid]
            self.assertEqual(lineage['plan_sha256'],self.plan)
            self.assertEqual(lineage['outputs'][0]['artifact_id'],result[0]['artifact_id'])

    def test_worker_output_still_refuses_worker_intake_cap(self):
        with patch('casework.MAX_ARTIFACT',4),patch('casework.MAX_WORKER_ARTIFACT',4):
            with self.assertRaises(CaseError):self.register(disk=512)
        self.assertEqual(self.cases.status(self.case)['artifact_count'],1)

    def test_symlink_and_hardlink_outputs_denied(self):
        original = self.target
        original.unlink()
        other = self.home / "other.bin"
        other.write_bytes(b"test")
        original.symlink_to(other)
        with self.assertRaises(OutputError):
            self.register()
        original.unlink()
        os.link(other, original)
        with self.assertRaises(OutputError):
            self.register()
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 1)

    def test_unapproved_name_and_quota_fail_without_artifact(self):
        with self.assertRaises(OutputError):
            self.register(names=["different.json"])
        with self.assertRaises(OutputError):
            self.register(disk=0)
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 1)

    def test_registration_rolls_back_after_second_artifact_fails(self):
        (self.out / "second.json").write_bytes(b"second")
        (self.out / "second.json").chmod(0o600)
        actual = self.cases.register
        call_count = 0

        def broken(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise CaseError("simulated storage failure")
            return actual(*args, **kwargs)

        with patch.object(self.cases, "register", side_effect=broken):
            with self.assertRaises(CaseError):
                self.register(names=["result.json", "second.json"])
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 1)
        with self.cases._locked(self.case) as (folder, manifest):
            self.assertNotIn(self.execid, manifest.get("execution_derivatives", {}))
            self.assertEqual(len(list((folder / "originals").iterdir())), 1)

    def test_interrupted_run_removes_only_its_derived_outputs(self):
        artifact = self.register()[0]["artifact_id"]
        fixed = recover_interrupted_outputs(self.cases, self.case, self.execid)
        self.assertEqual(fixed["tagged_removed"], 1)
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 1)
        with self.cases._locked(self.case) as (folder, manifest):
            self.assertNotIn(self.execid, manifest.get("execution_derivatives", {}))
            self.assertNotIn(artifact, manifest["artifacts"])
            self.assertEqual(len(list((folder / "originals").iterdir())), 1)
        self.assertEqual(recover_interrupted_outputs(
            self.cases, self.case, self.execid)["tagged_removed"], 0)

    def test_recovery_resumes_after_crash_between_manifest_and_unlink(self):
        artifact = self.register()[0]["artifact_id"]
        from casework import _write_json_atomic
        with self.cases._locked(self.case) as (folder, manifest):
            manifest.setdefault("execution_derivatives_cleanup", {})[self.execid] = [artifact]
            manifest["artifacts"].pop(artifact)
            manifest["execution_derivatives"].pop(self.execid)
            _write_json_atomic(folder / "manifest.json", manifest)
            stranded = folder / "originals" / artifact
            self.assertTrue(stranded.exists())
        result = recover_interrupted_outputs(self.cases, self.case, self.execid)
        self.assertEqual(result["tagged_removed"], 1)
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 1)
        with self.cases._locked(self.case) as (folder, manifest):
            self.assertNotIn("execution_derivatives_cleanup", manifest)
            self.assertFalse((folder / "originals" / artifact).exists())

    def test_crash_before_manifest_registration_removes_orphan_original(self):
        with self.cases._locked(self.case) as (folder, manifest):
            orphan = folder / "originals" / ("f" * 32)
            orphan.write_bytes(b"uncommitted synthetic derived bytes")
            orphan.chmod(0o600)
        clean = recover_interrupted_outputs(self.cases, self.case, self.execid)
        self.assertEqual(clean["orphan_originals_removed"], 1)
        self.assertFalse(orphan.exists())
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 1)

    def test_unsafe_orphan_blocks_recovery_and_keeps_evidence(self):
        with self.cases._locked(self.case) as (folder, manifest):
            orphan = folder / "originals" / ("e" * 32)
            orphan.symlink_to(self.src)
        with self.assertRaises(OutputError):
            recover_interrupted_outputs(self.cases, self.case, self.execid)
        self.assertTrue(orphan.is_symlink())
        self.assertEqual(self.cases.status(self.case)["artifact_count"], 1)

    def test_derived_artifact_marker_is_written_during_registration(self):
        record = self.register()[0]
        with self.cases._locked(self.case) as (_, manifest):
            self.assertEqual(
                manifest["artifacts"][record["artifact_id"]]["derived_execution_id"],
                self.execid)
            self.assertNotIn("derived_execution_id",
                             manifest["artifacts"][self.input["artifact_id"]])

    def test_repeated_execution_identity_cannot_overwrite_lineage(self):
        first = self.register()
        with self.assertRaises(OutputError):
            self.register()
        with self.cases._locked(self.case) as (_, manifest):
            self.assertEqual(manifest["execution_derivatives"][self.execid]["outputs"], first)
            # Source and original derived evidence remain intact.
            self.assertEqual(len(manifest["artifacts"]), 2)


if __name__ == "__main__":
    unittest.main()
