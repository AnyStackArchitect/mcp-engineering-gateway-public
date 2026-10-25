"""Source-bound, non-destructive, additive case preservation contract tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from casework import CaseError, CaseStore, _write_json_atomic
from preservationwork import propose_or_record, read_controls
from retentionwork import assess_case
import preservationwork


class PreservationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
        source = self.store.inbox / "private-host-do-not-expose.log"
        self.raw = b"password=never-send-this; operator-owned synthetic bytes\n"
        source.write_bytes(self.raw)
        source.chmod(0o600)
        self.artifact = self.store.register(self.case, source.name)
        self.original = self.store.cases / self.case / "originals" / self.artifact["artifact_id"]
        self.root = self.store.cases / self.case / "preservation"
        self.reference = hashlib.sha256(b"local-reference-fixture-not-validated").hexdigest()
        with self.store._locked(self.case) as (folder, manifest):
            manifest["created_at"] = (self.now - timedelta(days=35)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)

    def plan(self, *, action="PRESERVATION_HOLD", reason_code="investigation",
             minimum_days=None, confirm=False, plan_sha256=None):
        return propose_or_record(self.store, self.case, action=action,
                                 reference_sha256=self.reference,
                                 reason_code=reason_code,
                                 minimum_days=minimum_days, confirm=confirm,
                                 plan_sha256=plan_sha256)

    def add_hold(self, reason_code="investigation"):
        view = self.plan(reason_code=reason_code)
        return self.plan(reason_code=reason_code, confirm=True,
                         plan_sha256=view["plan_sha256"])

    def add_floor(self, days):
        view = self.plan(action="MINIMUM_RETENTION_DAYS",
                         reason_code=None, minimum_days=days)
        return self.plan(action="MINIMUM_RETENTION_DAYS",
                         reason_code=None, minimum_days=days,
                         confirm=True, plan_sha256=view["plan_sha256"])

    def retention(self, threshold=30):
        return assess_case(self.store, self.case,
                           minimum_age_days=threshold, now=self.now)

    def test_preview_is_read_only_and_requires_two_step_sha_confirmation(self):
        preview = self.plan()
        self.assertEqual(preview["status"], "PREVIEW_ONLY")
        self.assertFalse(self.root.exists())
        self.assertFalse(preview["deletion_authorized"])
        with self.assertRaisesRegex(CaseError, "preview SHA-256"):
            self.plan(confirm=True)
        with self.assertRaisesRegex(CaseError, "cannot carry confirmation"):
            self.plan(plan_sha256="b" * 64)
        result = self.plan(confirm=True, plan_sha256=preview["plan_sha256"])
        self.assertEqual(result["status"], "PRESERVATION_RECORD_COMMITTED")
        self.assertEqual(result["active_preservation_holds"], 1)
        self.assertEqual(result["record_count_after"], 1)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list(self.root.iterdir())), 1)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in self.root.iterdir()))
        self.assertEqual(self.original.read_bytes(), self.raw)
        self.assertFalse(result["legal_hold_authority_verified"])

    def test_local_hold_blocks_age_review_but_never_authorizes_delete(self):
        previous = self.retention()
        self.assertTrue(previous["review_candidate"])
        self.add_hold()
        result = self.retention()
        self.assertFalse(result["review_candidate"])
        self.assertIn("LOCAL_PRESERVATION_HOLD_ACTIVE", result["blockers"])
        self.assertEqual(result["local_preservation_holds_active"], 1)
        self.assertTrue(result["operator_declarations_checked"])
        self.assertFalse(result["legal_hold_checked"])
        self.assertFalse(result["deletion_authorized"])
        self.assertEqual(result["source_originals_removed"], 0)
        self.assertNotEqual(previous["assessment_sha256"], result["assessment_sha256"])
        self.assertEqual(self.original.read_bytes(), self.raw)

    def test_minimum_days_strengthens_age_screen_and_can_only_increase(self):
        self.add_floor(90)
        observed = self.retention()
        self.assertTrue(observed["age_threshold_met"])
        self.assertFalse(observed["review_candidate"])
        self.assertEqual(observed["declared_minimum_retention_days"], 90)
        self.assertIn("DECLARED_MINIMUM_RETENTION_UNMET", observed["blockers"])
        for lower in (80, 90):
            with self.subTest(lower=lower), self.assertRaisesRegex(CaseError, "cannot be lowered"):
                self.plan(action="MINIMUM_RETENTION_DAYS",
                          reason_code=None, minimum_days=lower)
        self.add_floor(120)
        self.assertEqual(read_controls(self.store, self.case)["minimum_retention_days"], 120)
        self.assertEqual(read_controls(self.store, self.case)["record_count"], 2)
        self.assertFalse(self.retention()["review_candidate"])

    def test_case_age_after_floor_does_not_authorize_erasure(self):
        self.add_floor(20)
        result = self.retention(30)
        self.assertTrue(result["age_threshold_met"])
        self.assertTrue(result["review_candidate"])
        self.assertEqual(result["declared_minimum_retention_days"], 20)
        self.assertFalse(result["deletion_authorized"])
        self.assertFalse(result["hold_release_supported"])
        self.assertEqual(self.original.read_bytes(), self.raw)

    def test_preview_plan_rejects_new_event_and_mutated_manifest(self):
        view = self.plan()
        self.add_hold(reason_code="customer_request")
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.plan(confirm=True, plan_sha256=view["plan_sha256"])
        preview = self.plan(reason_code="investigation")
        with self.store._locked(self.case) as (folder, manifest):
            manifest["created_at"] = self.now.isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.plan(confirm=True, plan_sha256=preview["plan_sha256"])

    def test_invalid_inputs_rejected_without_creating_records(self):
        bad = [
            ("RELEASE_HOLD", "investigation", None),
            ("DELETE_CASE", "investigation", None),
            ([], "investigation", None),
            ("PRESERVATION_HOLD", "customer-identifying freeform note", None),
            ("PRESERVATION_HOLD", [], None),
            ("PRESERVATION_HOLD", None, None),
            ("MINIMUM_RETENTION_DAYS", None, 0),
            ("MINIMUM_RETENTION_DAYS", None, 3651),
            ("MINIMUM_RETENTION_DAYS", None, True),
            ("MINIMUM_RETENTION_DAYS", None, "30"),
            ("MINIMUM_RETENTION_DAYS", "investigation", 30),
        ]
        for action, reason, days in bad:
            with self.subTest(action=action, reason=reason, days=days):
                with self.assertRaises(CaseError):
                    self.plan(action=action, reason_code=reason, minimum_days=days)
        with self.assertRaises(CaseError):
            propose_or_record(self.store, self.case, action="PRESERVATION_HOLD",
                              reference_sha256="bad", reason_code="investigation")
        self.assertFalse(self.root.exists())

    def test_published_chain_detects_modified_records(self):
        self.add_hold()
        self.add_floor(30)
        first = sorted(self.root.iterdir())[0]
        doc = json.loads(first.read_bytes())
        doc["reason_code"] = "customer_request"
        first.write_bytes(preservationwork._canonical(doc))
        with self.assertRaisesRegex(CaseError, "chain invalid"):
            read_controls(self.store, self.case)
        with self.assertRaises(CaseError):
            self.retention()

    def test_deleted_sequence_and_renamed_sequence_fail_closed(self):
        self.add_hold()
        self.add_floor(30)
        first, second = sorted(self.root.iterdir())
        first.unlink()
        with self.assertRaisesRegex(CaseError, "sequence invalid"):
            read_controls(self.store, self.case)
        second.rename(self.root / ("0099-" + second.name[5:]))
        with self.assertRaises(CaseError):
            self.retention()

    def test_malformed_record_and_unexpected_sidecar_fail_closed(self):
        self.add_hold()
        outside = self.root / "unknown.tmp"
        outside.write_bytes(b"test")
        outside.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "filename or sequence"):
            self.retention()
        outside.unlink()
        original = next(self.root.iterdir())
        original.write_bytes(b'{"schema": 1, "bad": "synthetic"}')
        with self.assertRaisesRegex(CaseError, "not canonical"):
            read_controls(self.store, self.case)

    def test_symlink_hardlink_and_unsafe_permissions_refused(self):
        self.add_hold()
        path = next(self.root.iterdir())
        backup = self.home / "alias"
        os.link(path, backup)
        with self.assertRaisesRegex(CaseError, "identity or size"):
            read_controls(self.store, self.case)
        backup.unlink()
        path.chmod(0o644)
        with self.assertRaisesRegex(CaseError, "identity or size"):
            self.retention()
        path.chmod(0o600)
        path.unlink()
        path.symlink_to(self.original)
        with self.assertRaisesRegex(CaseError, "identity or size"):
            read_controls(self.store, self.case)

    def test_empty_directory_and_partial_record_fail_closed(self):
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(CaseError, "Empty preservation directory"):
            self.retention()
        partial = self.root / ("0001-" + "a" * 32 + ".json")
        partial.write_bytes(b"{")
        partial.chmod(0o600)
        with self.assertRaises(CaseError):
            self.retention()

    def test_preservation_inventory_overflow_is_rejected_before_file_reads(self):
        self.root.mkdir(mode=0o700)
        # This is deliberately an invalid bulk inventory. Refuse it before
        # reading arbitrary per-file bodies or certifying missing protections.
        for n in range(preservationwork.MAX_RECORDS + 1):
            (self.root / f"untrusted-{n:04d}").write_bytes(b"not-an-event")
        with patch.object(preservationwork, "_read_record",
                          side_effect=AssertionError("must stop before record read")):
            with self.assertRaisesRegex(CaseError, "inventory exceeds fixed bound"):
                read_controls(self.store, self.case)
        self.assertEqual(self.original.read_bytes(), self.raw)

    def test_failed_fsync_leaves_record_for_explicit_review(self):
        view = self.plan()
        genuine = preservationwork._sync_directory
        seen = 0
        def fail_second(folder):
            nonlocal seen
            seen += 1
            if seen == 2:
                raise CaseError("synthetic fsync after private event")
            return genuine(folder)
        with patch.object(preservationwork, "_sync_directory", side_effect=fail_second):
            with self.assertRaisesRegex(CaseError, "synthetic fsync"):
                self.plan(confirm=True, plan_sha256=view["plan_sha256"])
        self.assertEqual(len(list(self.root.iterdir())), 1)
        # An ambiguous result stays in the ledger; an approval based on the
        # original zero-event preview MUST fail after this partial commit.
        self.assertEqual(read_controls(self.store, self.case)["record_count"], 1)
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.plan(confirm=True, plan_sha256=view["plan_sha256"])

    def test_no_space_failure_precedes_new_directory_or_record(self):
        view = self.plan()
        with patch.object(preservationwork, "verify_committed_reserve",
                          side_effect=CaseError("synthetic no space")):
            with self.assertRaisesRegex(CaseError, "no space"):
                self.plan(confirm=True, plan_sha256=view["plan_sha256"])
        self.assertFalse(self.root.exists())

    def test_unverified_reference_is_not_claimed_as_source_authority(self):
        self.add_hold(reason_code="external_hold_request")
        record = read_controls(self.store, self.case)
        self.assertEqual(record["status"], "OPERATOR_DECLARATIONS_UNVERIFIED")
        self.assertFalse(record["source_reference_material_verified"])
        self.assertFalse(record["legal_hold_authority_verified"])
        self.assertFalse(record["hold_release_supported"])
        self.assertFalse(record["automatic_expiry_supported"])
        self.assertFalse(record["deletion_authorized"])
        self.assertNotIn(b"never-send-this", json.dumps(record).encode())

    def test_cli_independent_preview_confirm_and_destructive_argument_refusal(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "case_preservation_cli.py"
        env = {**os.environ, "HOME": str(self.home)}
        base = ["--case-id", self.case, "--source-reference-sha256",
                self.reference, "--hold-reason", "investigation"]
        def call(*args):
            return subprocess.run([sys.executable, "-u", str(script), *base, *args],
                                  env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=25, check=False)
        for args in [("--confirm",), ("--release",), ("--delete",),
                     ("--preview", "--plan-sha256", "c" * 64)]:
            rejected = call(*args)
            self.assertNotEqual(rejected.returncode, 0, args)
        preview = call("--preview")
        self.assertEqual(preview.returncode, 0, preview.stderr.decode())
        self.assertFalse(self.root.exists())
        info = json.loads(preview.stdout)
        confirmed = call("--confirm", "--plan-sha256", info["plan_sha256"])
        self.assertEqual(confirmed.returncode, 0, confirmed.stderr.decode())
        doc = json.loads(confirmed.stdout)
        self.assertEqual(doc["status"], "PRESERVATION_RECORD_COMMITTED")
        self.assertTrue(self.original.exists())
        self.assertNotIn(b"private-host", confirmed.stdout)
        self.assertNotIn(b"never-send-this", confirmed.stdout)
        self.assertNotIn(str(self.root).encode(), confirmed.stdout)


if __name__ == "__main__":
    unittest.main()
