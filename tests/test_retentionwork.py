"""Non-destructive original-retention reviews must never authorize deletion."""
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

from casework import CaseError, CaseStore, _write_json_atomic
from case_handoff import _canonical, handoff
from retentionwork import assess_case


class RetentionReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.store = CaseStore(self.home)
        self.case_id = self.store.open_case()["case_id"]
        self.payload = b"password=not-for-export; private host example\n"
        original = self.store.inbox / "customer-host-secret.log"
        original.write_bytes(self.payload)
        original.chmod(0o600)
        self.record = self.store.register(self.case_id, original.name)
        self.original = self.store.cases / self.case_id / "originals" / self.record["artifact_id"]
        self.now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
        self._set_age(days=35)

    def _set_age(self, days):
        with self.store._locked(self.case_id) as (folder, manifest):
            manifest["created_at"] = (self.now - timedelta(days=days)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)

    def inspect(self, days=30):
        return assess_case(self.store, self.case_id, minimum_age_days=days, now=self.now)

    def test_source_hash_and_operator_age_only_never_authorize_erase(self):
        original_before = self.original.read_bytes()
        record = self.inspect()
        self.assertEqual(record["status"], "REVIEW_ONLY")
        self.assertTrue(record["age_threshold_met"])
        self.assertTrue(record["review_candidate"])
        self.assertFalse(record["deletion_authorized"])
        self.assertFalse(record["legal_hold_checked"])
        self.assertEqual(record["source_originals_removed"], 0)
        self.assertFalse(record["public_disclosure_approved"])
        self.assertEqual(record["original_bytes_sha256_verified"], len(self.payload))
        self.assertEqual(record["original_artifacts_sha256_verified"], 1)
        self.assertEqual(self.original.read_bytes(), original_before)
        encoded = json.dumps(record).encode()
        for secret in (b"not-for-export", b"customer-host-secret", b"password="):
            self.assertNotIn(secret, encoded)
        self.assertEqual(record["assessment_sha256"], self.inspect()["assessment_sha256"])

    def test_recent_case_is_not_an_age_candidate(self):
        self._set_age(days=2)
        report = self.inspect(days=30)
        self.assertEqual(report["case_age_whole_days"], 2)
        self.assertFalse(report["age_threshold_met"])
        self.assertFalse(report["review_candidate"])

    def test_age_threshold_validation_clock_and_future_created_at(self):
        for age in (True, 0, -1, 3651, 1.5, "30"):
            with self.subTest(age=age), self.assertRaises(CaseError):
                assess_case(self.store, self.case_id, minimum_age_days=age, now=self.now)
        with self.assertRaisesRegex(CaseError, "timezone-aware"):
            assess_case(self.store, self.case_id, minimum_age_days=1,
                        now=datetime(2026, 10, 17, 12))
        self._set_age(days=-1)
        with self.assertRaisesRegex(CaseError, "future"):
            self.inspect(days=1)

    def test_changed_original_missing_original_and_alias_refused(self):
        data = self.original.read_bytes()
        self.original.write_bytes(b"X" * len(data))
        with self.assertRaisesRegex(CaseError, "SHA-256"):
            self.inspect()
        self.original.write_bytes(data)
        alias = self.home / "external-alias"
        os.link(self.original, alias)
        with self.assertRaisesRegex(CaseError, "identity is unsafe"):
            self.inspect()
        alias.unlink()
        self.original.unlink()
        with self.assertRaises(CaseError):
            self.inspect()

    def test_dirty_case_scratch_and_unfinished_indexes_refuse(self):
        scratch = self.store.cases / self.case_id / "scratch"
        scratch.mkdir(mode=0o700)
        (scratch / "partial").write_bytes(b"uncommitted")
        with self.assertRaisesRegex(CaseError, "unfinished case scratch"):
            self.inspect()
        (scratch / "partial").unlink()
        index = self.store.cases / self.case_id / "indexes" / ".tmp-abandoned.sqlite3"
        index.write_bytes(b"partial")
        index.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "unresolved index"):
            self.inspect()
        index.unlink()
        unknown = self.store.cases / self.case_id / "indexes" / "foreign.sqlite3"
        unknown.write_bytes(b"not a registered source")
        unknown.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "unknown or unfinished index"):
            self.inspect()

    def test_private_index_symlink_is_not_blessed(self):
        outside = self.home / "untrusted.sqlite3"
        outside.write_bytes(b"data")
        index = self.store.cases / self.case_id / "indexes" / (self.record["artifact_id"] + ".sqlite3")
        index.symlink_to(outside)
        with self.assertRaisesRegex(CaseError, "file identity unsafe"):
            self.inspect()

    def test_unattributed_handoff_scratch_blocks_review_without_deletion(self):
        exports = self.store.base / "handoff-manifests"
        exports.mkdir(mode=0o700)
        scratch = exports / (".tmp-handoff-" + "1" * 32)
        scratch.write_bytes(b"unattributed private bytes")
        scratch.chmod(0o600)
        result = self.inspect()
        self.assertFalse(result["review_candidate"])
        self.assertIn("UNATTRIBUTED_HANDOFF_SCRATCH", result["blockers"])
        self.assertTrue(scratch.exists())
        self.assertFalse(result["deletion_authorized"])

    def test_case_journal_blocks_but_other_case_journal_does_not(self):
        exports = self.store.base / "handoff-manifests"
        exports.mkdir(mode=0o700)
        for cid, workid in ((self.case_id, "a" * 32),
                            ("f" * 32, "b" * 32)):
            plan = "4" * 64
            journal = exports / (".handoff-work-" + workid + ".json")
            journal.write_bytes(_canonical({
                "version": 1, "case_id": cid, "work_id": workid,
                "plan_sha256": plan,
                "temp_name": ".tmp-handoff-" + workid,
                "final_name": cid + "-" + plan[:24] + ".json",
            }))
            journal.chmod(0o600)
        blocked = self.inspect()
        self.assertEqual(blocked["unclosed_handoff_journals"], 1)
        self.assertFalse(blocked["review_candidate"])
        self.assertIn("UNRESOLVED_CASE_HANDOFF_JOURNAL", blocked["blockers"])
        (exports / (".handoff-work-" + "a" * 32 + ".json")).unlink()
        unrelated = self.inspect()
        self.assertTrue(unrelated["review_candidate"])
        self.assertEqual(unrelated["unclosed_handoff_journals"], 0)

    def test_completed_handoff_is_only_metadata_not_raw_backup(self):
        preview = handoff(self.store, self.case_id)
        handoff(self.store, self.case_id, confirm=True,
                plan_sha256=preview["plan_sha256"])
        report = self.inspect()
        self.assertEqual(report["private_metadata_handoffs_verified"], 1)
        self.assertEqual(report["source_identity_scope"], "case_originals_not_backups")
        self.assertEqual(report["raw_originals_exported"], 0)
        self.assertFalse(report["deletion_authorized"])
        self.assertTrue(self.original.exists())

    def test_pending_unfinished_intake_blocks_review(self):
        token = ".upload-" + "c" * 32
        source = self.store.inbox / token
        source.write_bytes(b"abc")
        source.chmod(0o600)
        metadata = self.store.inbox / (token + ".session")
        metadata.write_text(json.dumps({
            "version": 1, "size": 1000, "sha256": hashlib.sha256(b"x").hexdigest(),
        }))
        metadata.chmod(0o600)
        report = self.inspect()
        self.assertIn("GLOBAL_UNFINISHED_INTAKE", report["blockers"])
        self.assertEqual(report["pending_global_intake_bytes"], 997)
        self.assertFalse(report["review_candidate"])

    def test_cli_requires_explicit_preview_and_does_not_expose_paths(self):
        cli = Path(__file__).resolve().parents[1] / "scripts" / "case_retention_cli.py"
        env = {**os.environ, "HOME": str(self.home)}
        def call(*args):
            return subprocess.run([sys.executable, "-u", str(cli), "--case-id",
                                   self.case_id, *args], env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
        for bad in ((), ("--confirm",), ("--preview", "--delete"),
                    ("--preview", "--minimum-age-days", "0")):
            rejected = call(*bad)
            self.assertNotEqual(rejected.returncode, 0, bad)
        accepted = call("--preview", "--minimum-age-days", "30")
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
        payload = json.loads(accepted.stdout)
        self.assertEqual(payload["status"], "REVIEW_ONLY")
        self.assertFalse(payload["deletion_authorized"])
        self.assertTrue(self.original.exists())
        self.assertNotIn(b"customer-host-secret", accepted.stdout)


if __name__ == "__main__":
    unittest.main()
