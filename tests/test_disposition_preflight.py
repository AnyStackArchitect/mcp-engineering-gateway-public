"""v0.31 permanent failure-path regression tests for read-only disposition."""
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
from disposition_preflight import (IRREDUCIBLE_GATES, SCENARIOS,
                                   SCENARIO_REQUIREMENTS, inspect_disposition)
from preservationwork import propose_or_record, read_controls


class RegisteredOriginalDispositionPreflightTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="rocky-disposition-tests-")
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.now = datetime.now(timezone.utc)
        self.secret = b"synthetic source password=never-print-this\n" * 19
        self.record = self.register("customer-original-secret.log", self.secret)
        self.original = (self.store.cases / self.case / "originals"
                         / self.record["artifact_id"])
        with self.store._locked(self.case) as (folder, manifest):
            manifest["created_at"] = (self.now - timedelta(days=90)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)

    def register(self, name: str, payload: bytes) -> dict:
        staged = self.store.inbox / name
        staged.write_bytes(payload)
        staged.chmod(0o600)
        return self.store.register(self.case, name)

    def hold(self, source_sha: str | None = None) -> None:
        values = dict(action="PRESERVATION_HOLD", reason_code="investigation",
                      reference_sha256=source_sha or self.record["sha256"])
        pre = propose_or_record(self.store, self.case, **values)
        committed = propose_or_record(self.store, self.case, **values,
                                      confirm=True, plan_sha256=pre["plan_sha256"])
        self.assertEqual(committed["status"], "PRESERVATION_RECORD_COMMITTED")

    def floor(self, days: int) -> None:
        values = dict(action="MINIMUM_RETENTION_DAYS",
                      reference_sha256=self.record["sha256"], minimum_days=days)
        pre = propose_or_record(self.store, self.case, **values)
        propose_or_record(self.store, self.case, **values, confirm=True,
                          plan_sha256=pre["plan_sha256"])

    def review(self, minimum: int = 30, stage: str | None = None,
               fingerprint: str | None = None):
        return inspect_disposition(
            self.store, self.case, minimum_age_days=minimum, scenario=stage,
            expected_preview_sha256=fingerprint, now=self.now)

    def test_even_old_unheld_evidence_is_always_disposition_blocked(self):
        result = self.review()
        self.assertEqual(result["status"], "DISPOSITION_BLOCKED_READ_ONLY_PREFLIGHT")
        self.assertTrue(result["advisory_minimum_age_met"])
        self.assertEqual(result["active_local_preservation_holds"], 0)
        self.assertEqual(result["registered_originals_fully_sha256_verified"], 1)
        self.assertEqual(result["registered_original_bytes_verified"], len(self.secret))
        for item in IRREDUCIBLE_GATES:
            self.assertIn(item, result["blockers"])
        self.assertGreaterEqual(len(result["blockers"]), len(IRREDUCIBLE_GATES))
        for field in ("policy_authority_verified", "independent_backup_exists_verified",
                      "off_host_recovery_custody_verified", "actual_restore_test_passed",
                      "most_recent_external_checkpoint_verified",
                      "dual_operator_approval_verified", "destructive_transaction_implemented",
                      "transaction_recovery_verified", "hold_release_authorized",
                      "deletion_authorized", "public_disclosure_approved"):
            self.assertFalse(result[field], field)
        self.assertEqual(result["originals_removed"], 0)
        self.assertEqual(result["raw_originals_exported"], 0)
        self.assertIsNone(result["simulation"])

    def test_proposed_interruption_stages_are_always_hypothetical(self):
        result = self.review()
        for stage in sorted(SCENARIOS):
            with self.subTest(stage=stage):
                modeled = self.review(stage=stage, fingerprint=result["preview_sha256"])
                scenario = modeled["simulation"]
                self.assertEqual(scenario["scenario"], stage)
                self.assertEqual(scenario["required_future_recovery_action"],
                                 SCENARIO_REQUIREMENTS[stage])
                self.assertTrue(scenario["simulated_interruption_only"])
                self.assertFalse(scenario["recovery_proven"])
                self.assertFalse(scenario["real_transaction_journal_exists"])
                self.assertFalse(scenario["cleanup_permitted"])
                self.assertFalse(modeled["deletion_authorized"])
                self.assertEqual(modeled["originals_removed"], 0)

    def test_no_original_or_manifest_modified_and_no_journal_created(self):
        original = self.original.read_bytes()
        manifest = (self.store.cases / self.case / "manifest.json")
        manifest_bytes = manifest.read_bytes()
        report = self.review()
        self.review(stage="DURING_ORIGINAL_DISPOSITION",
                    fingerprint=report["preview_sha256"])
        self.assertEqual(self.original.read_bytes(), original)
        self.assertEqual(manifest.read_bytes(), manifest_bytes)
        self.assertFalse((self.store.cases / self.case / "disposition").exists())
        self.assertFalse((self.store.cases / self.case / "preservation").exists())

    def test_repeat_assessments_have_stable_source_fingerprint(self):
        a = self.review()
        b = self.review()
        self.assertEqual(a["preview_sha256"], b["preview_sha256"])

    def test_matching_fingerprint_is_not_a_signature_or_permission(self):
        pre = self.review()
        result = self.review(stage="AFTER_ORIGINAL_DISPOSITION",
                             fingerprint=pre["preview_sha256"])
        self.assertFalse(result["dual_operator_approval_verified"])
        self.assertFalse(result["transaction_recovery_verified"])
        self.assertFalse(result["deletion_authorized"])
        self.assertIn("DUAL_OPERATOR_DELETION_APPROVAL_UNAVAILABLE", result["blockers"])

    def test_stale_preview_after_original_registration_refused(self):
        pre = self.review()
        self.register("another-source.log", b"changed synthetic evidence\n")
        with self.assertRaisesRegex(CaseError, "Stale disposition"):
            self.review(stage="BEFORE_INTENT_JOURNAL",
                        fingerprint=pre["preview_sha256"])

    def test_stale_preview_after_hold_append_refused(self):
        pre = self.review()
        self.hold()
        with self.assertRaisesRegex(CaseError, "Stale disposition"):
            self.review(stage="AFTER_INTENT_JOURNAL",
                        fingerprint=pre["preview_sha256"])

    def test_stale_preview_after_minimum_floor_change_refused(self):
        pre = self.review()
        self.floor(180)
        with self.assertRaisesRegex(CaseError, "Stale disposition"):
            self.review(stage="AFTER_RECOVERY_COPY_ASSERTION",
                        fingerprint=pre["preview_sha256"])

    def test_source_hold_always_blocks_regardless_of_age(self):
        self.hold()
        result = self.review(minimum=1)
        self.assertTrue(result["advisory_minimum_age_met"])
        self.assertIn("ACTIVE_LOCAL_PRESERVATION_HOLD", result["blockers"])
        self.assertEqual(read_controls(self.store, self.case)["active_hold_count"], 1)

    def test_longer_monotonic_floor_overrides_shorter_review_age(self):
        self.floor(250)
        result = self.review(minimum=1)
        self.assertEqual(result["strictest_advisory_minimum_days"], 250)
        self.assertFalse(result["advisory_minimum_age_met"])
        self.assertIn("MINIMUM_ADVISORY_RETENTION_AGE_UNMET", result["blockers"])
        self.assertEqual(read_controls(self.store, self.case)["minimum_retention_days"], 250)

    def test_unregistered_hold_source_material_is_undisclosed_blocker(self):
        digest = hashlib.sha256(b"source never registered").hexdigest()
        self.hold(source_sha=digest)
        result = self.review()
        self.assertEqual(result["unverified_preservation_source_references"], 1)
        self.assertIn("LOCAL_PRESERVATION_SOURCE_BYTES_UNVERIFIED", result["blockers"])
        self.assertNotIn(digest.encode(), json.dumps(result).encode())

    def test_unresolved_unjournaled_handoff_is_conservative_blocker(self):
        root = self.store.base / "handoff-manifests"
        root.mkdir(mode=0o700)
        ghost = root / (".tmp-handoff-" + "b"*32)
        ghost.write_bytes(b"")
        ghost.chmod(0o600)
        result = self.review()
        self.assertEqual(result["unattributed_handoff_scratch"], 1)
        self.assertIn("UNKNOWN_UNJOURNALED_HANDOFF_SCRATCH", result["blockers"])
        self.assertTrue(ghost.exists())

    def test_unsafe_unknown_index_file_refused(self):
        index = self.store.cases / self.case / "indexes" / "fake.tmp"
        index.write_bytes(b"not a verified index")
        index.chmod(0o600)
        with self.assertRaises(CaseError):
            self.review()

    def test_corrupt_local_preservation_chain_fails_closed(self):
        self.hold()
        p = next((self.store.cases / self.case / "preservation").iterdir())
        p.write_bytes(b'{"tampered":"yes"}')
        with self.assertRaises(CaseError):
            self.review()

    def test_tampered_same_length_original_fails_closed(self):
        self.original.write_bytes(b"X" * len(self.secret))
        with self.assertRaises(CaseError):
            self.review()

    def test_hardlinked_original_refused(self):
        alias = self.home / "wrong-link"
        os.link(self.original, alias)
        with self.assertRaises(CaseError):
            self.review()

    def test_invalid_case_identifier_and_missing_registered_originals(self):
        with self.assertRaises(CaseError):
            inspect_disposition(self.store, "../escape", minimum_age_days=30)
        other = self.store.open_case()["case_id"]
        with self.assertRaises(CaseError):
            inspect_disposition(self.store, other, minimum_age_days=30)

    def test_noninteger_bounds_and_wrong_simulation_parameters_refused(self):
        invalid = [False, 0, -1, 3651, 1.5, "60"]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(CaseError):
                self.review(minimum=value)
        pre = self.review()
        for stage, digest in [(None, pre["preview_sha256"]),
                              ("BOGUS", pre["preview_sha256"]),
                              ("BEFORE_INTENT_JOURNAL", None),
                              ("BEFORE_INTENT_JOURNAL", "not a sha")]:
            with self.subTest(stage=stage, sha=digest), self.assertRaises(CaseError):
                self.review(stage=stage, fingerprint=digest)

    def test_stale_wrong_sha_refused_not_treated_as_operator_approval(self):
        with self.assertRaisesRegex(CaseError, "Stale disposition"):
            self.review(stage="AFTER_ORIGINAL_DISPOSITION",
                        fingerprint="0"*64)

    def test_aware_clock_required_and_future_origin_refused(self):
        with self.assertRaises(CaseError):
            inspect_disposition(self.store, self.case, minimum_age_days=30,
                                now=datetime(2026, 10, 17))
        with self.store._locked(self.case) as (folder, manifest):
            manifest["created_at"] = (self.now + timedelta(days=5)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        with self.assertRaises(CaseError):
            self.review()

    def test_report_remains_private_metadata_only(self):
        report = self.review()
        encoded = json.dumps(report).encode()
        for secret in (self.secret, b"password=never-print-this",
                       b"customer-original-secret.log",
                       self.record["sha256"].encode(), str(self.home).encode()):
            self.assertNotIn(secret, encoded)

    def test_cli_requires_exact_read_only_actions_and_refuses_destructive_flags(self):
        cli = Path(__file__).resolve().parents[1] / "scripts" / "disposition_preflight_cli.py"
        env = {**os.environ, "HOME": str(self.home)}
        def call(*args):
            return subprocess.run([sys.executable, "-u", str(cli),
                                   "--case-id", self.case,
                                   "--minimum-age-days", "30", *args],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env, timeout=40)
        pre = call("--preview")
        self.assertEqual(pre.returncode, 0, pre.stderr.decode("ascii", "replace"))
        preview = json.loads(pre.stdout)
        self.assertFalse(preview["deletion_authorized"])
        simulation = call("--simulate", "DURING_ORIGINAL_DISPOSITION",
                          "--preview-sha256", preview["preview_sha256"])
        self.assertEqual(simulation.returncode, 0, simulation.stderr.decode("ascii", "replace"))
        self.assertTrue(json.loads(simulation.stdout)["simulation"]["simulated_interruption_only"])
        for forbidden in [
            ("--preview", "--delete"),
            ("--preview", "--confirm"),
            ("--preview", "--release"),
            ("--preview", "--execute"),
            ("--preview", "--export"),
            ("--simulate", "DURING_ORIGINAL_DISPOSITION"),
            ("--preview", "--preview-sha256", preview["preview_sha256"]),
            ("--simulate", "BOGUS", "--preview-sha256", preview["preview_sha256"]),
        ]:
            with self.subTest(forbidden=forbidden):
                self.assertEqual(call(*forbidden).returncode, 2)
        self.assertEqual(self.original.read_bytes(), self.secret)


if __name__ == "__main__":
    unittest.main()
