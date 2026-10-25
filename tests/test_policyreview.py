"""Review-only proposed retention policy and hold-release screening regressions."""
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
from case_handoff import _canonical
from policyreview import review_policy
from preservationwork import propose_or_record, read_controls
from retentionwork import assess_case


class PolicyReviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.now = datetime.now(timezone.utc)
        self.secret = b"private customer password=not-for-output\n"
        self.artifact = self.register("customer-private-original.log", self.secret)
        self.source_sha = self.artifact["sha256"]
        self.missing_sha = hashlib.sha256(b"unregistered supporting source").hexdigest()
        with self.store._locked(self.case) as (folder, manifest):
            manifest["created_at"] = (self.now - timedelta(days=45)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)

    def register(self, name: str, content: bytes):
        stage = self.store.inbox / name
        stage.write_bytes(content)
        stage.chmod(0o600)
        return self.store.register(self.case, name)

    def hold(self, sha: str | None = None):
        args = dict(action="PRESERVATION_HOLD", reason_code="investigation",
                    reference_sha256=sha or self.source_sha)
        preview = propose_or_record(self.store, self.case, **args)
        return propose_or_record(self.store, self.case, **args, confirm=True,
                                 plan_sha256=preview["plan_sha256"])

    def floor(self, days: int):
        args = dict(action="MINIMUM_RETENTION_DAYS",
                    reference_sha256=self.source_sha, minimum_days=days)
        view = propose_or_record(self.store, self.case, **args)
        return propose_or_record(self.store, self.case, **args, confirm=True,
                                 plan_sha256=view["plan_sha256"])

    def rule(self, kind="MINIMUM_DAYS", sha=None, days=60, rid="b"*32):
        row = {"rule_id": rid, "kind": kind,
               "source_sha256": sha or self.source_sha}
        if kind == "MINIMUM_DAYS":
            row["minimum_days"] = days
        return row

    def policy(self, rules=None, release=None):
        return {"schema": 1, "mode": "REVIEW_ONLY", "case_id": self.case,
                "policy_id": "a"*32,
                "rules": [self.rule()] if rules is None else rules,
                "release_review": release}

    def review(self, policy=None, *, raw=None):
        if raw is None:
            raw = _canonical(self.policy() if policy is None else policy)
        return review_policy(self.store, self.case, raw, now=self.now)

    def test_valid_proposal_is_review_only_never_an_approval(self):
        before = self.store.cases / self.case / "originals" / self.artifact["artifact_id"]
        original_digest = hashlib.sha256(before.read_bytes()).hexdigest()
        report = self.review()
        self.assertEqual(report["status"], "POLICY_REVIEW_ONLY")
        self.assertEqual(report["effective_advisory_minimum_days"], 60)
        self.assertEqual(report["case_age_whole_days_from_mutable_manifest"], 45)
        self.assertFalse(report["advisory_minimum_age_met"])
        self.assertIn("STRICTEST_MINIMUM_RETENTION_NOT_REACHED", report["blockers"])
        self.assertIn("POLICY_AND_CUSTODY_AUTHORITY_NOT_VERIFIED", report["blockers"])
        self.assertEqual(report["policy_source_references_unverified"], 0)
        for key in ("policy_authority_independently_verified", "document_signer_verified",
                    "latest_external_checkpoint_verified", "legal_hold_authority_verified",
                    "hold_release_authorized", "hold_release_executed",
                    "deletion_authorized", "public_disclosure_approved"):
            self.assertFalse(report[key], key)
        self.assertEqual(report["raw_originals_exported"], 0)
        self.assertEqual(report["originals_removed"], 0)
        self.assertEqual(hashlib.sha256(before.read_bytes()).hexdigest(), original_digest)
        self.assertEqual(report["review_sha256"], self.review()["review_sha256"])
        for private in (self.secret, b"customer-private-original.log",
                        self.source_sha.encode(), str(self.home).encode()):
            self.assertNotIn(private, json.dumps(report).encode())

    def test_active_local_hold_dominates_proposed_policies(self):
        self.hold()
        report = self.review(self.policy([self.rule(days=1)]))
        self.assertIn("LOCAL_PRESERVATION_HOLD_ACTIVE", report["blockers"])
        self.assertEqual(report["active_local_holds"], 1)
        self.assertFalse(report["hold_release_executed"])
        self.assertEqual(read_controls(self.store, self.case)["active_hold_count"], 1)

    def test_proposed_hold_also_blocks_without_modifying_local_ledger(self):
        policy = self.policy([self.rule(kind="PRESERVATION_HOLD")])
        report = self.review(policy)
        self.assertIn("PROPOSED_PRESERVATION_HOLD", report["blockers"])
        self.assertEqual(report["proposed_holds"], 1)
        self.assertEqual(report["active_local_holds"], 0)
        self.assertFalse((self.store.cases / self.case / "preservation").exists())

    def test_longest_duration_dominates_and_cannot_weaken_local_floor(self):
        self.floor(180)
        rules = [self.rule(days=30), self.rule(days=90, rid="c"*32)]
        report = self.review(self.policy(rules))
        self.assertEqual(report["local_minimum_days"], 180)
        self.assertEqual(report["proposed_strictest_minimum_days"], 90)
        self.assertEqual(report["effective_advisory_minimum_days"], 180)
        self.assertIn("STRICTEST_MINIMUM_RETENTION_NOT_REACHED", report["blockers"])
        self.assertEqual(read_controls(self.store, self.case)["minimum_retention_days"], 180)

    def test_multi_rule_strictest_proposed_floor(self):
        rules = [self.rule(days=10), self.rule(days=100, rid="c"*32,
                 sha=hashlib.sha256(b"other source").hexdigest())]
        report = self.review(self.policy(rules))
        self.assertEqual(report["effective_advisory_minimum_days"], 100)
        self.assertEqual(report["policy_source_references_unverified"], 1)

    def test_conflicting_terms_for_same_source_block_review(self):
        rules = [self.rule(days=10), self.rule(days=100, rid="c"*32)]
        report = self.review(self.policy(rules))
        self.assertEqual(report["conflicting_policy_source_terms"], 1)
        self.assertIn("CONFLICTING_TERMS_FOR_SAME_SOURCE", report["blockers"])
        self.assertEqual(report["proposed_strictest_minimum_days"], 100)

    def test_release_request_for_active_hold_remains_review_only(self):
        self.hold()
        proposal = self.policy([], {
            "target_hold_sequence": 1, "request_source_sha256": self.source_sha})
        report = self.review(proposal)
        self.assertTrue(report["hold_release_review_requested"])
        self.assertTrue(report["hold_release_target_is_active_local_hold"])
        self.assertEqual(report["hold_release_source_material_status"],
                         "REGISTERED_ORIGINAL_BYTES_MATCH_ONLY")
        self.assertIn("RELEASE_REQUIRES_SEPARATE_AUTHORITY_AND_REVIEW",
                      report["blockers"])
        self.assertFalse(report["hold_release_authorized"])
        self.assertFalse(report["hold_release_executed"])
        self.assertEqual(read_controls(self.store, self.case)["active_hold_count"], 1)

    def test_bad_release_target_does_not_change_hold(self):
        self.hold()
        report = self.review(self.policy([], {
            "target_hold_sequence": 2, "request_source_sha256": self.missing_sha}))
        self.assertFalse(report["hold_release_target_is_active_local_hold"])
        self.assertIn("RELEASE_TARGET_NOT_ACTIVE_LOCAL_HOLD", report["blockers"])
        self.assertIn("RELEASE_REQUEST_SOURCE_MATERIAL_UNVERIFIED", report["blockers"])
        self.assertEqual(read_controls(self.store, self.case)["active_hold_count"], 1)

    def test_unverified_local_source_is_reported_without_releasing_hold(self):
        self.hold(self.missing_sha)
        report = self.review(self.policy([self.rule(days=1)]))
        self.assertEqual(report["local_source_references_unverified"], 1)
        self.assertIn("LOCAL_PRESERVATION_SOURCE_MATERIAL_UNVERIFIED",
                      report["blockers"])
        self.assertIn("LOCAL_PRESERVATION_HOLD_ACTIVE", report["blockers"])

    def test_case_isolation_policy_identifier_and_manifest_clock(self):
        other = self.store.open_case()["case_id"]
        foreign = self.policy()
        foreign["case_id"] = other
        with self.assertRaises(CaseError):
            self.review(foreign)
        with self.assertRaises(CaseError):
            review_policy(self.store, other, _canonical(self.policy()), now=self.now)
        with self.assertRaises(CaseError):
            self.review(raw=_canonical({**self.policy(), "case_id": "../escape"}))
        with self.assertRaisesRegex(CaseError, "aware"):
            review_policy(self.store, self.case, _canonical(self.policy()),
                          now=datetime(2026, 10, 17))
        with self.store._locked(self.case) as (folder, manifest):
            manifest["created_at"] = (self.now + timedelta(days=1)).isoformat()
            _write_json_atomic(folder / "manifest.json", manifest)
        with self.assertRaisesRegex(CaseError, "future"):
            self.review()

    def test_policy_must_be_canonical_bounded_and_has_unique_fields(self):
        doc = self.policy()
        raw = _canonical(doc)
        for variant in [b"", b"X"*16385, raw.replace(b',"mode":', b', "mode":'),
                        raw.replace(b'"mode":', b'"mode":"REVIEW_ONLY","mode":', 1)]:
            with self.subTest(variant=variant[:50]), self.assertRaises(CaseError):
                self.review(raw=variant)

    def test_rule_schema_type_bounds_and_unknown_actions(self):
        bad = [
            {"rules": [self.rule(days=True)]},
            {"rules": [self.rule(days=0)]},
            {"rules": [self.rule(days=3651)]},
            {"rules": [self.rule(kind="DELETE_ORIGINAL")]},
            {"rules": [self.rule(kind="RELEASE_HOLD")]},
            {"rules": [dict(self.rule(), extra="unsupported")]},
            {"rules": [self.rule(rid="not hex")]},
            {"rules": [self.rule(sha="bad")]},
            {"rules": [self.rule(), self.rule()]},
            {"rules": [self.rule(days=1, rid=f"{i:032x}") for i in range(33)]},
        ]
        for change in bad:
            doc = {**self.policy(), **change}
            with self.subTest(change=str(change)[:60]), self.assertRaises(CaseError):
                self.review(doc)

    def test_release_request_invalid_types_and_unsupported_fields(self):
        bad = [
            {"target_hold_sequence": True, "request_source_sha256": self.source_sha},
            {"target_hold_sequence": 0, "request_source_sha256": self.source_sha},
            {"target_hold_sequence": 129, "request_source_sha256": self.source_sha},
            {"target_hold_sequence": 1, "request_source_sha256": "notsha"},
            {"target_hold_sequence": 1, "request_source_sha256": self.source_sha,
             "execute": True},
        ]
        for release in bad:
            with self.subTest(release=str(release)[:60]), self.assertRaises(CaseError):
                self.review(self.policy([], release))

    def test_fails_on_corrupt_local_preservation_chain(self):
        self.hold()
        file = next((self.store.cases / self.case / "preservation").iterdir())
        file.write_bytes(b"tampered")
        with self.assertRaises(CaseError):
            self.review()

    def test_fails_on_mutated_or_hardlinked_original(self):
        self.hold()
        path = self.store.cases / self.case / "originals" / self.artifact["artifact_id"]
        alias = self.home / "alias"
        os.link(path, alias)
        with self.assertRaisesRegex(CaseError, "identity is unsafe"):
            self.review()
        alias.unlink()
        path.write_bytes(b"X"*len(self.secret))
        with self.assertRaisesRegex(CaseError, "SHA-256"):
            self.review()

    def test_readonly_cli_stdin_and_destructive_command_refusal(self):
        cli = Path(__file__).resolve().parents[1] / "scripts" / "case_policy_review_cli.py"
        env = {**os.environ, "HOME": str(self.home)}
        raw = _canonical(self.policy())
        def call(*extra, input=raw):
            return subprocess.run(
                [sys.executable, "-u", str(cli), "--case-id", self.case, *extra],
                env=env, input=input,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        for options in ((), ("--review",), ("--policy-stdin",),
                        ("--review", "--policy-stdin", "--delete"),
                        ("--review", "--policy-stdin", "--release"),
                        ("--review", "--policy-stdin", "--export")):
            self.assertNotEqual(call(*options).returncode, 0, options)
        allowed = call("--review", "--policy-stdin")
        self.assertEqual(allowed.returncode, 0, allowed.stderr.decode())
        report = json.loads(allowed.stdout)
        self.assertEqual(report["status"], "POLICY_REVIEW_ONLY")
        self.assertFalse(report["deletion_authorized"])
        self.assertFalse(report["hold_release_executed"])
        self.assertTrue(report["blockers"])
        self.assertNotIn(b"password=not-for-output", allowed.stdout)
        self.assertNotIn(b"customer-private-original", allowed.stdout)
        self.assertNotIn(self.source_sha.encode(), allowed.stdout)

    def test_release_request_has_no_matching_original_so_cannot_establish_authority(self):
        request = self.policy([], {
            "target_hold_sequence": 1, "request_source_sha256": self.missing_sha})
        report = self.review(request)
        self.assertFalse(report["hold_release_target_is_active_local_hold"])
        self.assertFalse(report["hold_release_authorized"])
        self.assertFalse(report["hold_release_executed"])
        self.assertIn("RELEASE_REQUEST_SOURCE_MATERIAL_UNVERIFIED",
                      report["blockers"])

    def test_empty_rules_and_no_request_refused(self):
        with self.assertRaises(CaseError):
            self.review(self.policy([], None))


if __name__ == "__main__":
    unittest.main()
