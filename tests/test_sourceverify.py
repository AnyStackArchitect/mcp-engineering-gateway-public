"""Test bounded v0.28 case-local source material verification and negative trust states."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from casework import CaseError, CaseStore, _write_json_atomic
from preservationwork import propose_or_record, read_controls
from sourceverify import (
    verify_references, STATUS_VERIFIED, STATUS_MISSING,
    STATUS_AMBIGUOUS, STATUS_DERIVED, STATUS_EMPTY,
)


class PreservationSourceVerificationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.raw = b"private original reference, password=must-not-leak\n" * 17
        self.artifact = self._register("source-legal-paper.txt", self.raw)
        self.original = self._original(self.artifact)
        self.expected_sha = self.artifact["sha256"]
        self.missing_sha = hashlib.sha256(b"an unregistered offsite document").hexdigest()

    def _register(self, filename, payload):
        staged = self.store.inbox / filename
        staged.write_bytes(payload)
        staged.chmod(0o600)
        return self.store.register(self.case, filename)

    def _original(self, record):
        return self.store.cases / self.case / "originals" / record["artifact_id"]

    def _hold(self, sha=None, reason="investigation"):
        sha = self.expected_sha if sha is None else sha
        args = dict(action="PRESERVATION_HOLD", reference_sha256=sha,
                    reason_code=reason)
        preview = propose_or_record(self.store, self.case, **args)
        return propose_or_record(self.store, self.case, **args,
                                 confirm=True, plan_sha256=preview["plan_sha256"])

    def report(self):
        return verify_references(self.store, self.case)

    def test_absent_ledger_is_not_proof_that_holds_never_existed(self):
        result = self.report()
        self.assertEqual(result["status"], "UNVERIFIED_SOURCE_REFERENCE_MATERIAL")
        self.assertFalse(result["source_reference_material_verified"])
        self.assertEqual(result["preservation_record_count"], 0)
        self.assertEqual(result["reference_results"], [])
        self.assertFalse(result["legal_hold_authority_verified"])
        self.assertFalse(result["deletion_authorized"])

    def test_exact_registered_source_bytes_verified_without_authority(self):
        original_hash = hashlib.sha256(self.original.read_bytes()).hexdigest()
        self._hold()
        result = self.report()
        self.assertEqual(result["status"], "MATERIAL_BYTES_VERIFIED_ONLY")
        self.assertTrue(result["source_reference_material_verified"])
        self.assertEqual(result["reference_results"],
                         [{"sequence": 1, "source_material_status": STATUS_VERIFIED}])
        self.assertEqual(result["registered_originals_sha256_verified"], 1)
        self.assertEqual(result["registered_original_bytes_sha256_verified"], len(self.raw))
        for key in ["source_reference_signer_verified",
                    "source_reference_provenance_verified",
                    "legal_hold_authority_verified", "case_ledger_independently_anchored",
                    "deletion_authorized", "public_disclosure_approved"]:
            self.assertFalse(result[key], key)
        self.assertEqual(result["raw_originals_exported"], 0)
        self.assertEqual(result["originals_removed"], 0)
        self.assertEqual(original_hash, hashlib.sha256(self.original.read_bytes()).hexdigest())
        self.assertEqual(result["verification_sha256"], self.report()["verification_sha256"])
        encoded = json.dumps(result).encode()
        for secret in [b"password=must-not-leak", b"source-legal-paper.txt",
                       self.expected_sha.encode(), str(self.original).encode()]:
            self.assertNotIn(secret, encoded)

    def test_unregistered_hash_remains_unverified_even_with_other_originals(self):
        self._hold(self.missing_sha)
        result = self.report()
        self.assertFalse(result["source_reference_material_verified"])
        self.assertEqual(result["references_missing_from_case"], 1)
        self.assertEqual(result["reference_results"][0]["source_material_status"],
                         STATUS_MISSING)
        self.assertEqual(result["registered_originals_sha256_verified"], 1)
        self.assertTrue(self.original.exists())

    def test_staged_but_unregistered_document_is_not_a_verified_reference(self):
        self._hold(self.missing_sha)
        unregistered = self.store.inbox / "never-registered.txt"
        unregistered.write_bytes(b"an unregistered offsite document")
        unregistered.chmod(0o600)
        self.assertEqual(self.report()["references_missing_from_case"], 1)

    def test_document_registered_to_different_case_cannot_satisfy_reference(self):
        other_case = self.store.open_case()["case_id"]
        staged = self.store.inbox / "external-referenced-document"
        staged.write_bytes(b"an unregistered offsite document")
        staged.chmod(0o600)
        self.store.register(other_case, staged.name)
        self._hold(self.missing_sha)
        self.assertEqual(self.report()["references_missing_from_case"], 1)

    def test_duplicate_registered_sha_is_ambiguous_not_single_source(self):
        duplicate = self._register("source-legal-paper-duplicate.txt", self.raw)
        self.assertEqual(duplicate["sha256"], self.expected_sha)
        self._hold()
        result = self.report()
        self.assertFalse(result["source_reference_material_verified"])
        self.assertEqual(result["references_with_ambiguous_matches"], 1)
        self.assertEqual(result["reference_results"][0]["source_material_status"],
                         STATUS_AMBIGUOUS)

    def test_only_matching_derived_evidence_is_not_original_reference(self):
        root = self.artifact
        derived = self._register("derived-note.txt",
                                 b"derived reference payload, not independent source")
        with self.store._locked(self.case) as (folder, manifest):
            manifest["artifacts"][derived["artifact_id"]]["derived_from"] = root["artifact_id"]
            _write_json_atomic(folder / "manifest.json", manifest)
        self._hold(derived["sha256"])
        result = self.report()
        self.assertFalse(result["source_reference_material_verified"])
        self.assertEqual(result["references_matching_only_derived_evidence"], 1)
        self.assertEqual(result["reference_results"][0]["source_material_status"],
                         STATUS_DERIVED)

    def test_empty_original_does_not_verify_source_material(self):
        empty = self._register("empty-document.txt", b"")
        self._hold(empty["sha256"])
        result = self.report()
        self.assertFalse(result["source_reference_material_verified"])
        self.assertEqual(result["references_matching_empty_originals"], 1)
        self.assertEqual(result["reference_results"][0]["source_material_status"],
                         STATUS_EMPTY)

    def test_multiple_record_summary_counts_each_reference_without_omission(self):
        self._hold()
        self._hold(self.missing_sha, reason="customer_request")
        result = self.report()
        self.assertEqual(result["preservation_record_count"], 2)
        self.assertEqual(len(result["reference_results"]), 2)
        self.assertEqual(result["references_with_verified_nonempty_source_bytes"], 1)
        self.assertEqual(result["references_missing_from_case"], 1)
        self.assertEqual([v["sequence"] for v in result["reference_results"]], [1, 2])
        self.assertFalse(result["source_reference_material_verified"])

    def test_changed_same_length_original_refuses_all_verification(self):
        self._hold()
        mutated = b"X" * len(self.raw)
        self.original.write_bytes(mutated)
        with self.assertRaisesRegex(CaseError, "SHA-256"):
            self.report()

    def test_hardlinked_original_identity_refused(self):
        self._hold()
        alias = self.home / "external-original-link"
        os.link(self.original, alias)
        with self.assertRaisesRegex(CaseError, "identity is unsafe"):
            self.report()

    def test_malformed_or_tampered_ledger_refuses_report(self):
        self._hold()
        record = next((self.store.cases / self.case / "preservation").iterdir())
        record.write_bytes(b'{"unsafe":"tampered"}')
        with self.assertRaises(CaseError):
            self.report()

    def test_read_controls_keeps_digest_inventory_private(self):
        self._hold()
        record = read_controls(self.store, self.case)
        self.assertEqual(record["record_count"], 1)
        self.assertNotIn("source_references", record)
        self.assertFalse(record["source_reference_material_verified"])

    def test_wrong_case_identifier_and_nonexistent_case_fail(self):
        with self.assertRaises(CaseError):
            verify_references(self.store, "bad/id")
        with self.assertRaises(CaseError):
            verify_references(self.store, "c" * 32)

    def test_cli_preview_is_mandatory_and_exit_status_tracks_integrity(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "verify_preservation_sources.py"
        env = {**os.environ, "HOME": str(self.home)}
        def call(*args):
            return subprocess.run([sys.executable, "-u", str(script),
                                   "--case-id", self.case, *args],
                                  stdin=subprocess.DEVNULL, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=35, check=False)
        for invalid in [(), ("--verify", "--delete"), ("--confirm",),
                        ("--verify", "--export")]:
            self.assertEqual(call(*invalid).returncode, 2, invalid)
        self._hold(self.missing_sha)
        unverified = call("--verify")
        self.assertEqual(unverified.returncode, 3, unverified.stderr.decode())
        self.assertFalse(json.loads(unverified.stdout)["source_reference_material_verified"])
        self.assertNotIn(b"password=must-not-leak", unverified.stdout)
        self.assertNotIn(str(self.original).encode(), unverified.stdout)

    def test_cli_exact_match_is_byte_only_no_raw_export(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "verify_preservation_sources.py"
        self._hold()
        response = subprocess.run([sys.executable, "-u", str(script), "--case-id",
                                   self.case, "--verify"],
                                  stdin=subprocess.DEVNULL,
                                  env={**os.environ, "HOME": str(self.home)},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=35, check=False)
        self.assertEqual(response.returncode, 0, response.stderr.decode())
        report = json.loads(response.stdout)
        self.assertTrue(report["source_reference_material_verified"])
        self.assertFalse(report["legal_hold_authority_verified"])
        self.assertEqual(report["raw_originals_exported"], 0)
        self.assertEqual(self.original.read_bytes(), self.raw)
        self.assertNotIn(self.expected_sha.encode(), response.stdout)


if __name__ == "__main__":
    unittest.main()
