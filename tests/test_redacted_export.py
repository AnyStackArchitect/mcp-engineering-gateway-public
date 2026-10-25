"""Permanent negative regressions for private allowlisted v0.32 review ZIP."""
from __future__ import annotations

import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from casework import CaseError, CaseStore, _write_json_atomic
from case_handoff import _canonical
import redacted_export
from redacted_export import (MAX_PACKAGE, MEMBERS, _byte_band, _count_band,
                             review_redacted_export)
from preservationwork import propose_or_record


class PrivateRedactedPackageTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="rocky-redacted-review-")
        self.addCleanup(work.cleanup)
        self.home = Path(work.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.payload = b"private customer password=never-include-in-package\n" * 23
        self.original = self._register("secret-customer-name.log", self.payload)
        self.case_path = self.store.cases / self.case
        self.original_path = self.case_path / "originals" / self.original["artifact_id"]
        self.dest = self.store.base / redacted_export.OUT_DIR

    def _register(self, filename, payload):
        staged = self.store.inbox / filename
        staged.write_bytes(payload)
        staged.chmod(0o600)
        return self.store.register(self.case, filename)

    def _hold(self):
        fields = {"action": "PRESERVATION_HOLD", "reason_code": "investigation",
                  "reference_sha256": self.original["sha256"]}
        plan = propose_or_record(self.store, self.case, **fields)
        propose_or_record(self.store, self.case, **fields,
                          confirm=True, plan_sha256=plan["plan_sha256"])

    def preview(self):
        return review_redacted_export(self.store, self.case)

    def prepare(self, preview):
        return review_redacted_export(self.store, self.case, prepare=True,
                                      preview_sha256=preview["review_fingerprint_sha256"])

    def _zip(self, result):
        assert self.dest.is_dir()
        return self.dest / result["package_name"]

    def test_preview_only_no_zip_or_output_dir(self):
        result = self.preview()
        self.assertEqual(result["status"], "PRIVATE_REDACTED_PREVIEW_ONLY")
        self.assertEqual(result["contents"], list(MEMBERS))
        self.assertEqual(result["raw_originals_exported"], 0)
        self.assertEqual(result["originals_removed"], 0)
        self.assertFalse(result["public_disclosure_approved"])
        self.assertFalse(result["network_upload_performed"])
        self.assertFalse(result["operator_confirmation_is_disclosure_permission"])
        self.assertEqual(len(result["review_fingerprint_sha256"]), 64)
        self.assertFalse(self.dest.exists())

    def test_two_phase_prepare_private_fixed_members_not_public(self):
        before = hashlib.sha256(self.original_path.read_bytes()).hexdigest()
        preview = self.preview()
        output = self.prepare(preview)
        self.assertEqual(output["status"], "PRIVATE_REDACTED_PACKAGE_PREPARED_NOT_APPROVED")
        self.assertTrue(output["private_storage_only"])
        self.assertTrue(output["source_snapshot_reverified"])
        self.assertFalse(output["public_disclosure_approved"])
        folder = self.dest
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        exported = self._zip(output)
        self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o600)
        self.assertLess(exported.stat().st_size, MAX_PACKAGE)
        data = exported.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), preview["package_sha256"])
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            self.assertEqual(archive.namelist(), list(MEMBERS))
            self.assertTrue(all(x.compress_type == zipfile.ZIP_STORED
                                for x in archive.infolist()))
            self.assertTrue(all(not x.flag_bits & 1 for x in archive.infolist()))
            summary = json.loads(archive.read("summary.json"))
            review = json.loads(archive.read("review.json"))
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(summary["kind"], "REDACTED_CASE_STRUCTURE_ONLY")
            self.assertEqual(summary["artifact_count_band"], "1")
            self.assertEqual(summary["verified_original_bytes_band"], "1B-1MiB")
            self.assertFalse(summary["raw_evidence_included"])
            self.assertFalse(review["human_disclosure_review_completed"])
            self.assertFalse(review["independent_privacy_approval_verified"])
            self.assertFalse(review["public_disclosure_approved"])
            self.assertFalse(review["external_transmission_performed"])
            self.assertEqual(review["raw_originals_exported"], 0)
            self.assertEqual(set(manifest["members"]),
                             {"summary.json", "review.json", "README.txt"})
            for member, meta in manifest["members"].items():
                data_member = archive.read(member)
                self.assertEqual(meta["sha256"], hashlib.sha256(data_member).hexdigest())
        for secret in [self.payload, b"secret-customer-name.log",
                       b"password=never-include-in-package",
                       self.original["sha256"].encode(),
                       self.original["artifact_id"].encode(),
                       self.case.encode(), str(self.home).encode()]:
            self.assertNotIn(secret, data)
        self.assertEqual(hashlib.sha256(self.original_path.read_bytes()).hexdigest(), before)
        self.assertFalse((self.case_path / "disposition").exists())

    def test_preview_digest_stable_identical_case(self):
        a, b = self.preview(), self.preview()
        self.assertEqual(a, b)

    def test_package_bytes_deterministic_and_fixed_zip_metadata(self):
        from case_handoff import _snapshot
        from capacitywork import admission_lock
        with admission_lock(self.store):
            snapshot = _snapshot(self.store, self.case)
        package1 = redacted_export._render(snapshot)
        package2 = redacted_export._render(snapshot)
        self.assertEqual(package1, package2)
        with zipfile.ZipFile(io.BytesIO(package1)) as archive:
            self.assertTrue(all(entry.date_time == (1980, 1, 1, 0, 0, 0)
                                for entry in archive.infolist()))

    def test_no_duplicate_private_package_overwrite(self):
        p = self.preview()
        first = self.prepare(p)
        before = self._zip(first).read_bytes()
        with self.assertRaisesRegex(CaseError, "already exists"):
            self.prepare(p)
        self.assertEqual(self._zip(first).read_bytes(), before)

    def test_source_change_after_preview_is_refused(self):
        preview = self.preview()
        extra = self._register("second-source.log", b"second source")
        with self.assertRaisesRegex(CaseError, "snapshot changed"):
            self.prepare(preview)
        self.assertFalse(self.dest.exists())
        self.assertTrue((self.case_path / "originals" / extra["artifact_id"]).exists())

    def test_hold_append_invalidates_review_fingerprint(self):
        preview = self.preview()
        self._hold()
        with self.assertRaisesRegex(CaseError, "snapshot changed"):
            self.prepare(preview)
        self.assertFalse(self.dest.exists())

    def test_pending_handoff_journal_blocks_preview(self):
        exports = self.store.base / "handoff-manifests"
        exports.mkdir(mode=0o700)
        journal = exports / (".tmp-handoff-" + "f" * 32)
        journal.write_bytes(b"")
        journal.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "unfinished"):
            self.preview()
        self.assertTrue(journal.exists())

    def test_unregistered_original_inventory_detected(self):
        orphan = self.case_path / "originals" / ("a"*32)
        orphan.write_bytes(b"unregistered")
        orphan.chmod(0o600)
        with self.assertRaises(CaseError):
            self.preview()

    def test_mutated_original_content_refused(self):
        self.original_path.write_bytes(b"Z" * len(self.payload))
        with self.assertRaises(CaseError):
            self.preview()

    def test_original_hardlink_refused(self):
        alias = self.home / "unsafe-linked-evidence"
        os.link(self.original_path, alias)
        with self.assertRaises(CaseError):
            self.preview()

    def test_symlinked_source_refused(self):
        replacement = self.home / "stored-original"
        self.original_path.rename(replacement)
        self.original_path.symlink_to(replacement)
        # O_NOFOLLOW on Linux rejects the link at os.open with ELOOP;
        # the existing source verifier correctly fails closed without
        # necessarily normalizing that OS error into CaseError.
        try:
            self.preview()
        except OSError as exc:
            self.assertEqual(exc.errno, errno.ELOOP)
        except CaseError:
            pass
        else:
            self.fail("Symlinked registered original was accepted")

    def test_unfinished_index_blocks(self):
        temp = self.case_path / "indexes" / ".tmp-broken"
        temp.write_bytes(b"")
        temp.chmod(0o600)
        with self.assertRaises(CaseError):
            self.preview()

    def test_corrupt_preservation_ledger_fails(self):
        self._hold()
        bad = next((self.case_path / "preservation").iterdir())
        bad.write_bytes(b"{not_json")
        with self.assertRaises(CaseError):
            self.preview()

    def test_stale_plan_wrong_hash_and_malformed_case_refused(self):
        with self.assertRaises(CaseError):
            review_redacted_export(self.store, "../bad")
        with self.assertRaises(CaseError):
            review_redacted_export(self.store, self.case, prepare=True)
        with self.assertRaises(CaseError):
            review_redacted_export(self.store, self.case, preview_sha256="0"*64)
        with self.assertRaises(CaseError):
            review_redacted_export(self.store, self.case, prepare=True,
                                   preview_sha256="z"*64)
        with self.assertRaises(CaseError):
            review_redacted_export(self.store, self.case, prepare=True,
                                   preview_sha256="a"*64)

    def test_empty_case_never_produces_a_private_package(self):
        empty = self.store.open_case()["case_id"]
        with self.assertRaises(CaseError):
            review_redacted_export(self.store, empty)

    def test_untrusted_manifest_notes_and_classification_not_exported(self):
        with self.store._locked(self.case) as (folder, manifest):
            manifest["customer_name"] = "ACME_SECRET_CUSTOMER_2026"
            manifest["artifacts"][self.original["artifact_id"]]["secret"] = "INV-PRIVATE-0001"
            _write_json_atomic(folder / "manifest.json", manifest)
        report = self.prepare(self.preview())
        data = self._zip(report).read_bytes()
        self.assertNotIn(b"ACME_SECRET_CUSTOMER_2026", data)
        self.assertNotIn(b"INV-PRIVATE-0001", data)

    def test_rejected_unknown_file_in_private_package_directory(self):
        self.dest.mkdir(mode=0o700)
        other = self.dest / "unexpected.bin"
        other.write_bytes(b"unknown")
        other.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "Unexpected file"):
            self.preview()

    def test_symlinked_private_package_directory_fails(self):
        external = self.home / "other-private"
        external.mkdir(mode=0o700)
        self.dest.symlink_to(external)
        with self.assertRaises(CaseError):
            self.preview()

    def test_preexisting_final_symlink_refuses_no_overwrite(self):
        preview = self.preview()
        self.dest.mkdir(mode=0o700)
        final = self.dest / ("redacted-" + preview["review_fingerprint_sha256"][:24] + ".zip")
        target = self.home / "protected.txt"
        target.write_bytes(b"do-not-modify")
        target.chmod(0o600)
        final.symlink_to(target)
        with self.assertRaises(CaseError):
            self.prepare(preview)
        self.assertEqual(target.read_bytes(), b"do-not-modify")

    def test_failure_during_publication_keeps_private_journal_and_source(self):
        preview = self.preview()
        with patch.object(redacted_export.os, "link", side_effect=OSError("simulated disk failure")):
            with self.assertRaises(OSError):
                self.prepare(preview)
        files = list(self.dest.iterdir())
        self.assertTrue(any(x.name.startswith(".review-work-") for x in files))
        self.assertTrue(any(x.name.startswith(".tmp-review-") for x in files))
        self.assertEqual(self.original_path.read_bytes(), self.payload)
        with self.assertRaisesRegex(CaseError, "Interrupted"):
            self.preview()

    def test_failed_readback_keeps_final_and_journal_for_review(self):
        preview = self.preview()
        with patch.object(redacted_export, "_verified_readback", side_effect=CaseError("injected")):
            with self.assertRaisesRegex(CaseError, "injected"):
                self.prepare(preview)
        files = list(self.dest.iterdir())
        self.assertTrue(any(x.name.startswith(".review-work-") for x in files))
        self.assertTrue(any(x.name.startswith("redacted-") for x in files))
        self.assertEqual(self.original_path.read_bytes(), self.payload)

    def test_coarse_bands_known_answer_boundary(self):
        count_cases = {0:"0", 1:"1", 2:"2-10", 10:"2-10",
                       11:"11-100", 100:"11-100", 101:"101-1000",
                       1000:"101-1000", 1001:"1001+"}
        for value, result in count_cases.items():
            self.assertEqual(_count_band(value), result)
        size_cases = {0:"0", 1:"1B-1MiB", 1024**2-1:"1B-1MiB",
                      1024**2:"1MiB-1GiB",1024**3-1:"1MiB-1GiB",
                      1024**3:"1GiB-16GiB",16*1024**3-1:"1GiB-16GiB",
                      16*1024**3:"16GiB+"}
        for value, result in size_cases.items():
            self.assertEqual(_byte_band(value), result)
        for value in [True, -1, "1", 1.1]:
            with self.assertRaises(CaseError):
                _count_band(value)
            with self.assertRaises(CaseError):
                _byte_band(value)

    def test_cli_local_preview_prepare_and_deny_destructive_flags(self):
        cli = Path(__file__).resolve().parents[1] / "scripts/redacted_export_cli.py"
        env = {**os.environ, "HOME": str(self.home)}
        def call(*args):
            return subprocess.run([sys.executable, "-u", str(cli),
                                   "--case-id", self.case, *args],
                                  stdin=subprocess.DEVNULL, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=40, check=False)
        preview = call("--preview")
        self.assertEqual(preview.returncode, 0, preview.stderr.decode())
        packet = json.loads(preview.stdout)
        report = call("--prepare", "--review-fingerprint",
                      packet["review_fingerprint_sha256"])
        self.assertEqual(report.returncode, 0, report.stderr.decode())
        prepared = json.loads(report.stdout)
        self.assertEqual(prepared["status"], "PRIVATE_REDACTED_PACKAGE_PREPARED_NOT_APPROVED")
        self.assertFalse(prepared["public_disclosure_approved"])
        for args in [
            ("--preview", "--transmit"),
            ("--preview", "--upload"),
            ("--preview", "--dest", "/tmp/public"),
            ("--prepare", "--delete"),
            ("--prepare", "--release"),
            ("--prepare", "--execute"),
            ("--prepare",),
            ("--preview", "--review-fingerprint", "0"*64),
        ]:
            self.assertEqual(call(*args).returncode, 2, args)
        self.assertEqual(self.original_path.read_bytes(), self.payload)


if __name__ == "__main__":
    unittest.main()
