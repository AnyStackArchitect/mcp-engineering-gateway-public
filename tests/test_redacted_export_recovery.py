"""Source-bound export recovery: crash phases, hostile state, and no disclosure."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from case_handoff import _canonical
from casework import CaseError, CaseStore
from preservationwork import propose_or_record
import redacted_export as export
import redacted_export_recovery as recovery
from scripts.smoke_redacted_export_recovery import (PHASES, PUBLICATION_CHILD,
                                                   RECOVERY_CHILD, _fixture)

ROOT = Path(__file__).resolve().parents[1]


class RedactedExportRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="redacted-recovery-unit-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.store, self.case, self.original, self.raw = _fixture(self.home)
        self.plan = export.review_redacted_export(self.store, self.case)
        self.exports = self.store.base / export.OUT_DIR
        self.final = self.exports / (
            "redacted-" + self.plan["review_fingerprint_sha256"][:24] + ".zip")

    def interrupted(self, stage: int = 2):
        real_sync = export._sync_directory
        count = 0

        def durable_boundary(folder):
            nonlocal count
            real_sync(folder)
            if Path(folder) == self.exports:
                count += 1
                if count == stage:
                    raise CaseError("synthetic publication interruption")

        with patch.object(export, "_sync_directory", side_effect=durable_boundary):
            with self.assertRaisesRegex(CaseError, "synthetic publication interruption"):
                export.review_redacted_export(
                    self.store, self.case, prepare=True,
                    preview_sha256=self.plan["review_fingerprint_sha256"])
        journal = next(self.exports.glob(".review-work-*.json"))
        doc = json.loads(journal.read_bytes())
        return doc["transaction_id"], journal, self.exports / doc["tmp_name"]

    def preview(self, work: str, **kwargs):
        return recovery.recover(self.store, self.case, work, **kwargs)

    def confirm(self, work: str, preview: dict, **kwargs):
        return recovery.recover(self.store, self.case, work, confirm=True,
                                recovery_plan_sha256=preview["recovery_plan_sha256"],
                                **kwargs)

    def assert_original_preserved(self):
        self.assertEqual(self.original.read_bytes(), self.raw)
        self.assertEqual(self.original.stat().st_nlink, 1)

    def test_new_journal_binds_exact_source_without_copying_source_prose(self):
        work, journal, _ = self.interrupted()
        doc = json.loads(journal.read_bytes())
        self.assertEqual(doc["schema"], 2)
        self.assertEqual(doc["case_id"], self.case)
        self.assertEqual(doc["preview_sha256"], self.plan["review_fingerprint_sha256"])
        self.assertEqual(doc["package_sha256"], self.plan["package_sha256"])
        self.assertEqual(doc["package_size_bytes"], self.plan["package_size_bytes"])
        self.assertEqual(doc["transaction_id"], work)
        self.assertEqual(len(doc["source_snapshot_sha256"]), 64)
        self.assertLessEqual(journal.stat().st_size, export.MAX_JOURNAL)
        self.assertNotIn(b"customer-private-source.log", journal.read_bytes())
        self.assertNotIn(self.raw, journal.read_bytes())
        self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)

    def test_parent_directory_is_durable_before_first_journal_open(self):
        real_sync, real_open = export._sync_directory, os.open
        events = []

        def synchronized(folder):
            real_sync(folder)
            if Path(folder) == self.store.base:
                events.append("parent_durable")

        def opened(path, flags, *args, **kwargs):
            if Path(path).name.startswith(".review-work-") and flags & os.O_CREAT:
                events.append("journal_open")
                self.assertIn("parent_durable", events)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(export, "_sync_directory", side_effect=synchronized):
            with patch.object(export.os, "open", side_effect=opened):
                export.review_redacted_export(
                    self.store, self.case, prepare=True,
                    preview_sha256=self.plan["review_fingerprint_sha256"])
        self.assertLess(events.index("parent_durable"), events.index("journal_open"))
        self.assertEqual(list(self.exports.iterdir()), [self.final])

    def test_parent_fsync_failure_prevents_any_journal_or_scratch(self):
        def failed_parent(_folder):
            raise OSError("synthetic parent fsync failure")
        with patch.object(export, "_sync_directory", side_effect=failed_parent):
            with self.assertRaises(OSError):
                export.review_redacted_export(
                    self.store, self.case, prepare=True,
                    preview_sha256=self.plan["review_fingerprint_sha256"])
        self.assertEqual(list(self.exports.iterdir()), [])
        self.assert_original_preserved()

    def test_preview_without_export_directory_does_not_create_one(self):
        listed = recovery.list_interrupted(self.store, self.case)
        self.assertEqual(listed["redacted_export_work_ids"], [])
        self.assertFalse(self.exports.exists())
        with self.assertRaisesRegex(CaseError, "No redacted recovery directory"):
            self.preview("a" * 32)
        self.assertFalse(self.exports.exists())

    def test_journal_only_recovers_immediately_after_lock_is_acquired(self):
        work, journal, temporary = self.interrupted(1)
        before = self.preview(work)
        self.assertEqual(before["minimum_age_seconds"], 0)
        self.assertEqual(before["scratch_files_to_remove"], 0)
        self.assertEqual(before["disposition"], "INTERRUPTED")
        self.assertTrue(journal.exists())
        self.assertFalse(temporary.exists())
        result = self.confirm(work, before)
        self.assertEqual(result["status"], "INTERRUPTED_SCRATCH_CLEARED")
        self.assertEqual(result["removed_unpublished_files"], 0)
        self.assertFalse(journal.exists())
        self.assertFalse(self.final.exists())
        self.assert_original_preserved()

    def test_partial_scratch_exact_prefix_is_recoverable(self):
        work, journal, temporary = self.interrupted()
        temporary.write_bytes(temporary.read_bytes()[:317])
        before = self.preview(work)
        self.assertEqual(before["scratch_bytes"], 317)
        self.assertTrue(temporary.exists())
        result = self.confirm(work, before)
        self.assertEqual(result["removed_unpublished_files"], 1)
        self.assertFalse(temporary.exists())
        self.assertFalse(journal.exists())
        self.assertFalse(self.final.exists())
        self.assert_original_preserved()

    def test_empty_scratch_is_a_valid_interrupted_write(self):
        work, journal, temporary = self.interrupted()
        temporary.write_bytes(b"")
        plan = self.preview(work)
        self.assertEqual(plan["scratch_bytes"], 0)
        self.assertEqual(plan["scratch_files_to_remove"], 1)
        self.confirm(work, plan)
        self.assertFalse(temporary.exists())
        self.assertFalse(journal.exists())

    def test_complete_unpublished_scratch_is_never_promoted_by_recovery(self):
        work, journal, temporary = self.interrupted()
        before = self.preview(work)
        with self.assertRaises(CaseError):
            recovery.recover(self.store, self.case, work, confirm=True)
        self.assertTrue(temporary.exists())
        self.assertTrue(journal.exists())
        complete = self.confirm(work, before)
        self.assertEqual(complete["committed_packages_removed"], 0)
        self.assertEqual(complete["registered_originals_removed"], 0)
        self.assertFalse(self.final.exists())
        retried = export.review_redacted_export(
            self.store, self.case, prepare=True,
            preview_sha256=self.plan["review_fingerprint_sha256"])
        self.assertEqual(retried["package_name"], self.final.name)
        self.assert_original_preserved()

    def test_after_link_retires_only_scratch_link_and_journal(self):
        work, journal, temporary = self.interrupted(3)
        original_inode = self.final.stat().st_ino
        final_bytes = self.final.read_bytes()
        self.assertEqual(self.final.stat().st_nlink, 2)
        before = self.preview(work)
        self.assertEqual(before["disposition"], "COMMITTED")
        result = self.confirm(work, before)
        self.assertEqual(result["status"], "COMMITTED_JOURNAL_CLEARED")
        self.assertFalse(journal.exists())
        self.assertFalse(temporary.exists())
        self.assertEqual(self.final.stat().st_ino, original_inode)
        self.assertEqual(self.final.stat().st_nlink, 1)
        self.assertEqual(self.final.read_bytes(), final_bytes)
        self.assertFalse(result["public_disclosure_approved"])
        self.assert_original_preserved()

    def test_final_with_only_journal_retains_final_bytes_and_inode(self):
        work, journal, temporary = self.interrupted(4)
        before = self.preview(work)
        final_identity = (self.final.stat().st_ino, self.final.read_bytes())
        self.assertFalse(temporary.exists())
        self.confirm(work, before)
        self.assertFalse(journal.exists())
        self.assertEqual((self.final.stat().st_ino, self.final.read_bytes()), final_identity)
        with self.assertRaisesRegex(CaseError, "already exists"):
            export.review_redacted_export(
                self.store, self.case, prepare=True,
                preview_sha256=self.plan["review_fingerprint_sha256"])

    def test_keyboard_interrupt_keeps_provenance_and_originals(self):
        real_sync = export._sync_directory
        count = 0

        def cancel(folder):
            nonlocal count
            real_sync(folder)
            if Path(folder) == self.exports:
                count += 1
                if count == 2:
                    raise KeyboardInterrupt

        with patch.object(export, "_sync_directory", side_effect=cancel):
            with self.assertRaises(KeyboardInterrupt):
                export.review_redacted_export(self.store, self.case, prepare=True,
                    preview_sha256=self.plan["review_fingerprint_sha256"])
        work = recovery.list_interrupted(self.store, self.case)["redacted_export_work_ids"][0]
        self.confirm(work, self.preview(work))
        self.assert_original_preserved()

    def test_zero_minimum_age_does_not_add_an_implicit_clock_order_requirement(self):
        work,journal,temporary=self.interrupted(3)
        preview=self.preview(work,now_ns=0)
        with self.assertRaisesRegex(CaseError,'too recent'):
            self.preview(work,now_ns=0,minimum_age_seconds=1)
        self.confirm(work,preview,now_ns=0)
        self.assert_original_preserved()

    def test_recovery_interruption_requires_a_new_fingerprint(self):
        work, journal, temporary = self.interrupted(3)
        first = self.preview(work)
        with patch.object(recovery, "_sync_directory", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                self.confirm(work, first)
        self.assertFalse(temporary.exists())
        self.assertTrue(journal.exists())
        self.assertTrue(self.final.exists())
        next_plan = self.preview(work)
        self.assertNotEqual(first["recovery_plan_sha256"], next_plan["recovery_plan_sha256"])
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(work, first)
        self.confirm(work, next_plan)
        self.assert_original_preserved()

    def test_journal_unlink_failure_retains_committed_final_and_journal(self):
        work, journal, temporary = self.interrupted(3)
        before = self.preview(work)
        original_unlink = os.unlink

        def fail_journal(path, *args, **kwargs):
            if str(path) == journal.name:
                raise OSError("synthetic journal unlink failure")
            return original_unlink(path, *args, **kwargs)

        with patch.object(recovery.os, "unlink", side_effect=fail_journal):
            with self.assertRaises(OSError):
                self.confirm(work, before)
        self.assertTrue(journal.exists())
        self.assertTrue(self.final.exists())
        self.assertFalse(temporary.exists())
        self.confirm(work, self.preview(work))
        self.assert_original_preserved()

    def test_final_mutation_during_cleanup_keeps_journal(self):
        work, journal, temporary = self.interrupted(3)
        plan = self.preview(work)
        real_sync = recovery._sync_directory

        def mutate(folder):
            self.final.write_bytes(b"unexpected changed final")
            real_sync(folder)

        with patch.object(recovery, "_sync_directory", side_effect=mutate):
            with self.assertRaises(CaseError):
                self.confirm(work, plan)
        self.assertTrue(journal.exists())
        self.assertTrue(self.final.exists())
        self.assertFalse(temporary.exists())
        self.assert_original_preserved()

    def test_unrelated_inventory_mutation_during_cleanup_keeps_journal(self):
        work, journal, _ = self.interrupted()
        plan = self.preview(work)
        real_sync = recovery._sync_directory

        def add_surprise(folder):
            unexpected = self.exports / "unexpected.log"
            unexpected.write_bytes(b"untrusted")
            unexpected.chmod(0o600)
            real_sync(folder)

        with patch.object(recovery, "_sync_directory", side_effect=add_surprise):
            with self.assertRaisesRegex(CaseError, "Unexpected"):
                self.confirm(work, plan)
        self.assertTrue(journal.exists())
        self.assert_original_preserved()

    def test_valid_partial_change_invalidates_old_preview_without_deletion(self):
        work, journal, temporary = self.interrupted()
        first = self.preview(work)
        temporary.write_bytes(temporary.read_bytes()[:20])
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(work, first)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())
        self.confirm(work, self.preview(work))

    def test_identical_bytes_replaced_inode_invalidates_old_preview(self):
        work, journal, temporary = self.interrupted()
        plan = self.preview(work)
        replacement = self.home / "replacement"
        replacement.write_bytes(temporary.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(temporary)
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(work, plan)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())

    def test_unrelated_valid_final_change_invalidates_full_inventory_preview(self):
        work, journal, temporary = self.interrupted()
        plan = self.preview(work)
        unrelated = self.exports / ("redacted-" + "0" * 24 + ".zip")
        unrelated.write_bytes(temporary.read_bytes())
        unrelated.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(work, plan)
        self.assertTrue(journal.exists())
        self.assertTrue(unrelated.exists())

    def test_modified_original_blocks_recovery_and_preserves_all_outputs(self):
        work, journal, temporary = self.interrupted()
        self.original.write_bytes(b"X" * len(self.raw))
        with self.assertRaises(CaseError):
            self.preview(work)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())

    def test_changed_registered_source_plan_is_not_implicitly_rebound(self):
        work, journal, temporary = self.interrupted()
        extra = self.store.inbox / "additional.log"
        extra.write_bytes(b"additional registered synthetic evidence")
        extra.chmod(0o600)
        self.store.register(self.case, extra.name)
        with self.assertRaisesRegex(CaseError, "source plan changed"):
            self.preview(work)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())
        self.assert_original_preserved()

    def test_changed_preservation_head_blocks_old_source_plan(self):
        work, journal, temporary = self.interrupted()
        hold = {"action": "PRESERVATION_HOLD", "reason_code": "investigation",
                "reference_sha256": hashlib.sha256(self.raw).hexdigest()}
        proposed = propose_or_record(self.store, self.case, **hold)
        propose_or_record(self.store, self.case, **hold, confirm=True,
                          plan_sha256=proposed["plan_sha256"])
        with self.assertRaisesRegex(CaseError, "source plan changed"):
            self.preview(work)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())

    def test_wrong_case_cannot_recover_another_case_journal(self):
        work, journal, temporary = self.interrupted()
        other = self.store.open_case()["case_id"]
        self.assertEqual(recovery.list_interrupted(self.store, other)["redacted_export_work_ids"], [])
        with self.assertRaisesRegex(CaseError, "no matching source case"):
            recovery.recover(self.store, other, work)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())

    def test_legacy_journal_is_discoverable_only_as_manual_review(self):
        work, journal, temporary = self.interrupted()
        doc = json.loads(journal.read_bytes())
        for field in ("case_id", "source_snapshot_sha256", "package_size_bytes"):
            del doc[field]
        doc["schema"] = 1
        journal.write_bytes(_canonical(doc))
        listed = recovery.list_interrupted(self.store, self.case)
        self.assertEqual(listed["status"], "PARTIAL")
        self.assertEqual(listed["redacted_export_work_ids"], [])
        self.assertEqual(listed["legacy_journals"], 1)
        with self.assertRaisesRegex(CaseError, "manual review"):
            self.preview(work)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())

    def test_malformed_truncated_and_noncanonical_journals_stay_untouched(self):
        work, journal, temporary = self.interrupted()
        valid = journal.read_bytes()
        for raw in (b"", valid[:31], valid + b" ", b"{bad",
                    valid.replace(b'"schema":2', b'"schema":2,"schema":2')):
            with self.subTest(raw_length=len(raw)):
                journal.write_bytes(raw)
                listed = recovery.list_interrupted(self.store, self.case)
                self.assertEqual(listed["status"], "PARTIAL")
                self.assertEqual(listed["malformed_journals"], 1)
                with self.assertRaises(CaseError):
                    self.preview(work)
                self.assertEqual(journal.read_bytes(), raw)
                self.assertTrue(temporary.exists())

    def test_tampered_journal_paths_hashes_schema_and_sizes_are_refused(self):
        work, journal, temporary = self.interrupted()
        original = json.loads(journal.read_bytes())
        cases = {"tmp_name": "../originals/source", "package_name": "outside.zip",
                 "transaction_id": "b" * 32, "source_snapshot_sha256": "z" * 64,
                 "case_id": "../escape", "package_sha256": "bad",
                 "schema": True, "package_size_bytes": True}
        for field, value in cases.items():
            with self.subTest(field=field):
                journal.write_bytes(_canonical({**original, field: value}))
                with self.assertRaises(CaseError):
                    self.preview(work)
                self.assertTrue(journal.exists())
                self.assertTrue(temporary.exists())
        journal.write_bytes(_canonical({**original, "source_snapshot_sha256": "a" * 64}))
        with self.assertRaisesRegex(CaseError, "source plan changed"):
            self.preview(work)

    def test_orphan_scratch_and_unknown_sidecar_are_not_swept(self):
        work, journal, temporary = self.interrupted()
        orphan = self.exports / (".tmp-review-" + "b" * 32)
        orphan.write_bytes(b"private unknown scratch")
        orphan.chmod(0o600)
        listed = recovery.list_interrupted(self.store, self.case)
        self.assertEqual(listed["orphan_scratch_files"], 1)
        with self.assertRaisesRegex(CaseError, "manual review"):
            self.preview(work)
        orphan.unlink()
        sidecar = self.exports / (temporary.name + ".extra")
        sidecar.write_bytes(b"unknown sidecar")
        sidecar.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "Unexpected"):
            self.preview(work)
        self.assertTrue(journal.exists())
        self.assertTrue(sidecar.exists())
        self.assertTrue(temporary.exists())

    def test_corrupt_scratch_cannot_be_approved_as_ordinary_crash_prefix(self):
        work, journal, temporary = self.interrupted()
        temporary.write_bytes(b"CUSTOMER_SECRETS_MUST_NOT_BE_RETURNED")
        with self.assertRaisesRegex(CaseError, "exact package prefix"):
            self.preview(work)
        self.assertTrue(temporary.exists())
        self.assertTrue(journal.exists())

    def test_corrupt_committed_zip_is_preserved_for_manual_review(self):
        work, journal, _ = self.interrupted(4)
        self.final.write_bytes(self.final.read_bytes() + b"appended-untrusted-data")
        with self.assertRaisesRegex(CaseError, "committed package bytes invalid"):
            self.preview(work)
        self.assertTrue(self.final.exists())
        self.assertTrue(journal.exists())

    def test_separate_same_byte_scratch_and_final_are_ambiguous(self):
        work, journal, temporary = self.interrupted()
        self.final.write_bytes(temporary.read_bytes())
        self.final.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "scratch and final identity disagree"):
            self.preview(work)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())
        self.assertTrue(self.final.exists())

    def test_unexplained_scratch_hardlink_and_third_published_link_refused(self):
        work, journal, temporary = self.interrupted()
        alias = self.home / "outside-link"
        os.link(temporary, alias)
        with self.assertRaisesRegex(CaseError, "unexplained hardlink"):
            self.preview(work)
        os.link(temporary, self.final)
        with self.assertRaises(CaseError):
            self.preview(work)
        self.assertTrue(alias.exists())
        self.assertTrue(journal.exists())
        self.assert_original_preserved()

    def test_symlinked_scratch_and_output_directory_refused(self):
        work, journal, temporary = self.interrupted()
        original_scratch = self.home / "original-scratch"
        temporary.rename(original_scratch)
        temporary.symlink_to(original_scratch)
        with self.assertRaises(CaseError):
            self.preview(work)
        self.assertTrue(journal.exists())
        temporary.unlink()
        original_scratch.rename(temporary)
        moved = self.store.base / "moved-exports"
        self.exports.rename(moved)
        self.exports.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(CaseError):
            self.preview(work)
        self.assertTrue((moved / journal.name).exists())
        self.assert_original_preserved()

    def test_public_file_modes_and_nonregular_journal_are_refused(self):
        work, journal, temporary = self.interrupted()
        temporary.chmod(0o640)
        with self.assertRaises(CaseError):
            self.preview(work)
        temporary.chmod(0o600)
        journal.unlink()
        journal.mkdir(mode=0o700)
        with self.assertRaises(CaseError):
            self.preview(work)
        self.assertTrue(journal.is_dir())
        self.assertTrue(temporary.exists())

    def test_size_limits_apply_before_unbounded_read(self):
        work, journal, temporary = self.interrupted()
        temporary.write_bytes(b"X" * (export.MAX_PACKAGE + 1))
        with self.assertRaisesRegex(CaseError, "bounded size"):
            self.preview(work)
        temporary.write_bytes(b"")
        journal.write_bytes(b"X" * (export.MAX_JOURNAL + 1))
        with self.assertRaisesRegex(CaseError, "bounded size"):
            recovery.list_interrupted(self.store, self.case)
        self.assertTrue(journal.exists())

    def test_inventory_stops_before_reading_files_over_bound(self):
        self.exports.mkdir(mode=0o700)
        for number in range(export.MAX_ENTRIES + 1):
            path = self.exports / ("redacted-" + f"{number:024x}" + ".zip")
            path.write_bytes(b"x")
            path.chmod(0o600)
        with patch.object(recovery, "_hashed", side_effect=AssertionError("must not read")):
            with self.assertRaisesRegex(CaseError, "inventory is over limit"):
                recovery.list_interrupted(self.store, self.case)

    def test_publisher_reserves_inventory_room_for_journal_scratch_and_final(self):
        self.exports.mkdir(mode=0o700)
        for number in range(export.MAX_ENTRIES - 2):
            path = self.exports / ("redacted-" + f"{number:024x}" + ".zip")
            path.write_bytes(b"x")
            path.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "publication reserve"):
            export.review_redacted_export(self.store, self.case, prepare=True,
                preview_sha256=self.plan["review_fingerprint_sha256"])
        self.assertFalse(any(item.name.startswith(".") for item in self.exports.iterdir()))
        self.assert_original_preserved()

    def test_optional_age_is_checked_and_bound_to_recovery_plan(self):
        work, journal, temporary = self.interrupted()
        with self.assertRaisesRegex(CaseError, "too recent"):
            self.preview(work, minimum_age_seconds=3600)
        future = time.time_ns() + 7200 * 1_000_000_000
        zero = self.preview(work, now_ns=future)
        one = self.preview(work, minimum_age_seconds=1, now_ns=future)
        self.assertNotEqual(zero["recovery_plan_sha256"], one["recovery_plan_sha256"])
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(work, zero, minimum_age_seconds=1, now_ns=future)
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())

    def test_invalid_confirmation_work_age_and_clock_inputs_fail_closed(self):
        work, journal, temporary = self.interrupted()
        kwargs_cases = [
            {"confirm": True}, {"confirm": 1}, {"recovery_plan_sha256": "0" * 64},
            {"confirm": True, "recovery_plan_sha256": "z" * 64},
            {"minimum_age_seconds": True}, {"minimum_age_seconds": -1},
            {"minimum_age_seconds": recovery.MAX_MINIMUM_AGE_SECONDS + 1},
            {"now_ns": True}, {"now_ns": -1},
        ]
        for kwargs in kwargs_cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(CaseError):
                    self.preview(work, **kwargs)
        with self.assertRaises(CaseError):
            self.preview("../escape")
        with self.assertRaises(CaseError):
            recovery.list_interrupted(self.store, "bad")
        self.assertTrue(journal.exists())
        self.assertTrue(temporary.exists())

    def test_recovery_responses_do_not_disclose_source_ids_names_hashes_or_text(self):
        work, _, _ = self.interrupted()
        listed = recovery.list_interrupted(self.store, self.case)
        plan = self.preview(work)
        complete = self.confirm(work, plan)
        response = json.dumps([listed, plan, complete], sort_keys=True).encode()
        for private in (self.raw, self.case.encode(), self.original.name.encode(),
                        hashlib.sha256(self.raw).hexdigest().encode(),
                        b"customer-private-source.log", b"PRIVATE_ONLY", str(self.home).encode()):
            self.assertNotIn(private, response)
        self.assertFalse(complete["public_disclosure_approved"])
        self.assertFalse(complete["network_upload_performed"])

    @unittest.skipUnless(os.geteuid() == 0, "root-only refusal regression")
    def test_cli_refuses_root(self):
        command = [sys.executable, str(ROOT / "scripts/redacted_export_recovery_cli.py"),
                   "--case-id", self.case, "--list"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"refuses root", result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "real non-root CLI is exercised by hosted CI")
    def test_cli_preview_confirm_and_deny_generic_paths_or_disclosure(self):
        work, journal, _ = self.interrupted()
        def call(*args):
            return subprocess.run(
                [sys.executable, str(ROOT / "scripts/redacted_export_recovery_cli.py"),
                 "--case-id", self.case, *args], env={**os.environ, "HOME": str(self.home)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        listed = call("--list")
        self.assertEqual(listed.returncode, 0)
        self.assertEqual(json.loads(listed.stdout)["redacted_export_work_ids"], [work])
        preview = call("--work-id", work)
        self.assertEqual(preview.returncode, 0)
        plan = json.loads(preview.stdout)
        for args in [("--list", "--confirm"), ("--work-id", work, "--confirm"),
                     ("--work-id", work, "--delete"), ("--work-id", work, "--transmit"),
                     ("--work-id", work, "--dest", "/tmp/public"),
                     ("--work-id", work, "--minimum-age-seconds", "-1")]:
            self.assertEqual(call(*args).returncode, 2, args)
        complete = call("--work-id", work, "--confirm", "--recovery-plan-sha256",
                        plan["recovery_plan_sha256"])
        self.assertEqual(complete.returncode, 0)
        self.assertFalse(journal.exists())
        self.assert_original_preserved()


class RedactedExportProcessTests(unittest.TestCase):
    """Real kernel signals using the unchanged API; no identity/refusal bypass."""
    def test_real_publisher_kill_and_cancel_at_all_durable_boundaries(self):
        for phase in PHASES:
            with self.subTest(phase=phase):
                with tempfile.TemporaryDirectory(prefix="export-sigkill-unit-") as name:
                    home = Path(name)
                    store, case, original, raw = _fixture(home)
                    before = export.review_redacted_export(store, case)
                    killed = subprocess.run(
                        [sys.executable, "-c", PUBLICATION_CHILD, str(ROOT), str(home), case, phase],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=20, check=False)
                    expected = -signal.SIGTERM if phase == "cancelled" else -signal.SIGKILL
                    self.assertEqual(killed.returncode, expected, killed.stderr.decode())
                    listed = recovery.list_interrupted(store, case)
                    work_ids = listed["redacted_export_work_ids"]
                    if phase == "retired_journal":
                        self.assertEqual(work_ids, [])
                    else:
                        self.assertEqual(len(work_ids), 1)
                        work = work_ids[0]
                        plan = recovery.recover(store, case, work)
                        result = recovery.recover(store, case, work, confirm=True,
                            recovery_plan_sha256=plan["recovery_plan_sha256"])
                        self.assertEqual(result["committed_packages_removed"], 0)
                        self.assertEqual(result["registered_originals_removed"], 0)
                    final = store.base / export.OUT_DIR / (
                        "redacted-" + before["review_fingerprint_sha256"][:24] + ".zip")
                    committed = phase in ("linked", "retired_scratch", "retired_journal")
                    self.assertEqual(final.exists(), committed)
                    if committed:
                        self.assertEqual(hashlib.sha256(final.read_bytes()).hexdigest(),
                                         before["package_sha256"])
                    self.assertEqual(original.read_bytes(), raw)

    def test_real_recoverer_kill_rejects_old_plan_and_retires_only_journal(self):
        with tempfile.TemporaryDirectory(prefix="recoverer-sigkill-unit-") as name:
            home = Path(name)
            store, case, original, raw = _fixture(home)
            killed = subprocess.run(
                [sys.executable, "-c", PUBLICATION_CHILD, str(ROOT), str(home), case, "linked"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
            self.assertEqual(killed.returncode, -signal.SIGKILL)
            work = recovery.list_interrupted(store, case)["redacted_export_work_ids"][0]
            first = recovery.recover(store, case, work)
            killed = subprocess.run(
                [sys.executable, "-c", RECOVERY_CHILD, str(ROOT), str(home), case, work,
                 first["recovery_plan_sha256"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False)
            self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr.decode())
            fresh = recovery.recover(store, case, work)
            self.assertEqual(fresh["scratch_files_to_remove"], 0)
            with self.assertRaisesRegex(CaseError, "plan changed"):
                recovery.recover(store, case, work, confirm=True,
                                  recovery_plan_sha256=first["recovery_plan_sha256"])
            recovery.recover(store, case, work, confirm=True,
                             recovery_plan_sha256=fresh["recovery_plan_sha256"])
            self.assertEqual(original.read_bytes(), raw)

    def test_common_lock_excludes_live_publisher_then_allows_immediate_recovery(self):
        with tempfile.TemporaryDirectory(prefix="export-lock-unit-") as name:
            home = Path(name)
            store, case, original, raw = _fixture(home)
            writer = subprocess.Popen(
                [sys.executable, "-u", "-c", PUBLICATION_CHILD, str(ROOT), str(home), case,
                 "wait_for_kill"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            cleaner = None
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(writer.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(10), "publisher did not reach durable scratch")
                self.assertEqual(writer.stdout.readline(), b"READY\n")
                journal = next((store.base / export.OUT_DIR).glob(".review-work-*.json"))
                work = json.loads(journal.read_bytes())["transaction_id"]
                preview_child = (
                    "import json,sys\nfrom pathlib import Path\n"
                    "sys.path.insert(0,sys.argv[1])\nfrom casework import CaseStore\n"
                    "from redacted_export_recovery import recover\n"
                    "print('STARTED',flush=True)\n"
                    "print(json.dumps(recover(CaseStore(Path(sys.argv[2])),sys.argv[3],sys.argv[4])),flush=True)\n")
                cleaner = subprocess.Popen(
                    [sys.executable, "-u", "-c", preview_child, str(ROOT), str(home), case, work],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with selectors.DefaultSelector() as selector:
                    selector.register(cleaner.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(10), "recoverer did not start")
                self.assertEqual(cleaner.stdout.readline(), b"STARTED\n")
                time.sleep(0.1)
                self.assertIsNone(cleaner.poll(), "recovery bypassed a live publisher's lock")
                writer.kill()
                writer.communicate(timeout=10)
                self.assertEqual(writer.returncode, -signal.SIGKILL)
                response, error = cleaner.communicate(timeout=10)
                self.assertEqual(cleaner.returncode, 0, error.decode())
                preview = json.loads(response)
                self.assertEqual(preview["minimum_age_seconds"], 0)
                recovery.recover(store, case, work, confirm=True,
                    recovery_plan_sha256=preview["recovery_plan_sha256"])
                self.assertEqual(original.read_bytes(), raw)
            finally:
                for process in (writer, cleaner):
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
