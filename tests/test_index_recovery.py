"""SQLite crash-journal preservation, source identity, explicit recovery and denial."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import casework
from casework import CaseError, CaseStore
import index_recovery


class IndexCrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.home = Path(t.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.data = (b"2026-10-17T16:00:00Z ERROR synthetic password=dont-publish\n"
                     * 2200)
        source = self.store.inbox / "source.log"
        source.write_bytes(self.data)
        source.chmod(0o600)
        self.artifact = self.store.register(self.case, source.name)
        self.aid = self.artifact["artifact_id"]
        self.folder = self.store.cases / self.case
        self.indexes = self.folder / "indexes"
        self.work = "c" * 32
        self.temporary = self.indexes / (".tmp-" + self.work + ".sqlite3")
        self.journal = self.indexes / (".tmp-" + self.work + ".index.json")
        self.final = self.indexes / (self.aid + ".sqlite3")
        self.now = time.time_ns()
        self.old = self.now - 26 * 3600 * 1_000_000_000

    def fake_journal(self):
        casework._write_json_atomic(self.journal, {
            "version": 1, "case_id": self.case, "artifact_id": self.aid,
            "source_sha256": self.artifact["sha256"],
            "temp_name": self.temporary.name,
        })

    def age(self, *paths):
        for path in paths:
            os.utime(path, ns=(self.old, self.old))

    def preview(self):
        return index_recovery.recover(
            self.store, self.case, self.work, now_ns=self.now)

    def confirm(self, plan):
        return index_recovery.recover(
            self.store, self.case, self.work, now_ns=self.now, confirm=True,
            plan_sha256=plan["plan_sha256"])

    def test_normal_completed_index_has_no_journal_or_temporary_file(self):
        outcome = self.store.index_log(self.case, self.aid, worker=True)
        self.assertEqual(outcome["status"], "PASS")
        self.assertTrue(self.final.exists())
        self.assertEqual(list(self.indexes.iterdir()), [self.final])
        self.assertEqual(
            self.store.search_log(self.case, self.aid, "ERROR")["matches"][0]["line"], 1)

    def test_interrupted_private_database_requires_preview_and_explicit_confirmation(self):
        self.fake_journal()
        self.temporary.write_bytes(b"synthetic uncommitted SQLite bytes")
        self.temporary.chmod(0o600)
        self.age(self.journal, self.temporary)
        before = self.store.cases / self.case / "originals" / self.aid
        plan = self.preview()
        self.assertEqual(plan["status"], "PREVIEW_ONLY")
        self.assertEqual(plan["disposition"], "INTERRUPTED")
        self.assertEqual(plan["source_sha256"], self.artifact["sha256"])
        self.assertTrue(self.temporary.exists())
        self.assertTrue(self.journal.exists())
        with self.assertRaisesRegex(CaseError, "preview SHA-256"):
            index_recovery.recover(
                self.store, self.case, self.work, now_ns=self.now, confirm=True)
        done = self.confirm(plan)
        self.assertEqual(done["status"], "INTERRUPTED_TEMP_CLEARED")
        self.assertEqual(done["registered_originals_removed"], 0)
        self.assertFalse(self.temporary.exists())
        self.assertFalse(self.journal.exists())
        self.assertEqual(before.read_bytes(), self.data)
        self.assertEqual(self.store.index_log(self.case, self.aid, worker=True)["status"], "PASS")

    def test_recent_index_is_not_eligible(self):
        self.fake_journal()
        self.temporary.write_bytes(b"in progress")
        self.temporary.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "too recent"):
            self.preview()
        self.assertTrue(self.journal.exists())

    def test_changed_content_or_identity_invalidates_prior_plan(self):
        self.fake_journal()
        self.temporary.write_bytes(b"unfinished")
        self.temporary.chmod(0o600)
        self.age(self.journal, self.temporary)
        plan = self.preview()
        self.temporary.write_bytes(b"different unfinished")
        self.age(self.temporary)
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(plan)
        self.assertTrue(self.temporary.exists())
        self.assertTrue(self.journal.exists())

    def test_incorrect_source_identity_blocks_cleanup(self):
        self.fake_journal()
        before = json.loads(self.journal.read_text())
        before["source_sha256"] = "f" * 64
        casework._write_json_atomic(self.journal, before)
        self.age(self.journal)
        with self.assertRaisesRegex(CaseError, "matching original"):
            self.preview()
        self.assertTrue(self.journal.exists())

    def test_temp_symlink_and_hardlink_are_not_deleted(self):
        self.fake_journal()
        external = self.home / "keep"
        external.write_bytes(b"unrelated user evidence")
        self.temporary.symlink_to(external)
        self.age(self.journal)
        with self.assertRaises(CaseError):
            self.preview()
        self.assertEqual(external.read_bytes(), b"unrelated user evidence")
        self.temporary.unlink()
        self.temporary.write_bytes(b"regular but hardlinked")
        self.temporary.chmod(0o600)
        alias = self.home / "same-inode"
        os.link(self.temporary, alias)
        self.age(self.journal, self.temporary)
        with self.assertRaises(CaseError):
            self.preview()
        self.assertTrue(alias.exists())

    def test_unknown_sqlite_sidecar_refuses(self):
        self.fake_journal()
        self.temporary.write_bytes(b"test")
        self.temporary.chmod(0o600)
        unexpected = self.indexes / (self.temporary.name + "-shm")
        unexpected.write_bytes(b"unexpected")
        unexpected.chmod(0o600)
        self.age(self.journal, self.temporary, unexpected)
        with self.assertRaisesRegex(CaseError, "Unrecognized"):
            self.preview()
        self.assertTrue(unexpected.exists())

    def test_valid_rollback_sidecar_recovery(self):
        self.fake_journal()
        self.temporary.write_bytes(b"partial db")
        self.temporary.chmod(0o600)
        sidecar = self.indexes / (self.temporary.name + "-journal")
        sidecar.write_bytes(b"synthetic rollback pages")
        sidecar.chmod(0o600)
        self.age(self.journal, self.temporary, sidecar)
        plan = self.preview()
        self.assertEqual(plan["scratch_bytes"], len(b"partial db") + len(b"synthetic rollback pages"))
        self.confirm(plan)
        self.assertFalse(self.journal.exists())
        self.assertFalse(self.temporary.exists())
        self.assertFalse(sidecar.exists())

    def test_post_rename_directory_sync_failure_preserves_published_index(self):
        original = index_recovery.sync_index_directory
        count = 0
        def intermittent(path):
            nonlocal count
            count += 1
            if count == 2:
                raise CaseError("Injected durable rename fsync failure")
            return original(path)
        with patch.object(index_recovery, "sync_index_directory", side_effect=intermittent):
            with self.assertRaisesRegex(CaseError, "durable rename"):
                self.store.index_log(self.case, self.aid, worker=True)
        self.assertTrue(self.final.exists())
        journals = list(self.indexes.glob(".tmp-*.index.json"))
        self.assertEqual(len(journals), 1)
        found = index_recovery.JOURNAL_NAME.fullmatch(journals[0].name)
        self.assertIsNotNone(found)
        self.work = found.group(1)
        self.journal = journals[0]
        self.temporary = self.indexes / (".tmp-" + self.work + ".sqlite3")
        self.assertFalse(self.temporary.exists())
        self.age(self.journal, self.final)
        plan = self.preview()
        self.assertEqual(plan["disposition"], "COMMITTED")
        done = self.confirm(plan)
        self.assertEqual(done["status"], "COMMITTED_JOURNAL_CLEARED")
        self.assertTrue(self.final.exists())
        self.assertEqual(self.store.search_log(self.case, self.aid, "ERROR")["matches"][0]["line"], 1)

    def test_rename_committed_then_reported_error_retains_journal_and_index(self):
        actual_replace = os.replace
        def ambiguous(src, dst):
            actual_replace(src, dst)
            if Path(dst) == self.final:
                raise OSError("synthetic after-rename report failure")
        with patch.object(casework.os, "replace", side_effect=ambiguous):
            with self.assertRaisesRegex(OSError, "after-rename"):
                self.store.index_log(self.case, self.aid, worker=True)
        self.assertTrue(self.final.exists())
        journals = list(self.indexes.glob(".tmp-*.index.json"))
        self.assertEqual(len(journals), 1)
        found = index_recovery.JOURNAL_NAME.fullmatch(journals[0].name)
        self.assertIsNotNone(found)
        self.work = found.group(1)
        self.journal = journals[0]
        self.temporary = self.indexes / (".tmp-" + self.work + ".sqlite3")
        self.age(self.journal, self.final)
        outcome = self.preview()
        self.assertEqual(outcome["disposition"], "COMMITTED")
        recovered = self.confirm(outcome)
        self.assertEqual(recovered["status"], "COMMITTED_JOURNAL_CLEARED")
        self.assertTrue(self.final.is_file())
        self.assertEqual((self.folder / "originals" / self.aid).read_bytes(), self.data)

    def test_cleanup_can_resume_after_sidecar_removed_but_temp_unlink_fails(self):
        self.fake_journal()
        self.temporary.write_bytes(b"unfinished database")
        self.temporary.chmod(0o600)
        sidecar = self.indexes / (self.temporary.name + "-journal")
        sidecar.write_bytes(b"rollback pages")
        sidecar.chmod(0o600)
        self.age(self.journal, self.temporary, sidecar)
        original_unlink = Path.unlink
        def interrupt(path, *args, **kwargs):
            if path == self.temporary:
                raise OSError("synthetic cleanup interrupted")
            return original_unlink(path, *args, **kwargs)
        before = self.preview()
        with patch.object(Path, "unlink", autospec=True, side_effect=interrupt):
            with self.assertRaisesRegex(OSError, "cleanup interrupted"):
                self.confirm(before)
        self.assertFalse(sidecar.exists())
        self.assertTrue(self.temporary.exists())
        self.assertTrue(self.journal.exists())
        # Retained scratch identities have changed; a new inspected plan is
        # required. The original plan cannot authorize a second deletion.
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(before)
        fresh = self.preview()
        self.assertEqual(self.confirm(fresh)["status"], "INTERRUPTED_TEMP_CLEARED")
        self.assertFalse(self.temporary.exists())
        self.assertFalse(self.journal.exists())
        self.assertEqual((self.folder / "originals" / self.aid).read_bytes(), self.data)

    def test_failure_after_journal_removal_never_deletes_committed_index(self):
        original = index_recovery.sync_index_directory
        calls = 0
        def fail_after_commit(path):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise CaseError("synthetic post-journal directory sync failure")
            return original(path)
        with patch.object(index_recovery, "sync_index_directory",
                          side_effect=fail_after_commit):
            with self.assertRaisesRegex(CaseError, "post-journal"):
                self.store.index_log(self.case, self.aid, worker=True)
        self.assertTrue(self.final.is_file())
        self.assertFalse(list(self.indexes.glob(".tmp-*.index.json")))
        self.assertEqual(self.store.search_log(
            self.case, self.aid, "ERROR")["matches"][0]["line"], 1)
        self.assertEqual((self.folder / "originals" / self.aid).read_bytes(), self.data)

    def test_list_only_reports_exact_journal_names(self):
        self.fake_journal()
        unknown = self.indexes / ".tmp-unknown.sqlite3"
        unknown.write_text("leave untouched")
        unknown.chmod(0o600)
        listing = index_recovery.list_interrupted(self.store, self.case)
        self.assertEqual(listing["index_work_ids"], [self.work])
        self.assertEqual(listing["unmatched_temp_entries"], 1)
        self.assertEqual(listing["status"], "PARTIAL")
        self.assertTrue(unknown.exists())

    def test_preview_rejects_incorrect_or_missing_confirmation(self):
        self.fake_journal()
        self.age(self.journal)
        plan = self.preview()
        with self.assertRaisesRegex(CaseError, "plan changed"):
            index_recovery.recover(
                self.store, self.case, self.work, now_ns=self.now, confirm=True,
                plan_sha256="e" * 64)
        with self.assertRaisesRegex(CaseError, "cannot accept"):
            index_recovery.recover(
                self.store, self.case, self.work, now_ns=self.now,
                plan_sha256=plan["plan_sha256"])
        self.assertTrue(self.journal.exists())


if __name__ == "__main__":
    unittest.main()
