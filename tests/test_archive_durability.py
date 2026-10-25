"""Linux directory-fsync and ambiguous archive persistence regression tests.

Synthetic fault injections prove order and safe failure handling. They do NOT
constitute evidence of an actual power-loss durability test on Rocky Linux.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

import archivework
from archive_recovery import list_workdirs, recover
from casework import CaseStore, CaseError

DAY_NS = 24 * 3600 * 1_000_000_000


class ArchiveDirectoryDurabilityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.store = CaseStore(self.home)
        self.case_id = self.store.open_case()["case_id"]
        inp = io.BytesIO()
        with zipfile.ZipFile(inp, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("evidence/one.log", b"synthetic sample one\n")
            archive.writestr("evidence/two.log", b"synthetic sample two\n")
        staged = self.store.inbox / "synthetic.zip"
        staged.write_bytes(inp.getvalue())
        staged.chmod(0o600)
        self.source = self.store.register(self.case_id, staged.name)
        self.folder = self.store.cases / self.case_id
        self.scratch = self.folder / "scratch"
        self.originals = self.folder / "originals"
        self.future = time.time_ns() + 96 * DAY_NS

    def unpack(self):
        return archivework.unpack_case_archive(
            self.store, self.case_id, self.source["artifact_id"])

    def work_ids(self):
        return list_workdirs(self.store, self.case_id)["work_ids"]

    def verify(self):
        return archivework.verify_case(self.store, self.case_id)

    def clear_recovery(self, disposition: str):
        ids = self.work_ids()
        self.assertEqual(len(ids), 1)
        plan = recover(self.store, self.case_id, ids[0], now_ns=self.future)
        self.assertEqual(plan["disposition"], disposition)
        result = recover(self.store, self.case_id, ids[0], now_ns=self.future,
                         confirm=True, plan_sha256=plan["plan_sha256"])
        self.assertEqual(result["removed_registered_originals"], 0)
        self.assertEqual(self.verify()["status"], "PASS")
        return result

    def test_success_orders_durable_journals_moves_and_manifest(self):
        events = []
        real_sync = archivework._sync_private_directory
        real_writer = archivework._write_json_atomic
        real_move = archivework.os.replace
        real_copy = archivework._copy_stream

        def sync(folder):
            events.append(("sync", Path(folder).name))
            return real_sync(folder)

        def writer(path, doc):
            if Path(path).name == "journal.json":
                events.append(("journal", doc["phase"]))
            if Path(path).name == "manifest.json":
                events.append(("manifest", "replace"))
            return real_writer(path, doc)

        def move(src, dst):
            if Path(src).parent.name.startswith("expand-") and Path(dst).parent.name == "originals":
                events.append(("move", Path(dst).name))
            return real_move(src, dst)

        def copy(*args, **kwargs):
            events.append(("copy", "data"))
            return real_copy(*args, **kwargs)

        with patch.object(archivework, "_sync_private_directory", side_effect=sync), \
             patch.object(archivework, "_write_json_atomic", side_effect=writer), \
             patch.object(archivework.os, "replace", side_effect=move), \
             patch.object(archivework, "_copy_stream", side_effect=copy):
            result = self.unpack()

        self.assertEqual(result["status"], "PASS")
        events = [(kind, ("WORKDIR" if value.startswith("expand-") else value))
                  for kind, value in events]
        staging_write = events.index(("journal", "STAGING"))
        copy_start = events.index(("copy", "data"))
        moving_write = events.index(("journal", "MOVING"))
        first_move = next(i for i, row in enumerate(events) if row[0] == "move")
        manifest_write = events.index(("manifest", "replace"))
        self.assertLess(staging_write, events.index(("sync", "WORKDIR")))
        self.assertLess(events.index(("sync", "scratch")), copy_start)
        self.assertLess(moving_write, first_move)
        self.assertIn(("sync", "WORKDIR"), events[moving_write:first_move])
        self.assertIn(("sync", "originals"), events[first_move:manifest_write])
        self.assertIn(("sync", "WORKDIR"), events[first_move:manifest_write])
        self.assertIn(("sync", self.case_id), events[manifest_write:])
        self.assertEqual(self.verify()["status"], "PASS")
        self.assertEqual(self.work_ids(), [])

    def test_initial_journal_directory_sync_failure_leaves_no_moved_bytes(self):
        with patch.object(archivework, "_sync_private_directory",
                          side_effect=OSError("synthetic initial journal fsync failure")):
            with self.assertRaisesRegex(OSError, "initial journal"):
                self.unpack()
        self.assertEqual(self.work_ids(), [])
        self.assertEqual(self.verify()["status"], "PASS")

    def test_moving_journal_sync_failure_cannot_promote_any_original(self):
        real = archivework._sync_private_directory
        workdir_calls = 0

        def fail_second(folder):
            nonlocal workdir_calls
            if Path(folder).name.startswith("expand-"):
                workdir_calls += 1
                if workdir_calls == 2:
                    raise OSError("synthetic MOVING journal sync failure")
            return real(folder)

        with patch.object(archivework, "_sync_private_directory", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "MOVING journal"):
                self.unpack()
        self.assertEqual(self.work_ids(), [])
        self.assertEqual(self.verify()["status"], "PASS")

    def test_move_directory_sync_error_rolls_back_before_manifest_commit(self):
        real = archivework._sync_private_directory
        rejected_once = False

        def reject_once(folder):
            nonlocal rejected_once
            if Path(folder) == self.originals and not rejected_once:
                rejected_once = True
                raise OSError("synthetic moved-original fsync failure")
            return real(folder)

        with patch.object(archivework, "_sync_private_directory", side_effect=reject_once):
            with self.assertRaisesRegex(OSError, "moved-original"):
                self.unpack()
        self.assertTrue(rejected_once)
        self.assertEqual(self.work_ids(), [])
        self.assertEqual(self.verify()["status"], "PASS")

    def test_failed_rollback_sync_keeps_source_bound_recovery_journal(self):
        real = archivework._sync_private_directory

        def deny_originals(folder):
            if Path(folder) == self.originals:
                raise OSError("synthetic rollback directory fsync failure")
            return real(folder)

        with patch.object(archivework, "_sync_private_directory", side_effect=deny_originals):
            with self.assertRaisesRegex(OSError, "rollback directory"):
                self.unpack()
        self.assertEqual(self.verify()["status"], "PARTIAL")
        self.assertEqual(len(self.work_ids()), 1)
        self.clear_recovery("INTERRUPTED")

    def test_post_manifest_directory_sync_error_preserves_committed_evidence(self):
        real = archivework._sync_private_directory

        def deny_manifest_folder(folder):
            if Path(folder) == self.folder:
                raise OSError("synthetic late manifest directory sync failure")
            return real(folder)

        with patch.object(archivework, "_sync_private_directory", side_effect=deny_manifest_folder):
            with self.assertRaisesRegex(OSError, "late manifest"):
                self.unpack()
        with self.store._locked(self.case_id) as (_, manifest):
            self.assertEqual(len(manifest["artifacts"]), 3)
        self.assertEqual(self.verify()["status"], "PARTIAL")
        self.clear_recovery("COMMITTED")


    def test_private_directory_sync_rejects_symlink_and_open_permissions(self):
        outside = self.home / "safe-directory"
        outside.mkdir(mode=0o700)
        marker = outside / "leave-alone"
        marker.write_bytes(b"synthetic original")
        alias = self.home / "symlink-target"
        alias.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((CaseError, OSError)):
            archivework._sync_private_directory(alias)
        self.assertEqual(marker.read_bytes(), b"synthetic original")
        loose = self.home / "loose-directory"
        loose.mkdir(mode=0o700)
        loose.chmod(0o755)
        with self.assertRaisesRegex(CaseError, "durability boundary is unsafe"):
            archivework._sync_private_directory(loose)

    def test_post_cleanup_scratch_sync_failure_does_not_erase_committed_vault(self):
        real = archivework._sync_private_directory
        scratch_syncs = 0

        def fail_final_scratch(folder):
            nonlocal scratch_syncs
            if Path(folder) == self.scratch:
                scratch_syncs += 1
                if scratch_syncs == 2:
                    raise OSError("synthetic post-cleanup directory fsync failure")
            return real(folder)

        with patch.object(archivework, "_sync_private_directory",
                          side_effect=fail_final_scratch):
            with self.assertRaisesRegex(OSError, "post-cleanup"):
                self.unpack()
        self.assertEqual(scratch_syncs, 2)
        with self.store._locked(self.case_id) as (_, manifest):
            self.assertEqual(len(manifest["artifacts"]), 3)
        # An ambiguous cleanup result must not invalidate a manifest whose
        # originals were already synced and registered.
        self.assertEqual(self.verify()["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
