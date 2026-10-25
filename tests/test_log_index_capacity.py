"""Bounded SQLite log index capacity and source-preserving refusal tests."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import casework
from casework import CaseError, CaseStore, FREE_RESERVE
import resumable_transfer as resume

MIB = 1024 * 1024


class LogIndexCapacityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.store = CaseStore(self.home)
        self.case_id = self.store.open_case()["case_id"]
        self.data = (b"2026-10-17T11:12:13Z ERROR recovery failed password=test-secret\n" * 900)
        source = self.store.inbox / "capacity.log"
        source.write_bytes(self.data)
        source.chmod(0o600)
        self.artifact = self.store.register(self.case_id, source.name)
        self.aid = self.artifact["artifact_id"]
        self.index_path = self.store.cases / self.case_id / "indexes" / (self.aid + ".sqlite3")

    def index(self):
        return self.store.index_log(self.case_id, self.aid, worker=True)

    def test_refuse_when_reserved_headroom_cannot_fit_even_minimum_index(self):
        token = ".upload-" + "b" * 32
        pending = 3 * MIB
        resume.begin(self.store, token, pending, "a" * 64)
        fake_free = FREE_RESERVE + pending + casework.INDEX_SAFETY_MARGIN + 3 * casework.INDEX_PAGE_BYTES
        with patch.object(shutil, "disk_usage",
                          return_value=SimpleNamespace(free=fake_free)):
            with self.assertRaisesRegex(CaseError, "Insufficient safe capacity"):
                self.index()
        self.assertFalse(self.index_path.exists())
        self.assertEqual(list(self.index_path.parent.iterdir()), [])
        self.assertEqual(self.store.status(self.case_id)["artifact_count"], 1)

    def test_index_and_search_preserve_unfinished_other_upload_reservation(self):
        token = ".upload-" + "b" * 32
        pending = 8 * MIB
        resume.begin(self.store, token, pending, "a" * 64)
        report = self.index()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["lines_indexed"], 900)
        self.assertTrue(self.index_path.exists())
        self.assertEqual(self.index_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.search_log(
            self.case_id, self.aid, "ERROR")["matches"][0]["line"], 1)
        self.assertIn("[REDACTED]",
                      self.store.search_log(self.case_id, self.aid, "ERROR")["matches"][0]["excerpt"])
        self.assertTrue((self.store.inbox / token).exists())
        self.assertTrue((self.store.inbox / (token + ".session")).exists())

    def test_external_disk_pressure_between_batches_refuses_unpublished_index(self):
        calls = 0
        healthy = FREE_RESERVE + 512 * MIB
        low = FREE_RESERVE + casework.INDEX_SAFETY_MARGIN - 1
        def falling(_):
            nonlocal calls
            calls += 1
            return SimpleNamespace(free=healthy if calls < 4 else low)
        with patch.object(shutil, "disk_usage", side_effect=falling):
            with self.assertRaisesRegex(CaseError, "reserved storage"):
                self.index()
        self.assertGreaterEqual(calls, 4)
        self.assertFalse(self.index_path.exists())
        self.assertEqual(list(self.index_path.parent.iterdir()), [])
        with self.store._locked(self.case_id) as (folder, manifest):
            self.assertIn(self.aid, manifest["artifacts"])
            self.assertEqual((folder / "originals" / self.aid).read_bytes(), self.data)

    def test_sqlite_page_limit_aborts_without_publishing_truncated_index(self):
        # This should reach SQLite's own 4KiB page cap, not the periodic free
        # probe, and leave the registered original intact.
        source = self.store.inbox / "big-log.log"
        payload = b"2026-10-17T10:00:00Z ERROR " + b"X" * 90 + b"\n"
        original = payload * 7000
        source.write_bytes(original)
        source.chmod(0o600)
        art = self.store.register(self.case_id, source.name)
        storage = sum([len(self.data), len(original)])
        target = self.store.cases / self.case_id / "indexes" / (art["artifact_id"] + ".sqlite3")
        with patch.object(casework, "MAX_CASE_STORAGE", storage + 64 * 1024):
            with self.assertRaisesRegex(CaseError, "capacity|quota|SQLite"):
                self.store.index_log(self.case_id, art["artifact_id"], worker=True)
        self.assertFalse(target.exists())
        self.assertEqual(list(target.parent.iterdir()), [])
        with self.store._locked(self.case_id) as (folder, manifest):
            self.assertEqual((folder / "originals" / art["artifact_id"]).read_bytes(), original)

    def test_oversized_skipped_lines_still_count_toward_worker_line_limit(self):
        source = self.store.inbox / "huge-lines.log"
        data = (b"X" * (casework.MAX_LINE + 3) + b"\n") * 2
        source.write_bytes(data)
        source.chmod(0o600)
        art = self.store.register(self.case_id, source.name)
        target = self.store.cases / self.case_id / "indexes" / (art["artifact_id"] + ".sqlite3")
        with patch.object(casework, "MAX_WORKER_LINES", 1):
            with self.assertRaisesRegex(CaseError, "Line count exceeds"):
                self.store.index_log(self.case_id, art["artifact_id"], worker=True)
        self.assertFalse(target.exists())
        self.assertEqual((self.store.cases / self.case_id / "originals" /
                          art["artifact_id"]).read_bytes(), data)

    def test_untrusted_preexisting_index_file_blocks_index_admission(self):
        outside = self.home / "preserve-owner-data"
        outside.write_bytes(b"never change this")
        name = self.index_path.parent / ".tmp-hijacked.sqlite3"
        name.symlink_to(outside)
        with self.assertRaisesRegex(CaseError, "Unsafe pre-existing index"):
            self.index()
        self.assertEqual(outside.read_bytes(), b"never change this")
        self.assertFalse(self.index_path.exists())


if __name__ == "__main__":
    unittest.main()
