"""Operator-confirmed retention cannot delete unrelated or active evidence."""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from casework import CaseError, CaseStore
import resumable_transfer as resume
from transfer_retention import inventory


class RetentionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.home = Path(scratch.name)
        self.store = CaseStore(self.home)
        self.token = ".upload-" + "a" * 32
        self.now = time.time_ns()
        self.payload = b"synthetic-only interrupted upload" * 17
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def make_session(self, token=None, *, aged=True, payload=None):
        tok = token or self.token
        data = self.payload if payload is None else payload
        resume.begin(self.store, tok, len(data) + 9, hashlib.sha256(data + b"remaining!").hexdigest())
        resume.append(self.store, tok, 0, io.BytesIO(data))
        source, meta = self.store.inbox / tok, self.store.inbox / (tok + ".session")
        if aged:
            old = self.now - (96 * 3600 * 1_000_000_000)
            os.utime(source, ns=(old, old))
            os.utime(meta, ns=(old, old))
        return source, meta

    def preview(self):
        return inventory(self.store, older_hours=72, now_ns=self.now)

    def approve(self, plan):
        return inventory(self.store, older_hours=72, now_ns=self.now,
                         confirm=True, expected_plan_sha256=plan["plan_sha256"])

    def test_preview_is_read_only_and_requires_exact_hash_confirmation(self):
        source, meta = self.make_session()
        plan = self.preview()
        self.assertEqual(plan["status"], "PREVIEW_ONLY")
        self.assertEqual(plan["eligible_sessions"], 1)
        self.assertEqual(plan["reclaimable_bytes"], len(self.payload))
        self.assertTrue(source.exists())
        self.assertTrue(meta.exists())
        with self.assertRaisesRegex(CaseError, "requires plan"):
            inventory(self.store, older_hours=72, confirm=True, now_ns=self.now)
        with self.assertRaisesRegex(CaseError, "inventory changed"):
            inventory(self.store, older_hours=72, now_ns=self.now,
                      confirm=True, expected_plan_sha256="f" * 64)
        self.assertTrue(source.exists())
        done = self.approve(plan)
        self.assertEqual(done["status"], "CONFIRMED_REMOVED")
        self.assertEqual(done["removed_sessions"], 1)
        self.assertEqual(done["reclaimed_bytes"], len(self.payload))
        self.assertFalse(source.exists())
        self.assertFalse(meta.exists())

    def test_preserve_recent_legacy_and_registered_case_evidence(self):
        old, meta = self.make_session()
        active = ".upload-" + "b" * 32
        new_source, _ = self.make_session(active, aged=False)
        legacy = self.store.inbox / (".upload-" + "c" * 32)
        legacy.write_bytes(b"legacy scp partial without session metadata")
        legacy.chmod(0o600)
        staged = self.store.inbox / "verified.log"
        staged.write_bytes(b"unrelated staged case original")
        staged.chmod(0o600)
        case = self.store.open_case()["case_id"]
        original = self.store.register(case, "verified.log")
        plan = self.preview()
        self.assertEqual(plan["tokens"], [self.token])
        self.approve(plan)
        self.assertFalse(old.exists())
        self.assertTrue(new_source.exists())
        self.assertEqual(legacy.read_bytes(), b"legacy scp partial without session metadata")
        with self.store._locked(case) as (folder, manifest):
            self.assertIn(original["artifact_id"], manifest["artifacts"])
            self.assertEqual((folder / "originals" / original["artifact_id"]).read_bytes(),
                             b"unrelated staged case original")

    def test_updated_session_invalidates_earlier_plan_without_any_removal(self):
        source, meta = self.make_session()
        plan = self.preview()
        source.write_bytes(self.payload + b"x")
        with self.assertRaisesRegex(CaseError, "inventory changed"):
            self.approve(plan)
        self.assertTrue(source.exists())
        self.assertTrue(meta.exists())

    def test_added_stale_session_invalidates_earlier_plan(self):
        original, _ = self.make_session()
        plan = self.preview()
        newcomer = ".upload-" + "d" * 32
        other, _ = self.make_session(newcomer)
        with self.assertRaisesRegex(CaseError, "inventory changed"):
            self.approve(plan)
        self.assertTrue(original.exists())
        self.assertTrue(other.exists())

    def test_active_writer_lock_blocks_preview_and_confirmation(self):
        source, _ = self.make_session()
        plan = self.preview()
        fd = os.open(source, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(CaseError, "busy"):
                self.preview()
            with self.assertRaisesRegex(CaseError, "busy"):
                self.approve(plan)
            self.assertTrue(source.exists())
        finally:
            os.close(fd)

    def test_recent_active_writer_does_not_block_stale_session_cleanup(self):
        aged_source, _ = self.make_session()
        fresh = ".upload-" + "b" * 32
        fresh_source, _ = self.make_session(fresh, aged=False)
        fd = os.open(fresh_source, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            planned = self.preview()
            self.assertEqual(planned["tokens"], [self.token])
            cleaned = self.approve(planned)
            self.assertEqual(cleaned["removed_sessions"], 1)
            self.assertFalse(aged_source.exists())
            self.assertTrue(fresh_source.exists())
        finally:
            os.close(fd)

    def test_source_hardlink_and_metadata_symlink_block_cleanup(self):
        source, meta = self.make_session()
        hard = self.home / "another-reference"
        os.link(source, hard)
        with self.assertRaises(CaseError):
            self.preview()
        hard.unlink()
        outside = self.home / "private-operator-note"
        outside.write_bytes(b"keep me")
        meta.unlink()
        meta.symlink_to(outside)
        with self.assertRaises(CaseError):
            self.preview()
        self.assertEqual(outside.read_bytes(), b"keep me")
        self.assertTrue(source.exists())

    def test_orphan_metadata_is_explicitly_reclaimed(self):
        source, meta = self.make_session()
        source.unlink()
        plan = self.preview()
        self.assertEqual(plan["orphan_metadata"], 1)
        self.assertEqual(plan["reclaimable_bytes"], 0)
        result = self.approve(plan)
        self.assertEqual(result["removed_sessions"], 1)
        self.assertFalse(meta.exists())

    def test_malformed_metadata_blocks_all_retention(self):
        source, meta = self.make_session()
        meta.write_bytes(b'{"version":"wrong","size":1}')
        old = self.now - 97 * 3600 * 1_000_000_000
        os.utime(meta, ns=(old, old))
        with self.assertRaises(CaseError):
            self.preview()
        self.assertTrue(source.exists())

    def test_minimum_age_and_maximum_inventory_constraints(self):
        self.make_session()
        for age in (0, 1, 23, -1, 999999, True, 24.5):
            with self.assertRaises(CaseError):
                inventory(self.store, older_hours=age, now_ns=self.now)
        with patch("transfer_retention.MAX_INBOX_ENTRIES", 1):
            with self.assertRaisesRegex(CaseError, "exceeds"):
                self.preview()

    def test_subprocess_cli_requires_preview_plan_before_removal(self):
        source, meta = self.make_session()
        cli = Path(__file__).resolve().parents[1] / "transfer_bridge.py"
        env = {**os.environ, "HOME": str(self.home)}
        def invoke(*args):
            return subprocess.run([sys.executable, "-u", str(cli), *args],
                                  env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=30, check=False)
        preview = invoke("retention", "--older-hours", "72")
        self.assertEqual(preview.returncode, 0, preview.stderr)
        plan = json.loads(preview.stdout)
        self.assertEqual(plan["eligible_sessions"], 1)
        self.assertTrue(source.exists())
        denied = invoke("retention", "--older-hours", "72", "--confirm")
        self.assertNotEqual(denied.returncode, 0)
        self.assertTrue(source.exists())
        accepted = invoke("retention", "--older-hours", "72", "--confirm",
                          "--plan-sha256", plan["plan_sha256"])
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(json.loads(accepted.stdout)["removed_sessions"], 1)
        self.assertFalse(source.exists())
        self.assertFalse(meta.exists())


if __name__ == "__main__":
    unittest.main()
