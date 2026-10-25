"""SIGKILL-style archive crash journals and explicit source-bound cleanup tests."""
from __future__ import annotations

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
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from archive_recovery import list_workdirs, recover
from archivework import unpack_case_archive, verify_case
from casework import CaseStore, CaseError

SOURCE_ROOT = Path(__file__).resolve().parent.parent
DAY_NS = 24 * 3600 * 1_000_000_000

CRASH_PROGRAM = r"""
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from casework import CaseStore
import archivework
root, case_id, artifact_id, point = Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
store=CaseStore(root)
if point in ('MOVED', 'BEFORE_MOVE'):
    real=archivework.os.replace
    def replace(src, dst):
        if (Path(src).parent.name.startswith('expand-')
                and Path(dst).parent.name == 'originals'):
            if point == 'BEFORE_MOVE':
                os._exit(91)
            real(src, dst)
            os._exit(92)
        return real(src, dst)
    archivework.os.replace=replace
elif point == 'STAGING':
    real=archivework._copy_stream
    def halted(*a, **kw):
        real(*a, **kw)
        os._exit(93)
    archivework._copy_stream=halted
elif point == 'COMMITTED':
    real=archivework._write_json_atomic
    def killed(path, doc):
        real(path, doc)
        if (Path(path).name == 'manifest.json'
                and any(isinstance(v,dict) and v.get('derived_from') == artifact_id
                        for v in doc['artifacts'].values())):
            os._exit(94)
    archivework._write_json_atomic=killed
else:
    raise RuntimeError("Invalid synthetic crash point")
archivework.unpack_case_archive(store, case_id, artifact_id)
raise RuntimeError("Crash point was not reached")
"""


class ArchiveCrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.store = CaseStore(self.home)
        self.case_id = self.store.open_case()["case_id"]
        self.content = b"2026-10-17T12:03:00Z ERROR synthetic-only source\n" * 12
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("logs/one.log", self.content)
            z.writestr("logs/two.log", b"synthetic configuration snapshot\n")
        self.bundle = self.store.inbox / "synthetic.zip"
        self.bundle.write_bytes(b.getvalue())
        self.bundle.chmod(0o600)
        self.parent = self.store.register(self.case_id, self.bundle.name)
        self.future = time.time_ns() + 96 * DAY_NS

    def crash(self, point: str) -> tuple[str, Path]:
        r = subprocess.run(
            [sys.executable, "-c", CRASH_PROGRAM, str(SOURCE_ROOT),
             str(self.home), self.case_id, self.parent["artifact_id"], point],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25,
            check=False)
        expected = {"MOVED": 92, "BEFORE_MOVE": 91, "STAGING": 93,
                    "COMMITTED": 94}
        self.assertEqual(r.returncode, expected[point], r.stderr.decode("utf-8", "replace")[:200])
        state = list_workdirs(self.store, self.case_id)
        self.assertEqual(len(state["work_ids"]), 1)
        work_id = state["work_ids"][0]
        return work_id, self.store.cases / self.case_id / "scratch" / ("expand-" + work_id)

    def inspect(self, work_id: str):
        return recover(self.store, self.case_id, work_id, now_ns=self.future)

    def commit(self, work_id: str, plan: dict):
        return recover(self.store, self.case_id, work_id,
                       now_ns=self.future, confirm=True,
                       plan_sha256=plan["plan_sha256"])

    def artifact_count(self):
        with self.store._locked(self.case_id) as (_, manifest):
            return len(manifest["artifacts"])

    def test_normal_archive_does_not_leave_a_recovery_journal(self):
        result = unpack_case_archive(self.store, self.case_id, self.parent["artifact_id"])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["derived_artifact_count"], 2)
        self.assertEqual(list_workdirs(self.store, self.case_id)["work_ids"], [])
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")

    def test_sigkill_during_staging_requires_review_and_clears_only_scratch(self):
        work_id, root = self.crash("STAGING")
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PARTIAL")
        with self.assertRaisesRegex(CaseError, "not sufficiently old"):
            recover(self.store, self.case_id, work_id)
        plan = self.inspect(work_id)
        self.assertEqual(plan["disposition"], "INTERRUPTED")
        self.assertEqual(plan["scratch_files"], 1)
        self.assertEqual(plan["unregistered_originals"], 0)
        with self.assertRaisesRegex(CaseError, "requires exact"):
            recover(self.store, self.case_id, work_id, confirm=True, now_ns=self.future)
        self.assertEqual(self.commit(work_id, plan)["status"], "RECOVERED_INTERRUPTED")
        self.assertFalse(root.exists())
        self.assertEqual(self.artifact_count(), 1)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")

    def test_sigkill_after_first_move_removes_only_journaled_orphan(self):
        work_id, root = self.crash("MOVED")
        initial = self.artifact_count()
        originals = list((self.store.cases / self.case_id / "originals").iterdir())
        self.assertEqual(len(originals), 2)
        plan = self.inspect(work_id)
        self.assertEqual(plan["unregistered_originals"], 1)
        self.assertEqual(plan["scratch_files"], 1)
        result = self.commit(work_id, plan)
        self.assertEqual(result["removed_unregistered_originals"], 1)
        self.assertEqual(result["removed_registered_originals"], 0)
        self.assertFalse(root.exists())
        self.assertEqual(self.artifact_count(), initial)
        originals = list((self.store.cases / self.case_id / "originals").iterdir())
        self.assertEqual(len(originals), 1)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")

    def test_committed_manifest_survives_kill_before_journal_cleanup(self):
        work_id, root = self.crash("COMMITTED")
        self.assertEqual(self.artifact_count(), 3)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PARTIAL")
        plan = self.inspect(work_id)
        self.assertEqual(plan["disposition"], "COMMITTED")
        self.assertEqual(plan["unregistered_originals"], 0)
        self.assertEqual(self.commit(work_id, plan)["status"], "CLEARED_COMMITTED_JOURNAL")
        self.assertFalse(root.exists())
        self.assertEqual(self.artifact_count(), 3)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")
        derived = self.store.list_artifacts(
            self.case_id, source_artifact_id=self.parent["artifact_id"])
        self.assertEqual(derived["total"], 2)

    def test_manifest_committed_then_writer_error_preserves_registered_originals(self):
        # Regression: os.replace(manifest) may succeed before an I/O error is
        # reported. Ordinary rollback must NOT unlink already registered data.
        import archivework
        real = archivework._write_json_atomic
        def late_failure(path, document):
            real(path, document)
            if (Path(path).name == "manifest.json" and
                    any(isinstance(m, dict) and
                        m.get("derived_from") == self.parent["artifact_id"]
                        for m in document.get("artifacts", {}).values())):
                raise OSError("synthetic post-commit filesystem error")
        with patch.object(archivework, "_write_json_atomic",
                          side_effect=late_failure):
            with self.assertRaisesRegex(OSError, "post-commit"):
                unpack_case_archive(self.store, self.case_id,
                                    self.parent["artifact_id"])
        self.assertEqual(self.artifact_count(), 3)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PARTIAL")
        pending = list_workdirs(self.store, self.case_id)["work_ids"]
        self.assertEqual(len(pending), 1)
        plan = self.inspect(pending[0])
        self.assertEqual(plan["disposition"], "COMMITTED")
        self.assertEqual(plan["unregistered_originals"], 0)
        self.assertEqual(self.commit(pending[0], plan)["removed_registered_originals"], 0)
        self.assertEqual(self.artifact_count(), 3)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")

    def test_manifest_writer_fails_before_commit_rolls_back_moved_files(self):
        import archivework
        real = archivework._write_json_atomic
        def refused(path, document):
            if (Path(path).name == "manifest.json" and
                    any(isinstance(m, dict) and m.get("derived_from")
                        for m in document.get("artifacts", {}).values())):
                raise OSError("synthetic pre-commit filesystem error")
            return real(path, document)
        with patch.object(archivework, "_write_json_atomic",
                          side_effect=refused):
            with self.assertRaisesRegex(OSError, "pre-commit"):
                unpack_case_archive(self.store, self.case_id,
                                    self.parent["artifact_id"])
        self.assertEqual(self.artifact_count(), 1)
        self.assertEqual(list_workdirs(self.store, self.case_id)["work_ids"], [])
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")

    def test_failed_rollback_unlink_retains_journal_and_unregistered_original(self):
        import archivework
        real_write = archivework._write_json_atomic
        real_unlink = Path.unlink
        def precommit_failure(path, document):
            if (Path(path).name == "manifest.json" and
                    any(isinstance(m, dict) and m.get("derived_from")
                        for m in document.get("artifacts", {}).values())):
                raise OSError("synthetic failed manifest before replacement")
            return real_write(path, document)
        def denied_unlink(path, *args, **kwargs):
            if Path(path).parent.name == "originals" and Path(path).name != self.parent["artifact_id"]:
                raise PermissionError("synthetic original unlink rejected")
            return real_unlink(path, *args, **kwargs)
        with patch.object(archivework, "_write_json_atomic",
                          side_effect=precommit_failure), \
             patch.object(archivework.Path, "unlink", new=denied_unlink):
            with self.assertRaisesRegex(OSError, "failed manifest"):
                unpack_case_archive(self.store, self.case_id, self.parent["artifact_id"])
        # Failed rollback must not erase its only source-bound recovery journal.
        self.assertEqual(self.artifact_count(), 1)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PARTIAL")
        pending = list_workdirs(self.store, self.case_id)["work_ids"]
        self.assertEqual(len(pending), 1)
        preview = self.inspect(pending[0])
        self.assertEqual(preview["disposition"], "INTERRUPTED")
        self.assertGreater(preview["unregistered_originals"], 0)
        self.assertEqual(self.commit(pending[0], preview)["removed_registered_originals"], 0)
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")

    def test_modified_orphan_hash_blocks_cleanup_and_preserves_original(self):
        work_id, root = self.crash("MOVED")
        originals = self.store.cases / self.case_id / "originals"
        moved = next(path for path in originals.iterdir()
                     if path.name != self.parent["artifact_id"])
        moved.write_bytes(b"tampered-derived-output")
        moved.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "differs"):
            self.inspect(work_id)
        self.assertTrue(moved.exists())
        self.assertTrue(root.exists())
        self.assertEqual(self.artifact_count(), 1)

    def test_preview_hash_changes_if_staged_file_or_journal_changes(self):
        work_id, root = self.crash("BEFORE_MOVE")
        plan = self.inspect(work_id)
        self.assertEqual(plan["scratch_files"], 2)
        staged = next(p for p in root.iterdir() if p.name != "journal.json")
        os.utime(staged, ns=(staged.stat().st_atime_ns,
                             staged.stat().st_mtime_ns + 1_000_000))
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.commit(work_id, plan)
        self.assertTrue(staged.exists())
        self.assertEqual(self.artifact_count(), 1)

    def test_unknown_symlink_and_unjournaled_scratch_are_not_deleted(self):
        work_id, root = self.crash("STAGING")
        outside = self.home / "do-not-delete"
        outside.write_bytes(b"important unrelated material")
        target = root / ("f" * 32)
        target.symlink_to(outside)
        with self.assertRaisesRegex(CaseError, "unsafe"):
            self.inspect(work_id)
        self.assertEqual(outside.read_bytes(), b"important unrelated material")
        target.unlink()
        journal = root / "journal.json"
        journal.unlink()
        with self.assertRaises(FileNotFoundError):
            self.inspect(work_id)
        self.assertTrue(root.exists())

    def test_source_mismatch_and_invalid_work_id_refused(self):
        work_id, root = self.crash("STAGING")
        jpath = root / "journal.json"
        doc = json.loads(jpath.read_bytes())
        doc["source_sha256"] = "f" * 64
        jpath.write_text(json.dumps(doc))
        jpath.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "source identity"):
            self.inspect(work_id)
        with self.assertRaisesRegex(CaseError, "Invalid archive recovery work"):
            self.inspect("../not-an-id")

    def test_failed_initial_journal_creation_cleans_staging(self):
        from unittest.mock import patch
        import archivework
        with patch.object(archivework, "_write_json_atomic",
                          side_effect=OSError("synthetic full filesystem")):
            with self.assertRaises(OSError):
                unpack_case_archive(self.store, self.case_id, self.parent["artifact_id"])
        self.assertEqual(list_workdirs(self.store, self.case_id)["work_ids"], [])
        self.assertEqual(verify_case(self.store, self.case_id)["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
