"""Offline resumable SSH intake contract: bounded streaming and truthful recovery."""
from __future__ import annotations

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
from types import SimpleNamespace
from unittest.mock import patch

from casework import CaseStore, CaseError, FREE_RESERVE, MAX_WORKER_ARTIFACT
import transfer_bridge
import resumable_transfer as resume


class ResumableUploadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.store = CaseStore(self.home)
        self.temp = ".upload-" + "a" * 32
        self.payload = b"\x00\xff" + b"2026-10-16T23:12:00Z synthetic-only evidence\n" * 5
        self.sha = hashlib.sha256(self.payload).hexdigest()

    @property
    def source(self):
        return self.store.inbox / self.temp

    @property
    def metadata(self):
        return self.store.inbox / (self.temp + ".session")

    def start(self):
        return resume.begin(self.store, self.temp, len(self.payload), self.sha)

    def test_idle_stdin_releases_lock_and_preserves_exact_prefix(self):
        self.start()
        prefix = self.payload[:27]
        with patch.object(resume, "_read_stdin", side_effect=[
                prefix, CaseError("Upload input idle")]):
            with self.assertRaisesRegex(CaseError, "Upload input idle"):
                resume.append(self.store, self.temp, 0)
        state = resume.status(self.store, self.temp)
        self.assertEqual(state["bytes_staged"], len(prefix))
        self.assertEqual(state["prefix_sha256"], hashlib.sha256(prefix).hexdigest())
        resume.append(self.store, self.temp, len(prefix), io.BytesIO(self.payload[len(prefix):]))
        self.assertEqual(resume.status(self.store, self.temp)["status"], "COMPLETE_UNVERIFIED")

    def test_real_open_pipe_idle_preserves_short_prefix_and_unlocks(self):
        self.start()
        reader, writer = os.pipe()
        self.addCleanup(os.close, writer)
        with os.fdopen(reader, "rb") as source:
            prefix = self.payload[:27]
            os.write(writer, prefix)
            with patch.object(resume.sys, "stdin", SimpleNamespace(buffer=source)), \
                    patch.object(resume, "APPEND_IDLE_SECONDS", 0.05):
                with self.assertRaisesRegex(CaseError, "Upload input idle"):
                    resume.append(self.store, self.temp, 0)
        state = resume.status(self.store, self.temp)
        self.assertEqual(state["bytes_staged"], len(prefix))
        self.assertEqual(state["prefix_sha256"], hashlib.sha256(prefix).hexdigest())

    def test_idle_descriptor_is_bounded_and_does_not_attempt_read(self):
        with patch.object(resume.sys, "stdin", SimpleNamespace(buffer=SimpleNamespace(fileno=lambda: 7))), \
                patch.object(resume.select, "select", return_value=([], [], [])) as wait, \
                patch.object(resume.os, "read") as read:
            with self.assertRaisesRegex(CaseError, "Upload input idle"):
                resume._read_stdin()
            wait.assert_called_once_with([7], [], [], 30)
            read.assert_not_called()

    def test_ready_stdin_uses_short_descriptor_read(self):
        with patch.object(resume.sys, "stdin", SimpleNamespace(buffer=SimpleNamespace(fileno=lambda: 7))), \
                patch.object(resume.select, "select", return_value=([7], [], [])), \
                patch.object(resume.os, "read", return_value=b"short") as read:
            self.assertEqual(resume._read_stdin(), b"short")
            read.assert_called_once_with(7, resume.CHUNK)

    def test_two_appends_resume_by_verified_prefix_then_finalize_into_case(self):
        begin = self.start()
        self.assertEqual(begin["status"], "SESSION_CREATED")
        n = 27
        first = resume.append(self.store, self.temp, 0, io.BytesIO(self.payload[:n]))
        self.assertEqual(first["bytes_staged"], n)
        progress = resume.status(self.store, self.temp)
        self.assertEqual(progress["status"], "PARTIAL")
        self.assertEqual(progress["prefix_sha256"],
                         hashlib.sha256(self.payload[:n]).hexdigest())
        self.assertEqual(progress["remaining_bytes"], len(self.payload) - n)
        second = resume.append(self.store, self.temp, n, io.BytesIO(self.payload[n:]))
        self.assertEqual(second["status"], "COMPLETE_UNVERIFIED")
        self.assertFalse(second["ready_for_case_import"])
        self.assertTrue(self.metadata.exists())
        result = transfer_bridge.finalize(self.store, self.temp, "capture.bin",
                                           len(self.payload), self.sha)
        self.assertEqual(result["status"], "STAGED")
        self.assertFalse(self.source.exists())
        self.assertFalse(self.metadata.exists())
        self.assertEqual((self.store.inbox / "capture.bin").read_bytes(), self.payload)
        self.assertEqual((self.store.inbox / "capture.bin").stat().st_mode & 0o777, 0o600)
        case = self.store.open_case()["case_id"]
        artifact = self.store.register(case, "capture.bin")
        self.assertEqual(artifact["sha256"], self.sha)

    def test_failed_stream_retains_resumable_verified_prefix(self):
        class DropConnection:
            def __init__(self):
                self.calls = 0
            def read(self, n):
                self.calls += 1
                if self.calls == 1:
                    return self.payload[:32]
                raise OSError("synthetic SSH channel disconnected")
        self.start()
        broken = DropConnection()
        broken.payload = self.payload
        with self.assertRaises(OSError):
            resume.append(self.store, self.temp, 0, broken)
        progress = resume.status(self.store, self.temp)
        self.assertEqual(progress["bytes_staged"], 32)
        self.assertEqual(progress["prefix_sha256"],
                         hashlib.sha256(self.payload[:32]).hexdigest())
        result = resume.append(self.store, self.temp, 32,
                               io.BytesIO(self.payload[32:]))
        self.assertEqual(result["status"], "COMPLETE_UNVERIFIED")
        staged = transfer_bridge.finalize(self.store, self.temp, "logs.dat",
                                          len(self.payload), self.sha)
        self.assertEqual(staged["sha256"], self.sha)

    def test_wrong_offset_refuses_without_overwriting_existing_prefix(self):
        self.start()
        resume.append(self.store, self.temp, 0, io.BytesIO(self.payload[:21]))
        with self.assertRaisesRegex(CaseError, "offset"):
            resume.append(self.store, self.temp, 0, io.BytesIO(b"overwrite"))
        self.assertEqual(self.source.read_bytes(), self.payload[:21])

    def test_declared_size_blocks_extra_bytes(self):
        self.start()
        with self.assertRaisesRegex(CaseError, "exceeds"):
            resume.append(self.store, self.temp, 0, io.BytesIO(self.payload + b"x"))
        self.assertEqual(self.source.read_bytes(), b"")
        self.assertEqual(resume.status(self.store, self.temp)["status"], "PARTIAL")

    def test_complete_but_wrong_hash_is_never_staged(self):
        self.start()
        wrong = b"z" * len(self.payload)
        resume.append(self.store, self.temp, 0, io.BytesIO(wrong))
        self.assertEqual(resume.status(self.store, self.temp)["status"],
                         "COMPLETE_UNVERIFIED")
        with self.assertRaisesRegex(CaseError, "digest"):
            transfer_bridge.finalize(self.store, self.temp, "bad.log",
                                      len(wrong), self.sha)
        self.assertFalse((self.store.inbox / "bad.log").exists())
        self.assertTrue(self.source.exists())

    def test_finalization_wrong_session_identity_is_denied(self):
        self.start()
        resume.append(self.store, self.temp, 0, io.BytesIO(self.payload))
        with self.assertRaisesRegex(CaseError, "identity"):
            transfer_bridge.finalize(self.store, self.temp, "bad.log",
                                      len(self.payload), "f" * 64)
        self.assertTrue(self.source.exists())
        self.assertFalse((self.store.inbox / "bad.log").exists())

    def test_abort_removes_both_upload_prefix_and_private_session(self):
        self.start()
        resume.append(self.store, self.temp, 0, io.BytesIO(self.payload[:30]))
        result = transfer_bridge.abort(self.store, self.temp)
        self.assertEqual(result["status"], "TEMPORARY_FILE_REMOVED")
        self.assertFalse(self.source.exists())
        self.assertFalse(self.metadata.exists())
        self.assertEqual(transfer_bridge.abort(self.store, self.temp)["status"],
                         "NO_TEMPORARY_FILE")

    def test_orphan_meta_after_crash_can_be_removed_without_touching_final(self):
        self.start()
        self.source.unlink()
        final = self.store.inbox / "safe.log"
        final.write_bytes(b"existing result")
        final.chmod(0o600)
        state = transfer_bridge.abort(self.store, self.temp)
        self.assertEqual(state["status"], "ORPHAN_SESSION_REMOVED")
        self.assertFalse(self.metadata.exists())
        self.assertEqual(final.read_bytes(), b"existing result")

    def test_existing_temp_token_and_target_cannot_be_overwritten(self):
        self.start()
        with self.assertRaises((FileExistsError, CaseError)):
            self.start()
        resume.append(self.store, self.temp, 0, io.BytesIO(self.payload))
        target = self.store.inbox / "already.log"
        target.write_bytes(b"protected")
        target.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "Destination exists"):
            transfer_bridge.finalize(self.store, self.temp, "already.log",
                                      len(self.payload), self.sha)
        self.assertEqual(target.read_bytes(), b"protected")

    def test_metadata_symlink_and_source_hardlink_refused(self):
        self.start()
        outside = self.home / "operator-document"
        outside.write_text("not-upload-data")
        self.metadata.unlink()
        self.metadata.symlink_to(outside)
        with self.assertRaises((OSError, CaseError)):
            resume.status(self.store, self.temp)
        self.metadata.unlink()
        alias = self.home / "same-inode"
        os.link(self.source, alias)
        with self.assertRaises((OSError, CaseError)):
            resume.append(self.store, self.temp, 0, io.BytesIO(b"x"))
        self.assertEqual(outside.read_text(), "not-upload-data")

    def test_zero_and_bool_offsets_and_negative_sizes_rejected(self):
        self.start()
        with self.assertRaises(CaseError):
            resume.append(self.store, self.temp, True, io.BytesIO(b"x"))
        with self.assertRaises(CaseError):
            resume.begin(self.store, ".upload-" + "b" * 32, -1, self.sha)
        with self.assertRaises(CaseError):
            resume.begin(self.store, ".upload-" + "c" * 32, True, self.sha)
        with self.assertRaises(CaseError):
            resume.begin(self.store, ".upload-" + "d" * 32, MAX_WORKER_ARTIFACT + 1, self.sha)

    def test_size_aware_prepare_refuses_free_space_below_reserved_headroom(self):
        self.store._ensure_store()
        with patch.object(transfer_bridge.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=FREE_RESERVE + 7)):
            with self.assertRaisesRegex(CaseError, "safe capacity"):
                transfer_bridge.prepare(self.store, proposed_size=8)
            self.assertEqual(transfer_bridge.prepare(self.store)["safe_available_bytes"], 7)
            with self.assertRaises(CaseError):
                resume.begin(self.store, self.temp, 8, self.sha)

    def test_stream_rejects_append_if_free_space_drops_to_reserved_limit(self):
        self.start()
        with patch.object(resume.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=FREE_RESERVE)):
            with self.assertRaisesRegex(CaseError, "reserved"):
                resume.append(self.store, self.temp, 0, io.BytesIO(self.payload))
        self.assertEqual(self.source.stat().st_size, 0)

    def test_mid_stream_disk_reserve_loss_keeps_only_verified_partial(self):
        # Prove reserve is checked repeatedly, not only at session creation.
        chunk = 1024 * 1024
        payload = b"\x00" + b"R" * (2 * chunk + 18)
        token = ".upload-" + "e" * 32
        sha = hashlib.sha256(payload).hexdigest()
        resume.begin(self.store, token, len(payload), sha)
        ok_space = SimpleNamespace(free=FREE_RESERVE + 5 * chunk)
        no_space = SimpleNamespace(free=FREE_RESERVE)
        with patch.object(resume.shutil, "disk_usage", side_effect=[ok_space, no_space]):
            with self.assertRaisesRegex(CaseError, "reserved"):
                resume.append(self.store, token, 0, io.BytesIO(payload))
        state = resume.status(self.store, token)
        self.assertEqual(state["status"], "PARTIAL")
        self.assertEqual(state["bytes_staged"], chunk)
        self.assertEqual(state["prefix_sha256"], hashlib.sha256(payload[:chunk]).hexdigest())
        self.assertEqual((self.store.inbox / token).read_bytes(), payload[:chunk])
        self.assertFalse((self.store.inbox / "never-finalized.bin").exists())

    def test_fd_lock_rejects_conflicting_writer(self):
        import fcntl
        self.start()
        fd = os.open(self.source, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(CaseError, "busy"):
                resume.append(self.store, self.temp, 0, io.BytesIO(self.payload))
            with self.assertRaisesRegex(CaseError, "busy"):
                transfer_bridge.finalize(self.store, self.temp, "busy.log",
                                          len(self.payload), self.sha)
        finally:
            os.close(fd)

    def test_real_binary_cli_across_separate_ssh_style_processes(self):
        cli = Path(__file__).resolve().parents[1] / "transfer_bridge.py"
        env = {**os.environ, "HOME": str(self.home)}
        self.store._ensure_store()
        tok = ".upload-" + "b" * 32
        def run(*args, data=None):
            p = subprocess.run([sys.executable, "-u", str(cli), *args], input=data,
                               capture_output=True, env=env, timeout=15, check=False)
            self.assertEqual(p.returncode, 0, p.stderr.decode("utf-8", "replace"))
            return json.loads(p.stdout)
        self.assertEqual(run("prepare", "--size", str(len(self.payload)))["status"], "READY")
        run("begin", "--temp", tok, "--size", str(len(self.payload)), "--sha256", self.sha)
        run("append", "--temp", tok, "--offset", "0", data=self.payload[:15])
        current = run("status", "--temp", tok)
        self.assertEqual(current["prefix_sha256"], hashlib.sha256(self.payload[:15]).hexdigest())
        run("append", "--temp", tok, "--offset", "15", data=self.payload[15:])
        finalized = run("finalize", "--temp", tok, "--filename", "case.bin",
                        "--size", str(len(self.payload)), "--sha256", self.sha)
        self.assertEqual(finalized["status"], "STAGED")
        self.assertEqual((self.store.inbox / "case.bin").read_bytes(), self.payload)


if __name__ == "__main__":
    unittest.main()
