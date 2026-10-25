"""Verify upload reservations and case imports under a cross-process capacity lock."""
from __future__ import annotations

import hashlib
import io
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from casework import CaseStore, CaseError, FREE_RESERVE
from capacitywork import admission_lock, new_upload_capacity, outstanding_reservations
import resumable_transfer as resume
import transfer_bridge

MIB = 1024 * 1024


def competing_begin(home: str, token: str, size: int, fixed_free: int,
                    barrier, results) -> None:
    # Independent process, same synthetic physical-free reading. Without
    # an interprocess admission lock BOTH can succeed, overcommitting reserve.
    from unittest.mock import patch
    import shutil
    try:
        store = CaseStore(Path(home))
        barrier.wait(timeout=10)
        with patch.object(shutil, "disk_usage", return_value=SimpleNamespace(free=fixed_free)):
            resume.begin(store, token, size, "a" * 64)
        results.put(("accepted", token))
    except (CaseError, OSError) as exc:
        results.put(("refused", token))
    except BaseException as exc:
        results.put(("error", type(exc).__name__))


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.store = CaseStore(self.home)
        self.first = ".upload-" + "a" * 32
        self.second = ".upload-" + "b" * 32
        self.data = b"RAW:\x00\xff synthetic only\n"
        self.sha = hashlib.sha256(self.data).hexdigest()

    def disk(self, free: int):
        import shutil
        return patch.object(shutil, "disk_usage", return_value=SimpleNamespace(free=free))

    def test_prepare_reports_uncommitted_capacity_for_new_sessions_only(self):
        with self.disk(FREE_RESERVE + 2 * MIB):
            first = resume.begin(self.store, self.first, MIB, self.sha)
            self.assertEqual(first["status"], "SESSION_CREATED")
            pre = transfer_bridge.prepare(self.store)
            self.assertEqual(pre["safe_available_bytes"], MIB)
            self.assertEqual(pre["capacity_applies_to"], "new_upload_only")
            with self.assertRaisesRegex(CaseError, "concurrent reservations"):
                transfer_bridge.prepare(self.store, proposed_size=MIB + 1)
            with self.assertRaisesRegex(CaseError, "concurrent reservations"):
                resume.begin(self.store, self.second, MIB + 1, self.sha)
            self.assertFalse((self.store.inbox / self.second).exists())

    def test_physical_append_consumes_existing_reserved_capacity(self):
        data = b"R" * (2 * MIB)
        digest = hashlib.sha256(data).hexdigest()
        with self.disk(FREE_RESERVE + 2 * MIB):
            resume.begin(self.store, self.first, len(data), digest)
            pre = transfer_bridge.prepare(self.store)
            self.assertEqual(pre["safe_available_bytes"], 0)
            result = resume.append(self.store, self.first, 0, io.BytesIO(data))
            self.assertEqual(result["bytes_staged"], len(data))
            self.assertEqual(result["status"], "COMPLETE_UNVERIFIED")
            with admission_lock(self.store):
                self.assertEqual(outstanding_reservations(self.store), 0)
                self.assertEqual(new_upload_capacity(self.store), 2 * MIB)

    def test_case_vault_copy_cannot_steal_reserved_upload_bytes(self):
        self.store._ensure_store()
        staged = self.store.inbox / "from-staged.bin"
        staged.write_bytes(self.data)
        staged.chmod(0o600)
        case = self.store.open_case()["case_id"]
        pending = MIB
        with self.disk(FREE_RESERVE + pending + len(self.data) - 1):
            resume.begin(self.store, self.first, pending, self.sha)
            with self.assertRaisesRegex(CaseError, "pending upload commitments"):
                self.store.register(case, "from-staged.bin", worker=True)
            self.assertEqual(self.store.status(case)["artifact_count"], 0)
            self.assertEqual(staged.read_bytes(), self.data)
        transfer_bridge.abort(self.store, self.first)
        with self.disk(FREE_RESERVE + len(self.data) + MIB):
            accepted = self.store.register(case, "from-staged.bin", worker=True)
        self.assertEqual(accepted["status"], "REGISTERED")
        self.assertEqual(accepted["sha256"], self.sha)

    def test_bad_session_metadata_fails_all_new_admission(self):
        resume.begin(self.store, self.first, len(self.data), self.sha)
        sidecar = self.store.inbox / (self.first + ".session")
        sidecar.write_bytes(b"malformed")
        sidecar.chmod(0o600)
        with self.assertRaises(CaseError):
            transfer_bridge.prepare(self.store)
        with self.assertRaises(CaseError):
            resume.begin(self.store, self.second, len(self.data), self.sha)
        self.assertFalse((self.store.inbox / self.second).exists())

    def test_admission_lock_contention_is_bounded_and_fails_closed(self):
        with admission_lock(self.store):
            # It must not wait indefinitely behind a stalled vault import.
            with patch("capacitywork.ADMISSION_WAIT_SECONDS", 0.025), \
                 patch("capacitywork.ADMISSION_POLL_SECONDS", 0.005):
                with self.assertRaisesRegex(CaseError, "busy"):
                    transfer_bridge.prepare(self.store)
        self.assertEqual(transfer_bridge.prepare(self.store)["status"], "READY")

    def test_unsafe_capacity_lock_symlink_refused(self):
        self.store._ensure_store()
        lock = self.store.base / ".capacity.lock"
        outside = self.home / "leave-alone"
        outside.write_bytes(b"untouched")
        lock.symlink_to(outside)
        with self.assertRaises((CaseError, OSError)):
            transfer_bridge.prepare(self.store)
        self.assertEqual(outside.read_bytes(), b"untouched")

    def test_two_independent_processes_cannot_both_claim_same_bytes(self):
        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        output = ctx.Queue()
        free = FREE_RESERVE + 3 * MIB
        amount = 2 * MIB
        ps = [ctx.Process(target=competing_begin,
                          args=(str(self.home), name, amount, free, barrier, output))
              for name in (self.first, self.second)]
        try:
            for p in ps:
                p.start()
            results = [output.get(timeout=20), output.get(timeout=20)]
            for p in ps:
                p.join(timeout=15)
            self.assertTrue(all(p.exitcode == 0 for p in ps), results)
            self.assertEqual(sorted(x[0] for x in results), ["accepted", "refused"])
            with admission_lock(self.store):
                self.assertEqual(outstanding_reservations(self.store), amount)
        finally:
            for p in ps:
                if p.is_alive():
                    p.kill()
                p.join(timeout=5)
            output.close()


if __name__ == "__main__":
    unittest.main()
