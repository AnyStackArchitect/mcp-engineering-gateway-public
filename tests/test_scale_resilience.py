"""Disposable-process interruption and injected storage faults, never live state."""
import errno
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

import casework
from casework import CaseError
import index_recovery
import jobwork
import protocolwork
from test_protocolwork import ipv4, udp, pcap, pcapng


def gated_worker(home, ready, release):
    """Pause only after a real private SQLite transaction is in progress."""
    jobs = jobwork.JobStore(Path(home))
    original = jobs.cases.index_log
    def index(*args, **kwargs):
        callback = kwargs['should_cancel']
        calls = 0
        def gate():
            nonlocal calls
            calls += 1
            if calls == 4:
                ready.send('INDEX_IN_PROGRESS')
                if not release.wait(20):
                    raise RuntimeError('Test synchronization timed out')
            callback()
        kwargs['should_cancel'] = gate
        return original(*args, **kwargs)
    jobs.cases.index_log = index
    jobs.work_once()


class ScaleResilienceTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.home = Path(t.name)
        self.jobs = jobwork.JobStore(self.home)
        self.store = self.jobs.cases
        self.cid = self.store.open_case()['case_id']
        self.originals = {}

    def register(self, name, raw):
        p = self.store.inbox/name
        p.write_bytes(raw)
        p.chmod(0o600)
        aid = self.store.register(self.cid, name, worker=True)['artifact_id']
        self.originals[aid] = hashlib.sha256(raw).hexdigest()
        return aid

    def original(self, aid):
        p = self.store.cases/self.cid/'originals'/aid
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), self.originals[aid])

    def index_path(self, aid):
        return self.store.cases/self.cid/'indexes'/(aid+'.sqlite3')

    def worker(self):
        ctx = multiprocessing.get_context('spawn')
        parent, child = ctx.Pipe(duplex=False)
        release = ctx.Event()
        process = ctx.Process(target=gated_worker, args=(str(self.home), child, release))
        process.start()
        child.close()
        def cleanup():
            if process.is_alive():
                process.kill()
            process.join(timeout=10)
            parent.close()
        self.addCleanup(cleanup)
        self.assertTrue(parent.poll(20), 'Analysis did not reach an in-progress index')
        self.assertEqual(parent.recv(), 'INDEX_IN_PROGRESS')
        return process, release

    def test_sigkill_private_worker_preserves_original_and_explicit_recovery(self):
        aid = self.register('interrupt.txt', b'2026-10-24T12:00:00Z synthetic row\n'*20_000)
        submitted = self.jobs.submit('index_log', self.cid, artifact_id=aid)
        process, _ = self.worker()
        self.assertEqual(self.jobs.status(submitted['job_id'])['state'], 'RUNNING')
        os.kill(process.pid, signal.SIGKILL)
        process.join(timeout=10)
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        self.assertFalse(self.index_path(aid).exists())
        self.jobs.work_once()  # Exclusive worker lock proves prior worker is gone.
        outcome = self.jobs.result(submitted['job_id'])
        self.assertEqual(outcome['state'], 'INTERRUPTED')
        self.assertEqual(outcome['failure_code'], 'worker_interrupted')
        ids = index_recovery.list_interrupted(self.store, self.cid)['index_work_ids']
        self.assertEqual(len(ids), 1)
        with self.assertRaisesRegex(CaseError, 'too recent'):
            index_recovery.recover(self.store, self.cid, ids[0])
        # Advance only the explicit recovery API's synthetic clock, not host time.
        future = time.time_ns()+25*3600*1_000_000_000
        plan = index_recovery.recover(self.store, self.cid, ids[0], now_ns=future)
        self.assertEqual(plan['disposition'], 'INTERRUPTED')
        with self.assertRaises(CaseError):
            index_recovery.recover(self.store, self.cid, ids[0], now_ns=future, confirm=True)
        done = index_recovery.recover(self.store, self.cid, ids[0], now_ns=future,
                                      confirm=True, plan_sha256=plan['plan_sha256'])
        self.assertEqual(done['registered_originals_removed'], 0)
        self.assertEqual(done['committed_indexes_removed'], 0)
        self.original(aid)
        self.assertEqual(self.store.index_log(self.cid, aid, worker=True)['lines_indexed'], 20_000)

    def test_running_job_cancellation_cleans_partial_index_and_can_retry(self):
        aid = self.register('cancel.txt', b'2026-10-24T12:00:00Z synthetic row\n'*20_000)
        submitted = self.jobs.submit('index_log', self.cid, artifact_id=aid)
        process, release = self.worker()
        self.assertTrue(self.jobs.cancel(submitted['job_id'])['cancel_requested'])
        release.set()
        process.join(timeout=15)
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(self.jobs.result(submitted['job_id'])['state'], 'CANCELLED')
        self.assertFalse(self.index_path(aid).exists())
        self.assertEqual(list(self.index_path(aid).parent.iterdir()), [])
        self.original(aid)
        self.assertEqual(self.store.index_log(self.cid, aid, worker=True)['lines_indexed'], 20_000)

    def test_expired_analysis_deadline_is_not_success(self):
        aid = self.register('deadline.txt', b'2026-10-24T12:00:00Z row\n')
        submitted = self.jobs.submit('index_log', self.cid, artifact_id=aid)
        with patch.object(jobwork, 'MAX_WORK_SECONDS', 0):
            self.jobs.work_once()
        result = self.jobs.result(submitted['job_id'])
        self.assertEqual(result['state'], 'CANCELLED')
        self.assertEqual(result['failure_code'], 'job_timeout')
        self.assertFalse(self.index_path(aid).exists())
        self.original(aid)

    def test_sqlite_disk_full_commit_refuses_and_leaves_no_published_index(self):
        aid = self.register('full.txt', b'2026-10-24T12:00:00Z row\n'*5000)
        connect = sqlite3.connect
        class FullCommit(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError('database or disk is full')
        with patch.object(casework.sqlite3, 'connect',
                          side_effect=lambda *a, **kw: connect(*a, factory=FullCommit, **kw)):
            with self.assertRaisesRegex(CaseError, 'quota|capacity|SQLite'):
                self.store.index_log(self.cid, aid, worker=True)
        self.assertFalse(self.index_path(aid).exists())
        self.assertEqual(list(self.index_path(aid).parent.iterdir()), [])
        self.original(aid)
        self.assertEqual(self.store.index_log(self.cid, aid, worker=True)['lines_indexed'], 5000)

    def test_cancelled_and_disk_full_capture_rebuild_preserve_committed_report(self):
        raw = pcap([ipv4(b'\x0a\0\0\1', b'\x0a\0\0\2', 17, udp(1, 2, b'x'))]*1024)
        aid = self.register('capture.pcap', raw)
        protocolwork.analyze_capture(self.store, self.cid, aid)
        path = self.store.cases/self.cid/'indexes'/('protocol-'+aid+'.json')
        baseline = path.read_bytes()
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            if calls == 3:
                raise jobwork.JobCancelled('synthetic_cancel')
        with self.assertRaises(jobwork.JobCancelled):
            protocolwork.analyze_capture(self.store, self.cid, aid, should_cancel=cancel)
        self.assertEqual(path.read_bytes(), baseline)
        with patch.object(protocolwork, '_write_report', side_effect=OSError(errno.ENOSPC, 'synthetic disk full')):
            with self.assertRaises(OSError):
                protocolwork.analyze_capture(self.store, self.cid, aid)
        self.assertEqual(path.read_bytes(), baseline)
        self.original(aid)

    def test_oversized_record_is_partial_and_invalid_utf8_cannot_hide_next_line(self):
        raw = (b'X'*(casework.MAX_LINE+50)+b'\n'+
               b'2026-10-24T12:00:00Z invalid \xff\n'+
               b'2026-10-24T12:00:01Z FINDLAST\n')
        aid = self.register('malformed.txt', raw)
        result = self.store.index_log(self.cid, aid, worker=True)
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['lines_skipped'], 1)
        self.assertEqual(self.store.search_log(self.cid, aid, 'FINDLAST')['matches'][0]['line'], 3)
        self.original(aid)

    def test_actual_sync_line_limit_refuses_instead_of_truncating_success(self):
        aid = self.register('over-lines.txt', b'2026-10-24T12:00:00Z row\n'*(casework.MAX_SYNC_LINES+1))
        with self.assertRaisesRegex(CaseError, 'Line count'):
            self.store.index_log(self.cid, aid)
        self.assertFalse(self.index_path(aid).exists())
        self.original(aid)

    def test_actual_packet_count_limit_refuses_without_publishing(self):
        frame = ipv4(b'\x0a\0\0\1', b'\x0a\0\0\2', 17, udp(1, 2, b'x'))
        header = pcap([])
        record = struct.pack('<IIII', 1720000000, 0, len(frame), len(frame))+frame
        aid = self.register('over-frames.pcap', header+record*(protocolwork.MAX_FRAMES+1))
        with self.assertRaisesRegex(protocolwork.ProtocolError, 'count exceeds'):
            protocolwork.analyze_capture(self.store, self.cid, aid)
        self.assertFalse((self.store.cases/self.cid/'indexes'/('protocol-'+aid+'.json')).exists())
        self.original(aid)

    def test_malformed_tail_cannot_publish_partial_capture_as_success(self):
        frame = ipv4(b'\x0a\0\0\1', b'\x0a\0\0\2', 17, udp(1, 2, b'x'))
        for fmt, raw in [('pcap', pcap([frame]*1000, broken=True)),
                         ('pcapng', pcapng([frame]*1000)[:-1])]:
            aid = self.register('bad.'+fmt, raw)
            with self.assertRaises(protocolwork.ProtocolError):
                protocolwork.analyze_capture(self.store, self.cid, aid)
            with self.assertRaises(CaseError):
                protocolwork.protocol_report(self.store, self.cid, aid)
            self.original(aid)


if __name__ == '__main__':
    unittest.main()
