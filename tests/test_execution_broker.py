"""Broker/OS-boundary development regressions; actual UID proof is a separate smoke."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest

from casework import CaseStore, _regular_open
from execution_broker import (ExecutionBroker, ExecutionBrokerClient, BrokerError,
                              _decode, _receive, _send, _peer, _socket_parent)
from execution_policy import ExecutionPolicy, IdentityError
from sandboxwork import ExecutionStore
import gateway

IMAGE = "localhost/rocky-sandbox@sha256:" + "a" * 64

class BridgeTests(unittest.TestCase):
    def test_client_releases_case_lock_before_worker_rpc(self):
        from unittest.mock import patch
        import fcntl
        client=ExecutionBrokerClient(self.source.home)
        def exchange(request,descriptors):
            folder=self.source.cases/self.case
            fd=os.open(folder/'.lock',os.O_RDWR)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual(os.fstat(descriptors[0]).st_size,self.meta['bytes'])
            finally:os.close(fd)
            return {'checked':True}
        with patch.object(client,'_exchange',side_effect=exchange):
            result=client.prepare(self.case,"print('fixture')\n",[self.artifact],['out.json'])
        self.assertTrue(result['checked'])

    def test_source_snapshot_preserves_shared_reserve_before_write(self):
        from unittest.mock import patch
        import casework
        descriptor=self.fd()
        try:
            with patch('execution_broker.verify_committed_reserve',side_effect=casework.CaseError('reserved')):
                with self.assertRaises(casework.CaseError):self.broker.dispatch(self.request(),[descriptor],os.getuid())
        finally:os.close(descriptor)
        self.assertEqual(self.target.cases.list_cases()['cases_found'],0)
        self.assertFalse(any(self.target.cases.inbox.glob('exec-*.dat')))

    def test_bounded_large_snapshot_and_plan_above_old_limit(self):
        path=self.inbox/'large-readonly.img'
        with path.open('wb') as stream:stream.truncate(128*1024**2)
        path.chmod(0o600)
        aid=self.source.register(self.case,path.name)['artifact_id']
        meta=next(v for v in self.source.status(self.case)['artifacts'] if v['artifact_id']==aid)
        request=self.request();request['inputs']=[{'artifact_id':aid,'sha256':meta['sha256'],'bytes':meta['bytes']}]
        with self.source._locked(self.case) as (folder,manifest):
            original,_=self.source._artifact(folder,manifest,aid)
            descriptor=_regular_open(original)[0]
        try:result=self.broker.dispatch(request,[descriptor],os.getuid())
        finally:os.close(descriptor)
        self.assertEqual(result['inputs'][0]['bytes'],128*1024**2)
        self.assertEqual(result['inputs'][0]['sha256'],meta['sha256'])
        request['inputs'][0]['bytes']=4*1024**3+1
        descriptor=self.fd()
        try:
            with self.assertRaises(BrokerError):self.broker.dispatch(request,[descriptor],os.getuid())
        finally:os.close(descriptor)

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="rocky-execbridge-test-")
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        (base / "gateway").mkdir(mode=0o700)
        (base / "worker").mkdir(mode=0o700)
        self.source = CaseStore(base / "gateway")
        self.target = ExecutionStore(base / "worker", approval_dir=base / "unused-trust",
                                     trusted_approval_uid=os.getuid())
        config = self.target.cases.home / ".config" / "rocky-mcp-gateway"
        config.mkdir(parents=True, mode=0o700)
        image = config / "sandbox-image.txt"
        image.write_text(IMAGE + "\n")
        image.chmod(0o600)
        self.case = self.source.open_case()["case_id"]
        self.inbox = self.source.inbox
        self.log = self.inbox / "host.log"
        self.log.write_bytes(b"2026-10-16T17:00:00Z hello from case\n")
        self.log.chmod(0o600)
        self.artifact = self.source.register(self.case, "host.log")["artifact_id"]
        self.policy = ExecutionPolicy(os.getuid(), os.getuid() + 10000, os.getgid())
        self.broker = ExecutionBroker(self.target, self.policy)
        self.meta = self.source.status(self.case)["artifacts"][0]

    def request(self):
        return {"op": "prepare", "source_case_id": self.case,
                "script": "print('offline')\n",
                "inputs": [{"artifact_id": self.artifact,
                            "sha256": self.meta["sha256"], "bytes": self.meta["bytes"]}],
                "output_names": ["out.json"],
                "timeout_seconds": 30, "memory_mib": 256, "disk_mib": 32}

    def fd(self):
        with self.source._locked(self.case) as (folder, manifest):
            file, _ = self.source._artifact(folder, manifest, self.artifact)
            return _regular_open(file)[0]

    def test_broker_snapshots_an_evidence_fd_without_source_path(self):
        descriptor = self.fd()
        try:
            plan = self.broker.dispatch(self.request(), [descriptor], os.getuid())
        finally:
            os.close(descriptor)
        self.assertEqual(plan["state"], "PREPARED")
        self.assertEqual(len(plan["inputs"]), 1)
        self.assertEqual(plan["inputs"][0]["sha256"], self.meta["sha256"])
        self.assertNotEqual(plan["inputs"][0]["artifact_id"], self.artifact)
        self.assertEqual(self.target.status(plan["execution_id"])["state"], "PREPARED")
        self.assertEqual(self.source.status(self.case)["artifact_count"], 1)
        self.assertFalse((self.source.base / "execution.sqlite3").exists())
        self.assertTrue((self.target.base / "execution.sqlite3").exists())
        inspected, _ = self.target.inspect_local(plan["execution_id"])
        with self.target.cases._locked(inspected["plan"]["case_id"]) as (_, manifest):
            origin = manifest["execution_source"]
        self.assertEqual(origin["source_case_id"], self.case)
        self.assertEqual(origin["artifacts"][0]["source_artifact_id"], self.artifact)
        self.assertEqual(origin["artifacts"][0]["worker_artifact_id"],
                         plan["inputs"][0]["artifact_id"])
        self.assertEqual(origin["artifacts"][0]["sha256"], self.meta["sha256"])

    def test_mismatched_digest_rejected_and_never_queued(self):
        descriptor = self.fd()
        request = self.request()
        request["inputs"][0]["sha256"] = "0" * 64
        try:
            with self.assertRaises(BrokerError):
                self.broker.dispatch(request, [descriptor], os.getuid())
        finally:
            os.close(descriptor)
        self.assertEqual(self.source.status(self.case)["artifact_count"], 1)
        self.assertEqual(self.target.cases.list_cases()["cases_found"], 0)

    def test_rejected_plan_does_not_strand_worker_evidence(self):
        from unittest.mock import patch
        from sandboxwork import ExecutionError
        descriptor = self.fd()
        try:
            with patch.object(self.target, "prepare",
                              side_effect=ExecutionError("Execution plan capacity reached")):
                with self.assertRaises(ExecutionError):
                    self.broker.dispatch(self.request(), [descriptor], os.getuid())
        finally:
            os.close(descriptor)
        self.assertEqual(self.target.cases.list_cases()["cases_found"], 0)
        self.assertEqual(self.source.status(self.case)["artifact_count"], 1)

    def test_missing_or_extra_fds_rejected(self):
        with self.assertRaises(BrokerError):
            self.broker.dispatch(self.request(), [], os.getuid())
        descriptor = self.fd()
        try:
            with self.assertRaises(BrokerError):
                self.broker.dispatch({"op": "status", "execution_id": "a" * 32},
                                     [descriptor], os.getuid())
        finally:
            os.close(descriptor)

    def test_untrusted_peer_and_unknown_operation_refused(self):
        with self.assertRaises(BrokerError):
            self.broker.dispatch(self.request(), [], os.getuid() + 1)
        with self.assertRaises(BrokerError):
            self.broker.dispatch({"op": "execute_shell", "command": "whoami"},
                                 [], os.getuid())
        with self.assertRaises(BrokerError):
            self.broker.dispatch({"op": "status", "execution_id": "a" * 32,
                                  "bypass": True}, [], os.getuid())

    def test_worker_rejects_world_readable_source_fd(self):
        descriptor = self.fd()
        with self.source._locked(self.case) as (folder, manifest):
            f, _ = self.source._artifact(folder, manifest, self.artifact)
            f.chmod(0o644)
        try:
            with self.assertRaises(BrokerError):
                self.broker.dispatch(self.request(), [descriptor], os.getuid())
        finally:
            os.close(descriptor)

    def test_fd_passed_through_kernel_not_a_user_supplied_path(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        descriptor = self.fd()
        try:
            _send(a, self.request(), [descriptor])
            frame, rights = _receive(b)
            try:
                self.assertEqual(frame["op"], "prepare")
                self.assertEqual(len(rights), 1)
                self.assertEqual(os.fstat(rights[0]).st_size, self.meta["bytes"])
                self.assertEqual(_peer(b)[1], os.getuid())
            finally:
                for fd in rights:
                    os.close(fd)
        finally:
            os.close(descriptor)
            a.close()
            b.close()

    def test_duplicate_json_and_giant_frame_rejected(self):
        with self.assertRaises(BrokerError):
            _decode(b'{"op":"status","op":"prepare"}', 32768)
        with self.assertRaises(BrokerError):
            _decode(b"{}" * 20000, 32768)

    def test_shared_identity_configuration_is_rejected(self):
        with self.assertRaises(IdentityError):
            ExecutionPolicy(os.getuid(), os.getuid(), os.getgid())

    def test_socket_parent_cannot_be_gateway_writable(self):
        directory = self.source.home / "socket-dir"
        directory.mkdir(mode=0o700)
        trusted = ExecutionPolicy(os.getuid() + 10000, os.getuid(), os.getgid())
        directory.chmod(0o770)
        with self.assertRaises(BrokerError):
            _socket_parent(directory / "control.sock", trusted)

    def test_abandoned_private_socket_is_recovered_not_trusted_blindly(self):
        from unittest.mock import patch
        folder = self.source.home / "socket-test"
        folder.mkdir(mode=0o700)
        path = folder / "execution.sock"
        policy = ExecutionPolicy(os.getuid() + 10001, os.getuid(), os.getgid())
        broker = ExecutionBroker(self.target, policy, socket_path=path)
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        stale.bind(str(path))
        os.chmod(path, 0o660)
        stale.close()
        with patch.object(ExecutionPolicy, "check_worker", return_value=self.source.home):
            listening = broker.bind()
        try:
            self.assertTrue(path.exists())
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                client.connect(str(path))
        finally:
            listening.close()
            path.unlink(missing_ok=True)

    def test_live_worker_socket_is_not_unlinked_or_replaced(self):
        from unittest.mock import patch
        folder = self.source.home / "live-socket-test"
        folder.mkdir(mode=0o700)
        path = folder / "execution.sock"
        policy = ExecutionPolicy(os.getuid() + 10001, os.getuid(), os.getgid())
        live = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        live.bind(str(path))
        os.chmod(path, 0o660)
        live.listen(1)
        try:
            with patch.object(ExecutionPolicy, "check_worker", return_value=self.source.home):
                with self.assertRaises(BrokerError):
                    ExecutionBroker(self.target, policy, socket_path=path).bind()
            self.assertTrue(path.exists())
        finally:
            live.close()
            path.unlink(missing_ok=True)

    def test_forged_regular_file_at_worker_socket_is_preserved_and_rejected(self):
        from unittest.mock import patch
        folder = self.source.home / "forged-socket-test"
        folder.mkdir(mode=0o700)
        path = folder / "execution.sock"
        path.write_text("not a socket")
        path.chmod(0o660)
        policy = ExecutionPolicy(os.getuid() + 10001, os.getuid(), os.getgid())
        with patch.object(ExecutionPolicy, "check_worker", return_value=self.source.home):
            with self.assertRaises(BrokerError):
                ExecutionBroker(self.target, policy, socket_path=path).bind()
        self.assertEqual(path.read_text(), "not a socket")

    def test_gateway_tool_fails_closed_without_root_owned_policy_and_broker(self):
        normal = gateway.Gateway(gateway.Config({}, (), self.source.home))
        with self.assertRaises(gateway.GatewayError):
            normal.call("execution_status", {"execution_id": "a" * 32})
        self.assertFalse((self.source.base / "execution.sqlite3").exists())

if __name__ == "__main__":
    unittest.main()
