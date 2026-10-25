#!/usr/bin/env python3
"""OFF-HOST root-only smoke: two real Linux UIDs and an SCM_RIGHTS broker.

Only run on an ephemeral disposable CI runner. Creates temporary UIDs without
modifying passwd/shadow or system services. NO Podman or Rocky01 is touched.
"""
from __future__ import annotations
import os
from pathlib import Path
import select
import shutil
import socket
import stat
import sys
import tempfile
import time
# Invoked by CI as scripts/smoke_execution_boundary.py, not as an installed module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from execution_broker import ExecutionBroker, ExecutionBrokerClient, BrokerError
from execution_policy import ExecutionPolicy
from sandboxwork import ExecutionStore
from casework import CaseStore

GATEWAY_UID = 31001
WORKER_UID = 31002
SOCKET_GID = 31003
IMAGE = "localhost/ci-only@sha256:" + "a" * 64


def _owned(path: Path, uid: int, gid: int, mode: int) -> None:
    path.mkdir(mode=mode, parents=False)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _drop(uid: int) -> None:
    os.setgroups([])
    os.setgid(SOCKET_GID)
    os.setuid(uid)
    if os.geteuid() != uid:
        raise RuntimeError("UID separation failed")


def _worker(worker_home: Path, sockpath: Path, policy: ExecutionPolicy, notify: int) -> None:
    _drop(WORKER_UID)
    store = ExecutionStore(worker_home)
    broker = ExecutionBroker(store, policy, socket_path=sockpath)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        listener.bind(str(sockpath))
        os.chmod(sockpath, 0o660)
        listener.listen(8)
        listener.setblocking(False)
        os.write(notify, b"READY")
        os.close(notify)
        count = 0
        deadline = time.monotonic() + 40
        while count < 5 and time.monotonic() < deadline:
            readable, _, _ = select.select([listener], [], [], 1)
            if not readable:
                continue
            listener.setblocking(True)
            broker.serve_one(listener)
            listener.setblocking(False)
            count += 1
        if count != 5:
            raise RuntimeError("Expected broker calls were not completed")
    finally:
        listener.close()


def _client(home: Path, worker_home: Path, sockpath: Path,
            policy: ExecutionPolicy) -> None:
    _drop(GATEWAY_UID)
    source = CaseStore(home)
    case_id = source.open_case()["case_id"]
    input_file = source.inbox / "case.log"
    input_file.write_bytes(b"2026-10-16T19:01:00Z forensic sample\n")
    input_file.chmod(0o600)
    artifact_id = source.register(case_id, "case.log")["artifact_id"]
    client = ExecutionBrokerClient(home, policy=policy, socket_path=sockpath)
    plan = client.prepare(case_id, "print('analysis only')\n", [artifact_id],
                          ["out.json"])
    if plan["state"] != "PREPARED" or len(plan["inputs"]) != 1:
        raise RuntimeError("Broker did not create an evidence-backed plan")
    try:
        with (worker_home / ".local/share/rocky-mcp-gateway/execution.sqlite3").open("rb"):
            pass
    except PermissionError:
        pass
    else:
        raise RuntimeError("Gateway UID accessed private worker execution database")
    if client.status(plan["execution_id"])["state"] != "PREPARED":
        raise RuntimeError("Broker status read failed")
    if client.cancel(plan["execution_id"])["state"] != "CANCELLED":
        raise RuntimeError("Broker cancellation failed")
    try:
        client.import_signed_grant({"payload": {}, "signature": ""})
    except BrokerError:
        pass
    else:
        raise RuntimeError("Unsigned grant accepted")
    try:
        client._exchange({"op": "execute_shell", "command": "id"})
    except BrokerError:
        pass
    else:
        raise RuntimeError("Unapproved command operation was accepted")


def main() -> int:
    if os.geteuid() != 0:
        print("BLOCKED: this smoke requires root on a disposable CI runner", file=sys.stderr)
        return 2
    root = Path(tempfile.mkdtemp(prefix="rocky-eng-crossuid-"))
    os.chmod(root, 0o711)
    rootdir = root / "run"
    gateway = root / "gateway"
    worker = root / "worker"
    try:
        _owned(rootdir, WORKER_UID, SOCKET_GID, 0o750)
        _owned(gateway, GATEWAY_UID, SOCKET_GID, 0o700)
        _owned(worker, WORKER_UID, SOCKET_GID, 0o700)
        config = worker / ".config"
        _owned(config, WORKER_UID, SOCKET_GID, 0o700)
        cfg = config / "rocky-mcp-gateway"
        _owned(cfg, WORKER_UID, SOCKET_GID, 0o700)
        key = cfg / "sandbox-image.txt"
        key.write_text(IMAGE + "\n")
        os.chown(key, WORKER_UID, SOCKET_GID)
        key.chmod(0o600)
        sockpath = rootdir / "execution.sock"
        policy = ExecutionPolicy(GATEWAY_UID, WORKER_UID, SOCKET_GID)
        rfd, wfd = os.pipe()
        server = os.fork()
        if server == 0:
            os.close(rfd)
            try:
                _worker(worker, sockpath, policy, wfd)
            except BaseException as exc:
                # This off-host smoke uses synthetic evidence only. Preserve
                # exception CLASS to distinguish worker exit from client exit.
                print("SYNTHETIC_BOUNDARY_WORKER: " + type(exc).__name__ +
                      ": " + str(exc)[:170], file=sys.stderr, flush=True)
                os._exit(2)
            os._exit(0)
        os.close(wfd)
        ready = os.read(rfd, 5)
        os.close(rfd)
        if ready != b"READY":
            raise RuntimeError("Dedicated worker never started")
        client_pid = os.fork()
        if client_pid == 0:
            try:
                _client(gateway, worker, sockpath, policy)
            except BaseException as exc:
                print("SYNTHETIC_BOUNDARY_CLIENT: " + type(exc).__name__ +
                      ": " + str(exc)[:170], file=sys.stderr, flush=True)
                os._exit(3)
            os._exit(0)
        _, client_state = os.waitpid(client_pid, 0)
        _, worker_state = os.waitpid(server, 0)
        if os.waitstatus_to_exitcode(client_state) != 0 or os.waitstatus_to_exitcode(worker_state) != 0:
            raise RuntimeError("Cross-UID evidence broker or denial checks failed")
        print("PASS: distinct gateway/worker UIDs, private worker DB, SCM_RIGHTS evidence intake, invalid grants denied")
        return 0
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())
