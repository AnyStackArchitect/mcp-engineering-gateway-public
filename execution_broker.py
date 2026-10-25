#!/usr/bin/env python3
"""Bounded Unix SEQPACKET broker to a separately owned execution worker.

The client (chat-facing gateway UID) passes read-only case evidence FDs with
SCM_RIGHTS, never arbitrary host paths. The worker (different UID) creates its
own private evidence copies, approval ledger and Podman workspace. No general
command/shell execution or public/network listener is exposed.
"""
from __future__ import annotations

from array import array
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import time
from typing import Any

from casework import CaseStore, CASE_ID, _regular_open, _write_json_atomic
from sandboxwork import ExecutionStore, ExecutionError, MAX_INPUTS, MAX_INPUT_BYTES
from approvalwork import decode as decode_grant, MAX_GRANT_BYTES
from execution_policy import ExecutionPolicy, IdentityError, WORKER_SOCKET, _trusted_path
from providerplans import read_result as read_provider_result
from capacitywork import admission_lock, verify_committed_reserve

MAX_WIRE = 32768
MAX_REPLY = 12000
MAX_STAGE_SECONDS = 90
FD_BYTES = array("i").itemsize
HEX64 = re.compile(r"^[a-f0-9]{64}$")
OPS = frozenset(("prepare", "status", "result", "provider_result", "cancel", "export", "import_signed"))


class BrokerError(Exception):
    """A socket exchange was refused or could not be verified."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise BrokerError("Duplicate request field")
        obj[key] = value
    return obj


def _decode(raw: bytes, limit: int) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= limit:
        raise BrokerError("Request frame size invalid")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise BrokerError("Request frame invalid") from exc
    if not isinstance(value, dict):
        raise BrokerError("Request must be a JSON object")
    return value


def _encode(value: dict[str, Any], limit: int) -> bytes:
    data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(data) > limit:
        raise BrokerError("Response or request exceeds wire limit")
    return data


def _peer(sock: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrokerError("Linux peer credentials are unavailable")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _receive(sock: socket.socket) -> tuple[dict[str, Any], list[int]]:
    ancillary_limit = socket.CMSG_SPACE(FD_BYTES * MAX_INPUTS)
    raw, controls, flags, _ = sock.recvmsg(
        MAX_WIRE + 1, ancillary_limit, getattr(socket, "MSG_CMSG_CLOEXEC", 0))
    received: list[int] = []
    try:
        for level, kind, value in controls:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise BrokerError("Unknown ancillary control rejected")
            count = len(value) // FD_BYTES
            numbers = array("i")
            numbers.frombytes(value[:count * FD_BYTES])
            received.extend(numbers)
        if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(received) > MAX_INPUTS):
            raise BrokerError("Truncated broker frame or too many file descriptors")
        return _decode(raw, MAX_WIRE), received
    except BaseException:
        for fd in received:
            os.close(fd)
        raise


def _send(sock: socket.socket, value: dict[str, Any], fds: list[int] | None = None) -> None:
    raw = _encode(value, MAX_WIRE)
    extra = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", fds))] if fds else []
    sent = sock.sendmsg([raw], extra)
    if sent != len(raw):
        raise BrokerError("Incomplete broker message")


def _socket_parent(path: Path, policy: ExecutionPolicy) -> None:
    if path == WORKER_SOCKET:
        # The real /run ancestry must be administrator-controlled; only the
        # final private socket directory may be owned by the worker account.
        _trusted_path(path.parent.parent, file=False)
    elif path.is_relative_to(Path("/run/rocky-eng")):
        raise BrokerError("Unexpected worker socket name")
    # Alternate test paths cannot be selected by either runtime entrypoint.
    parent = path.parent
    if parent.is_symlink():
        raise BrokerError("Worker socket parent may not be a symlink")
    try:
        info = parent.lstat()
    except OSError as exc:
        raise BrokerError("Worker socket directory not provisioned") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != policy.worker_uid
            or info.st_gid != policy.socket_group_gid
            or info.st_mode & 0o027):
        raise BrokerError("Worker socket directory is not worker-controlled")


class ExecutionBroker:
    """Server-side broker; instantiate ONLY under the protected worker UID."""

    def __init__(self, store: ExecutionStore, policy: ExecutionPolicy,
                 socket_path: Path = WORKER_SOCKET):
        self.store = store
        self.policy = policy
        self.socket_path = socket_path

    def _reclaim_stale_socket(self) -> None:
        """Only reclaim a genuine abandoned worker-owned socket after lock acquisition."""
        try:
            prior = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISSOCK(prior.st_mode) or prior.st_uid != self.policy.worker_uid
                or prior.st_gid != self.policy.socket_group_gid
                or stat.S_IMODE(prior.st_mode) != 0o660):
            raise BrokerError("Untrusted existing worker socket cannot be replaced")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as probe:
            probe.settimeout(0.4)
            try:
                probe.connect(str(self.socket_path))
            except ConnectionRefusedError:
                current = self.socket_path.lstat()
                if (current.st_ino != prior.st_ino or current.st_dev != prior.st_dev
                        or not stat.S_ISSOCK(current.st_mode)
                        or current.st_uid != self.policy.worker_uid):
                    raise BrokerError("Worker socket changed while being reclaimed")
                self.socket_path.unlink()
            except OSError as exc:
                raise BrokerError("Worker socket status cannot be verified") from exc
            else:
                raise BrokerError("Existing worker listener remains active")

    def bind(self) -> socket.socket:
        self.policy.check_worker()
        _socket_parent(self.socket_path, self.policy)
        # Caller already holds the exclusive worker process lock.
        self._reclaim_stale_socket()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o660)
            info = self.socket_path.lstat()
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.policy.worker_uid
                    or info.st_gid != self.policy.socket_group_gid
                    or info.st_mode & 0o007):
                raise BrokerError("Worker socket ownership or permissions unsafe")
            listener.listen(8)
            listener.settimeout(1.0)
            return listener
        except BaseException:
            listener.close()
            raise

    def serve_one(self, listener: socket.socket) -> None:
        try:
            peer_socket, _ = listener.accept()
        except socket.timeout:
            return
        with peer_socket:
            peer_socket.settimeout(120)
            try:
                _, peer_uid, _ = _peer(peer_socket)
                if peer_uid != self.policy.gateway_uid:
                    raise BrokerError("Unapproved local client identity")
                request, fds = _receive(peer_socket)
                try:
                    response = self.dispatch(request, fds, peer_uid)
                finally:
                    for fd in fds:
                        os.close(fd)
                result = {"ok": True, "data": response}
            except (BrokerError, ExecutionError, IdentityError, OSError,
                    ValueError, TypeError, KeyError):
                result = {"ok": False, "error": "execution_broker_rejected"}
            except Exception:
                result = {"ok": False, "error": "execution_broker_failed"}
            try:
                peer_socket.send(_encode(result, MAX_REPLY))
            except (OSError, BrokerError):
                pass

    def _snapshot(self, request: dict[str, Any], fds: list[int], peer_uid: int) -> tuple[str, list[str]]:
        sources = request["inputs"]
        if (not isinstance(sources, list) or len(sources) > MAX_INPUTS
                or len(sources) != len(fds)
                or not isinstance(request["source_case_id"], str)
                or not CASE_ID.fullmatch(request["source_case_id"])):
            raise BrokerError("Invalid source evidence inventory")
        total = 0
        for item in sources:
            if (not isinstance(item, dict)
                    or set(item) != {"artifact_id", "sha256", "bytes"}
                    or not isinstance(item["artifact_id"], str)
                    or not CASE_ID.fullmatch(item["artifact_id"])
                    or not isinstance(item["sha256"], str)
                    or not HEX64.fullmatch(item["sha256"])
                    or type(item["bytes"]) is not int or item["bytes"] < 0):
                raise BrokerError("Invalid evidence metadata")
            total += item["bytes"]
        if total > MAX_INPUT_BYTES:
            raise BrokerError("Execution source evidence quota exceeded")
        cid = self.store.cases.open_case()["case_id"]
        try:
            registered = []
            deadline = time.monotonic() + MAX_STAGE_SECONDS
            for index, (item, fd) in enumerate(zip(sources, fds)):
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != peer_uid
                        or before.st_mode & 0o077 or before.st_nlink != 1
                        or before.st_size != item["bytes"]):
                    raise BrokerError("Source FD identity and metadata mismatch")
                os.lseek(fd, 0, os.SEEK_SET)
                staged = self.store.cases.inbox / ("exec-" + cid[:16] + "-" + str(index) + ".dat")
                target = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0), 0o600)
                digest = hashlib.sha256()
                amount = 0
                try:
                    with os.fdopen(target, "wb") as out:
                        while amount < item["bytes"]:
                            if time.monotonic() > deadline:
                                raise BrokerError("Evidence transfer time limit exceeded")
                            chunk = os.read(fd, min(1024 * 1024, item["bytes"] - amount))
                            if not chunk:
                                raise BrokerError("Source evidence truncated during transfer")
                            amount += len(chunk)
                            digest.update(chunk)
                            with admission_lock(self.store.cases):
                                verify_committed_reserve(self.store.cases,extra_bytes=len(chunk))
                                out.write(chunk)
                                out.flush()
                        out.flush()
                        os.fsync(out.fileno())
                    after = os.fstat(fd)
                    if (amount != item["bytes"] or digest.hexdigest() != item["sha256"]
                            or before.st_size != after.st_size
                            or before.st_mtime_ns != after.st_mtime_ns
                            or before.st_ctime_ns != after.st_ctime_ns):
                        raise BrokerError("Source evidence changed or digest mismatched")
                    registered.append(self.store.cases.register(cid, staged.name,worker=True)["artifact_id"])
                finally:
                    staged.unlink(missing_ok=True)
            with self.store.cases._locked(cid) as (folder, manifest):
                manifest["execution_source"] = {
                    "source_case_id": request["source_case_id"],
                    "artifacts": [
                        {"source_artifact_id": item["artifact_id"],
                         "worker_artifact_id": aid,
                         "sha256": item["sha256"], "bytes": item["bytes"]}
                        for item, aid in zip(sources, registered)
                    ],
                }
                _write_json_atomic(folder / "manifest.json", manifest)
            return cid, registered
        except BaseException:
            # This case was freshly created by the broker and is unknown to
            # other clients. An invalid source must not consume the finite
            # worker case quota or strand untrusted partially copied evidence.
            shutil.rmtree(self.store.cases.cases / cid)
            raise

    def dispatch(self, request: dict[str, Any], fds: list[int],
                 peer_uid: int) -> dict[str, Any]:
        if not isinstance(request, dict) or request.get("op") not in OPS:
            raise BrokerError("Unknown worker operation")
        if peer_uid != self.policy.gateway_uid:
            raise BrokerError("Worker request peer UID not permitted")
        op = request["op"]
        fields = {
            "prepare": {"op", "source_case_id", "script", "inputs", "output_names",
                        "timeout_seconds", "memory_mib", "disk_mib"},
            "status": {"op", "execution_id"},
            "result": {"op", "execution_id"},
            "provider_result": {"op", "execution_id"},
            "cancel": {"op", "execution_id"},
            "export": {"op", "execution_id"},
            "import_signed": {"op", "envelope"},
        }
        if set(request) != fields[op]:
            raise BrokerError("Worker operation shape invalid")
        if op != "prepare" and fds:
            raise BrokerError("Unexpected evidence descriptor")
        if op == "prepare":
            if (not isinstance(request["script"], str)
                    or not isinstance(request["output_names"], list)):
                raise BrokerError("Invalid execution preparation")
            cid, artifacts = self._snapshot(request, fds, peer_uid)
            try:
                return self.store.prepare(
                    cid, request["script"], artifacts, request["output_names"],
                    timeout_seconds=request["timeout_seconds"],
                    memory_mib=request["memory_mib"],
                    disk_mib=request["disk_mib"])
            except BaseException:
                # A rejected plan must not consume the finite worker-owned case
                # quota. Its new snapshot is not referenced by a committed plan.
                shutil.rmtree(self.store.cases.cases / cid)
                raise
        if op == "import_signed":
            if not isinstance(request["envelope"], dict):
                raise BrokerError("Signed grant envelope invalid")
            if len(_encode(request["envelope"], MAX_GRANT_BYTES)) > MAX_GRANT_BYTES:
                raise BrokerError("Signed grant envelope too large")
            return self.store.import_signed_grant(request["envelope"])
        if not isinstance(request["execution_id"], str) or not CASE_ID.fullmatch(request["execution_id"]):
            raise BrokerError("Invalid execution identifier")
        if op == "status":
            return self.store.status(request["execution_id"])
        if op == "result":
            return self.store.status(request["execution_id"], include_result=True)
        if op == "provider_result":
            return read_provider_result(self.store,request['execution_id'])
        if op == "cancel":
            return self.store.cancel(request["execution_id"])
        if op == "export":
            details, script = self.store.inspect_local(request["execution_id"])
            if details["state"] != "PREPARED":
                raise BrokerError("Only unapproved plans may be reviewed")
            return {**details, "script": script}
        raise BrokerError("Worker operation not supported")


class ExecutionBrokerClient:
    """Gateway/CLI client. Never opens a worker-private database or Podman."""

    def __init__(self, home: Path, *, policy: ExecutionPolicy | None = None,
                 socket_path: Path = WORKER_SOCKET):
        self.cases = CaseStore(home)
        self.policy = policy
        self.socket_path = socket_path

    def _exchange(self, request: dict[str, Any], fds: list[int] | None = None) -> dict[str, Any]:
        policy = self.policy or ExecutionPolicy.load()
        policy.check_gateway()
        _socket_parent(self.socket_path, policy)
        info = self.socket_path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != policy.worker_uid
                or info.st_gid != policy.socket_group_gid
                or stat.S_IMODE(info.st_mode) != 0o660):
            raise BrokerError("Worker socket identity cannot be verified")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
            conn.settimeout(120)
            try:
                conn.connect(str(self.socket_path))
                _, uid, _ = _peer(conn)
                if uid != policy.worker_uid:
                    raise BrokerError("Connected process is not the approved worker identity")
                _send(conn, request, fds)
                frame, _, flags, _ = conn.recvmsg(MAX_REPLY + 1)
            except (OSError, socket.timeout) as exc:
                raise BrokerError("Dedicated execution worker unavailable") from exc
        if flags & socket.MSG_TRUNC:
            raise BrokerError("Worker response truncated")
        response = _decode(frame, MAX_REPLY)
        if not response.get("ok") or not isinstance(response.get("data"), dict):
            raise BrokerError("Dedicated worker rejected the request")
        return response["data"]

    def prepare(self, case_id: str, script: str, artifact_ids: list[str],
                output_names: list[str], *, timeout_seconds: int = 60,
                memory_mib: int = 256, disk_mib: int = 32) -> dict[str, Any]:
        if (not isinstance(artifact_ids, list) or len(artifact_ids) > MAX_INPUTS
                or any(not isinstance(a, str) or not CASE_ID.fullmatch(a)
                       for a in artifact_ids)):
            raise BrokerError("Invalid execution evidence identifiers")
        descriptors = []
        inputs = []
        try:
            with self.cases._locked(case_id) as (folder, manifest):
                for aid in artifact_ids:
                    path, item = self.cases._artifact(folder, manifest, aid)
                    fd, info = _regular_open(path)
                    descriptors.append(fd)
                    if info.st_nlink != 1:
                        raise BrokerError("Evidence descriptor has multiple hard links")
                    inputs.append({"artifact_id": aid, "sha256": item["sha256"],
                                   "bytes": item["bytes"]})
            # Never hold gateway case locks over RPC: the worker may need
            # shared admission while another writer waits on this case.
            # Retained FDs plus worker hash/fstat checks bind source identity.
            return self._exchange({
                "op": "prepare", "source_case_id": case_id, "script": script,
                "inputs": inputs, "output_names": output_names,
                "timeout_seconds": timeout_seconds,
                "memory_mib": memory_mib, "disk_mib": disk_mib,
            }, descriptors)
        finally:
            for fd in descriptors:os.close(fd)

    def status(self, execution_id: str, *, include_result: bool = False) -> dict[str, Any]:
        return self._exchange({"op": "result" if include_result else "status",
                               "execution_id": execution_id})

    def provider_result(self,execution_id: str) -> dict[str,Any]:
        return self._exchange({'op':'provider_result','execution_id':execution_id})

    def cancel(self, execution_id: str) -> dict[str, Any]:
        return self._exchange({"op": "cancel", "execution_id": execution_id})

    def export_review(self, execution_id: str) -> dict[str, Any]:
        return self._exchange({"op": "export", "execution_id": execution_id})

    def import_signed_grant(self, envelope: dict[str, Any]) -> dict[str, Any]:
        return self._exchange({"op": "import_signed", "envelope": envelope})
