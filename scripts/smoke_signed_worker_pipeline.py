#!/usr/bin/env python3
"""Disposable CI-only: signed grant -> different-UID broker -> rootless Podman -> evidence.

The root test orchestrator creates an ephemeral synthetic gateway UID and an
ephemeral root-owned signing key; the existing GitHub runner UID is the worker
because it owns the disposable rootless Podman user session/image. No key is
put into worker/gateway state. The actual human terminal, production service
install and Rocky enforcing SELinux are NOT exercised by this test.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from approvalwork import DOMAIN, KEY_NAME, canonical
from casework import CaseStore
from execution_broker import ExecutionBroker, ExecutionBrokerClient, BrokerError
from execution_policy import ExecutionPolicy
from execworker import _run_jobs
from operator_sign import _read_review, _sign_bytes
from sandboxwork import ExecutionStore

SYNTHETIC_GATEWAY_UID = 31991
REVIEW_MAX = 30000
PIPE_MAX = 50000
TIMEOUT = 155


def exchange_write(fd: int, document: dict) -> None:
    raw = canonical(document) + b"\n"
    if len(raw) > PIPE_MAX:
        raise RuntimeError("Synthetic CI control frame too large")
    while raw:
        written = os.write(fd, raw)
        if written <= 0:
            raise RuntimeError("Synthetic CI control pipe failed")
        raw = raw[written:]


def exchange_read(fd: int, *, timeout: float = TIMEOUT) -> dict:
    deadline = time.monotonic() + timeout
    blob = bytearray()
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            break
        part = os.read(fd, 4096)
        if not part:
            raise RuntimeError("Synthetic CI control pipe closed")
        blob.extend(part)
        if len(blob) > PIPE_MAX:
            raise RuntimeError("Synthetic CI control frame exceeds quota")
        if b"\n" in blob:
            message, _ = bytes(blob).split(b"\n", 1)
            obj = json.loads(message)
            if not isinstance(obj, dict):
                raise RuntimeError("Synthetic CI control frame invalid")
            return obj
    raise RuntimeError("Synthetic CI control exchange timed out")


def drop(uid: int, gid: int, home: Path | None = None,
         runtime: str | None = None, bus: str | None = None) -> None:
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.geteuid() != uid:
        raise RuntimeError("CI test identity separation failed")
    if home is not None:
        os.environ.update({"HOME": str(home), "USER": home.name,
                           "LOGNAME": home.name, "XDG_RUNTIME_DIR": runtime or "",
                           "DBUS_SESSION_BUS_ADDRESS": bus or ""})


def worker_main(worker_uid: int, worker_gid: int, worker_home: Path,
                runtime: str, bus: str, ipc: Path, trust: Path,
                policy: ExecutionPolicy, ready_fd: int) -> None:
    drop(worker_uid, worker_gid, worker_home, runtime, bus)
    if os.access(trust.parent / "private_ed25519.pem", os.R_OK):
        raise RuntimeError("Worker can read private operator key")
    store = ExecutionStore(worker_home, approval_dir=trust, trusted_approval_uid=0)
    broker = ExecutionBroker(store, policy, socket_path=ipc)
    # Production bind() requires root-installed immutable modules. This
    # disposable runner uses the same stale-socket validation without
    # claiming its Git checkout passes that installation preflight.
    broker._reclaim_stale_socket()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(str(ipc))
    os.chmod(ipc, 0o660)
    listener.listen(8)
    listener.settimeout(0.5)
    stop = threading.Event()
    failed: list[str] = []

    def end(*_):
        stop.set()

    signal.signal(signal.SIGTERM, end)
    signal.signal(signal.SIGINT, end)
    # Same worker loop as production; socket is bound manually only because
    # the disposable runner's Git checkout is not the root-installed source.
    thread = threading.Thread(target=_run_jobs, args=(store, stop, failed), daemon=True)
    thread.start()
    os.write(ready_fd, b"READY")
    os.close(ready_fd)
    try:
        until = time.monotonic() + TIMEOUT
        while not stop.is_set() and time.monotonic() < until:
            broker.serve_one(listener)
        stop.set()
        thread.join(timeout=12)
        if failed or thread.is_alive():
            raise RuntimeError("CI worker loop failed to stop")
    finally:
        listener.close()
        ipc.unlink(missing_ok=True)


def poll(client: ExecutionBrokerClient, plan_id: str,
         target: set[str], timeout: float = 65) -> dict:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        state = client.status(plan_id)
        if state["state"] in target:
            return client.status(plan_id, include_result=True)
        if state["state"] in ("SUCCEEDED", "FAILED", "CANCELLED", "INTERRUPTED", "DENIED", "EXPIRED"):
            raise RuntimeError("Unexpected signed pipeline terminal state: " + state["state"])
        time.sleep(0.12)
    raise RuntimeError("Signed pipeline did not reach expected terminal state")


def gateway_main(gateway_home: Path, gateway_uid: int, worker_gid: int,
                 private_key: Path, socket_path: Path, policy: ExecutionPolicy,
                 request_fd: int, response_fd: int) -> None:
    drop(gateway_uid, worker_gid)
    if os.access(private_key, os.R_OK):
        raise RuntimeError("Gateway can read private operator key")
    store = CaseStore(gateway_home)
    case = store.open_case()["case_id"]
    src = store.inbox / "synthetic.log"
    value = b"2026-10-16T23:00:00Z synthetic-only Veeam backup job failure\n"
    src.write_bytes(value)
    src.chmod(0o600)
    artifact = store.register(case, src.name)
    client = ExecutionBrokerClient(gateway_home, policy=policy, socket_path=socket_path)
    expected_sha = hashlib.sha256(value).hexdigest()

    def signed_plan(script: str, output: str | list[str], decision: str,
                    timeout_seconds: int = 25) -> tuple[dict, dict]:
        plan = client.prepare(case, script, [artifact["artifact_id"]],
                              [output] if isinstance(output,str) else output, timeout_seconds=timeout_seconds)
        if plan["state"] != "PREPARED":
            raise RuntimeError("A script started before receiving a signed grant")
        review = client.export_review(plan["execution_id"])
        if review["plan"]["id"] != plan["execution_id"]:
            raise RuntimeError("Broker review bundle changed identity")
        exchange_write(request_fd, {"kind": "review", "decision": decision,
                                    "review": review})
        envelope = exchange_read(response_fd)
        if envelope.get("kind") != "signed_grant":
            raise RuntimeError("No signed grant returned by separate operator")
        grant = envelope["envelope"]
        accepted = client.import_signed_grant(grant)
        expected_state = "QUEUED" if decision == "APPROVE" else "DENIED"
        if accepted["state"] != expected_state:
            raise RuntimeError("Signed decision did not enforce expected state")
        # A previously imported grant must never re-queue or replay an execution.
        try:
            client.import_signed_grant(grant)
        except BrokerError:
            pass
        else:
            raise RuntimeError("Signed grant replay was accepted")
        return plan, review

    body = (
        "import hashlib, json\n"
        "from pathlib import Path\n"
        "inputs=[p for p in Path('/workspace').iterdir() if p.name != 'program.py']\n"
        "assert len(inputs)==1\n"
        f"assert hashlib.sha256(inputs[0].read_bytes()).hexdigest() == '{expected_sha}'\n"
        "Path('/output/result.json').write_text(json.dumps({'finding':'synthetic-only','source':"
        f"'{expected_sha}'}} , sort_keys=True))\n"
    )
    success, success_review = signed_plan(body, "result.json", "APPROVE")
    succeeded = poll(client, success["execution_id"], {"SUCCEEDED"})
    output = succeeded.get("result", {}).get("outputs", [])
    if len(output) != 1:
        raise RuntimeError("Successful signed execution has no durable artifact")
    derived = output[0]
    if (not isinstance(derived.get("artifact_id"), str)
            or len(derived["artifact_id"]) != 32
            or len(derived.get("sha256", "")) != 64):
        raise RuntimeError("Signed result lacks registered artifact identity/hash")

    # New read-only broker op must reject arbitrary approved script results.
    try:client.provider_result(success['execution_id'])
    except BrokerError:pass
    else:raise RuntimeError('Arbitrary script output passed fixed-provider reader')
    from providerplans import script_for
    provider, _ = signed_plan(script_for('ansible_syntax',expected_sha,'0.0.0'),
        ['provider-result.json','provider-raw.txt'],'APPROVE',timeout_seconds=120)
    poll(client,provider['execution_id'],{'SUCCEEDED'},timeout=130)
    metadata=client.provider_result(provider['execution_id'])
    if (metadata['provider_result']['status']!='NOT_AVAILABLE_VERSION_MISMATCH' or
            metadata['provider_result']['raw_output_disclosed'] or metadata['provider_result']['root_cause_established']):
        raise RuntimeError('Signed fixed-provider metadata boundary failed')

    refused, _ = signed_plan("print('DENIED MUST NOT RUN')\n", "denied.json", "DENY")
    denied = client.status(refused["execution_id"], include_result=True)
    if denied["state"] != "DENIED":
        raise RuntimeError("Signed DENY was not terminal")

    broken, _ = signed_plan("raise SystemExit(17)\n", "none.json", "APPROVE")
    failed = poll(client, broken["execution_id"], {"FAILED"})
    if failed.get("failure_code") != "script_nonzero_exit":
        raise RuntimeError("Nonzero script exit was not recorded as FAILED")

    hanging, _ = signed_plan("import time\ntime.sleep(50)\n", "later.json",
                             "APPROVE", timeout_seconds=30)
    poll(client, hanging["execution_id"], {"RUNNING"}, timeout=25)
    requested = client.cancel(hanging["execution_id"])
    if not requested["cancel_requested"]:
        raise RuntimeError("Cancellation request did not persist")
    cancelled = poll(client, hanging["execution_id"], {"CANCELLED"}, timeout=35)

    # Explicit real process crash: the separate root test orchestrator waits
    # until the container is actually running, SIGKILLs only this worker, then
    # starts a fresh worker with the same private grant/nonce database.
    orphan, _ = signed_plan("import time\ntime.sleep(90)\n", "orphan.json",
                            "APPROVE", timeout_seconds=120)
    poll(client, orphan["execution_id"], {"RUNNING"}, timeout=25)
    exchange_write(request_fd, {"kind": "interrupt",
                                "execution_id": orphan["execution_id"]})
    restarted = exchange_read(response_fd, timeout=55)
    if restarted.get("kind") != "worker_restarted":
        raise RuntimeError("Dedicated worker restart was not confirmed")
    interrupted = poll(client, orphan["execution_id"], {"INTERRUPTED"}, timeout=40)
    if interrupted.get("failure_code") != "worker_interrupted":
        raise RuntimeError("Orphan was not durably marked interrupted")

    exchange_write(request_fd, {
        "kind": "complete", "states": ["SUCCEEDED", "DENIED", "FAILED", "CANCELLED", "INTERRUPTED"],
        "worker_case_id": success_review["plan"]["case_id"],
        "worker_input_artifact_id": success["inputs"][0]["artifact_id"],
        "source_case": case, "artifact": derived,
        "success_execution": success["execution_id"],
        "source_sha256": expected_sha,
        "cancel_state": cancelled["state"],
        "interrupted_execution": orphan["execution_id"],
        "interrupted_state": interrupted["state"],
        "execution_ids": [success["execution_id"], refused["execution_id"],
                          broken["execution_id"], hanging["execution_id"],
                          orphan["execution_id"],provider['execution_id']],
        "fixed_provider_signed_read_boundary_verified": True,
    })


def wait_for_container(worker_uid: int, home: Path, runtime: str,
                       bus: str, execution_id: str) -> None:
    """Prove a real named container exists before killing the worker process."""
    username = pwd.getpwuid(worker_uid).pw_name
    name = "rocky-gw-job-" + execution_id
    command = ["/usr/sbin/runuser", "-u", username, "--", "/usr/bin/env",
               "HOME=" + str(home), "XDG_RUNTIME_DIR=" + runtime,
               "DBUS_SESSION_BUS_ADDRESS=" + bus,
               "/usr/bin/podman", "ps", "--format", "json"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=7, check=False)
        if result.returncode == 0:
            observed = json.loads(result.stdout)
            if any(name in (rec.get("Names") or []) for rec in observed):
                return
        time.sleep(0.3)
    raise RuntimeError("Interrupted worker never started a real Podman container")


def assert_container_gone(worker_uid: int, home: Path, runtime: str,
                          bus: str, execution_id: str) -> None:
    """The worker must remove the named orphan before reporting INTERRUPTED."""
    username = pwd.getpwuid(worker_uid).pw_name
    command = ["/usr/sbin/runuser", "-u", username, "--", "/usr/bin/env",
               "HOME=" + str(home), "XDG_RUNTIME_DIR=" + runtime,
               "DBUS_SESSION_BUS_ADDRESS=" + bus,
               "/usr/bin/podman", "ps", "-a", "--format", "json"]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=10, check=False)
    if result.returncode != 0:
        raise RuntimeError("Cannot verify crash container removal")
    name = "rocky-gw-job-" + execution_id
    records = json.loads(result.stdout)
    if any(name in (rec.get("Names") or []) for rec in records):
        raise RuntimeError("Interrupted sandbox container was not removed")


def sign_review(root: Path, private_key: Path, received: dict) -> dict:
    review = received["review"]
    if received.get("decision") not in ("APPROVE", "DENY"):
        raise RuntimeError("Unexpected synthetic operator decision")
    name = root / ("review-" + secrets.token_hex(8) + ".json")
    name.write_bytes(canonical(review) + b"\n")
    name.chmod(0o600)
    try:
        bundle, digest = _read_review(name)
    finally:
        name.unlink(missing_ok=True)
    now = int(time.time())
    expiry = min(now + 125, bundle["created"] + 1800)
    if expiry <= now:
        raise RuntimeError("Synthetic review expired")
    payload = {
        "domain": DOMAIN, "execution_id": bundle["plan"]["id"],
        "case_id": bundle["plan"]["case_id"], "plan_sha256": digest,
        "nonce": secrets.token_hex(16), "issued_at": now, "expires_at": expiry,
        "decision": received["decision"],
    }
    signature = _sign_bytes(private_key, canonical(payload), "/usr/bin/openssl")
    return {"kind": "signed_grant", "envelope": {
        "payload": payload, "signature": base64.b64encode(signature).decode("ascii")}}


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 2:
        print("CI root test orchestrator requires an immutable local image reference", file=sys.stderr)
        return 2
    worker_uid = int(os.environ["ROCKY_CI_WORKER_UID"])
    worker_gid = int(os.environ["ROCKY_CI_WORKER_GID"])
    home = Path(os.environ["ROCKY_CI_WORKER_HOME"])
    runtime = os.environ["ROCKY_CI_WORKER_RUNTIME"]
    bus = os.environ["ROCKY_CI_WORKER_BUS"]
    image = sys.argv[1]
    if (not image.startswith("localhost/rocky-ci-sandbox@sha256:")
            or len(image.rsplit("@sha256:", 1)[-1]) != 64):
        raise RuntimeError("Test image is not a canonical digest reference")

    parent = Path(tempfile.mkdtemp(prefix="rocky-eng-ci-e2e-", dir="/run"))
    parent.chmod(0o755)
    # /run is often a small tmpfs: keep only tiny socket/key control files
    # there. The case vault needs its full 5 GiB reserved headroom on disk.
    gateway_home = Path(tempfile.mkdtemp(prefix="rocky-e2e-gateway-", dir="/var/tmp"))
    os.chown(gateway_home, SYNTHETIC_GATEWAY_UID, worker_gid)
    gateway_home.chmod(0o700)
    sockdir = parent / "ipc"
    sockdir.mkdir()
    os.chown(sockdir, worker_uid, worker_gid)
    sockdir.chmod(0o750)
    sockpath = sockdir / "execution.sock"
    trust = parent / "operator-trust"
    trust.mkdir(mode=0o755)
    private = parent / "private_ed25519.pem"
    public = trust / KEY_NAME
    config_parent = home / ".config"
    if not config_parent.exists():
        config_parent.mkdir(mode=0o700)
        os.chown(config_parent, worker_uid, worker_gid)
    config = config_parent / "rocky-mcp-gateway"
    config.mkdir(mode=0o700, exist_ok=True)
    os.chown(config, worker_uid, worker_gid)
    config.chmod(0o700)
    pin = config / "sandbox-image.txt"
    if pin.exists() or pin.is_symlink():
        raise RuntimeError("Disposable worker image config unexpectedly already exists")
    pin.write_text(image + "\n")
    os.chown(pin, worker_uid, worker_gid)
    pin.chmod(0o600)
    subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519",
                    "-out", str(private)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    private.chmod(0o600)
    subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout",
                    "-out", str(public)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    public.chmod(0o644)
    policy = ExecutionPolicy(SYNTHETIC_GATEWAY_UID, worker_uid, worker_gid)
    ready_r, ready_w = os.pipe()
    requests_r, requests_w = os.pipe()
    grants_r, grants_w = os.pipe()
    worker = gateway = -1
    try:
        worker = os.fork()
        if worker == 0:
            os.close(ready_r)
            os.close(requests_r)
            os.close(requests_w)
            os.close(grants_r)
            os.close(grants_w)
            try:
                worker_main(worker_uid, worker_gid, home, runtime, bus,
                            sockpath, trust, policy, ready_w)
            except BaseException:
                traceback.print_exc()
                os._exit(31)
            os._exit(0)
        os.close(ready_w)
        ready = os.read(ready_r, 5)
        os.close(ready_r)
        if ready != b"READY":
            raise RuntimeError("Rootless execution worker did not start")
        gateway = os.fork()
        if gateway == 0:
            os.close(requests_r)
            os.close(grants_w)
            try:
                gateway_main(gateway_home, SYNTHETIC_GATEWAY_UID, worker_gid,
                             private, sockpath, policy, requests_w, grants_r)
            except BaseException:
                traceback.print_exc()
                os._exit(32)
            os._exit(0)
        os.close(requests_w)
        os.close(grants_r)
        completed = None
        for _ in range(10):
            item = exchange_read(requests_r)
            if item.get("kind") == "review":
                exchange_write(grants_w, sign_review(parent, private, item))
            elif item.get("kind") == "interrupt":
                execution_id = item.get("execution_id")
                if not isinstance(execution_id, str) or len(execution_id) != 32:
                    raise RuntimeError("Malformed interruption request")
                wait_for_container(worker_uid, home, runtime, bus, execution_id)
                os.kill(worker, signal.SIGKILL)
                _, killed = os.waitpid(worker, 0)
                worker = -1
                if os.waitstatus_to_exitcode(killed) != -signal.SIGKILL:
                    raise RuntimeError("Worker did not terminate at crash boundary")
                new_ready_r, new_ready_w = os.pipe()
                worker = os.fork()
                if worker == 0:
                    os.close(new_ready_r)
                    os.close(requests_r)
                    os.close(grants_w)
                    try:
                        worker_main(worker_uid, worker_gid, home, runtime, bus,
                                    sockpath, trust, policy, new_ready_w)
                    except BaseException:
                        traceback.print_exc()
                        os._exit(33)
                    os._exit(0)
                os.close(new_ready_w)
                if os.read(new_ready_r, 5) != b"READY":
                    raise RuntimeError("Restarted execution worker failed to bind")
                os.close(new_ready_r)
                # Startup recovery runs in a separate worker thread; the
                # listener can be READY before it has removed the orphan.
                # The gateway first waits for INTERRUPTED, then this root
                # controller checks no real container was stranded.
                exchange_write(grants_w, {"kind": "worker_restarted",
                                          "interrupted_execution": execution_id})
            elif item.get("kind") == "complete":
                completed = item
                break
            else:
                raise RuntimeError("Invalid CI operator workflow event")
        if completed is None or completed.get("states") != [
                "SUCCEEDED", "DENIED", "FAILED", "CANCELLED", "INTERRUPTED"]:
            raise RuntimeError("Signed pipeline did not complete all five states")
        assert_container_gone(worker_uid, home, runtime, bus,
                              completed["interrupted_execution"])
        for execution_id in completed["execution_ids"]:
            root = (home / ".local" / "share" / "rocky-mcp-gateway" /
                    "execution" / execution_id)
            if root.exists() or root.is_symlink():
                raise RuntimeError("Execution left a private temporary workspace")
        _, status = os.waitpid(gateway, 0)
        gateway = -1
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("Synthetic gateway workflow failed")
        worker_case = completed["worker_case_id"]
        aid = completed["artifact"]["artifact_id"]
        original = home / ".local" / "share" / "rocky-mcp-gateway" / "cases" / worker_case / "originals" / aid
        info = original.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != worker_uid
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise RuntimeError("Derived worker original is not private or regular")
        if hashlib.sha256(original.read_bytes()).hexdigest() != completed["artifact"]["sha256"]:
            raise RuntimeError("Derived worker original hash differs from execution result")
        manifest_path = original.parent.parent / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        lineage = manifest["execution_derivatives"][completed["success_execution"]]
        if (lineage["outputs"][0]["artifact_id"] != aid
                or lineage["input_artifacts"][0]["artifact_id"] != completed["worker_input_artifact_id"]
                or lineage["input_artifacts"][0]["sha256"] != completed["source_sha256"]):
            raise RuntimeError("Derived artifact has no verified source-input lineage")
        print(json.dumps({
            "qualification": "OFF_HOST_SIGNED_TWO_UID_PODMAN_PIPELINE",
            "status": "PASS",
            "states": completed["states"],
            "derived_artifact_sha256": completed["artifact"]["sha256"],
            "durable_worker_original_verified": True,
            "fixed_provider_signed_read_boundary_verified": completed['fixed_provider_signed_read_boundary_verified'],
            "source_to_derived_lineage_verified": True,
            "live_worker_sigkill_recovery_verified": True,
            "interrupted_container_absence_verified_after_restart": True,
            "operator_private_key_exposed_to_worker": False,
            "operator_private_key_exposed_to_gateway": False,
            "production_human_approval_qualified": False,
            "rocky_selinux_systemd_qualified": False,
        }, sort_keys=True))
        return 0
    finally:
        for fd in (requests_r, grants_w):
            try:
                os.close(fd)
            except OSError:
                pass
        for child in (gateway, worker):
            if child > 0:
                try:
                    os.kill(child, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
        pin.unlink(missing_ok=True)
        shutil.rmtree(parent)
        shutil.rmtree(gateway_home)


if __name__ == "__main__":
    raise SystemExit(main())
