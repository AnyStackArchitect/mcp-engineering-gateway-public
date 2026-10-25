#!/usr/bin/env python3
"""Executable OFF-HOST qualification of the exact Podman isolation argv.

Requires an already available *test-only* image with /usr/bin/python3. The CI
workflow prepares that image on a disposable Ubuntu runner, never Rocky01.
This intentionally does NOT import a real signed operator grant, provision an
operator key, or claim SELinux/systemd acceptance for Rocky Linux.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from podman_policy import (PODMAN, container_run_command, container_exec_command,
                           container_remove_command)
from outputcopy import copy_outputs
from casework import CaseStore

MAX_SECONDS = 55


def checked(argv: list[str], *, timeout: int = MAX_SECONDS,
            capture: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
        timeout=timeout, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Podman command failed: " + argv[1])
    return result


def available(image: str) -> dict:
    if os.geteuid() == 0:
        raise RuntimeError("Rootless qualification refuses root")
    if not Path(PODMAN).exists():
        raise RuntimeError("Podman binary unavailable; BLOCKED, not passed")
    raw = checked([PODMAN, "info", "--format=json"]).stdout
    info = json.loads(raw)
    if info.get("host", {}).get("security", {}).get("rootless") is not True:
        raise RuntimeError("Podman is not running in rootless mode")
    checked([PODMAN, "image", "exists", image])
    return {"rootless": True,
            "selinux_enabled": bool(info.get("host", {}).get("security", {}).get("selinuxEnabled")),
            "cgroup_manager": info.get("host", {}).get("cgroupManager", "unknown"),
            "graph_driver": info.get("store", {}).get("graphDriverName", "unknown")}


def script(port: int, expected_sha: str) -> bytes:
    return (f'''import hashlib, json, os, socket
from pathlib import Path
content = Path("/workspace/evidence.txt").read_bytes()
assert hashlib.sha256(content).hexdigest() == "{expected_sha}"
for destination in ("/workspace/illicit.txt", "/etc/rocky-exec-escape"):
    try:
        Path(destination).write_text("not-allowed")
    except OSError:
        pass
    else:
        raise RuntimeError("Readonly boundary failed: " + destination)
with socket.socket() as probe:
    probe.settimeout(2)
    if probe.connect_ex(("127.0.0.1", {port})) == 0:
        raise RuntimeError("Host loopback network was reachable from sandbox")
proc_status = Path("/proc/self/status").read_text().splitlines()
caps = next(x.split(":",1)[1].strip() for x in proc_status if x.startswith("CapEff:"))
nnp = next(x.split(":",1)[1].strip() for x in proc_status if x.startswith("NoNewPrivs:"))
if int(caps,16) != 0 or nnp != "1":
    raise RuntimeError("Dropped capabilities/no-new-privileges not enforced")
cgroup = Path("/sys/fs/cgroup")
memory = (cgroup / "memory.max").read_text().strip()
pids = (cgroup / "pids.max").read_text().strip()
cpu = (cgroup / "cpu.max").read_text().strip().split()
if (not memory.isdigit() or int(memory) > 256 * 1024 * 1024
        or not pids.isdigit() or int(pids) > 64
        or len(cpu) != 2 or not all(v.isdigit() for v in cpu)
        or int(cpu[0]) > int(cpu[1])):
    raise RuntimeError("Cgroup v2 memory/pids/CPU limits not enforced")
output_bytes = os.statvfs("/output").f_frsize * os.statvfs("/output").f_blocks
if output_bytes > 32 * 1024 * 1024:
    raise RuntimeError("Output tmpfs size limit not enforced")
result = {{"result": "PASS", "evidence_sha256": "{expected_sha}", "uid": os.geteuid(), "network": "host-loopback-denied", "caps": caps, "no_new_privileges": nnp, "memory_bytes": int(memory), "pids_max": int(pids), "cpu_max": cpu, "output_tmpfs_bytes": output_bytes}}
Path("/output/result.json").write_text(json.dumps(result, sort_keys=True))
print("synthetic sandbox analysis complete")
''').encode("utf-8")


def exercise(image: str) -> dict:
    info = available(image)
    root = Path(tempfile.mkdtemp(prefix="rocky-podman-ci-"))
    os.chmod(root, 0o700)
    active_ids: list[str] = []
    try:
        readonly = root / "readonly"
        readonly.mkdir(mode=0o700)
        output = root / "copied"
        output.mkdir(mode=0o700)
        synthetic = b"synthetic-only; no real host or customer evidence\n"
        (readonly / "evidence.txt").write_bytes(synthetic)
        (readonly / "evidence.txt").chmod(0o600)
        digest = hashlib.sha256(synthetic).hexdigest()

        # The listener is on the disposable host loopback. Network=none must
        # prevent the isolated container connecting even to this listener.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            (readonly / "program.py").write_bytes(script(port, digest))
            (readonly / "program.py").chmod(0o600)
            plan_id = secrets.token_hex(16)
            plan = {"id": plan_id, "image": image, "memory_mib": 256, "disk_mib": 32}
            command = container_run_command(plan, readonly)
            if command.count("--volume") != 1 or "--network=none" not in command:
                raise RuntimeError("Production sandbox launch policy unexpectedly broadened")
            started = checked(command)
            active_ids.append(plan_id)
            if not started.stdout.strip():
                raise RuntimeError("Detached Podman did not report a container identity")
            outcome = checked(container_exec_command(plan_id), timeout=45)
            if b"synthetic sandbox analysis complete" not in outcome.stdout:
                raise RuntimeError("Expected isolated test script did not finish")
            capacity_home=root/'capacity-home';capacity_home.mkdir(mode=0o700)
            copy_outputs(CaseStore(capacity_home),{'id':plan_id,'disk_mib':8,'output_names':['result.json']},output)
            target = output / "result.json"
            if target.is_symlink() or not stat.S_ISREG(target.lstat().st_mode):
                raise RuntimeError("Missing or unsafe output file")
            result = json.loads(target.read_text())
            if (result.get("result") != "PASS" or result.get("network") != "host-loopback-denied"
                    or result.get("evidence_sha256") != digest or result.get("uid") != os.geteuid()
                    or int(result.get("caps", "1"), 16) != 0
                    or result.get("no_new_privileges") != "1"
                    or result.get("memory_bytes", 2**63) > 256 * 1024 * 1024
                    or result.get("pids_max", 10**6) > 64
                    or result.get("output_tmpfs_bytes", 2**63) > 32 * 1024 * 1024):
                raise RuntimeError("Runtime isolation proof content invalid")
            checked(container_remove_command(plan_id), timeout=30)
            active_ids.remove(plan_id)

        # A failed script must be reflected in an actual nonzero podman exec
        # code. An externally timed out exec must not leave an orphan.
        readonly_bad = root / "negative"
        readonly_bad.mkdir(mode=0o700)
        (readonly_bad / "program.py").write_text("raise SystemExit(17)\n")
        (readonly_bad / "program.py").chmod(0o600)
        failed_id = secrets.token_hex(16)
        negative_plan = {"id": failed_id, "image": image, "memory_mib": 256, "disk_mib": 32}
        checked(container_run_command(negative_plan, readonly_bad))
        active_ids.append(failed_id)
        failed = subprocess.run(container_exec_command(failed_id),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=False)
        if failed.returncode != 17:
            raise RuntimeError("Nonzero sandbox Python exit code not preserved")
        checked(container_remove_command(failed_id), timeout=30)
        active_ids.remove(failed_id)

        readonly_timeout = root / "timeout"
        readonly_timeout.mkdir(mode=0o700)
        (readonly_timeout / "program.py").write_text("import time; time.sleep(60)\n")
        (readonly_timeout / "program.py").chmod(0o600)
        timeout_id = secrets.token_hex(16)
        timeout_plan = {"id": timeout_id, "image": image, "memory_mib": 256, "disk_mib": 32}
        checked(container_run_command(timeout_plan, readonly_timeout))
        active_ids.append(timeout_id)
        child = subprocess.Popen(container_exec_command(timeout_id), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            try:
                child.wait(timeout=2)
                raise RuntimeError("Timeout fixture returned unexpectedly")
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
        checked(container_remove_command(timeout_id), timeout=30)
        active_ids.remove(timeout_id)

        check = checked([PODMAN, "ps", "-a", "--format", "json"], timeout=30)
        remaining = json.loads(check.stdout)
        matching = [r for r in remaining if "rocky-gw-job-" in " ".join(r.get("Names", []))]
        if matching:
            raise RuntimeError("One or more named qualification containers remain")
        info.update({"real_container_policy": "PASS", "readonly_evidence": "PASS",
                     "readonly_root": "PASS", "no_host_loopback": "PASS",
                     "drop_all_caps": "PASS", "bounded_output_copy": "PASS",
                     "nonzero_exit": "PASS", "kill_and_remove": "PASS",
                     "no_orphan": "PASS", "cgroup_v2_limits": "PASS",
                     "no_new_privileges": "PASS", "output_tmpfs_quota": "PASS",
                     "selinux_rocky_qualified": False,
                     "systemd_rocky_qualified": False,
                     "signed_grant_end_to_end_qualified": False})
        return info
    finally:
        # Cleanup even if the test fails. Failure to verify cleanup remains
        # a failure, not a successful result.
        cleanup_errors = []
        for execution_id in active_ids:
            try:
                checked(container_remove_command(execution_id), timeout=30)
            except (OSError, subprocess.SubprocessError, RuntimeError):
                cleanup_errors.append(execution_id)
        import shutil
        shutil.rmtree(root, ignore_errors=False)
        if cleanup_errors:
            raise RuntimeError("Sandbox cleanup was not verified")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: qualify_podman_runtime.py TEST_ONLY_IMAGE", file=sys.stderr)
        return 2
    try:
        result = exercise(sys.argv[1])
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError,
            json.JSONDecodeError) as exc:
        print("BLOCKED/FAIL: " + type(exc).__name__ + ": " + str(exc)[:160], file=sys.stderr)
        return 2
    print(json.dumps({"qualification": "OFF_HOST_UBUNTU_ONLY",
                      "status": "PASS", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
