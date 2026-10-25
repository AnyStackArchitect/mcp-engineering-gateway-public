#!/usr/bin/env python3
"""READ-ONLY future Rocky10 execution-worker prerequisite report.

Does not provision users, install packages, change SELinux, alter systemd,
pull images, launch Podman or open the execution socket. A successful
prerequisite report is NOT a runtime/sandbox/deployment qualification.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import pwd
import stat
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from execution_policy import (ExecutionPolicy, IdentityError, MODULE_NAMES,
                              PUBLIC_KEY_FILE, WORKER_SOCKET, _trusted_path)

ROOT_CODE = Path("/opt/rocky-eng")


def _os_release(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, val = line.split("=", 1)
        props[key] = val.strip().strip('"')
    return props


def run_checks(*, os_release: Path = Path("/etc/os-release"),
               cgroup: Path = Path("/sys/fs/cgroup/cgroup.controllers"),
               selinux: Path = Path("/sys/fs/selinux/enforce")) -> dict[str, Any]:
    checks: dict[str, str] = {}
    policy = None

    def report(label: str, check) -> None:
        try:
            if not check():
                raise ValueError("check failed")
        except (OSError, ValueError, KeyError, TypeError, IdentityError):
            checks[label] = "BLOCKED"
        else:
            checks[label] = "OK"

    report("rocky10", lambda: (
        (lambda value: value.get("ID") == "rocky" and value.get("VERSION_ID", "").startswith("10."))
        (_os_release(os_release))))
    report("cgroup_v2_controllers",
           lambda: {"cpu", "memory", "pids"} <= set(cgroup.read_text("ascii").split()))
    report("selinux_enforcing", lambda: selinux.read_text("ascii").strip() == "1")
    report("root_owned_worker_source", lambda: (
        _trusted_path(ROOT_CODE, file=False) is not None
        and all(_trusted_path(ROOT_CODE / name) is not None for name in MODULE_NAMES)))
    report("root_owned_approval_public_key",
           lambda: _trusted_path(PUBLIC_KEY_FILE) is not None)

    try:
        policy = ExecutionPolicy.load()
        checks["trusted_execution_policy"] = "OK"
    except (IdentityError, OSError):
        checks["trusted_execution_policy"] = "BLOCKED"

    if policy is not None:
        def dedicated_home() -> bool:
            account = pwd.getpwuid(policy.worker_uid)
            path = Path(account.pw_dir)
            info = path.lstat()
            return (not path.is_symlink() and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == policy.worker_uid
                    and info.st_mode & 0o077 == 0)
        report("dedicated_worker_home", dedicated_home)

        def user_session() -> bool:
            directory = Path(f"/run/user/{policy.worker_uid}")
            info = directory.lstat()
            bus = directory / "bus"
            b = bus.lstat()
            return (not directory.is_symlink() and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == policy.worker_uid
                    and info.st_mode & 0o077 == 0
                    and not bus.is_symlink() and stat.S_ISSOCK(b.st_mode))
        report("worker_user_systemd_bus", user_session)

        def worker_socket() -> bool:
            info = WORKER_SOCKET.lstat()
            return (not WORKER_SOCKET.is_symlink()
                    and stat.S_ISSOCK(info.st_mode)
                    and info.st_uid == policy.worker_uid
                    and info.st_gid == policy.socket_group_gid
                    and stat.S_IMODE(info.st_mode) == 0o660)
        report("protected_execution_socket", worker_socket)
    else:
        for name in ("dedicated_worker_home", "worker_user_systemd_bus",
                     "protected_execution_socket"):
            checks[name] = "BLOCKED"

    # This read-only script deliberately does not test rootless Podman:
    # sudo-ing into worker identity or creating namespaces here would violate
    # prerequisite-inspection scope and mask missing operator approval.
    return {"qualification": "READ_ONLY_FUTURE_ROCKY_PREREQUISITES",
            "prerequisite_status": (
                "AVAILABLE_FOR_RUNTIME_TESTING" if all(v == "OK" for v in checks.values())
                else "BLOCKED"),
            "checks": checks,
            "rootless_podman_execution": "NOT_TESTED",
            "worker_systemd_install": "NOT_TESTED",
            "ed25519_operator_handoff": "NOT_TESTED",
            "release_gate": "OPEN"}


def main() -> int:
    if len(sys.argv) != 1:
        print("Read-only prerequisite checker accepts no arguments", file=sys.stderr)
        return 2
    try:
        result = run_checks()
    except Exception:
        print('{"prerequisite_status":"BLOCKED","error":"preflight_failed"}')
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["prerequisite_status"] == "AVAILABLE_FOR_RUNTIME_TESTING" else 2


if __name__ == "__main__":
    raise SystemExit(main())
