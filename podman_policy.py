"""Single source of truth for the rootless analysis-container launch policy.

No subprocess invocation or privilege crossing occurs in this module. The
execution worker supplies an already verified SHA-256-pinned image and private
read-only staging path. The isolated CI runtime smoke exercises these exact
argv fields using a disposable TEST-ONLY image, not a production image.
"""
from __future__ import annotations

from pathlib import Path
import os

PODMAN = "/usr/bin/podman"
PYTHON = "/usr/bin/python3"


def container_name(execution_id: str) -> str:
    return "rocky-gw-job-" + execution_id


def container_run_command(plan: dict, readonly_dir: Path,
                          *, uid: int | None = None,
                          gid: int | None = None) -> list[str]:
    """Build the exact detached Podman policy without running it."""
    user = os.getuid() if uid is None else uid
    group = os.getgid() if gid is None else gid
    return [
        PODMAN, "run", "--detach", "--name", container_name(plan["id"]),
        "--pull=never", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--userns=keep-id", "--user", f"{user}:{group}",
        "--pids-limit=64", "--cpus=1",
        "--memory=" + str(plan["memory_mib"]) + "m",
        "--memory-swap=" + str(plan["memory_mib"]) + "m",
        "--ulimit", "nofile=64:64", "--ulimit", "core=0:0",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
        "--tmpfs", "/output:rw,nosuid,nodev,size=" + str(plan["disk_mib"]) + "m",
        "--volume", str(readonly_dir) + ":/workspace:ro,Z",
        "--workdir", "/workspace", "--entrypoint", PYTHON,
        "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
        plan["image"], "-I", "-B", "-c",
        "import time; time.sleep(1000000)",
    ]


def container_exec_command(execution_id: str) -> list[str]:
    return [PODMAN, "exec", container_name(execution_id), PYTHON,
            "-I", "-B", "/workspace/program.py"]


def container_remove_command(execution_id: str) -> list[str]:
    return [PODMAN, "rm", "--force", "--ignore", container_name(execution_id)]
