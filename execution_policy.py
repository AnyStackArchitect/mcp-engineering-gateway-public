#!/usr/bin/env python3
"""Trusted, fail-closed OS identity policy for the separate sandbox worker.

Production entrypoints load ONLY /etc/rocky-eng/execution-policy.json. An
environment variable, MCP argument or same-user writable file cannot select
the execution identity or grant ownership.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
import os
from pathlib import Path
import pwd
import stat

POLICY_FILE = Path("/etc/rocky-eng/execution-policy.json")
PUBLIC_KEY_FILE = Path("/etc/rocky-eng/approval_ed25519_pub.pem")
WORKER_SOCKET = Path("/run/rocky-eng/execution.sock")
MODULE_NAMES = ("execution_policy.py", "execution_broker.py",
                "execworker.py", "sandboxwork.py", "approvalwork.py",
                "casework.py", "podman_policy.py", "outputwork.py",
                "capacitywork.py", "sharedcapacity.py", "providerplans.py", "provider_runner.py", "windows_memory_runner.py", "xfs_recovery_runner.py", "outputcopy.py")


class IdentityError(Exception):
    """The worker or gateway lacks a trustworthy runtime security boundary."""


def _trusted_path(path: Path, *, file: bool = True) -> os.stat_result:
    """Check every component; never follow a symlink in an admin-managed path."""
    if not path.is_absolute():
        raise IdentityError("Administrator-managed path must be absolute")
    chain = list(reversed(path.parents)) + [path]
    last = None
    for i, component in enumerate(chain):
        try:
            last = component.lstat()
        except OSError as exc:
            raise IdentityError("Administrator-managed path is missing") from exc
        if stat.S_ISLNK(last.st_mode) or last.st_uid != 0 or last.st_mode & 0o022:
            raise IdentityError("Administrator-managed path can be changed by another identity")
        if i < len(chain) - 1 and not stat.S_ISDIR(last.st_mode):
            raise IdentityError("Invalid administrator-managed path")
    if last is None or (file and (not stat.S_ISREG(last.st_mode) or last.st_nlink != 1)):
        raise IdentityError("Administrator-managed file type is unsafe")
    if not file and not stat.S_ISDIR(last.st_mode):
        raise IdentityError("Administrator-managed directory type is unsafe")
    return last


@dataclass(frozen=True)
class ExecutionPolicy:
    gateway_uid: int
    worker_uid: int
    socket_group_gid: int

    def __post_init__(self):
        ids = (self.gateway_uid, self.worker_uid, self.socket_group_gid)
        if any(type(value) is not int or value < 100 or value > 2**31 - 1 for value in ids):
            raise IdentityError("Dedicated system identity configuration invalid")
        if self.gateway_uid == self.worker_uid:
            raise IdentityError("Gateway and sandbox worker must have different UIDs")

    @classmethod
    def load(cls) -> "ExecutionPolicy":
        """Only the root-owned machine policy may configure runtime identities."""
        info = _trusted_path(POLICY_FILE)
        if info.st_size <= 0 or info.st_size > 1024:
            raise IdentityError("Worker policy size invalid")
        try:
            raw = POLICY_FILE.read_text("ascii")
            obj = json.loads(raw)
        except (OSError, UnicodeError, ValueError) as exc:
            raise IdentityError("Worker policy unreadable") from exc
        if not isinstance(obj, dict) or set(obj) != {
                "schema", "gateway_uid", "worker_uid", "socket_group_gid"} or obj["schema"] != 1:
            raise IdentityError("Worker policy schema invalid")
        return cls(obj["gateway_uid"], obj["worker_uid"], obj["socket_group_gid"])

    def check_worker(self, *, uid: int | None = None, gid: int | None = None,
                     module_dir: Path | None = None) -> Path:
        actual_uid = os.geteuid() if uid is None else uid
        actual_gid = os.getegid() if gid is None else gid
        if actual_uid != self.worker_uid or actual_uid == 0:
            raise IdentityError("Sandbox worker is not running under the dedicated identity")
        if actual_gid != self.socket_group_gid:
            raise IdentityError("Sandbox worker has the wrong IPC socket group")
        directory = (Path(__file__).resolve().parent if module_dir is None else module_dir)
        _trusted_path(directory, file=False)
        for name in MODULE_NAMES:
            _trusted_path(directory / name)
        _trusted_path(PUBLIC_KEY_FILE)
        try:
            account = pwd.getpwuid(self.worker_uid)
            home = Path(account.pw_dir)
            info = home.lstat()
        except (KeyError, OSError) as exc:
            raise IdentityError("Dedicated worker account unavailable") from exc
        if (home.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != self.worker_uid or info.st_mode & 0o077):
            raise IdentityError("Dedicated worker home must be private")
        return home

    def check_gateway(self, *, uid: int | None = None) -> None:
        actual_uid = os.geteuid() if uid is None else uid
        if actual_uid != self.gateway_uid or actual_uid == self.worker_uid:
            raise IdentityError("Gateway may not run under the sandbox worker identity")
