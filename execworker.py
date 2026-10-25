#!/usr/bin/env python3
"""Dedicated non-root execution-worker service (prototype, not install-ready).

Must be installed as root-owned code and started as the separately provisioned
sandbox worker UID. The chat-facing gateway UID has NO access to this worker's
home, approval database, replay ledger, writable runtime or Podman storage.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import signal
import stat
import sys
import threading
from typing import Any

from casework import CaseStore
from execution_broker import ExecutionBroker, BrokerError
from execution_policy import ExecutionPolicy, IdentityError
from sandboxwork import ExecutionStore, ExecutionError


def _exclusive(store: ExecutionStore) -> int:
    store.cases._ensure_store()
    path = store.base / "execution.worker.lock"
    if path.is_symlink():
        raise ExecutionError("Execution worker lock symlink forbidden")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ExecutionError("Execution worker lock owner or mode invalid")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _run_jobs(store: ExecutionStore, stop: threading.Event, failed: list[str]) -> None:
    try:
        # Startup recovery MUST finish before any newly approved job is claimed.
        store.recover_orphans()
        while not stop.is_set():
            result = store.work_once()
            if not result["processed"]:
                stop.wait(0.4)
    except Exception:
        failed.append("isolated_worker_failed")
        stop.set()


def main() -> int:
    os.umask(0o077)
    if len(sys.argv) != 1:
        print("The execution worker takes no runtime identity or path arguments", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("Execution worker refuses root", file=sys.stderr)
        return 2
    try:
        policy = ExecutionPolicy.load()
        home = policy.check_worker()
        store = ExecutionStore(home)
        lock = _exclusive(store)
    except (IdentityError, ExecutionError, OSError) as exc:
        print("Protected worker startup refused: " + type(exc).__name__, file=sys.stderr)
        return 2
    listener = None
    stop = threading.Event()
    failed: list[str] = []
    try:
        broker = ExecutionBroker(store, policy)
        listener = broker.bind()
        thread = threading.Thread(target=_run_jobs, args=(store, stop, failed), daemon=True)
        def request_stop(*_: Any) -> None:
            stop.set()
        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        thread.start()
        while not stop.is_set():
            broker.serve_one(listener)
        # No promise that an in-flight script can finish during service shutdown.
        thread.join(timeout=2)
        return 2 if failed or thread.is_alive() else 0
    except (BrokerError, ExecutionError, OSError, IdentityError):
        return 2
    finally:
        stop.set()
        if listener is not None:
            listener.close()
            # We own this private runtime directory and hold the worker lock.
            # Refuse unlink if an unexpected replacement changed socket identity.
            path = broker.socket_path
            try:
                info = path.lstat()
                if (stat.S_ISSOCK(info.st_mode) and info.st_uid == policy.worker_uid):
                    path.unlink()
            except OSError:
                pass
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


if __name__ == "__main__":
    raise SystemExit(main())
