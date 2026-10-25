#!/usr/bin/env python3
"""Disposable CI SSH dispatcher; never install this test endpoint on Rocky01.

The normal path execs the unchanged transfer bridge. The one-shot fault path
feeds real authenticated SSH stdin to a real bridge process, kills that process
after a persisted prefix, then kills only its own unprivileged sshd session.
No generated bridge responses or SSH substitutes are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
from casework import CaseStore, FILE_NAME  # noqa: E402
from smoke_evidence import call, job  # noqa: E402

STATE = Path.home() / ".ssh-ci"
BRIDGE = ROOT / "transfer_bridge.py"
CHUNK = 1024 * 1024
CUT = 2 * CHUNK


def record(value: dict) -> None:
    STATE.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(STATE / "trace.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="ascii") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def trace() -> list[dict]:
    path = STATE / "trace.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def drop_connection(argv: list[str]) -> None:
    """A real channel loss after durable bytes, not a fabricated partial ACK."""
    token = argv[argv.index("--temp") + 1]
    store = CaseStore(Path.home())
    source = store.inbox / token
    parent = os.getppid()
    parent_info = Path(f"/proc/{parent}/status").read_text()
    parent_name = next(line.split()[1] for line in parent_info.splitlines()
                       if line.startswith("Name:"))
    parent_uids = next(line.split()[1:] for line in parent_info.splitlines()
                       if line.startswith("Uid:"))
    if parent_name not in ("sshd", "sshd-session") or set(parent_uids) != {str(os.getuid())}:
        raise RuntimeError("Refusing to kill a process other than this unprivileged sshd session")
    child = subprocess.Popen([sys.executable, "-u", str(BRIDGE), *argv],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    try:
        assert child.stdin is not None
        for _ in range(CUT // CHUNK):
            block = sys.stdin.buffer.read(CHUNK)
            if len(block) != CHUNK:
                raise RuntimeError("Fault test source ended before the cut point")
            child.stdin.write(block)
            child.stdin.flush()
        deadline = time.monotonic() + 10
        while source.stat().st_size != CUT:
            if child.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Real bridge did not persist the required partial length")
            time.sleep(0.02)
        with source.open("rb") as stream:
            os.fsync(stream.fileno())
            prefix_sha = hashlib.file_digest(stream, "sha256").hexdigest()
        child.kill()
        code = child.wait(timeout=10)
        if code != -signal.SIGKILL:
            raise RuntimeError("Bridge was not actually terminated by SIGKILL")
        record({"event": "forced_disconnect", "token": token, "partial_bytes": CUT,
                "prefix_sha256": prefix_sha, "bridge_signal": "SIGKILL",
                "sshd_session_pid": parent, "sshd_session_uid": os.getuid()})
        # This closes an actual authenticated SSH transport. The listener,
        # other sessions, and the next retry are unaffected.
        os.kill(parent, signal.SIGKILL)
        os._exit(99)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def dispatch() -> None:
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if len(connection) != 4 or connection[0] != "127.0.0.1" or connection[2] != "127.0.0.1":
        raise RuntimeError("CI dispatcher permits loopback SSH only")
    argv = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    if argv == ["/usr/lib/openssh/sftp-server"]:
        record({"event": "sftp"})
        os.execv(argv[0], argv)
    if len(argv) < 4 or argv[:2] != ["python3", "-u"]:
        raise RuntimeError("Unsupported CI SSH command")
    if argv[2] == str(BRIDGE) and argv[3] in {
            "prepare", "begin", "status", "append", "finalize", "abort"}:
        action = argv[3]
        item = {"event": "bridge", "action": action}
        if "--temp" in argv:
            item["token"] = argv[argv.index("--temp") + 1]
        if "--offset" in argv:
            item["offset"] = int(argv[argv.index("--offset") + 1])
        record(item)
        armed = STATE / "drop-once"
        if action == "append" and armed.exists():
            armed.unlink()
            drop_connection(argv[3:])
        os.execv(sys.executable, [sys.executable, "-u", str(BRIDGE), *argv[3:]])
    if argv[2] == str(Path(__file__).resolve()) and argv[3] in {
            "identity", "arm-drop", "inspect", "register"}:
        os.execv(sys.executable, [sys.executable, "-u", argv[2], *argv[3:]])
    raise RuntimeError("Unsupported CI SSH command")


def main() -> None:
    os.umask(0o077)
    if os.geteuid() == 0:
        raise RuntimeError("CI transfer account must be unprivileged")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["dispatch", "identity", "arm-drop", "inspect", "register"])
    parser.add_argument("--filename")
    parser.add_argument("--size", type=int)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    if args.action == "dispatch":
        dispatch()
        raise RuntimeError("SSH dispatcher returned unexpectedly")
    if args.action == "identity":
        result = {"uid": os.getuid(), "python": sys.version.split()[0],
                  "kernel": os.uname().release, "bridge_sha256": hashlib.sha256(BRIDGE.read_bytes()).hexdigest()}
    elif args.action == "arm-drop":
        STATE.mkdir(mode=0o700, exist_ok=True)
        (STATE / "drop-once").write_text("one authenticated append only\n")
        result = {"status": "ARMED", "cut_bytes": CUT}
    elif args.action == "inspect":
        store = CaseStore(Path.home())
        store._ensure_store()
        artifacts = {}
        for path in store.inbox.iterdir():
            if FILE_NAME.fullmatch(path.name) and not path.name.startswith("."):
                with path.open("rb") as stream:
                    artifacts[path.name] = {"bytes": path.stat().st_size,
                                            "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
        result = {"trace": trace(), "artifacts": artifacts,
                  "session_count": len(list(store.inbox.glob(".upload-*.session")))}
    else:
        if not args.filename or not FILE_NAME.fullmatch(args.filename):
            raise RuntimeError("Missing or invalid registration filename")
        case = call(Path.home(), "case_open", {})["case_id"]
        entry = job(Path.home(), "import_staged", case, filename=args.filename)
        check = job(Path.home(), "verify_case", case)
        if (entry["status"] != "REGISTERED" or entry["bytes"] != args.size
                or entry["sha256"] != args.sha256 or check["status"] != "PASS"
                or check["verified_count"] != 1):
            raise RuntimeError("Actual gateway/worker registration or vault proof failed")
        result = {"status": "REGISTERED_AND_VERIFIED", "case_id": case,
                  "bytes": entry["bytes"], "sha256": entry["sha256"], "verified_count": 1}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
