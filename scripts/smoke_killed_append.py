#!/usr/bin/env python3
"""Physically SIGKILL a live SSH-style append and recover from disk afterward.

Synthetic bytes only. Runs as an unprivileged user on disposable Linux CI;
does not simulate a true network/TCP outage or host power loss.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from casework import CaseStore
import resumable_transfer as resume
import transfer_bridge

MIB = 1024 * 1024
BLOCK = hashlib.sha256(b"rocky-ci-v016-killed-append").digest() * (MIB // 32)
TOTAL = 64 * MIB + 47
ROOT = Path(__file__).resolve().parents[1]


def digest_for(length: int) -> str:
    h = hashlib.sha256()
    full, remaining = divmod(length, MIB)
    for _ in range(full):
        h.update(BLOCK)
    h.update(BLOCK[:remaining])
    return h.hexdigest()


class Continuation:
    def __init__(self, offset: int):
        self.offset = offset

    def read(self, n: int) -> bytes:
        if self.offset >= TOTAL:
            return b""
        num = min(n, TOTAL - self.offset)
        shift = self.offset % MIB
        data = BLOCK[shift:shift + num]
        if len(data) < num:
            data += BLOCK[:num - len(data)]
        self.offset += num
        return data


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Worker SIGKILL test refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-killed-append-") as scratch:
        home = Path(scratch)
        store = CaseStore(home)
        token = ".upload-" + "f" * 32
        expected = digest_for(TOTAL)
        resume.begin(store, token, TOTAL, expected)
        env = {**os.environ, "HOME": str(home)}
        command = [sys.executable, "-u", str(ROOT / "transfer_bridge.py"),
                   "append", "--temp", token, "--offset", "0"]
        child = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 bufsize=0)
        try:
            if child.stdin is None:
                raise RuntimeError("Synthetic input pipe not created")
            # Write enough bytes that a child could not buffer it all inside
            # the pipe; each blocking write proves some bytes were consumed.
            for _ in range(32):
                pending = memoryview(BLOCK)
                while pending:
                    wrote = child.stdin.write(pending)
                    if wrote is None or wrote <= 0:
                        raise RuntimeError("Synthetic SSH pipe stopped accepting bytes")
                    pending = pending[wrote:]
                if child.poll() is not None:
                    raise RuntimeError("Appender terminated before SIGKILL")
            os.kill(child.pid, signal.SIGKILL)
            code = child.wait(timeout=20)
            if code != -signal.SIGKILL:
                raise RuntimeError("Append child was not actually SIGKILLed")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=20)
            if child.stdin:
                child.stdin.close()
            if child.stdout:
                child.stdout.close()
            if child.stderr:
                child.stderr.close()

        observed = resume.status(store, token)
        offset = observed["bytes_staged"]
        if (observed["status"] != "PARTIAL" or offset < 8 * MIB
                or offset > 32 * MIB):
            raise RuntimeError("Killed append did not retain plausible partial evidence")
        if observed["prefix_sha256"] != digest_for(offset):
            raise RuntimeError("Killed append lost or changed physical prefix bytes")
        restored = resume.append(store, token, offset, Continuation(offset))
        if restored["status"] != "COMPLETE_UNVERIFIED":
            raise RuntimeError("Restarted append did not finish unverified evidence")
        final = transfer_bridge.finalize(store, token, "killed-synthetic.bin",
                                         TOTAL, expected)
        if final["status"] != "STAGED" or final["sha256"] != expected:
            raise RuntimeError("Killed/resumed transfer did not finalize unchanged")
        case = store.open_case()["case_id"]
        item = store.register(case, "killed-synthetic.bin", worker=True)
        if item["status"] != "REGISTERED" or item["sha256"] != expected:
            raise RuntimeError("Killed/resumed upload was not copied into vault intact")
        print(json.dumps({
            "status": "OFF_HOST_SIGKILL_RESUME_PASS",
            "kill_signal": "SIGKILL", "partial_bytes": offset,
            "final_bytes": TOTAL, "sha256": expected,
            "private_case_registered": True,
            "real_network_interruption_proven": False,
            "real_host_power_loss_proven": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
