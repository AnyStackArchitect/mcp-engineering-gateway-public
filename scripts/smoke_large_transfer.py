#!/usr/bin/env python3
"""2+ GiB allocated-byte, bounded-RSS, off-host evidence interruption benchmark.

Requires an actual disposable runner with sufficient physical free capacity.
Does not use sparse files, content compression, mocks, real customer data,
Rocky01, remote SSH, root privileges or the production operator key.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from casework import CaseStore, FREE_RESERVE
import resumable_transfer
import transfer_bridge

MIB = 1024 ** 2
GIB = 1024 ** 3
TOTAL = 2 * GIB + 257
DROP_AT = 513 * MIB + 257
BLOCK = hashlib.sha256(b"rocky01-mcp-v016-large-synthetic-only").digest() * (MIB // 32)
MAX_RSS_KIB = 256 * 1024


class SyntheticBinarySource:
    """Constant-space, deterministic and intentionally non-sparse input bytes."""
    def __init__(self, offset: int, stop: int, drop_at: int | None = None):
        self.offset = offset
        self.stop = stop
        self.drop_at = drop_at

    def read(self, n: int) -> bytes:
        if self.drop_at is not None and self.offset >= self.drop_at:
            raise OSError("synthetic interrupted transport")
        if self.offset >= self.stop:
            return b""
        amount = min(n, self.stop - self.offset)
        if self.drop_at is not None:
            amount = min(amount, self.drop_at - self.offset)
        if amount < 1:
            raise OSError("synthetic interrupted transport")
        shift = self.offset % MIB
        result = BLOCK[shift:shift + amount]
        if len(result) != amount:
            result += BLOCK[:amount - len(result)]
        self.offset += amount
        return result


def expected_digest(length: int) -> str:
    sha = hashlib.sha256()
    full, tail = divmod(length, MIB)
    for _ in range(full):
        sha.update(BLOCK)
    sha.update(BLOCK[:tail])
    return sha.hexdigest()


def assert_reserve(path: Path, addition: int) -> int:
    free = shutil.disk_usage(path).free
    if free < FREE_RESERVE + addition:
        raise RuntimeError("BLOCKED: physical disk cannot preserve the 5 GiB reserve")
    return free


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Refusing benchmark as root")
    started = time.monotonic()
    # Two durable 2+ GiB copies (inbox and case vault) and one more GiB of
    # test-only safety allowance in addition to the 5 GiB required reserve.
    disk_root = Path(os.environ.get("RUNNER_TEMP", "/var/tmp"))
    original_free = assert_reserve(disk_root, 2 * TOTAL + GIB)
    with tempfile.TemporaryDirectory(prefix="rocky-large-evidence-ci-", dir=disk_root) as tmp:
        home = Path(tmp)
        casework = CaseStore(home)
        token = ".upload-" + "a" * 32
        expected = expected_digest(TOTAL)
        if len(BLOCK) != MIB:
            raise RuntimeError("Synthetic chunk generator invalid")
        initialized = resumable_transfer.begin(casework, token, TOTAL, expected)
        if initialized["status"] != "SESSION_CREATED":
            raise RuntimeError("Large evidence upload did not begin")
        t1 = time.monotonic()
        try:
            resumable_transfer.append(casework, token, 0,
                                      SyntheticBinarySource(0, TOTAL, DROP_AT))
        except OSError as exc:
            if str(exc) != "synthetic interrupted transport":
                raise
        else:
            raise RuntimeError("Fixture did not actually interrupt the upload")
        partial = resumable_transfer.status(casework, token)
        if partial["status"] != "PARTIAL" or partial["bytes_staged"] != DROP_AT:
            raise RuntimeError("Physical multi-GB upload interruption was misreported")
        if partial["prefix_sha256"] != expected_digest(DROP_AT):
            raise RuntimeError("Partial evidence digest differs from original prefix")
        t2 = time.monotonic()
        completed = resumable_transfer.append(
            casework, token, DROP_AT, SyntheticBinarySource(DROP_AT, TOTAL))
        if (completed["status"] != "COMPLETE_UNVERIFIED"
                or completed["bytes_staged"] != TOTAL):
            raise RuntimeError("Multi-GB resumed upload did not reach full size")
        # Staged evidence is still not registered or analysis-authorized.
        staged = transfer_bridge.finalize(casework, token,
                                          "large-synthetic.bin", TOTAL, expected)
        if staged["sha256"] != expected or staged["bytes"] != TOTAL:
            raise RuntimeError("Large evidence finalization mismatch")
        t3 = time.monotonic()
        case_id = casework.open_case()["case_id"]
        result = casework.register(case_id, "large-synthetic.bin", worker=True)
        if (result["status"] != "REGISTERED" or result["sha256"] != expected
                or result["bytes"] != TOTAL):
            raise RuntimeError("Large private worker case import is not source-exact")
        original = casework.cases / case_id / "originals" / result["artifact_id"]
        if (not original.is_file() or original.stat().st_size != TOTAL
                or original.stat().st_mode & 0o077):
            raise RuntimeError("Large worker original not private and regular")
        with casework._locked(case_id) as (_, manifest):
            if (manifest["artifacts"][result["artifact_id"]]["sha256"] != expected
                    or manifest["artifacts"][result["artifact_id"]]["bytes"] != TOTAL):
                raise RuntimeError("Registered case manifest does not match source")
        t4 = time.monotonic()
        live_free = shutil.disk_usage(home).free
        if live_free < FREE_RESERVE:
            raise RuntimeError("Reserved physical free space was violated")
        private_file = casework.inbox / "large-synthetic.bin"
        if not private_file.is_file():
            raise RuntimeError("Staged original unexpectedly removed")
        # Distinguish genuinely allocated, separately copied bytes from a
        # misleading sparse/truncated or filesystem-compressed synthetic test.
        source_allocated = private_file.stat().st_blocks * 512
        vault_allocated = original.stat().st_blocks * 512
        if min(source_allocated, vault_allocated) < int(TOTAL * 0.95):
            raise RuntimeError("Large fixture was not physically allocated on disk")
        if (casework.inbox / token).exists() or (casework.inbox / (token + ".session")).exists():
            raise RuntimeError("Finalized session residue remains")
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if rss > MAX_RSS_KIB:
            raise RuntimeError("Large evidence benchmark exceeded 256 MiB peak RSS")
        print(json.dumps({
            "status": "OFF_HOST_SYNTHETIC_LARGE_TRANSFER_PASS",
            "bytes": TOTAL,
            "gib": round(TOTAL / GIB, 4),
            "sha256": expected,
            "drop_offset": DROP_AT,
            "prefix_sha256_verified": True,
            "final_sha256_verified": True,
            "worker_case_original_verified": True,
            "reserved_bytes": FREE_RESERVE,
            "allocated_source_gib": round(source_allocated / GIB, 3),
            "allocated_vault_gib": round(vault_allocated / GIB, 3),
            "starting_free_gib": round(original_free / GIB, 2),
            "minimum_free_after_intake_gib": round(live_free / GIB, 2),
            "peak_rss_mib": round(rss / 1024, 2),
            "first_partial_seconds": round(t2 - t1, 3),
            "resume_and_finalize_seconds": round(t3 - t2, 3),
            "worker_case_import_seconds": round(t4 - t3, 3),
            "total_seconds": round(t4 - started, 3),
            "actual_windows_openssh_proven": False,
            "rocky_selinux_systemd_proven": False,
        }, sort_keys=True))
        # TemporaryDirectory deletes test evidence only. It is not the
        # product's future retention policy or a customer-case deletion path.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
