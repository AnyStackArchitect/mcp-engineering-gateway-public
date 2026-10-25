#!/usr/bin/env python3
"""Real 64 MiB synthetic log indexing with a separate pending upload reservation.

Off-host filesystem test only: no raw customer logs, networking, or Rocky01.
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
from resumable_transfer import begin

MIB = 1024 * 1024
LINE_BYTES = 512
LINES = 131072
PENDING = 8 * MIB
RAW = (b"2026-10-17T12:00:00Z ERROR SYNTHETIC_INDEX_PROBE "
       b"token=never-publish-this-secret")
if len(RAW) >= LINE_BYTES:
    raise RuntimeError("Synthetic template invalid")
LINE = RAW + b" " * (LINE_BYTES - len(RAW) - 1) + b"\n"


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Off-host index smoke refuses root")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="rocky-log-index-ci-") as root:
        store = CaseStore(Path(root))
        case = store.open_case()["case_id"]
        source = store.inbox / "synthetic-large.log"
        source_digest = hashlib.sha256()
        with source.open("xb") as fd:
            os.chmod(source, 0o600)
            for _ in range(LINES):
                fd.write(LINE)
                source_digest.update(LINE)
            fd.flush()
            os.fsync(fd.fileno())
        if source.stat().st_size != 64 * MIB:
            raise RuntimeError("Synthetic source length mismatch")
        registered = store.register(case, source.name, worker=True)
        if registered["sha256"] != source_digest.hexdigest():
            raise RuntimeError("Source registration hash incorrect")
        token = ".upload-" + "d" * 32
        begin(store, token, PENDING, "a" * 64)
        start_index = time.monotonic()
        summary = store.index_log(case, registered["artifact_id"], worker=True)
        elapsed = time.monotonic() - start_index
        if (summary["status"] != "PASS" or summary["lines_indexed"] != LINES
                or summary["lines_skipped"] != 0
                or summary["artifact_sha256"] != source_digest.hexdigest()):
            raise RuntimeError("Large source indexing was incomplete or changed identity")
        found = store.search_log(case, registered["artifact_id"], "SYNTHETIC_INDEX_PROBE")
        if not found["matches"] or found["matches"][0]["line"] != 1:
            raise RuntimeError("Large SQLite source-offset search failed")
        if "never-publish-this-secret" in json.dumps(found):
            raise RuntimeError("Private log token appeared in searchable output")
        index = store.cases / case / "indexes" / (registered["artifact_id"] + ".sqlite3")
        idxstat = index.stat()
        if (not index.is_file() or idxstat.st_mode & 0o077
                or idxstat.st_size == 0 or idxstat.st_blocks == 0):
            raise RuntimeError("Large log index is not a private allocated file")
        inbox_session = store.inbox / (token + ".session")
        if not inbox_session.exists():
            raise RuntimeError("Log index consumed another upload reservation")
        free = shutil.disk_usage(store.inbox).free
        if free < FREE_RESERVE + PENDING:
            raise RuntimeError("Log index consumed reserved upload or emergency headroom")
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if peak > 220 * 1024:
            raise RuntimeError("Log index exceeded 220 MiB process RSS")
        print(json.dumps({
            "status": "OFF_HOST_RESERVED_LOG_INDEX_PASS",
            "input_bytes": source.stat().st_size,
            "input_sha256": source_digest.hexdigest(),
            "lines_indexed": summary["lines_indexed"],
            "lines_skipped": summary["lines_skipped"],
            "index_bytes": idxstat.st_size,
            "allocated_index_bytes": idxstat.st_blocks * 512,
            "source_line_query_verified": True,
            "redaction_verified": True,
            "pending_upload_bytes_preserved": PENDING,
            "minimum_physical_reserve_bytes": FREE_RESERVE,
            "index_elapsed_seconds": round(elapsed, 3),
            "total_seconds": round(time.monotonic() - started, 3),
            "peak_rss_mib": round(peak / 1024, 2),
            "actual_rocky_host_qualified": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
