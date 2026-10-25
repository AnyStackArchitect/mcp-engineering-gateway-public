#!/usr/bin/env python3
"""Physically allocated 2.25 GiB synthetic ZIP -> worker -> indexes -> export.

This is an off-host qualification fixture, not a customer-data generator or a
Rocky01 installer. It runs the real fixed worker in separate nonroot processes,
keeps the product's quotas/reserve intact, and reports measured coverage only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from archivework import verify_case
from capacitywork import admission_lock, outstanding_reservations
from case_handoff import handoff
from casework import CaseStore, FREE_RESERVE
from jobwork import JobStore, apply_worker_limits
from redacted_export import MEMBERS as EXPORT_MEMBERS, review_redacted_export
from resumable_transfer import begin
from transfer_bridge import abort

MIB = 1024 ** 2
GIB = 1024 ** 3
LINE_BYTES = 1024
MEMBER_BYTES = 768 * MIB
LINES_PER_MEMBER = MEMBER_BYTES // LINE_BYTES
NAMES = ("veeam/session.log", "vmware/host.log", "linux/storage.log")
PENDING_BYTES = 8 * MIB
MAX_RSS_KIB = 256 * 1024
SECRET = "stage-a-synthetic-secret-never-disclose"


def log_line(member: int, line: int, marker: str = "") -> bytes:
    level = "ERROR" if line % 97 == 0 else "WARN" if line % 31 == 0 else "INFO"
    message = marker or f"synthetic-operation-{line % 64:02d}"
    prefix = (f"2026-10-17T12:{member:02d}:{line % 60:02d}Z {level} "
              f"{message} component={NAMES[member].split('/')[0]} "
              f"thread={line % 17} token={SECRET} status=observed ")
    # A tail-only marker deliberately lies outside the 350-character searchable
    # excerpt, so the fixture verifies the documented coverage limitation too.
    filler = hashlib.sha256(f"synthetic-{member}-{line % 64}".encode()).hexdigest()
    tail = " TAIL_ONLY_NOT_INDEXED"
    length = LINE_BYTES - len(prefix) - len(tail) - 1
    if length < 0:
        raise RuntimeError("Synthetic line template exceeds its declared size")
    value = (prefix + (filler * ((length + 63) // 64))[:length] + tail + "\n").encode("ascii")
    if len(value) != LINE_BYTES:
        raise RuntimeError("Synthetic record size mismatch")
    return value


def generate_bundle(path: Path) -> dict[str, dict]:
    expected = {}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as raw:
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED,
                             allowZip64=True) as archive:
            for number, name in enumerate(NAMES):
                markers = {
                    1: f"STAGE_A_{number}_FIRST",
                    LINES_PER_MEMBER // 2: f"STAGE_A_{number}_MIDDLE",
                    LINES_PER_MEMBER: f"STAGE_A_{number}_LAST",
                }
                digest = hashlib.sha256()
                block_lines = 1024
                normal = [log_line(number, line) for line in range(1, block_lines + 1)]
                with archive.open(name, "w", force_zip64=True) as stream:
                    for start in range(1, LINES_PER_MEMBER + 1, block_lines):
                        records = list(normal)
                        for line, marker in markers.items():
                            if start <= line < start + block_lines:
                                records[line - start] = log_line(number, line, marker)
                        chunk = b"".join(records)
                        stream.write(chunk)
                        digest.update(chunk)
                expected[name] = {"sha256": digest.hexdigest(), "bytes": MEMBER_BYTES,
                                  "markers": markers}
        raw.flush()
        os.fsync(raw.fileno())
    return expected


def worker_job(jobs: JobStore, home: Path, kind: str, case_id: str,
               artifact_id: str | None = None, filename: str | None = None) -> dict:
    queued = jobs.submit(kind, case_id, artifact_id, filename=filename)
    done = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()),
         "--worker-root", str(home)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1200,
        check=False)
    if done.returncode or len(done.stdout) > 8192:
        raise RuntimeError(f"Separate fixed worker failed for {kind}: exit {done.returncode}")
    outcome = json.loads(done.stdout)
    result = jobs.result(queued["job_id"])
    if (outcome.get("job_id") != queued["job_id"] or
            outcome.get("state") != "SUCCEEDED" or result["state"] != "SUCCEEDED"):
        raise RuntimeError(f"Fixed {kind} job did not succeed: {result.get('failure_code')}")
    return result["result"]


def check_private_allocated(path: Path, expected_bytes: int) -> int:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1
            or info.st_size != expected_bytes):
        raise RuntimeError("Qualification evidence identity or permissions invalid")
    allocated = info.st_blocks * 512
    if allocated < int(expected_bytes * 0.95):
        raise RuntimeError("Qualification source was sparse or not physically allocated")
    return allocated


def qualify() -> dict:
    began = time.monotonic()
    disk_root = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    # Archive, vault archive, expanded logs, bounded indexes and scratch margin.
    required = FREE_RESERVE + 4 * len(NAMES) * MEMBER_BYTES + GIB
    starting_free = shutil.disk_usage(disk_root).free
    if starting_free < required:
        raise RuntimeError("BLOCKED: insufficient physical disk for scale proof and unchanged reserve")
    with tempfile.TemporaryDirectory(prefix="rocky-stage-a-scale-", dir=disk_root) as temporary:
        home = Path(temporary)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        bundle = store.inbox / "synthetic-stage-a.zip"
        expected = generate_bundle(bundle)
        archive_bytes = bundle.stat().st_size
        archive_allocated = check_private_allocated(bundle, archive_bytes)
        jobs = JobStore(home)
        imported = worker_job(jobs, home, "import_staged", case, filename=bundle.name)
        if imported["bytes"] != archive_bytes or imported["type"] != "zip":
            raise RuntimeError("Multi-GB archive import identity mismatch")
        check_private_allocated(store.cases / case / "originals" / imported["artifact_id"], archive_bytes)
        token = ".upload-" + "9" * 32
        begin(store, token, PENDING_BYTES, hashlib.sha256(b"reserved synthetic upload").hexdigest())
        expanded = worker_job(jobs, home, "unpack_archive", case, imported["artifact_id"])
        if (expanded["expanded_bytes"] != len(NAMES) * MEMBER_BYTES or
                expanded["derived_artifact_count"] != len(NAMES)):
            raise RuntimeError("Multi-GB archive expansion was incomplete")
        derived = []
        with store._locked(case) as (folder, manifest):
            for aid, item in manifest["artifacts"].items():
                if item.get("derived_from") != imported["artifact_id"]:
                    continue
                reference = expected.get(item["intake_name"])
                if reference is None or (item["sha256"], item["bytes"]) != (reference["sha256"], reference["bytes"]):
                    raise RuntimeError("Expanded source lineage/hash mismatch")
                check_private_allocated(folder / "originals" / aid, MEMBER_BYTES)
                derived.append((aid, reference))
        if len(derived) != len(NAMES):
            raise RuntimeError("Multi-GB source manifest omitted a member")
        indexed_lines = 0
        search_probes = 0
        index_started = time.monotonic()
        for aid, reference in derived:
            indexed = worker_job(jobs, home, "index_log", case, aid)
            if (indexed["status"] != "PASS" or indexed["lines_examined"] != LINES_PER_MEMBER
                    or indexed["lines_indexed"] != LINES_PER_MEMBER or indexed["lines_skipped"] != 0
                    or indexed["artifact_sha256"] != reference["sha256"]):
                raise RuntimeError("Multi-GB source indexing did not cover every physical line")
            indexed_lines += indexed["lines_indexed"]
            for line, marker in reference["markers"].items():
                found = store.search_log(case, aid, marker)
                if (len(found["matches"]) != 1 or found["matches"][0]["line"] != line
                        or not found["searched_redacted_excerpt_only"] or found["has_more"]):
                    raise RuntimeError("First/middle/last indexed source-line lookup failed")
                if SECRET in json.dumps(found):
                    raise RuntimeError("Synthetic secret appeared in searchable excerpt")
                search_probes += 1
            tail = store.search_log(case, aid, "TAIL_ONLY_NOT_INDEXED")
            if tail["matches"] or not tail["searched_redacted_excerpt_only"]:
                raise RuntimeError("Indexer misrepresented excerpt-only search coverage")
        indexing_seconds = time.monotonic() - index_started
        with admission_lock(store):
            if outstanding_reservations(store) != PENDING_BYTES:
                raise RuntimeError("Archive/index writes consumed another transfer's reservation")
        audit = worker_job(jobs, home, "verify_case", case)
        if audit["status"] != "PASS" or audit["verified_count"] != 4:
            raise RuntimeError("Multi-GB vault integrity verification failed")
        abort(store, token)
        view = handoff(store, case)
        exported = handoff(store, case, confirm=True, plan_sha256=view["plan_sha256"])
        if exported["status"] != "PRIVATE_METADATA_EXPORTED":
            raise RuntimeError("Large-case metadata handoff failed")
        preview = review_redacted_export(store, case)
        prepared = review_redacted_export(store, case, prepare=True,
                                          preview_sha256=preview["review_fingerprint_sha256"])
        package = store.base / "redacted-review-packages" / prepared["package_name"]
        with zipfile.ZipFile(package) as redacted:
            if tuple(redacted.namelist()) != EXPORT_MEMBERS:
                raise RuntimeError("Large-case redacted export has unexpected members")
            public_bytes = b"".join(redacted.read(name) for name in redacted.namelist())
            if SECRET.encode() in public_bytes or any(name.encode() in public_bytes for name in NAMES):
                raise RuntimeError("Private review ZIP contains source text or source filenames")
        final_audit = verify_case(store, case)
        if final_audit["status"] != "PASS":
            raise RuntimeError("Handoff/export changed an original")
        free = shutil.disk_usage(home).free
        if free < FREE_RESERVE:
            raise RuntimeError("Physical scale proof violated the product free-space reserve")
        parent_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        worker_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if max(parent_rss, worker_rss) > MAX_RSS_KIB:
            raise RuntimeError("Scale qualification exceeded the 256 MiB measured RSS budget")
        return {
            "status": "OFF_HOST_STAGE_A_SCALE_PASS", "synthetic_sources_only": True,
            "archive_bytes": archive_bytes, "archive_allocated_bytes": archive_allocated,
            "expanded_log_bytes": len(NAMES) * MEMBER_BYTES,
            "log_members": len(NAMES), "total_physical_lines_indexed": indexed_lines,
            "first_middle_last_search_probes": search_probes,
            "search_scope": "redacted first 350 characters of each bounded line",
            "full_line_content_search_proven": False,
            "source_and_archive_sha256_verified": True,
            "private_handoff_and_redacted_zip_verified": True,
            "reserved_upload_bytes_preserved": PENDING_BYTES,
            "product_free_reserve_bytes": FREE_RESERVE,
            "starting_free_bytes": starting_free, "free_after_pipeline_bytes": free,
            "parent_peak_rss_mib": round(parent_rss / 1024, 2),
            "worker_peak_rss_mib": round(worker_rss / 1024, 2),
            "index_and_search_seconds": round(indexing_seconds, 3),
            "elapsed_seconds": round(time.monotonic() - began, 3),
            "rocky_host_qualified": False, "forty_gib_case_proven": False,
            "public_disclosure_approved": False,
        }


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Stage A scale qualification refuses root")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-root", type=Path, help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.worker_root is not None:
        apply_worker_limits()
        print(json.dumps(JobStore(options.worker_root).work_once(), sort_keys=True))
    else:
        print(json.dumps(qualify(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
