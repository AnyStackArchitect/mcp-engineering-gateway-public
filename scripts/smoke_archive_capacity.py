#!/usr/bin/env python3
"""Medium-large, bounded-memory synthetic ZIP -> fixed worker -> private vault.

No customer files, network, root, Rocky01 installation, arbitrary extraction
path or publication. CI uses synthetic non-sparse ZIP members and source SHA.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from casework import CaseStore
from jobwork import JobStore
from archivework import verify_case
import resumable_transfer as resume
import capacitywork

MIB = 1024 * 1024
MEMBERS = ("logs/a.raw", "logs/b.raw")
CHUNKS_PER_MEMBER = 32
MAX_RSS_KIB = 192 * 1024


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Archive smoke refuses root")
    began = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="rocky-archive-ci-", dir=os.environ.get("RUNNER_TEMP", "/var/tmp")) as root:
        home = Path(root)
        store = CaseStore(home)
        store._ensure_store()
        archive = store.inbox / "support-bundle.zip"
        expected: dict[str, tuple[str, int]] = {}
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as bundle:
            for name in MEMBERS:
                digest = hashlib.sha256()
                with bundle.open(name, "w") as output:
                    for i in range(CHUNKS_PER_MEMBER):
                        block = hashlib.shake_256(f"{name}|{i}|synthetic".encode("ascii")).digest(MIB)
                        output.write(block)
                        digest.update(block)
                expected[name] = digest.hexdigest(), CHUNKS_PER_MEMBER * MIB
            event = b"2026-10-17T09:00:00Z ERROR synthetic backup timeout\n"
            bundle.writestr("logs/events.log", event)
            expected["logs/events.log"] = hashlib.sha256(event).hexdigest(), len(event)
        archive.chmod(0o600)
        if archive.stat().st_blocks * 512 < 60 * MIB:
            raise RuntimeError("Synthetic test ZIP was not substantially physically allocated")
        cases = store.open_case()
        case = cases["case_id"]
        parent = store.register(case, "support-bundle.zip", worker=True)
        if parent["type"] != "zip":
            raise RuntimeError("Case importer did not recognize ZIP source")
        token = ".upload-" + "a" * 32
        promised = 8 * MIB
        resume.begin(store, token, promised, "b" * 64)
        jobs = JobStore(home)
        queued = jobs.submit("unpack_archive", case, parent["artifact_id"])
        run = jobs.work_once()
        if run["state"] != "SUCCEEDED":
            raise RuntimeError("Fixed archive job did not succeed")
        result = jobs.result(queued["job_id"])
        if result["state"] != "SUCCEEDED" or result["result"]["derived_artifact_count"] != len(expected):
            raise RuntimeError("Archive produced incomplete derived-artifact manifest")
        if result["result"]["expanded_bytes"] != sum(x[1] for x in expected.values()):
            raise RuntimeError("Archive expanded byte count mismatch")
        with store._locked(case) as (folder, manifest):
            derived = [(id, metadata) for id, metadata in manifest["artifacts"].items()
                       if metadata.get("derived_from") == parent["artifact_id"]]
            if len(derived) != len(expected):
                raise RuntimeError("Archive derived artifact count mismatch")
            for aid, meta in derived:
                reference = expected.pop(meta["intake_name"], None)
                if reference is None or (meta["sha256"], meta["bytes"]) != reference:
                    raise RuntimeError("Archive derived member hash/length mismatch")
                original = folder / "originals" / aid
                st = original.lstat()
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                        or st.st_mode & 0o077 or st.st_uid != os.getuid()):
                    raise RuntimeError("Expanded evidence original is not private regular")
        if expected:
            raise RuntimeError("Missing member during archive validation")
        audit = verify_case(store, case)
        if (audit["status"] != "PASS" or audit["verified_count"] != 4):
            raise RuntimeError("Vault could not independently verify all source/derived artifacts")
        with capacitywork.admission_lock(store):
            if capacitywork.outstanding_reservations(store) != promised:
                raise RuntimeError("Archive expansion stole a pending SSH session reservation")
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if rss > MAX_RSS_KIB:
            raise RuntimeError("Archive fixture exceeded bounded memory budget")
        print(json.dumps({
            "status": "OFF_HOST_SYNTHETIC_ARCHIVE_PASS",
            "source_bytes": parent["bytes"],
            "expanded_bytes": result["result"]["expanded_bytes"],
            "derived_count": result["result"]["derived_artifact_count"],
            "archive_sha256": parent["sha256"],
            "vault_audit_status": audit["status"],
            "preserved_upload_reservation_bytes": promised,
            "peak_rss_mib": round(rss / 1024, 2),
            "elapsed_seconds": round(time.monotonic() - began, 3),
            "rocky_host_qualified": False,
            "customer_bundle_formats_qualified": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
