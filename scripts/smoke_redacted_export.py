#!/usr/bin/env python3
"""True local subprocess smoke for a private redacted-review ZIP."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseStore
from preservationwork import propose_or_record
from redacted_export import MEMBERS, OUT_DIR

CLI = Path(__file__).resolve().parent / "redacted_export_cli.py"


def call(home: Path, case_id: str, args: list[str], code: int = 0) -> dict | None:
    command = [sys.executable, "-u", str(CLI), "--case-id", case_id, *args]
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            env={**os.environ, "HOME": str(home)},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=50, check=False)
    if result.returncode != code or len(result.stdout) > 16384:
        raise RuntimeError("Redacted review subprocess failed contract")
    return json.loads(result.stdout) if result.stdout else None


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Redacted review subprocess smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-redacted-smoke-") as folder:
        home = Path(folder)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        original_bytes = b"secret customer=XYZ password=NEVER_EXPOSE\n" * 307
        stage = store.inbox / "private-customer-network.log"
        stage.write_bytes(original_bytes)
        stage.chmod(0o600)
        record = store.register(case, stage.name)
        original = store.cases / case / "originals" / record["artifact_id"]
        source_digest = hashlib.sha256(original.read_bytes()).hexdigest()
        before = call(home, case, ["--preview"])
        if (before["status"] != "PRIVATE_REDACTED_PREVIEW_ONLY"
                or before["public_disclosure_approved"]):
            raise RuntimeError("Redacted review preview incorrectly approved disclosure")
        prepared = call(home, case, [
            "--prepare", "--review-fingerprint", before["review_fingerprint_sha256"]])
        if (prepared["status"] != "PRIVATE_REDACTED_PACKAGE_PREPARED_NOT_APPROVED"
                or prepared["public_disclosure_approved"]
                or prepared["raw_originals_exported"]):
            raise RuntimeError("Private packaging was mistaken for disclosure")
        output = store.base / OUT_DIR / prepared["package_name"]
        content = output.read_bytes()
        if hashlib.sha256(content).hexdigest() != before["package_sha256"]:
            raise RuntimeError("ZIP publication digest not verified")
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            if tuple(archive.namelist()) != MEMBERS:
                raise RuntimeError("Allowlisted ZIP members changed")
            report = json.loads(archive.read("review.json"))
            if report["public_disclosure_approved"] or report["external_transmission_performed"]:
                raise RuntimeError("Private review package falsely marked public")
        if (original_bytes in content or record["sha256"].encode() in content
                or b"private-customer-network.log" in content
                or case.encode() in content or b"NEVER_EXPOSE" in content):
            raise RuntimeError("Private source details leaked")
        if source_digest != hashlib.sha256(original.read_bytes()).hexdigest():
            raise RuntimeError("Original was modified by read-only publication")
        call(home, case, ["--prepare", "--review-fingerprint",
                          before["review_fingerprint_sha256"]], code=2)
        hold = dict(action="PRESERVATION_HOLD", reason_code="investigation",
                    reference_sha256=record["sha256"])
        plan = propose_or_record(store, case, **hold)
        propose_or_record(store, case, **hold,
                          confirm=True, plan_sha256=plan["plan_sha256"])
        call(home, case, ["--prepare", "--review-fingerprint",
                          before["review_fingerprint_sha256"]], code=2)
        print(json.dumps({
            "qualification": "OFF_HOST_PRIVATE_REDACTED_REVIEW_PACKAGE",
            "status": "PASS",
            "fixed_zip_members": len(MEMBERS),
            "raw_evidence_included": False,
            "originals_removed": 0,
            "external_transmission_performed": False,
            "independent_disclosure_approval_verified": False,
            "rocky10_host_validated": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
