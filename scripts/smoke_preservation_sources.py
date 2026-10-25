#!/usr/bin/env python3
"""Independent nonroot subprocess fixture for v0.28 source byte verification.

Only synthetic private case data in a disposable home; no Rocky01 host work,
customer payload, publication, legal authority, grant, deletion or export.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseStore
from preservationwork import propose_or_record

VERIFY_CLI = Path(__file__).resolve().parent / "verify_preservation_sources.py"


def verify(home: Path, case: str, expected_code: int) -> dict | None:
    outcome = subprocess.run([sys.executable, "-u", str(VERIFY_CLI),
                              "--case-id", case, "--verify"],
                             env={**os.environ, "HOME": str(home)},
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=45, check=False)
    if outcome.returncode != expected_code or len(outcome.stdout) > 32768:
        raise RuntimeError("Wrong bounded verification exit state")
    return json.loads(outcome.stdout) if outcome.stdout else None


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Off-host source material smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-reference-source-") as temp:
        home = Path(temp)
        store = CaseStore(home)
        case_id = store.open_case()["case_id"]
        log = store.inbox / "private-support-log.txt"
        log.write_bytes(b"private password=not-for-chat\n")
        log.chmod(0o600)
        store.register(case_id, log.name)
        paper = b"synthetic untrusted operator preservation source bytes\n" * 25
        paper_digest = hashlib.sha256(paper).hexdigest()
        args = {"action": "PRESERVATION_HOLD", "reason_code": "investigation",
                "reference_sha256": paper_digest}
        planned = propose_or_record(store, case_id, **args)
        propose_or_record(store, case_id, **args, confirm=True,
                          plan_sha256=planned["plan_sha256"])
        missing = verify(home, case_id, 3)
        if (missing["references_missing_from_case"] != 1 or
                missing["source_reference_material_verified"]):
            raise RuntimeError("Unregistered reference incorrectly blessed")
        pending = store.inbox / "operator-preservation-source.pdf"
        pending.write_bytes(paper)
        pending.chmod(0o600)
        registered = store.register(case_id, pending.name)
        preserved = store.cases / case_id / "originals" / registered["artifact_id"]
        original = hashlib.sha256(preserved.read_bytes()).hexdigest()
        report = verify(home, case_id, 0)
        if (report["status"] != "MATERIAL_BYTES_VERIFIED_ONLY"
                or report["references_with_verified_nonempty_source_bytes"] != 1
                or report["legal_hold_authority_verified"]
                or report["deletion_authorized"]
                or report["raw_originals_exported"]):
            raise RuntimeError("Reference-byte identity or authority boundary broken")
        if original != hashlib.sha256(preserved.read_bytes()).hexdigest():
            raise RuntimeError("Read-only verifier changed reference bytes")
        if (b"password=not-for-chat" in json.dumps(report).encode()
                or paper in json.dumps(report).encode()
                or paper_digest.encode() in json.dumps(report).encode()):
            raise RuntimeError("Reference report leaked source evidence")
        invalid = subprocess.run([sys.executable, "-u", str(VERIFY_CLI),
                                  "--case-id", case_id, "--verify", "--delete"],
                                 env={**os.environ, "HOME": str(home)},
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 stdin=subprocess.DEVNULL, timeout=20)
        if invalid.returncode != 2:
            raise RuntimeError("Forbidden erase option accepted")
        preserved.write_bytes(b"X" * len(paper))
        if verify(home, case_id, 2) is not None:
            raise RuntimeError("Mutated source could be verified")
        if not preserved.exists():
            raise RuntimeError("Synthetic source was deleted")
        print(json.dumps({
            "qualification": "OFF_HOST_REGISTERED_PRESERVATION_SOURCE_BYTES",
            "status": "PASS",
            "missing_registered_reference_refused": True,
            "matched_nonempty_original_verified": True,
            "mutated_original_refused": True,
            "rootless_operator": True,
            "rocky10_host_validated": False,
            "legal_hold_authority_verified": False,
            "source_originals_removed": 0,
            "raw_evidence_exported": 0,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
