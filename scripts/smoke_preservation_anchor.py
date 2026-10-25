#!/usr/bin/env python3
"""Disposable OFF-HOST end-to-end synthetic Ed25519 checkpoint comparison.

The private signing key lives only inside this test fixture, never Rocky01.
Human operator trust/custody and actual root-owned public-key provisioning
remain deliberately unproven.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from anchorwork import verify_signed_checkpoint
from casework import CaseStore
from case_handoff import _canonical
from operator_sign_preservation_checkpoint import sign_preview
from preservationwork import propose_or_record

CLI = Path(__file__).resolve().parent / "preservation_anchor_cli.py"


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("Preservation anchor smoke refuses root")
    with tempfile.TemporaryDirectory(prefix="rocky-checkpoint-smoke-") as temp:
        base = Path(temp)
        home = base / "gateway-fixture"
        home.mkdir(mode=0o700)
        trust = base / "operator-owned-public-key-fixture"
        trust.mkdir(mode=0o700)
        operator = base / "offline-operator-fixture"
        operator.mkdir(mode=0o700)
        key = operator / "dedicated-test-only-ed25519.pem"
        public = trust / "preservation_anchor_ed25519_pub.pem"
        openssl = shutil.which("openssl")
        if not openssl:
            raise RuntimeError("Test requires native OpenSSL Ed25519 provider")
        for command in [
            [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(key)],
            [openssl, "pkey", "-in", str(key), "-pubout", "-out", str(public)]
        ]:
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=15)
            if result.returncode:
                raise RuntimeError("Synthetic Ed25519 fixture unavailable")
        key.chmod(0o600)
        public.chmod(0o644)
        store = CaseStore(home)
        case = store.open_case()["case_id"]
        req = dict(action="PRESERVATION_HOLD", reason_code="investigation",
                   reference_sha256="a" * 64)
        plan = propose_or_record(store, case, **req)
        propose_or_record(store, case, **req, confirm=True,
                          plan_sha256=plan["plan_sha256"])
        export = subprocess.run(
            [sys.executable, "-u", str(CLI), "preview", "--case-id", case],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30,
            env={**os.environ, "HOME": str(home)})
        if export.returncode:
            raise RuntimeError("Unsigned checkpoint CLI refused")
        checkpoint = json.loads(export.stdout)
        if checkpoint["status"] != "UNSIGNED_CHECKPOINT_PREVIEW":
            raise RuntimeError("Checkpoint incorrectly labelled signed")
        signed = _canonical(sign_preview(export.stdout, key, openssl))
        def match():
            return verify_signed_checkpoint(store, case, signed,
                                            trust_root=trust,
                                            trusted_uid=os.getuid())
        exact = match()
        if (exact["status"] != "SIGNED_CHECKPOINT_MATCHES_CURRENT_LEDGER" or
                not exact["checkpoint_signature_verified"] or
                exact["external_custody_independently_verified"] or
                exact["deletion_authorized"]):
            raise RuntimeError("Signed prefix or human-custody boundary incorrect")
        # An extra valid event cannot inherit an older checkpoint as a
        # current exact anchor.
        req["reason_code"] = "customer_request"
        next_plan = propose_or_record(store, case, **req)
        propose_or_record(store, case, **req, confirm=True,
                          plan_sha256=next_plan["plan_sha256"])
        extended = match()
        if (extended["status"] != "SIGNED_PREFIX_MATCHES_WITH_UNANCHORED_TAIL"
                or extended["signed_checkpoint_covers_current_ledger"]):
            raise RuntimeError("Unanchored new preservation event silently accepted")
        # Restore the exact anchored prefix, then simulate a same-UID
        # rewrite of the first event (a valid locally rehashed chain).
        preservation = store.cases / case / "preservation"
        second = sorted(preservation.iterdir())[1]
        second.unlink()
        first = next(preservation.iterdir())
        doc = json.loads(first.read_bytes())
        doc["reason_code"] = "compliance_review"
        first.write_bytes(_canonical(doc))
        divergence = match()
        if divergence["status"] != "LEDGER_PREFIX_DIVERGED_FROM_SIGNED_CHECKPOINT":
            raise RuntimeError("External checkpoint missed rewritten history")
        print(json.dumps({
            "qualification": "OFF_HOST_SIGNED_PRESERVATION_CHECKPOINT",
            "status": "PASS",
            "real_synthetic_ed25519": True,
            "current_signed_prefix_proven": True,
            "unanchored_tail_not_approved": True,
            "same_uid_rewrite_detected": True,
            "rocky10_host_validated": False,
            "external_custody_independently_verified": False,
            "legal_hold_authority_verified": False,
            "originals_removed": 0,
            "raw_evidence_exported": 0,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
