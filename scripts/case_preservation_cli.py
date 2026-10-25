#!/usr/bin/env python3
"""Local nonroot operator preview/confirm for additive case preservation only.

No release, delete, expiry, raw original export, arbitrary filesystem path,
remote access, legal authority or MCP endpoint.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseError, CaseStore, CASE_ID
from preservationwork import HOLD_REASONS, propose_or_record


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Preservation operator refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="Additive local case preservation, not deletion/hold release")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--source-reference-sha256", required=True)
    kind = parser.add_mutually_exclusive_group(required=True)
    kind.add_argument("--hold-reason", choices=sorted(HOLD_REASONS))
    kind.add_argument("--minimum-days", type=int)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--preview", action="store_true")
    choice.add_argument("--confirm", action="store_true")
    parser.add_argument("--plan-sha256")
    args = parser.parse_args(argv)
    if CASE_ID.fullmatch(args.case_id) is None:
        parser.error("Invalid case ID")
    if args.preview and args.plan_sha256 is not None:
        parser.error("Preview cannot accept confirmation digest")
    if args.confirm and not args.plan_sha256:
        parser.error("Confirmation requires a separately previewed SHA-256")
    action = ("PRESERVATION_HOLD" if args.hold_reason is not None
              else "MINIMUM_RETENTION_DAYS")
    try:
        result = propose_or_record(
            CaseStore(Path.home()), args.case_id, action=action,
            reference_sha256=args.source_reference_sha256,
            reason_code=args.hold_reason, minimum_days=args.minimum_days,
            confirm=args.confirm, plan_sha256=args.plan_sha256)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")))
        return 0
    except (CaseError, OSError, ValueError) as exc:
        # Never echo customer notes, evidence content, paths or private hashes.
        print("Preservation operation refused: " + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
