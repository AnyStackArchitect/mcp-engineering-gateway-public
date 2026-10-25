#!/usr/bin/env python3
"""Operator-local read-only registered original disposition preflight.

No deletion, hold release, quarantine, transaction journal or file exports.
A matching preview SHA merely permits *modelling* an interruption scenario.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseError, CaseStore, CASE_ID
from disposition_preflight import SCENARIOS, inspect_disposition


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Disposition preflight requires nonroot operator", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="Non-destructive original disposition eligibility and interruption review")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--minimum-age-days", required=True, type=int)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--simulate", choices=sorted(SCENARIOS))
    parser.add_argument("--preview-sha256")
    args = parser.parse_args(argv)
    if not isinstance(args.case_id, str) or CASE_ID.fullmatch(args.case_id) is None:
        parser.error("Invalid case identifier")
    if args.simulate is None and args.preview_sha256 is not None:
        parser.error("Preview cannot accept an existing fingerprint")
    if args.simulate is not None and args.preview_sha256 is None:
        parser.error("Simulation requires an exact preview SHA-256")
    try:
        result = inspect_disposition(
            CaseStore(Path.home()),
            args.case_id,
            minimum_age_days=args.minimum_age_days,
            scenario=args.simulate,
            expected_preview_sha256=args.preview_sha256,
        )
        encoded = json.dumps(result, sort_keys=True, ensure_ascii=True,
                             separators=(",", ":"))
        if len(encoded) > 16384:
            raise CaseError("Disposition preflight output exceeds fixed bound")
        print(encoded)
        # Exit 0 means READ-ONLY ASSESSMENT COMPUTED, never approval/clearance.
        return 0
    except (CaseError, OSError, ValueError, TypeError, OverflowError) as exc:
        # Do not copy paths, payloads, or untrusted strings into diagnostics.
        print("Disposition preflight refused: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
