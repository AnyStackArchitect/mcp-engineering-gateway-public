#!/usr/bin/env python3
"""Non-root local operator preview/confirmation for one private export journal."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseError, CaseStore, CASE_ID
from redacted_export_recovery import list_interrupted, recover


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Private redacted export recovery refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="List, preview, or explicitly clear ONE private redacted export journal")
    parser.add_argument("--case-id", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list", action="store_true")
    action.add_argument("--work-id")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--recovery-plan-sha256")
    parser.add_argument("--minimum-age-seconds", type=int, default=0)
    args = parser.parse_args(argv)
    if not isinstance(args.case_id, str) or CASE_ID.fullmatch(args.case_id) is None:
        parser.error("Invalid case identifier")
    if args.list and (args.confirm or args.recovery_plan_sha256 is not None
                      or args.minimum_age_seconds != 0):
        parser.error("Listing does not accept recovery controls")
    try:
        store = CaseStore(Path.home())
        if args.list:
            result = list_interrupted(store, args.case_id)
        else:
            result = recover(store, args.case_id, args.work_id, confirm=args.confirm,
                             recovery_plan_sha256=args.recovery_plan_sha256,
                             minimum_age_seconds=args.minimum_age_seconds)
        encoded = json.dumps(result, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":"))
        if len(encoded) > 16384:
            raise CaseError("Redacted recovery response exceeds bounded size")
        print(encoded)
        return 0
    except (CaseError, OSError, ValueError, TypeError, OverflowError) as exc:
        print("Private redacted export recovery refused: " + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
