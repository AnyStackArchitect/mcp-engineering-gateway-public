#!/usr/bin/env python3
"""Non-root operator CLI: explicitly inspect or clean one journaled archive job.

No MCP auto-delete tool or network listener. Only registered case ID, opaque
work ID, minimum age and previously previewed SHA-256 are accepted. Actual
Rocky10 operator use remains blocked pending host qualification.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from archive_recovery import list_workdirs, recover
from casework import CaseStore, CaseError, CASE_ID


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Archive recovery operator refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description="Preview and explicitly recover journaled archive scratch")
    parser.add_argument("--case-id", required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--list", action="store_true")
    modes.add_argument("--work-id")
    parser.add_argument("--older-hours", type=int, default=24)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--plan-sha256")
    args = parser.parse_args(argv)
    if not CASE_ID.fullmatch(args.case_id):
        parser.error("Invalid case identifier")
    if args.list and (args.confirm or args.plan_sha256):
        parser.error("List is read-only")
    try:
        store = CaseStore(Path.home())
        if args.list:
            result = list_workdirs(store, args.case_id)
        else:
            result = recover(store, args.case_id, args.work_id,
                             older_hours=args.older_hours,
                             confirm=args.confirm, plan_sha256=args.plan_sha256)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (CaseError, OSError, ValueError) as exc:
        # Private paths and contents must not appear in CLI error output.
        print("Archive recovery refused: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
