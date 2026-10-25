#!/usr/bin/env python3
"""Non-root local operator recovery of one aged journaled private handoff.

No generic path argument, MCP cleanup route, public sharing or case-original
deletion. The operator must preview and explicitly confirm one SHA-bound plan.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from casework import CaseStore, CaseError, CASE_ID
from handoff_recovery import list_interrupted, recover


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Private handoff recovery refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="List or inspect/confirm ONE aged private handoff publication journal")
    parser.add_argument("--case-id", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true")
    group.add_argument("--work-id")
    parser.add_argument("--older-hours", type=int, default=24)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--recovery-plan-sha256")
    args = parser.parse_args(argv)
    if not isinstance(args.case_id, str) or CASE_ID.fullmatch(args.case_id) is None:
        parser.error("Invalid case identifier")
    if args.list and (args.confirm or args.recovery_plan_sha256 is not None):
        parser.error("Listing is read-only")
    try:
        store = CaseStore(Path.home())
        if args.list:
            result = list_interrupted(store, args.case_id)
        else:
            result = recover(
                store, args.case_id, args.work_id,
                older_hours=args.older_hours, confirm=args.confirm,
                recovery_plan_sha256=args.recovery_plan_sha256)
        print(json.dumps(result, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":")))
        return 0
    except (CaseError, OSError, ValueError) as exc:
        print("Private handoff recovery refused: " + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
