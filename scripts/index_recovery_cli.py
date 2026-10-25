#!/usr/bin/env python3
"""Non-root, local operator command for interrupted private SQLite index files.

Only an opaque case ID and index-work ID are accepted. No filename/path,
network, MCP automatic cleanup or registered case-original deletion.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from casework import CaseStore, CaseError, CASE_ID
from index_recovery import list_interrupted, recover


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Index recovery operator refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="List, preview and explicitly clean ONE aged journaled SQLite index")
    parser.add_argument("--case-id", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true")
    group.add_argument("--work-id")
    parser.add_argument("--older-hours", type=int, default=24)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--plan-sha256")
    options = parser.parse_args(argv)
    if CASE_ID.fullmatch(options.case_id) is None:
        parser.error("Invalid case identifier")
    if options.list and (options.confirm or options.plan_sha256):
        parser.error("Listing is read-only")
    try:
        cases = CaseStore(Path.home())
        if options.list:
            output = list_interrupted(cases, options.case_id)
        else:
            output = recover(
                cases, options.case_id, options.work_id,
                older_hours=options.older_hours, confirm=options.confirm,
                plan_sha256=options.plan_sha256)
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (CaseError, OSError, ValueError) as exc:
        print("Index recovery refused: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
