#!/usr/bin/env python3
"""Local operator-only disposition. No model-accessible MCP registration."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseStore, CaseError
from case_disposition import preview, execute, abort_initialization
from disposition_grants import MAX_BYTES, canonical, DispositionGrantError


def main(argv=None) -> int:
    os.umask(0o077)
    if os.name != "posix" or os.geteuid() == 0:
        print("Disposition requires a nonroot POSIX operator", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description="Dual-signed, disabled-by-default case disposition")
    modes = parser.add_subparsers(dest="mode", required=True)
    review = modes.add_parser("preview")
    review.add_argument("--case-id", required=True)
    review.add_argument("--action", choices=("RETIRE", "RESTORE", "FINAL_DELETE"), required=True)
    review.add_argument("--minimum-age-days", type=int, required=True)
    review.add_argument("--retention-start-utc", required=True)
    modes.add_parser("execute", help="Read two canonical signed grants from bounded stdin")
    abort = modes.add_parser("abort-initialization", help="Remove only unpublished transaction metadata")
    abort.add_argument("--case-id", required=True)
    args = parser.parse_args(argv)
    try:
        store = CaseStore(Path.home())
        if args.mode == "preview":
            result = preview(store, args.case_id, action=args.action,
                             minimum_age_days=args.minimum_age_days, retention_start_utc=args.retention_start_utc)
        elif args.mode == "execute":
            result = execute(store, sys.stdin.buffer.read(MAX_BYTES + 1))
        else:
            result = abort_initialization(store, args.case_id)
        print(canonical(result).decode("ascii"))
        return 0
    except (CaseError, DispositionGrantError, OSError, ValueError, TypeError) as exc:
        print("Disposition refused: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
