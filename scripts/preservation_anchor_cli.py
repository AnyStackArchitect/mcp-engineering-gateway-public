#!/usr/bin/env python3
"""Local, nonroot checkpoint preview and signed checkpoint verification only.

No private signing key, configurable trust path, hold release, deletion,
network export, scheduled task, or MCP mutating action.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from anchorwork import (MAX_ENVELOPE_BYTES, create_unsigned_checkpoint,
                        verify_signed_checkpoint)
from casework import CaseError, CaseStore, CASE_ID


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Preservation checkpoint requires a nonroot operator", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="Unsigned checkpoint preview or trusted signed checkpoint comparison")
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("preview", help="Generate bounded UNSIGNED checkpoint packet")
    make.add_argument("--case-id", required=True)
    verify = sub.add_parser("verify", help="Compare a signed checkpoint from stdin")
    verify.add_argument("--case-id", required=True)
    verify.add_argument("--signed-stdin", action="store_true", required=True)
    args = parser.parse_args(argv)
    if not isinstance(args.case_id, str) or CASE_ID.fullmatch(args.case_id) is None:
        parser.error("Invalid case identifier")
    try:
        store = CaseStore(Path.home())
        if args.action == "preview":
            result = create_unsigned_checkpoint(store, args.case_id)
            exit_code = 0
        else:
            # No arbitrary host path or key override: verify only against a
            # distinct operator-anchoring public key provisioned by admin.
            raw = sys.stdin.buffer.read(MAX_ENVELOPE_BYTES + 1)
            result = verify_signed_checkpoint(store, args.case_id, raw)
            exit_code = 0 if result["signed_checkpoint_covers_current_ledger"] else 3
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        return exit_code
    except (CaseError, OSError, ValueError) as exc:
        # Never reflect raw stdin, checkpoint source, private paths or key data.
        print("Preservation checkpoint operation refused: " +
              type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
