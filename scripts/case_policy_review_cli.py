#!/usr/bin/env python3
"""Nonroot local read-only assessment of proposed preservation terms."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CASE_ID, CaseError, CaseStore
from policyreview import MAX_POLICY_BYTES, review_policy

def main() -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Policy review requires nonroot operator", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description="Review proposed retention terms only")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--review", action="store_true", required=True)
    parser.add_argument("--policy-stdin", action="store_true", required=True)
    args = parser.parse_args()
    if not isinstance(args.case_id, str) or CASE_ID.fullmatch(args.case_id) is None:
        parser.error("Invalid case identifier")
    try:
        policy = sys.stdin.buffer.read(MAX_POLICY_BYTES + 1)
        result = review_policy(CaseStore(Path.home()), args.case_id, policy)
        output = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if len(output) > MAX_POLICY_BYTES:
            raise CaseError("Policy review output too large")
        print(output)
        return 0
    except (CaseError, OSError, ValueError, TypeError) as error:
        print("Policy review refused: " + type(error).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
