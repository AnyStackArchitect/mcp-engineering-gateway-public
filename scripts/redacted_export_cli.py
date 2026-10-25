#!/usr/bin/env python3
"""Local-only redacted review ZIP: preview or prepare, NEVER transmit."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseStore, CaseError, CASE_ID
from redacted_export import review_redacted_export

def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Redacted package review refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="Prepare a PRIVATE redacted structural review ZIP, not an approved disclosure")
    parser.add_argument("--case-id", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preview", action="store_true")
    action.add_argument("--prepare", action="store_true")
    parser.add_argument("--review-fingerprint")
    args = parser.parse_args(argv)
    if not isinstance(args.case_id, str) or CASE_ID.fullmatch(args.case_id) is None:
        parser.error("Invalid case identifier")
    if args.preview and args.review_fingerprint is not None:
        parser.error("Preview must not include confirmation fingerprint")
    if args.prepare and not args.review_fingerprint:
        parser.error("Private preparation requires a reviewed fingerprint")
    try:
        result = review_redacted_export(
            CaseStore(Path.home()), args.case_id,
            prepare=args.prepare, preview_sha256=args.review_fingerprint)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True)
        if len(encoded) > 16384:
            raise CaseError("Redacted package operator response exceeds limit")
        print(encoded)
        return 0
    except (CaseError, OSError, ValueError, TypeError, OverflowError) as exc:
        print("Redacted package operation refused: " + type(exc).__name__,
              file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
