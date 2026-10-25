#!/usr/bin/env python3
"""Local non-root, no-delete retention and registered-original integrity review."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseError, CaseStore, CASE_ID
from retentionwork import assess_case


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Retention preview refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="Read-only original integrity and advisory age review; NO deletion")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--minimum-age-days", required=True, type=int)
    parser.add_argument("--preview", action="store_true", required=True)
    options = parser.parse_args(argv)
    if not CASE_ID.fullmatch(options.case_id):
        parser.error("Invalid case ID")
    try:
        result = assess_case(CaseStore(Path.home()), options.case_id,
                             minimum_age_days=options.minimum_age_days)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True))
        return 0
    except (CaseError, OSError, ValueError) as exc:
        # Do not echo customer paths, original names, manifests or raw bytes.
        print("Retention assessment refused: " + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
