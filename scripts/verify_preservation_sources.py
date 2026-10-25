#!/usr/bin/env python3
"""Nonroot local read-only check of recorded preservation source *bytes*.

This is not policy/hold authenticity verification, an export, or legal
authorization. Source documents must already be independently registered.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from casework import CaseError, CaseStore, CASE_ID
from sourceverify import verify_references


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Preservation source verification refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="Read-only byte matching against case registered originals")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--verify", required=True, action="store_true")
    options = parser.parse_args(argv)
    if not isinstance(options.case_id, str) or CASE_ID.fullmatch(options.case_id) is None:
        parser.error("Invalid case identifier")
    try:
        report = verify_references(CaseStore(Path.home()), options.case_id)
        print(json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
        # Missing material is an explicit, machine-readable NONZERO result.
        return 0 if report["source_reference_material_verified"] else 3
    except (CaseError, OSError, ValueError) as exc:
        # Do not echo raw paths, usernames or diagnostic source payloads.
        print("Preservation source verification refused: " + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
