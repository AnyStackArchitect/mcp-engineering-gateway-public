#!/usr/bin/env python3
"""Non-root local case handoff approval, with no raw-content or path exposure."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from casework import CaseStore, CaseError, CASE_ID
from case_handoff import handoff


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Private case handoff refuses root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(
        description="Review and explicitly confirm a local metadata-only case handoff")
    parser.add_argument("--case-id", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preview", action="store_true")
    group.add_argument("--confirm", action="store_true")
    parser.add_argument("--plan-sha256")
    opts = parser.parse_args(argv)
    if CASE_ID.fullmatch(opts.case_id) is None:
        parser.error("Invalid case identifier")
    if opts.preview and opts.plan_sha256 is not None:
        parser.error("Preview cannot accept a confirmation hash")
    if opts.confirm and not opts.plan_sha256:
        parser.error("Confirmation requires a preview plan SHA-256")
    try:
        store = CaseStore(Path.home())
        result = handoff(store, opts.case_id, confirm=opts.confirm,
                         plan_sha256=opts.plan_sha256)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")))
        return 0
    except (CaseError, OSError, ValueError) as exc:
        print("Private case handoff refused: " + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
