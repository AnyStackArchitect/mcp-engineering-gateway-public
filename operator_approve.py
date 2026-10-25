#!/usr/bin/env python3
"""Local review-bundle EXPORT and signed-grant IMPORT. Cannot issue approvals.

Only the operator workstation can sign a grant; its private key must never be
present on this gateway. These local actions are intentionally not MCP tools.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import sys
from execution_broker import ExecutionBrokerClient, BrokerError
from approvalwork import decode as decode_grant, canonical as _canonical, MAX_GRANT_BYTES

def _read_private(path: Path) -> bytes:
    if path.is_symlink():
        raise BrokerError("Signed grant symlink refused")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or info.st_size > MAX_GRANT_BYTES):
            raise BrokerError("Signed grant file owner, mode or size invalid")
        data = os.read(descriptor, MAX_GRANT_BYTES + 1)
        after = os.fstat(descriptor)
        if (len(data) != info.st_size or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns):
            raise BrokerError("Signed grant changed during read")
        return data
    finally:
        os.close(descriptor)

def main() -> int:
    if os.geteuid() == 0:
        print("Non-root local operator access required", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description="Review bundle export / signed grant import only")
    subs = parser.add_subparsers(dest="action", required=True)
    export = subs.add_parser("export", help="Export a pending execution for OFF-HOST human review")
    export.add_argument("execution_id")
    export.add_argument("--out", required=True, type=Path)
    signed = subs.add_parser("import", help="Verify off-host Ed25519 grant and queue it")
    signed.add_argument("signed_grant", type=Path)
    args = parser.parse_args()
    try:
        store = ExecutionBrokerClient(Path.home())
        if args.action == "export":
            details = store.export_review(args.execution_id)
            if details["state"] != "PREPARED":
                raise BrokerError("Execution is not awaiting operator review")
            raw = _canonical(details) + b"\n"
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(raw)
            print("Review bundle exported. Move only this bundle to your operator workstation.")
        else:
            envelope = decode_grant(_read_private(args.signed_grant))
            result = store.import_signed_grant(envelope)
            print("Signed decision processed:", result["state"], result["execution_id"])
        return 0
    except (BrokerError, OSError, ValueError, TypeError) as exc:
        print("Operator handoff refused: " + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
