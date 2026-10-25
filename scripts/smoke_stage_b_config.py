#!/usr/bin/env python3
"""Nonroot actual gateway-process evidence snapshot semantic-delta known answers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
META = {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}}


def raw_call(home: Path, tool: str, args: dict) -> dict:
    wire = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {**META, "name": tool, "arguments": args}}) + "\n"
    proc = subprocess.run([sys.executable, "-u", str(ROOT / "gateway.py")],
        text=True, input=wire, capture_output=True, timeout=30,
        env={**os.environ, "HOME": str(home)})
    if proc.returncode or proc.stderr:
        raise RuntimeError("Gateway execution failed in semantic-delta smoke")
    response = json.loads(proc.stdout)
    if response.get("id") != 7 or "error" in response:
        raise RuntimeError("Invalid semantic-delta JSONRPC envelope")
    return response["result"]


def accepted(home: Path, tool: str, args: dict) -> dict:
    result = raw_call(home, tool, args)
    if result.get("isError"):
        raise RuntimeError("Unexpected semantic-delta MCP refusal")
    return json.loads(result["content"][0]["text"])


def main():
    if os.geteuid() == 0:
        raise RuntimeError("Semantic-delta fixture must run unprivileged")
    with tempfile.TemporaryDirectory(prefix="rocky-config-delta-") as folder:
        home = Path(folder)
        cid = accepted(home, "case_open", {})["case_id"]
        inbox = home / ".local/share/rocky-mcp-gateway/inbox"
        before = json.dumps({"vms": [
            {"id": "PRIVATE-HOST-A", "enabled": True, "password": "private-before"},
            {"id": "PRIVATE-HOST-B", "enabled": True, "timeout": 20}
        ]})
        after = json.dumps({"vms": [
            {"id": "PRIVATE-HOST-B", "timeout": 20, "enabled": True},
            {"id": "PRIVATE-HOST-A", "enabled": False, "password": "private-after"}
        ]})
        ids = []
        for name, value in (("snapshot-a.json", before), ("snapshot-b.json", after)):
            path = inbox / name
            path.write_text(value, encoding="utf-8")
            path.chmod(0o600)
            ids.append(accepted(home, "artifact_register", {
                "case_id": cid, "filename": name})["artifact_id"])
        request = {"case_id": cid, "before_artifact_id": ids[0],
                   "after_artifact_id": ids[1], "format": "json"}
        result = accepted(home, "config_compare", request)
        if (result["status"] != "PASS" or result["changed_fields"] != 3 or
                result["values_exposed"] or result["causality_established"] or
                result["change_time_known"] or result["same_system_verified"] or
                result["before_sha256"] != hashlib.sha256(before.encode()).hexdigest() or
                result["after_sha256"] != hashlib.sha256(after.encode()).hexdigest()):
            raise RuntimeError("Semantic-delta identity/layout evidence invalid")
        fields = [entry["field"] for entry in result["changes"]]
        if (len(fields) != 3 or "array_layout" not in fields or
                "enabled" not in fields or
                sum(1 for f in fields if f.startswith("field-")) != 1):
            raise RuntimeError("Semantic-delta expected structural change evidence missing")
        if not any(c["field"].startswith("field-") and "field_ref" in c
                   for c in result["changes"]):
            raise RuntimeError("Sensitive configuration field not masked")
        doc = json.dumps(result)
        for secret in ("PRIVATE-HOST-A", "PRIVATE-HOST-B", "private-before",
                       "private-after", "password", "snapshot-a.json",
                       "snapshot-b.json", str(home)):
            if secret in doc:
                raise RuntimeError("Original configuration leaked through MCP")
        # Source identity mismatch after registration invalidates the case
        # snapshot even though byte count remains constant.
        original = home / ".local/share/rocky-mcp-gateway/cases" / cid / "originals" / ids[0]
        with original.open("r+b") as fp:
            fp.seek(4)
            fp.write(b"X")
        if not raw_call(home, "config_compare", request).get("isError"):
            raise RuntimeError("Tampered configuration source was not refused")
    print("PASS: real nonroot MCP semantic config layout, identity, redaction and tamper refusal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
