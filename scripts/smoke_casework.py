#!/usr/bin/env python3
"""Unprivileged end-to-end intake -> log search -> PCAP summary MCP smoke.

Uses private disposable HOME and synthetic evidence only. No SSH, Podman,
network, privileged operations or arbitrary command execution.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

GATEWAY = Path(__file__).resolve().parents[1] / "gateway.py"
MODERN = {"_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}}


def tool(home: Path, name: str, arguments: dict[str, object]) -> dict:
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {**MODERN, "name": name, "arguments": arguments}}
    env = dict(os.environ, HOME=str(home))
    result = subprocess.run([sys.executable, "-u", str(GATEWAY)],
                            input=json.dumps(request) + "\n", text=True,
                            capture_output=True, env=env, timeout=12, check=False)
    if result.returncode != 0 or result.stderr or len(result.stdout.splitlines()) != 1:
        raise RuntimeError(f"Gateway stdio failure: exit={result.returncode}; stderr present={bool(result.stderr)}")
    response = json.loads(result.stdout)
    if response.get("id") != 1 or "error" in response or response["result"].get("isError"):
        raise RuntimeError("Gateway returned MCP error")
    return json.loads(response["result"]["content"][0]["text"])


def main() -> int:
    if os.geteuid() == 0:
        print("Run as an unprivileged Linux user", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="rocky-mcp-case-smoke-") as temp:
        home = Path(temp)
        created = tool(home, "case_open", {})
        case_id = created["case_id"]
        inbox = home / ".local/share/rocky-mcp-gateway/inbox"
        log = inbox / "case.log"
        original = b"2026-10-15T22:00:00Z boot\n2026-10-15T22:02:00Z ERROR token=secret123\n"
        log.write_bytes(original)
        log.chmod(0o600)
        artifact = tool(home, "artifact_register", {"case_id": case_id, "filename": "case.log"})
        if artifact["sha256"] != hashlib.sha256(original).hexdigest():
            raise RuntimeError("Artifact digest mismatch")
        indexed = tool(home, "log_index", {"case_id": case_id, "artifact_id": artifact["artifact_id"]})
        search = tool(home, "log_search", {"case_id": case_id,
                                          "artifact_id": artifact["artifact_id"], "query": "ERROR"})
        if indexed["lines_indexed"] != 2 or len(search["matches"]) != 1:
            raise RuntimeError("Log index or search mismatch")
        if "secret123" in json.dumps(search):
            raise RuntimeError("Secret appeared in MCP result")
        capture = inbox / "sample.cap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2,4,0,0,65535,1) +
                            struct.pack("<IIII", 1,0,4,4) + b"ABCD")
        capture.chmod(0o600)
        p = tool(home, "artifact_register", {"case_id": case_id, "filename": "sample.cap"})
        summary = tool(home, "pcap_summary", {"case_id": case_id, "artifact_id": p["artifact_id"]})
        if summary["packets_examined"] != 1 or summary["payloads_examined"]:
            raise RuntimeError("PCAP metadata summary mismatch")
        status = tool(home, "case_status", {"case_id": case_id})
        if status["artifact_count"] != 2:
            raise RuntimeError("Case state was not persistent across sessions")
        if original != log.read_bytes():
            raise RuntimeError("Source evidence changed")
        audit = home / ".local/state/rocky-mcp-gateway/audit.jsonl"
        if audit.stat().st_mode & 0o077:
            raise RuntimeError("Audit log permissions unsafe")
        if "secret123" in audit.read_text():
            raise RuntimeError("Audit log retained a secret")
    print("PASS: case open/intake/log index/search/PCAP summary/persistence/audit across seven MCP sessions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
