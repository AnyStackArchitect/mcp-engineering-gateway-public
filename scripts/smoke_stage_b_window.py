#!/usr/bin/env python3
"""Real separate-process Phase B MCP/worker event-window and rebuild proof."""
from __future__ import annotations
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


def run(home, script, payload=None):
    argv = [sys.executable, "-u", str(ROOT / script)]
    if script == "jobwork.py":
        argv.append("--once")
    proc = subprocess.run(argv, input=payload, text=True, capture_output=True,
        env={**os.environ, "HOME": str(home)}, timeout=35)
    if proc.returncode or proc.stderr:
        raise RuntimeError("Phase B process failed: " + script)
    return proc.stdout


def call(home, name, args):
    request = json.dumps({"jsonrpc": "2.0", "id": 3,
        "method": "tools/call", "params": {
            **META, "name": name, "arguments": args}}) + "\n"
    packet = json.loads(run(home, "gateway.py", request))
    if packet.get("id") != 3 or "error" in packet or packet.get("result", {}).get("isError"):
        raise RuntimeError("Phase B MCP refused: " + name)
    return json.loads(packet["result"]["content"][0]["text"])


def main():
    if os.geteuid() == 0:
        raise RuntimeError("Must use genuine nonroot host identity")
    with tempfile.TemporaryDirectory(prefix="rocky-stage-b-") as folder:
        home = Path(folder)
        cid = call(home, "case_open", {})["case_id"]
        inbox = home / ".local/share/rocky-mcp-gateway/inbox"
        for name, line in [
            ("left.log", "2026-10-17T10:00:00Z ERROR password=hidden-source\n"),
            ("right.log", "2026-10-17T10:00:00.250Z WARN response\n"),
        ]:
            path = inbox / name
            path.write_text(line)
            path.chmod(0o600)
            call(home, "artifact_register", {"case_id": cid, "filename": name})
        for kind in ("build_timeline", "build_correlation"):
            job = call(home, "job_submit", {"case_id": cid, "kind": kind})
            run(home, "jobwork.py")
            if call(home, "job_result", {"job_id": job["job_id"]})["state"] != "SUCCEEDED":
                raise RuntimeError("Required indexed evidence not built")
        query = call(home, "correlation_query", {"case_id": cid})
        anchor = query["events"][0]
        window = call(home, "correlation_window", {
            "case_id": cid, "index_revision": query["index_revision"],
            "anchor_event_id": anchor["event_id"], "before_ms": 1000,
            "after_ms": 1000})
        if (len(window["events"]) != 1 or
            window["events"][0]["observed_delta_ms"] != 250.0 or
            window["clock_alignment"] != "UNVERIFIED" or
            window["causality_inferred"] is not False):
            raise RuntimeError("Cross-process proximity semantics invalid")
        if "hidden-source" in json.dumps((query, window)):
            raise RuntimeError("Raw source secret disclosed")
        job = call(home, "job_submit", {"case_id": cid, "kind": "build_correlation"})
        run(home, "jobwork.py")
        if call(home, "job_result", {"job_id": job["job_id"]})["state"] != "SUCCEEDED":
            raise RuntimeError("Rebuild failed")
        rejected = json.loads(run(home, "gateway.py", json.dumps({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {**META, "name": "correlation_window",
                "arguments": {"case_id": cid, "index_revision": query["index_revision"],
                    "anchor_event_id": anchor["event_id"]}}}) + "\n"))
        if not rejected["result"].get("isError"):
            raise RuntimeError("Stale event reference silently accepted")
    print("PASS: actual nonroot MCP/worker cross-source window and stale-revision denial")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
