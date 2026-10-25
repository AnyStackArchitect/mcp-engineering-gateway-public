#!/usr/bin/env python3
"""End-to-end fixed-template job smoke using two processes and synthetic files."""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
MODERN = {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}}}


def call(home: Path, name: str, args: dict) -> dict:
    wire = {"jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": {**MODERN, "name": name, "arguments": args}}
    env = dict(os.environ, HOME=str(home))
    p = subprocess.run([sys.executable, "-u", str(PROJECT / "gateway.py")],
                       input=json.dumps(wire) + "\n", capture_output=True,
                       text=True, env=env, timeout=15, check=False)
    if p.returncode or p.stderr or len(p.stdout.splitlines()) != 1:
        raise RuntimeError("Invalid gateway response framing")
    response = json.loads(p.stdout)
    if response.get("id") != 42 or "error" in response or response["result"].get("isError"):
        raise RuntimeError("Gateway MCP call failed")
    return json.loads(response["result"]["content"][0]["text"])


def work(home: Path) -> None:
    env=dict(os.environ, HOME=str(home))
    p=subprocess.run([sys.executable, "-u", str(PROJECT / "jobwork.py"), "--once"],
                     capture_output=True,text=True,env=env,timeout=15,check=False)
    if p.returncode or p.stderr:
        raise RuntimeError("Fixed-template worker exited with an error")


def main() -> int:
    if os.geteuid() == 0:
        print("Run non-root",file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="rocky-jobs-smoke-") as tmp:
        home=Path(tmp)
        case_id=call(home,"case_open",{})["case_id"]
        inbox=home/".local/share/rocky-mcp-gateway/inbox"
        sample=b"2026-10-15T12:00:00Z startup\n2026-10-15T12:00:05Z ERROR password=never_log_me\n"
        (inbox/"node.log").write_bytes(sample)
        (inbox/"node.log").chmod(0o600)
        first=call(home,"job_submit",{"kind":"import_staged","case_id":case_id,"filename":"node.log"})["job_id"]
        if call(home,"job_status",{"job_id":first})["state"]!="QUEUED":
            raise RuntimeError("Job was not queued")
        work(home)
        imported=call(home,"job_result",{"job_id":first})
        if imported["state"]!="SUCCEEDED":
            raise RuntimeError("Artifact import did not succeed")
        aid=imported["result"]["artifact_id"]
        second=call(home,"job_submit",{"kind":"index_log","case_id":case_id,"artifact_id":aid})["job_id"]
        work(home)
        indexed=call(home,"job_result",{"job_id":second})
        if indexed["state"]!="SUCCEEDED" or indexed["result"]["lines_indexed"]!=2:
            raise RuntimeError("Log index job failed")
        found=call(home,"log_search",{"case_id":case_id,"artifact_id":aid,"query":"ERROR"})
        if len(found["matches"])!=1 or "never_log_me" in json.dumps(found):
            raise RuntimeError("Log evidence search failed or leaked token")
        pcap=(b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII",2,4,0,0,65535,1)+
              struct.pack("<IIII",12345,0,4,4)+b"DATA")
        (inbox/"packet.cap").write_bytes(pcap)
        (inbox/"packet.cap").chmod(0o600)
        third=call(home,"job_submit",{"kind":"import_staged","case_id":case_id,"filename":"packet.cap"})["job_id"]
        work(home)
        packet_id=call(home,"job_result",{"job_id":third})["result"]["artifact_id"]
        fourth=call(home,"job_submit",{"kind":"pcap_summary","case_id":case_id,"artifact_id":packet_id})["job_id"]
        work(home)
        result=call(home,"job_result",{"job_id":fourth})
        if result["state"]!="SUCCEEDED" or result["result"]["packets_examined"]!=1:
            raise RuntimeError("PCAP structural job failed")
        fifth=call(home,"job_submit",{"kind":"import_staged","case_id":case_id,"filename":"node.log"})["job_id"]
        cancelled=call(home,"job_cancel",{"job_id":fifth})
        if cancelled["state"]!="CANCELLED":
            raise RuntimeError("Queued cancellation failed")
        jobs=call(home,"job_list",{})
        if jobs["total_jobs"]!=5:
            raise RuntimeError("Job persistence/reporting failed")
        audit=home/".local/state/rocky-mcp-gateway/audit.jsonl"
        job_db=home/".local/share/rocky-mcp-gateway/jobs.sqlite3"
        for file in (audit,job_db):
            if file.stat().st_mode & 0o077:
                raise RuntimeError("Private audit/job database permissions failed")
        if "never_log_me" in audit.read_text():
            raise RuntimeError("Raw secret appeared in audit")
    print("PASS: fixed import, log index, PCAP summary, cancel, restart persistence and private audit across MCP sessions")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
