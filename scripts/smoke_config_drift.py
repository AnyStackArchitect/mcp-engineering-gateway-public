#!/usr/bin/env python3
"""Real unprivileged MCP semantic config drift, privacy and source-staleness smoke."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
META={"_meta":{
    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
    "io.modelcontextprotocol/clientCapabilities":{},
}}


def call(home,name,args,expect_error=False):
    req={"jsonrpc":"2.0","id":47,"method":"tools/call",
         "params":{**META,"name":name,"arguments":args}}
    p=subprocess.run([sys.executable,"-u",str(ROOT/"gateway.py")],
        input=json.dumps(req)+"\n",text=True,capture_output=True,
        env={**os.environ,"HOME":str(home)},timeout=30)
    if p.returncode or p.stderr:
        raise RuntimeError("Gateway MCP process failed")
    o=json.loads(p.stdout)
    err=o.get("error") or o.get("result",{}).get("isError")
    if bool(err)!=expect_error:
        raise RuntimeError("Unexpected MCP semantic-diff status")
    return None if expect_error else json.loads(o["result"]["content"][0]["text"])


def main():
    if os.geteuid()==0:
        raise RuntimeError("Use an actual unprivileged Linux identity")
    with tempfile.TemporaryDirectory(prefix="rocky-config-drift-") as root:
        home=Path(root)
        cid=call(home,"case_open",{})["case_id"]
        inbox=home/".local/share/rocky-mcp-gateway/inbox"
        entries=[
            ("before.json",{"network":{"enabled":True,"mtu":1500},
                            "secretTenant":["HIDDEN-A","HIDDEN-B"],
                            "password":"SECRET-OLD"}),
            ("after.json",{"password":"SECRET-NEW",
                           "secretTenant":["HIDDEN-B","HIDDEN-A"],
                           "network":{"enabled":False,"mtu":9000}}),
        ]
        ids=[]
        for name,content in entries:
            src=inbox/name
            src.write_text(json.dumps(content))
            src.chmod(0o600)
            ids.append(call(home,"artifact_register",{"case_id":cid,"filename":name})["artifact_id"])
        args={"case_id":cid,"before_artifact_id":ids[0],"after_artifact_id":ids[1]}
        got=call(home,"config_drift_report",args)
        if (got["status"]!="PASS" or got["changed_fields"]!=4 or
                got["change_totals"].get("ARRAY_ORDER_CHANGED")!=1 or
                got["change_totals"].get("VALUE_CHANGED")!=3 or
                got["causality_established"] or got["change_time_verified"] or
                not got["source_originals_sha256_verified"]):
            raise RuntimeError("Semantic drift count, coverage or uncertainty incorrect")
        legacy=call(home,"config_compare",args)
        if legacy["changed_fields"]!=4:
            raise RuntimeError("Existing config_compare contract regressed")
        serialized=json.dumps((got,legacy))
        for item in ("SECRET-OLD","SECRET-NEW","HIDDEN-A","HIDDEN-B",
                     "password","secretTenant","before.json","after.json"):
            if item in serialized:
                raise RuntimeError("Private key or value escaped semantic report")
        call(home,"config_drift_report",args|{"limit":True},expect_error=True)
        # Out-of-band byte edit makes a fresh on-demand comparison refuse.
        original=home/".local/share/rocky-mcp-gateway/cases"/cid/"originals"/ids[0]
        if not original.is_file():
            raise RuntimeError("Expected original not present")
        original.write_bytes(original.read_bytes()+b"x")
        call(home,"config_drift_report",args,expect_error=True)
    print("PASS: genuine nonroot MCP semantic config changes, legacy parity, private labels and original-stale refusal")


if __name__=="__main__":
    main()
