#!/usr/bin/env python3
"""Nonroot MCP-to-worker source-linked packet truth integration."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests"))
from test_protocolwork import pcap
from test_packettruth_integration import frames
from test_packet_coverage import quality_binary

META={"_meta":{
    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
    "io.modelcontextprotocol/clientCapabilities":{},
}}


def run(home,part,payload=None):
    cmd=[sys.executable,"-u",str(ROOT/part)]
    if part=="jobwork.py":
        cmd.append("--once")
    proc=subprocess.run(cmd,input=payload,capture_output=True,text=True,
                        env={**os.environ,"HOME":str(home)},timeout=35)
    if proc.returncode or proc.stderr:
        raise RuntimeError("Fixed gateway/worker smoke returned nonzero")
    return proc.stdout


def call(home,name,arguments):
    request=json.dumps({"jsonrpc":"2.0","id":42,"method":"tools/call",
        "params":{**META,"name":name,"arguments":arguments}})+"\n"
    reply=json.loads(run(home,"gateway.py",request))
    if reply.get("id")!=42 or "error" in reply or reply["result"].get("isError"):
        raise RuntimeError("Expected restricted MCP tool call denied")
    return json.loads(reply["result"]["content"][0]["text"])


def main():
    if os.geteuid()==0:
        raise RuntimeError("A real unprivileged gateway user is required")
    with tempfile.TemporaryDirectory(prefix="rocky-packet-mcp-") as temp:
        home=Path(temp)
        cid=call(home,"case_open",{})["case_id"]
        inbox=home/".local/share/rocky-mcp-gateway/inbox"
        src=inbox/"synthetic.pcap"
        src.write_bytes(pcap(frames()))
        src.chmod(0o600)
        aid=call(home,"artifact_register",{"case_id":cid,"filename":src.name})["artifact_id"]
        jid=call(home,"job_submit",{"case_id":cid,"kind":"decode_pcap","artifact_id":aid})["job_id"]
        run(home,"jobwork.py")
        result=call(home,"job_result",{"job_id":jid})
        if result["state"]!="SUCCEEDED":
            raise RuntimeError("Packet analysis failed or did not persist")
        doc=call(home,"pcap_protocol_report",{"case_id":cid,"artifact_id":aid})
        counts=doc["counters"]
        for key in ("dns_tuple_id_match_candidates","smb2_access_denied",
                    "smb2_response_error","tls_alert_40","tcp_rst"):
            if counts.get(key)!=1:
                raise RuntimeError("Expected known-answer packet marker missing")
        jid=call(home,"job_submit",{"case_id":cid,"kind":"build_correlation"})["job_id"]
        run(home,"jobwork.py")
        if call(home,"job_result",{"job_id":jid})["state"]!="SUCCEEDED":
            raise RuntimeError("Source-linked packet correlation did not persist")
        events=call(home,"correlation_query",{"case_id":cid})["events"]
        if "smb2_error" not in {e["signal"] for e in events}:
            raise RuntimeError("SMB error diagnostic not correlated to packet ordinal")
        exported=json.dumps((doc,events))
        for secret in ("secret.local","synthetic.pcap","10.1.2.3","password"):
            if secret in exported:
                raise RuntimeError("Packet source content accidentally disclosed")
        if doc["claim_boundaries"]["tcp_stream_reassembled"]:
            raise RuntimeError("Incomplete capture falsely called reassembled")
        quality=inbox/'quality.pcap'
        quality.write_bytes(quality_binary());quality.chmod(0o600)
        qid=call(home,'artifact_register',{'case_id':cid,'filename':quality.name})['artifact_id']
        qjob=call(home,'job_submit',{'case_id':cid,'kind':'decode_pcap','artifact_id':qid})['job_id']
        run(home,'jobwork.py')
        if call(home,'job_result',{'job_id':qjob})['state']!='SUCCEEDED':
            raise RuntimeError('Quality vector worker did not persist')
        sample=call(home,'pcap_observations',{'case_id':cid,'artifact_id':qid})
        source_frames={r['signal']:r['packet_no'] for r in sample['observations']}
        expected={'tcp_forward_sequence_gap_candidate':5,'tcp_repeated_seq_candidate':6,
                  'tcp_zero_window_advertised':7,'capture_frame_truncated':8}
        if any(source_frames.get(k)!=v for k,v in expected.items()):
            raise RuntimeError('Known-answer packet source-frame references missing')
        if sample['status']!='PARTIAL' or sample['packet_loss_proven']:
            raise RuntimeError('Packet loss or complete coverage incorrectly claimed')
        if 'private-payload' in json.dumps(sample) or '10.1.2.3' in json.dumps(sample):
            raise RuntimeError('Packet quality payload or endpoint leaked')
    print("PASS: nonroot process MCP/worker packet diagnostics and source-linked SMB2 correlation")


if __name__=="__main__":
    main()
