#!/usr/bin/env python3
"""Independent TShark comparison for bounded synthetic packet truth.

Synthetic known answers only; no live capture, DNS name resolution,
network scanning, raw customer evidence, arbitrary process commands or
pipeline outputs transferred to external services.
"""
from __future__ import annotations
from importlib import import_module
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/"tests"))
from test_protocolwork import pcap,pcapng
from test_packettruth_integration import frames
from casework import CaseStore
from protocolwork import analyze_capture,protocol_report,protocol_observations
from test_packet_coverage import quality_binary

FIELDS=("frame.number","tcp.flags.reset","dns.flags.rcode",
        "tls.record.content_type","smb2.nt_status", "frame.cap_len", "frame.len",
        "tcp.analysis.lost_segment", "tcp.analysis.retransmission", "tcp.analysis.zero_window")
EXPECTED_PACKET_COUNT=5
EXPECTED_REFERENCE_VERSION='4.2.2'


def tshark_version() -> str:
    proc=subprocess.run(["tshark","-v"],capture_output=True,text=True,timeout=10)
    if proc.returncode:
        raise RuntimeError("Versioned offline TShark provider unavailable")
    first=proc.stdout.splitlines()[0] if proc.stdout else ""
    found=re.search(r"\b(4\.[0-9]+\.[0-9]+)\b",first)
    if not found:
        raise RuntimeError("TShark version outside qualified major family")
    if found.group(1) != EXPECTED_REFERENCE_VERSION:
        raise RuntimeError('TShark runtime differs from qualified reference version')
    return found.group(1)


def tshark_fields(filename:Path) -> list[dict[str,str]]:
    argv=["tshark","-n","-r",str(filename),"-T","fields",
          "-E","separator=,", "-E","occurrence=f"]
    for name in FIELDS:
        argv+=["-e",name]
    result=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    if result.returncode:
        raise RuntimeError("TShark offline parser or selected field unsupported")
    output=[]
    for line in result.stdout.splitlines():
        fields=line.split(",")
        if len(fields)!=len(FIELDS):
            raise RuntimeError("TShark field output shape changed")
        output.append(dict(zip(FIELDS,fields)))
    return output


def main() -> int:
    if os.geteuid()==0:
        raise RuntimeError("Must run with genuine nonroot analysis identity")
    version=tshark_version()
    binary_path=shutil.which('tshark')
    if not binary_path:
        raise RuntimeError('Native reference executable unavailable')
    with open(binary_path,'rb') as stream:
        provider_sha256=hashlib.file_digest(stream,'sha256').hexdigest()
    with tempfile.TemporaryDirectory(prefix="rocky-packet-truth-") as root:
        home=Path(root)
        store=CaseStore(home)
        cid=store.open_case()["case_id"]
        for ext,binary in (("pcap",pcap(frames())),
                           ("pcapng",pcapng(frames()))):
            target=store.inbox/("known."+ext)
            target.write_bytes(binary);target.chmod(0o600)
            observed=tshark_fields(target)
            if len(observed)!=EXPECTED_PACKET_COUNT:
                raise RuntimeError("TShark physical packet-frame count mismatch")
            reset_values=[r["tcp.flags.reset"].strip().lower() for r in observed]
            # TShark 4.x boolean fields may print True/False or 1/0.
            if sum(value in ("true","1","set") for value in reset_values)!=1:
                raise RuntimeError("TShark TCP reset field mismatch: " + repr(reset_values))
            dns_values=[r["dns.flags.rcode"].strip().lower() for r in observed]
            if sum(value in ("0x0003","3","nxdomain (3)") for value in dns_values)!=1:
                raise RuntimeError("TShark DNS response-code mismatch: " + repr(dns_values))
            smb_values=[r["smb2.nt_status"].strip().lower() for r in observed]
            if not any("0xc0000022" in value for value in smb_values):
                raise RuntimeError("TShark SMB2 status mismatch: " + repr(smb_values))
            tls_values=[r["tls.record.content_type"].strip().lower() for r in observed]
            if not any(value=="21" or value=="alert (21)" for value in tls_values):
                raise RuntimeError("TShark TLS record type mismatch: " + repr(tls_values))
            aid=store.register(cid,target.name)["artifact_id"]
            decoded=analyze_capture(store,cid,aid)
            summary=protocol_report(store,cid,aid)
            c=summary["counters"]
            expected={"packets_examined":5, "tcp_rst":1,"dns_rcode_3":1,
                      "dns_tuple_id_match_candidates":1,"smb2_access_denied":1,
                      "smb2_response_error":1,"tls_alert_40":1}
            if any(c.get(k)!=v for k,v in expected.items()):
                raise RuntimeError("Gateway packet-local known-answer counters differ from TShark")
            if decoded["status"]!="PASS" or summary["status"]!="PASS":
                raise RuntimeError("Complete test fixture unexpectedly partial")
            if summary["claim_boundaries"]["capture_complete"] or summary["claim_boundaries"]["tcp_stream_reassembled"]:
                raise RuntimeError("Capture completeness or reassembly falsely claimed")
            serialized=json.dumps((decoded,summary,observed),sort_keys=True)
            if "secret.local" in serialized or "10.1.2.3" in serialized:
                raise RuntimeError("Raw packet endpoint or DNS name disclosed")
        quality_vectors=[]
        for fmt in ('pcap','pcapng'):
            target=store.inbox/('quality.'+fmt)
            target.write_bytes(quality_binary(fmt));target.chmod(0o600)
            native=tshark_fields(target)
            if len(native)!=8:
                raise RuntimeError('Independent quality vector frame count changed')
            def marked(field):
                return [int(row['frame.number']) for row in native
                        if row[field].strip().lower() in ('true','1','set')]
            if marked('tcp.analysis.lost_segment') != [5]:
                raise RuntimeError('Native reference missing-segment observation differs: '+repr(marked('tcp.analysis.lost_segment')))
            if marked('tcp.analysis.retransmission') != [6]:
                raise RuntimeError('Native reference repeat-sequence observation differs: '+repr(marked('tcp.analysis.retransmission')))
            if marked('tcp.analysis.zero_window') != [7]:
                raise RuntimeError('Native reference zero-window observation differs: '+repr(marked('tcp.analysis.zero_window')))
            truncated=[int(row['frame.number']) for row in native
                       if int(row['frame.cap_len'])<int(row['frame.len'])]
            if truncated != [8]:
                raise RuntimeError('Native physical capture truncation observation differs')
            aid=store.register(cid,target.name)['artifact_id']
            analyze_capture(store,cid,aid)
            summary=protocol_report(store,cid,aid)
            sample=protocol_observations(store,cid,aid)
            observed={r['signal']:r['packet_no'] for r in sample['observations']}
            expected={'tcp_forward_sequence_gap_candidate':5, 'tcp_repeated_seq_candidate':6,
                      'tcp_zero_window_advertised':7,'capture_frame_truncated':8}
            if any(observed.get(k)!=v for k,v in expected.items()):
                raise RuntimeError('Gateway quality source-frame locators differ from independent reference')
            if (summary['status']!='PARTIAL' or sample['packet_loss_proven'] or
                    summary['capture_quality']['snaplen_truncated_frames']!=1):
                raise RuntimeError('Gateway overstates capture/loss qualification')
            quality_vectors.append({'format':fmt,'frames':8,'known_quality_locators_verified':True})
        print(json.dumps({
            "status":"PASS","fixtures":["pcap","pcapng"],
            "frames_per_fixture":EXPECTED_PACKET_COUNT,
            "independent_provider":"TShark","provider_version":version,
            "provider_binary_sha256_observed":provider_sha256,
            "quality_vectors":quality_vectors,
            "tcp_reset_frames":1,"dns_nxdomain_frames":1,
            "smb2_access_denied_frames":1,"tls_alert_frames":1,
            "dns_pairing":"tuple_transaction_id_candidate_only",
            "stream_reassembled":False,"clock_skew_verified":False,
            "user_evidence_uploaded":False,"rocky01_qualified":False,
        },sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
