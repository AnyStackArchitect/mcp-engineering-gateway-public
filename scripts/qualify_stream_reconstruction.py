#!/usr/bin/env python3
"""Real pinned offline TShark follow-stream comparison on synthetic bytes only."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from casework import CaseStore
from protocolwork import analyze_capture,_checked_report,protocol_stream_coverage
from qualify_packet_truth import tshark_version
from test_protocolwork import pcap,pcapng,ipv4
from test_streamwork import stream_frames
from test_packet_coverage import A,B,segment


def follow(path):
    proc=subprocess.run(['tshark','-n','-r',str(path),'-q','-z','follow,tcp,raw,0'],
        stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
    if proc.returncode or len(proc.stdout)>16384:raise RuntimeError('Bounded synthetic reference failed')
    # There is only one data direction in these fixtures; no private input.
    parts=[bytes.fromhex(line.decode()) for line in proc.stdout.splitlines() if re.fullmatch(rb'[0-9a-fA-F]+',line)]
    return b''.join(parts)


def main():
    if os.geteuid()==0:raise RuntimeError('Run unprivileged')
    version=tshark_version();results=[]
    with tempfile.TemporaryDirectory(prefix='eng-stream-reference-') as folder:
        store=CaseStore(Path(folder));cid=store.open_case()['case_id']
        for fmt,encode in [('pcap',pcap),('pcapng',pcapng)]:
            for name,order,seq in [('ordered',(0,1),100),('reordered',(1,0),100),('wrap',(1,0),0xfffffffc),('duplicate',(0,1,0),100)]:
                path=store.inbox/(name+'.'+fmt);path.write_bytes(encode(stream_frames(order,seq)));path.chmod(0o600)
                aid=store.register(cid,path.name)['artifact_id'];analyze_capture(store,cid,aid)
                reference=follow(store.cases/cid/'originals'/aid)
                private=_checked_report(store,cid,aid)['tcp_reconstruction']['streams'][0]
                exposed=protocol_stream_coverage(store,cid,aid)
                expected=hashlib.sha256(b'ABCDEFGH').hexdigest()
                if reference!=b'ABCDEFGH' or hashlib.sha256(reference).hexdigest()!=private['private_contiguous_sha256'] or not private['syn_to_fin_payload_covered']:
                    raise RuntimeError('Actual reference reconstruction differs: '+name+'.'+fmt)
                if expected in json.dumps(exposed) or 'ABCDEFGH' in json.dumps(exposed):raise RuntimeError('Payload identity leaked into MCP projection')
                results.append({'format':fmt,'vector':name,'unique_bytes':private['unique_payload_bytes'],'reference_digest_matches':True})
            # Permanent known-answer missing-segment and conflicting-overlap
            # vectors explicitly withhold an unambiguous reconstructed digest.
            for name,frames,hole,conflict in [
                ('missing',stream_frames((0,),100),[{'start':4,'end':8}],0),
                ('conflict',stream_frames((0,1,0),100,(b'ABCD',b'EFGH'))[:-1]+[ipv4(A,B,6,segment(42001,443,103,0,0x18,b'XX')),ipv4(A,B,6,segment(42001,443,109,0,0x11))],[],2)]:
                path=store.inbox/(name+'.'+fmt);path.write_bytes(encode(frames));path.chmod(0o600)
                aid=store.register(cid,path.name)['artifact_id'];analyze_capture(store,cid,aid)
                row=_checked_report(store,cid,aid)['tcp_reconstruction']['streams'][0]
                if row['unobserved_ranges']!=hole or row['conflicting_byte_observations']!=conflict or row['private_contiguous_sha256'] is not None:
                    raise RuntimeError('Ambiguous reconstruction overclaimed')
                results.append({'format':fmt,'vector':name,'unambiguous_digest_withheld':True})
    print(json.dumps({'status':'OFF_HOST_CAPTURE_LOCAL_RECONSTRUCTION_PASS','tshark_version':version,'vectors':results,
        'reference_follow_vectors':8,'known_answer_ambiguous_vectors':4,'endpoint_delivery_or_actual_loss_proven':False,
        'full_protocol_or_causal_qualification':False},sort_keys=True))


if __name__=='__main__':main()
