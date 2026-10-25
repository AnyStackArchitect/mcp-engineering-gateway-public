#!/usr/bin/env python3
"""Real worker/MCP bounded stream coverage, no payload disclosure."""
import json,os
from pathlib import Path
import sys,tempfile
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from smoke_recipes import call,run
from test_protocolwork import pcapng
from test_streamwork import stream_frames


def main():
    if os.geteuid()==0:raise RuntimeError('Run unprivileged')
    with tempfile.TemporaryDirectory(prefix='eng-stream-mcp-') as folder:
        home=Path(folder);cid=call(home,'case_open',{})['case_id']
        path=home/'.local/share/rocky-mcp-gateway/inbox/fixture.pcapng'
        path.write_bytes(pcapng(stream_frames((1,0),0xfffffffc)));path.chmod(0o600)
        aid=call(home,'artifact_register',{'case_id':cid,'filename':path.name})['artifact_id']
        job=call(home,'job_submit',{'case_id':cid,'kind':'decode_pcap','artifact_id':aid});run(home,'jobwork.py')
        if call(home,'job_result',{'job_id':job['job_id']})['state']!='SUCCEEDED':raise RuntimeError('Decode worker failed')
        result=call(home,'pcap_stream_coverage',{'case_id':cid,'artifact_id':aid})
        row=result['streams'][0]
        if row['contributing_frames']!=[2,3] or not row['syn_to_fin_payload_covered'] or row['unique_payload_bytes']!=8:
            raise RuntimeError('Source-linked reconstruction lost identity')
        if result['status']!='PARTIAL' or result['endpoint_delivery_proven'] or 'private_contiguous_sha256' in json.dumps(result):
            raise RuntimeError('Reconstruction overclaims or discloses')
    print('PASS: actual nonroot MCP/worker PCAPNG reordering/wrap reconstruction with source frames; payload/hash withheld and delivery/loss unknown')


if __name__=='__main__':main()
