#!/usr/bin/env python3
"""Off-host integration smoke: MCP -> worker -> privacy-safe PCAP/EVTX results."""
from __future__ import annotations
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def call(requests: list[dict]) -> dict[int,dict]:
    wire=''.join(json.dumps(r)+'\n' for r in requests)
    p=subprocess.run([sys.executable,'-u',str(ROOT/'gateway.py')],input=wire,text=True,capture_output=True,timeout=20)
    if p.returncode or p.stderr or len(p.stdout.splitlines())!=len(requests):
        raise RuntimeError('MCP failed or produced unexpected stream output')
    result={}
    for raw in p.stdout.splitlines():
        row=json.loads(raw)
        if 'error' in row or row.get('jsonrpc')!='2.0':
            raise RuntimeError('Unexpected MCP response error')
        result[row['id']]=row['result']
    return result


def req(n:int,name:str,args:dict):
    return {'jsonrpc':'2.0','id':n,'method':'tools/call','params':{'name':name,'arguments':args, '_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28', 'io.modelcontextprotocol/clientCapabilities':{}}}}


def result(reply):
    # MCP content[0].text includes the normalized serialized tool result.
    if reply.get('isError'):
        raise RuntimeError('MCP tool failed')
    return json.loads(reply['content'][0]['text'])


def main():
    if os.geteuid()==0:
        raise RuntimeError('Run as unprivileged account')
    case=result(call([req(1,'case_open',{})])[1])['case_id']
    home=Path.home()
    inbox=home/'.local'/'share'/'rocky-mcp-gateway'/'inbox'
    # One valid Ethernet IPv4/TCP SYN frame, no packets sent to the network.
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,1,0,64,6,0,b'\x0a\x01\x00\x01',b'\x0a\x01\x00\x02')
    tcp=struct.pack('!HHIIBBHHH',55555,443,100,0,0x50,0x02,1024,0,0)
    frame=b'\x00'*12+b'\x08\x00'+ip+tcp
    pcap=(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)+
          struct.pack('<IIII',1720000000,0,len(frame),len(frame))+frame)
    (inbox/'tcp.pcap').write_bytes(pcap)
    (inbox/'tcp.pcap').chmod(0o600)
    (inbox/'events.evtx').write_bytes(b'ElfFile\x00'+b'\x00'*(4096-8))
    (inbox/'events.evtx').chmod(0o600)
    two=call([req(2,'artifact_register',{'case_id':case,'filename':'tcp.pcap'}),
              req(3,'artifact_register',{'case_id':case,'filename':'events.evtx'})])
    a=result(two[2])['artifact_id'];evtx=result(two[3])['artifact_id']
    jobs=call([req(4,'job_submit',{'case_id':case,'kind':'decode_pcap','artifact_id':a}),
               req(5,'job_submit',{'case_id':case,'kind':'analyze_evtx','artifact_id':evtx})])
    jid=result(jobs[4])['job_id'];ejid=result(jobs[5])['job_id']
    for _ in range(2):
        p=subprocess.run([sys.executable,'-u',str(ROOT/'jobwork.py'),'--once'],capture_output=True,timeout=30)
        if p.returncode:
            raise RuntimeError('Worker process failed')
    out=call([req(6,'job_result',{'job_id':jid}),req(7,'pcap_protocol_report',{'case_id':case,'artifact_id':a}),
              req(8,'pcap_flows',{'case_id':case,'artifact_id':a}),req(9,'job_result',{'job_id':ejid})])
    packet=result(out[6]);summary=result(out[7]);flows=result(out[8]);windows=result(out[9])
    if packet['state']!='SUCCEEDED' or summary['counters'].get('tcp_syn')!=1 or len(flows['flows'])!=1:
        raise RuntimeError('Packet analysis expected output missing')
    if windows['state']!='SUCCEEDED' or windows['result']['status']!='NOT_AVAILABLE':
        raise RuntimeError('Missing EVTX provider was not explicitly reported')
    if any(s in json.dumps(out) for s in ('10.1.0.1','10.1.0.2','ElfFile','/tmp/')):
        raise RuntimeError('Unsafe raw material disclosed through MCP')
    print('PASS: MCP cases, worker TCP decoding, sanitized flows, EVTX provider-unavailable reporting')


if __name__=='__main__':
    main()
