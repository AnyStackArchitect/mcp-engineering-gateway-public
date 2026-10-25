#!/usr/bin/env python3
"""Cross-process, non-root MCP/workers with real text and synthetic offline PCAP."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
META={'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28',
               'io.modelcontextprotocol/clientCapabilities':{}}}


def run(home,which,input=None):
    proc=subprocess.run([sys.executable,'-u',str(ROOT/which)]+(['--once'] if which=='jobwork.py' else []),
                        input=input,text=True,capture_output=True,
                        env={**os.environ,'HOME':str(home)},timeout=30)
    if proc.returncode or proc.stderr:
        raise RuntimeError(which+' subprocess rejected the controlled test')
    return proc.stdout


def call(home,tool,args):
    wire=json.dumps({'jsonrpc':'2.0','id':42,'method':'tools/call',
                     'params':{**META,'name':tool,'arguments':args}})+'\n'
    frames=run(home,'gateway.py',wire).splitlines()
    if len(frames)!=1:
        raise RuntimeError('Unexpected MCP response framing')
    frame=json.loads(frames[0])
    if frame.get('id')!=42 or 'error' in frame or frame.get('result',{}).get('isError'):
        raise RuntimeError('MCP tool failed: '+tool)
    return json.loads(frame['result']['content'][0]['text'])


def sample_pcap():
    src=b'\x0a\x01\x02\x03';dst=b'\x0a\x01\x02\x04'
    def frame(flags):
        tcp=struct.pack('!HHIIBBHHH',443,55555,1,0,0x50,flags,8192,0,0)
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,1,0,64,6,0,src,dst)
        return b'\0'*12+b'\x08\x00'+ip+tcp
    out=bytearray(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1))
    for i,packet in enumerate((frame(2),frame(4))):
        out+=struct.pack('<IIII',1720000000+i,0,len(packet),len(packet))+packet
    return bytes(out)


def main():
    if os.geteuid()==0:
        raise RuntimeError('Smoke must run as an unprivileged Linux account')
    with tempfile.TemporaryDirectory(prefix='rocky-correlate-') as root:
        home=Path(root)
        cid=call(home,'case_open',{})['case_id']
        inbox=home/'.local/share/rocky-mcp-gateway/inbox'
        stamp=datetime.fromtimestamp(1720000000,timezone.utc).isoformat()
        record=inbox/'host.log'
        record.write_text(stamp+' error password=never-emit\nOct 15 12:05:00 unknown-year syslog\n')
        record.chmod(0o600)
        cap=inbox/'sample.pcap';cap.write_bytes(sample_pcap());cap.chmod(0o600)
        evtx=inbox/'sample.evtx';evtx.write_bytes(b'ElfFile\x00'+b'\0'*(4096-8));evtx.chmod(0o600)
        logid=call(home,'artifact_register',{'case_id':cid,'filename':'host.log'})['artifact_id']
        pcapid=call(home,'artifact_register',{'case_id':cid,'filename':'sample.pcap'})['artifact_id']
        evtxid=call(home,'artifact_register',{'case_id':cid,'filename':'sample.evtx'})['artifact_id']
        jids=[]
        for kind,aid in [('build_timeline',None),('decode_pcap',pcapid),('analyze_evtx',evtxid)]:
            data={'case_id':cid,'kind':kind}
            if aid:data['artifact_id']=aid
            jids.append(call(home,'job_submit',data)['job_id'])
            run(home,'jobwork.py')
        for jobid in jids:
            result=call(home,'job_result',{'job_id':jobid})
            if result['state']!='SUCCEEDED':raise RuntimeError('Parent analyzer failed')
        jid=call(home,'job_submit',{'case_id':cid,'kind':'build_correlation'})['job_id']
        run(home,'jobwork.py')
        result=call(home,'job_result',{'job_id':jid})
        if result['state']!='SUCCEEDED' or result['result']['missing_indexes']!=1:
            raise RuntimeError('EVTX not-available condition was not preserved')
        summary=call(home,'correlation_summary',{'case_id':cid})
        if summary['status']!='PARTIAL' or summary['source_count']!=3:
            raise RuntimeError('Case correlation coverage should be partial')
        sources=call(home,'correlation_sources',{'case_id':cid})
        if len(sources['sources'])!=3 or not any(r['coverage']=='MISSING_INDEX' for r in sources['sources']):
            raise RuntimeError('Unavailable EVTX index was silently suppressed')
        q=call(home,'correlation_query',{'case_id':cid,'include_unknown':True})
        kinds={x['kind'] for x in q['events']}
        if kinds!={'text','pcap'} or q['events'][-1]['utc'] is not None:
            raise RuntimeError('Correlated source events were incorrect')
        packet=call(home,'correlation_query',{'case_id':cid,'kind':'pcap'})
        if {x['signal'] for x in packet['events']}!={'tcp_rst','tcp_syn'}:
            raise RuntimeError('Selected packet signals absent')
        visible=json.dumps((sources,summary,q,packet))
        for secret in ('never-emit','10.1.2.3','10.1.2.4','ElfFile','sample.pcap'):
            if secret in visible:raise RuntimeError('Private case evidence leaked to client')
        # A newly added source makes the old correlation stale.
        nextlog=inbox/'more.log';nextlog.write_text(stamp+' fresh\n');nextlog.chmod(0o600)
        call(home,'artifact_register',{'case_id':cid,'filename':'more.log'})
        raw=json.loads(run(home,'gateway.py',json.dumps({'jsonrpc':'2.0','id':1,
            'method':'tools/call','params':{**META,'name':'correlation_summary','arguments':{'case_id':cid}}})+'\n'))
        if not raw['result']['isError']:
            raise RuntimeError('Stale correlation was incorrectly accepted')
    print('PASS: cross-process MCP log/packet correlation with unavailable EVTX, redaction and stale evidence detection')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
