#!/usr/bin/env python3
"""Actual nonroot report MCP over text and packet sources; no live endpoints."""
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from casework import CaseStore
from reportwork import package
from smoke_recipes import call,run
from test_packettruth_integration import frames
from test_protocolwork import pcap


def main():
    if os.geteuid()==0:raise RuntimeError('Run unprivileged')
    with tempfile.TemporaryDirectory(prefix='eng-evidence-report-') as folder:
        home=Path(folder)
        cid=call(home,'case_open',{})['case_id']
        inbox=home/'.local/share/rocky-mcp-gateway/inbox'
        log=inbox/'private-source.log'
        log.write_text('2026-10-18T01:00:00Z private-customer-text password=hidden\n')
        capture=inbox/'private-capture.pcap';capture.write_bytes(pcap(frames()))
        for path in (log,capture):
            path.chmod(0o600)
            aid=call(home,'artifact_register',{'case_id':cid,'filename':path.name})['artifact_id']
            if path==capture:packet_id=aid
        for kind,args in [('build_timeline',{}),('decode_pcap',{'artifact_id':packet_id}),('build_correlation',{})]:
            job=call(home,'job_submit',{'case_id':cid,'kind':kind,**args})
            run(home,'jobwork.py')
            if call(home,'job_result',{'job_id':job['job_id']})['state']!='SUCCEEDED':raise RuntimeError('Report fixture worker failed')
        summary=call(home,'correlation_summary',{'case_id':cid})
        report=call(home,'case_evidence_report',{'case_id':cid,'index_revision':summary['index_revision']})
        producers={row['kind']:row['recorded_producer'] for row in report['observed_source_producers']}
        if not {'text','pcap'}<=set(producers) or 'protocolwork' not in producers['pcap']['modules']:
            raise RuntimeError('Report source producer identities missing')
        if 'private-customer-text' in json.dumps(report) or 'hidden' in json.dumps(report):
            raise RuntimeError('Report disclosed private source content')
        # Explicit synthetic operator fixture; not human custody qualification.
        result=package(CaseStore(home),cid,summary['index_revision'],report['review_sha256'],interactive=True)
        path=home/'.local/share/rocky-mcp-gateway/evidence-report-packages'/result['filename']
        with zipfile.ZipFile(BytesIO(path.read_bytes())) as archive:
            if set(archive.namelist())!={'report.json','report.md','manifest.json'}:raise RuntimeError('Unexpected package member')
        denied=subprocess.run([sys.executable,str(ROOT/'scripts/evidence_report_cli.py'),cid,summary['index_revision']],
            input='PACKAGE '+report['review_sha256']+'\n',text=True,capture_output=True,
            env=os.environ|{'HOME':str(home)},timeout=15)
        if denied.returncode!=1 or 'refused' not in denied.stderr:raise RuntimeError('Piped report review bypass')
    print('PASS: actual text/packet worker producer records, pinned MCP report, metadata-only reviewed local ZIP and noninteractive refusal; synthetic operator fixture only')


if __name__=='__main__':main()
