#!/usr/bin/env python3
"""Actual report MCP and local operator terminal; synthetic evidence only."""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from casework import CaseStore
from dossierwork import prepare
import timelinework,correlationwork
from smoke_recipes import call


def main():
    if os.geteuid()==0:raise RuntimeError('Run unprivileged')
    with tempfile.TemporaryDirectory(prefix='eng-rca-dossier-') as folder:
        home=Path(folder);store=CaseStore(home);cid=store.open_case()['case_id']
        source=store.inbox/'fixture.log';source.write_text('2026-10-18T01:00:00Z synthetic observation\n');source.chmod(0o600)
        store.register(cid,source.name);timelinework.build_timeline(store,cid);correlationwork.build_correlation(store,cid)
        rev=correlationwork.correlation_summary(store,cid)['index_revision']
        report=call(home,'case_evidence_report',{'case_id':cid,'index_revision':rev});row=report['observations'][0]
        data={'schema':1,'case_id':cid,'index_revision':rev,'environment':{'product':'synthetic','version':'fixture-1'},
            'symptoms':'Synthetic symptom supplied by operator','impact':'Synthetic impact','reproduction':['Read the fixture'],
            'observed_outputs':'One fixture observation','hypotheses':[{'claim':'Proposed explanation','status':'PROPOSED',
            'test':'Compare a second fixture','observed_result':'','supports':[{'event_id':row['event_id'],'source_sha256':row['source_sha256']}],
            'contradicts':[]}],'conclusion':None,'open_questions':['No causal claim established']}
        preview=prepare(store,data);path=home/'review.json';path.write_text(json.dumps(data));path.chmod(0o600)
        command=[sys.executable,str(ROOT/'scripts/rca_dossier_cli.py'),str(path)]
        env=os.environ|{'HOME':str(home),'PYTHONDONTWRITEBYTECODE':'1'}
        denied=subprocess.run(command,input='ACCEPT '+preview['review_sha256']+'\n',text=True,capture_output=True,env=env,timeout=10)
        if denied.returncode!=1:raise RuntimeError('Piped review bypass')
        master,slave=pty.openpty();child=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,env=env);os.close(slave)
        output=bytearray();sent=False;deadline=time.monotonic()+15
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],0.1)
                if ready:
                    try:block=os.read(master,4096)
                    except OSError:break
                    if not block:break
                    output.extend(block)
                    if len(output)>16384:raise RuntimeError('Unexpected CLI output growth')
                    if not sent and b'Type ACCEPT' in output:
                        os.write(master,('ACCEPT '+preview['review_sha256']+'\n').encode());sent=True
                if child.poll() is not None and not ready:break
            if child.wait(timeout=2)!=0 or not sent or b'LOCAL_REVIEWED_DOSSIER' not in output:raise RuntimeError('Actual terminal acceptance failed')
        finally:
            os.close(master)
            if child.poll() is None:child.kill();child.wait()
        result=call(home,'case_evidence_report',{'case_id':cid,'index_revision':rev})
        if result['reviewed_dossier']['review_sha256']!=preview['review_sha256'] or result['hypotheses'][0]['status']!='PROPOSED':
            raise RuntimeError('Reviewed interpretation lost identity')
        if result['facts']!=report['facts'] or result['status']!='PARTIAL':raise RuntimeError('Reasoning promoted to measured facts')
    print('PASS: actual nonroot terminal review and cross-process report MCP; immutable source-linked PROPOSED reasoning, no causal promotion; automated synthetic operator fixture only')


if __name__=='__main__':main()
