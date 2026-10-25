#!/usr/bin/env python3
"""Synthetic-only local operator/MCP retrieval boundary and real SQLite FTS."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from casework import CaseStore
from librarywork import prepare,accept
from smoke_recipes import call


def main():
    if os.geteuid()==0:raise RuntimeError('Run the smoke unprivileged')
    with tempfile.TemporaryDirectory(prefix='eng-library-') as folder:
        home=Path(folder)
        store=CaseStore(home)
        cid=store.open_case()['case_id']
        source=store.inbox/'synthetic-reference.txt'
        source.write_text('Synthetic quorum reference for controlled validation only.\n')
        source.chmod(0o600)
        aid=store.register(cid,source.name)['artifact_id']
        data={'kind':'reference','product':'proxmox','version':'lab-fixture',
            'title':'Synthetic reference','summary':'Controlled offline note; password=hidden',
            'source_case_id':cid,'source_artifact_id':aid,
            'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'source_line':1,'reference_uri':'https://example.org/synthetic-reference',
            'reference_date':'2026-10-18','rights_confirmed':True}
        missing=call(home,'knowledge_search',{'query':'quorum','product':'proxmox','version':'lab-fixture'})
        if missing['status']!='NOT_AVAILABLE':raise RuntimeError('Invented library availability')
        review=prepare(store,data)
        # Test fixture invokes the internal acceptance function explicitly.
        # This is NOT proof of real human custody or production operator trust.
        accepted=accept(store,data,review['review_sha256'],interactive=True)
        result=call(home,'knowledge_search',{'query':'quorum','product':'proxmox','version':'lab-fixture'})
        if len(result['matches'])!=1 or result['matches'][0]['entry_id']!=accepted['entry_id']:
            raise RuntimeError('Real FTS reference retrieval did not preserve identity')
        if 'hidden' in json.dumps(result) or 'quorum reference' in json.dumps(result):
            raise RuntimeError('Raw source or secret escaped reviewed summary')
        wrong=call(home,'knowledge_search',{'query':'quorum','product':'proxmox','version':'other'})
        if wrong['matches'] or wrong['incompatible_version_matches_excluded']!=1:
            raise RuntimeError('Incompatible version advice reused')
        review_path=home/'review.json';review_path.write_text(json.dumps(data));review_path.chmod(0o600)
        denied=subprocess.run([sys.executable,str(ROOT/'scripts/library_accept_cli.py'),str(review_path)],
            input='ACCEPT '+review['review_sha256']+'\n',text=True,capture_output=True,
            env=os.environ|{'HOME':str(home)},timeout=15)
        if denied.returncode!=1 or 'refused' not in denied.stderr:
            raise RuntimeError('Piped operator acceptance bypassed live-terminal boundary')
    print('PASS: actual cross-process library MCP, local SQLite FTS, exact versions, disclosure masking and noninteractive acceptance refusal; operator fixture trust only')


if __name__=='__main__':main()
