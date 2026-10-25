#!/usr/bin/env python3
"""Unprivileged multi-process evidence transfer/archive/vault smoke test."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

BASE=Path(__file__).resolve().parents[1]
MODERN={'_meta': {'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                 'io.modelcontextprotocol/clientCapabilities':{}}}


def invoke(home: Path, command: str, args: list[str], *, stdin: str | None = None) -> str:
    env=dict(os.environ,HOME=str(home))
    cmd=[sys.executable,'-u',str(BASE/command),*args]
    p=subprocess.run(cmd,input=stdin,env=env,text=True,capture_output=True,timeout=20,check=False)
    if p.returncode or p.stderr:
        raise RuntimeError(f'{command} subprocess exit={p.returncode}; do not disclose raw stderr')
    return p.stdout


def call(home: Path,tool: str,args: dict) -> dict:
    request={'jsonrpc':'2.0','id':42,'method':'tools/call',
             'params':{**MODERN,'name':tool,'arguments':args}}
    reply=invoke(home,'gateway.py',[],stdin=json.dumps(request)+'\n')
    if len(reply.splitlines())!=1:
        raise RuntimeError('Unexpected number of MCP frames')
    result=json.loads(reply)
    if result.get('id')!=42 or 'error' in result or result['result'].get('isError'):
        raise RuntimeError('MCP call returned error')
    return json.loads(result['result']['content'][0]['text'])


def once(home: Path) -> None:
    invoke(home,'jobwork.py',['--once'])


def job(home: Path,kind: str,case_id: str,artifact_id: str | None = None,filename: str | None = None):
    args={'kind':kind,'case_id':case_id}
    if artifact_id is not None:args['artifact_id']=artifact_id
    if filename is not None:args['filename']=filename
    jid=call(home,'job_submit',args)['job_id']
    once(home)
    result=call(home,'job_result',{'job_id':jid})
    if result['state']!='SUCCEEDED':
        raise RuntimeError('Analysis worker job did not succeed')
    return result['result']


def main() -> int:
    if os.geteuid()==0:
        print('Run smoke under an unprivileged account',file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix='rocky-ingest-') as working:
        home=Path(working)
        cid=call(home,'case_open',{})['case_id']
        lines=b'2026-10-15T12:02:00Z ERROR password=never_upload_this\n'
        compressed=io.BytesIO()
        with zipfile.ZipFile(compressed,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('system/service.log',lines)
        payload=compressed.getvalue()
        prepare=json.loads(invoke(home,'transfer_bridge.py',['prepare']))
        if prepare['status']!='READY':raise RuntimeError('Bridge prepare failed')
        inbox=Path(prepare['inbox'])
        token='.upload-'+'b'*32
        (inbox/token).write_bytes(payload)
        (inbox/token).chmod(0o644)
        digest=hashlib.sha256(payload).hexdigest()
        ready=json.loads(invoke(home,'transfer_bridge.py',[
            'finalize','--temp',token,'--filename','bundle.zip','--size',str(len(payload)),
            '--sha256',digest]))
        if ready['status']!='STAGED' or ready['sha256']!=digest:
            raise RuntimeError('Transfer identity mismatch')
        entry=job(home,'import_staged',cid,filename='bundle.zip')
        archive=job(home,'unpack_archive',cid,artifact_id=entry['artifact_id'])
        if archive['derived_artifact_count']!=1:raise RuntimeError('Archive expansion wrong count')
        aid=archive['artifact_ids'][0]
        index=job(home,'index_log',cid,artifact_id=aid)
        if index['lines_indexed']!=1:raise RuntimeError('Log index returned wrong evidence')
        found=call(home,'log_search',{'case_id':cid,'artifact_id':aid,'query':'ERROR'})
        if len(found['matches'])!=1:raise RuntimeError('Search returned wrong matches')
        manifest=job(home,'verify_case',cid)
        if manifest['status']!='PASS' or manifest['verified_count']!=2:
            raise RuntimeError('Vault proof incomplete')
        audit=home/'.local/state/rocky-mcp-gateway/audit.jsonl'
        result_dump=json.dumps({'entry':entry,'expand':archive,'index':index,'search':found,'check':manifest})
        if b'never_upload_this' in audit.read_bytes() or 'never_upload_this' in result_dump:
            raise RuntimeError('Raw sample secret escaped into chat-safe artifacts')
    print('PASS: staged file verification, job import, safe ZIP, redacted log index/search, vault SHA-256 audit across independent MCP/worker processes')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
