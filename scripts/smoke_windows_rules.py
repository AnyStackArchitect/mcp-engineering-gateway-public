#!/usr/bin/env python3
"""Synthetic XML -> real index -> separately launched metadata-only MCP.

The binary parser is mocked in this ordinary smoke. The separate real-EVTX
workflow independently exercises this API with an actual pinned public binary.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from casework import CaseStore
from evtxwork import analyze_evtx

META = {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                  'io.modelcontextprotocol/clientCapabilities': {}}}


def call(home, args):
    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
               'params': {**META, 'name': 'windows_rule_report', 'arguments': args}}
    process = subprocess.run([sys.executable, '-u', str(ROOT/'gateway.py')],
        input=json.dumps(request)+'\n', text=True, capture_output=True, timeout=20,
        env=os.environ | {'HOME': str(home)})
    if process.returncode or process.stderr:
        raise RuntimeError('Gateway failed synthetic Windows metadata request')
    result = json.loads(process.stdout)['result']
    if result.get('isError'):
        raise RuntimeError('Gateway refused expected indexed Windows metadata')
    return json.loads(result['content'][0]['text'])


class Record:
    def record_num(self):
        return 101

    def xml(self):
        return ('<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
                '<EventID>4625</EventID><Level>0</Level><Channel>Security</Channel>'
                '<TimeCreated SystemTime="2026-10-18T00:00:00Z"/></System>'
                '<EventData>private-principal-and-password</EventData></Event>')


class Provider:
    def __init__(self, _path): pass
    def __enter__(self): return self
    def __exit__(self, *_args): pass
    def records(self): return iter([Record()])


def main():
    if os.geteuid() == 0:
        raise RuntimeError('Normal nonroot user required')
    with tempfile.TemporaryDirectory(prefix='eng-windows-rules-') as folder:
        home = Path(folder)
        store = CaseStore(home)
        cid = store.open_case()['case_id']
        staged = store.inbox/'synthetic.evtx'
        staged.write_bytes(b'ElfFile\0' + b'\0'*(4096-8))
        staged.chmod(0o600)
        aid = store.register(cid, staged.name)['artifact_id']
        package = types.ModuleType('Evtx'); package.__path__ = []
        provider = types.ModuleType('Evtx.Evtx'); provider.Evtx = Provider
        with patch.dict(sys.modules, {'Evtx': package, 'Evtx.Evtx': provider}):
            analyze_evtx(store, cid, aid)
        report = call(home, {'case_id': cid, 'artifact_id': aid})
        if (report['rules'][0]['matches'] != 1 or report['matches'][0]['record'] != 101
                or report['rules'][2]['state'] != 'CHANNEL_NOT_OBSERVED'
                or report['status'] != 'PARTIAL' or report['collection_completeness_verified']):
            raise RuntimeError('Rule matching or missing-channel scope incorrect')
        visible = json.dumps(report)
        for value in ('private-principal-and-password', 'synthetic.evtx', str(home), '<EventData>'):
            if value in visible:
                raise RuntimeError('Private Windows evidence leaked')
    print('PASS: synthetic parser fixture, genuine nonroot cross-process Windows rule MCP, '
          'exact metadata matching, source records, missing-channel uncertainty and privacy')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
