#!/usr/bin/env python3
"""Independent-process, non-root timeline + job contract smoke on synthetic evidence."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
META = {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                  'io.modelcontextprotocol/clientCapabilities': {}}}


def run(home: Path, program: str, payload: str | None = None) -> str:
    env = dict(os.environ, HOME=str(home))
    proc = subprocess.run([sys.executable, '-u', str(ROOT / program)] +
                          (['--once'] if program == 'jobwork.py' else []),
                          input=payload, capture_output=True, text=True,
                          timeout=25, env=env, check=False)
    if proc.returncode or proc.stderr:
        raise RuntimeError(f'{program}: failed without exposing sensitive details')
    return proc.stdout


def call(home: Path, tool: str, args: dict) -> dict:
    wire = {'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
            'params': {**META, 'name': tool, 'arguments': args}}
    data = run(home, 'gateway.py', json.dumps(wire, separators=(',', ':')) + '\n')
    lines = data.splitlines()
    if len(lines) != 1:
        raise RuntimeError('Unexpected number of stdio frames')
    resp = json.loads(lines[0])
    if resp.get('id') != 7 or 'error' in resp or resp.get('result', {}).get('isError'):
        raise RuntimeError(f'{tool}: MCP error')
    return json.loads(resp['result']['content'][0]['text'])


def stage(home: Path, name: str, content: str) -> None:
    root = home/'.local/share/rocky-mcp-gateway/inbox'
    p = root/name
    p.write_text(content)
    p.chmod(0o600)


def main() -> int:
    if os.geteuid() == 0:
        print('Run smoke as an unprivileged login user', file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix='rocky-timeline-smoke-') as location:
        home = Path(location)
        case = call(home, 'case_open', {})['case_id']
        stage(home, 'first.log', '2026-10-15T16:00:10Z INFO baseline\n'
              '2026-10-15T16:01:15Z ERROR token=never_emit\n')
        stage(home, 'second.jsonl', '{"@timestamp":"2026-10-15T12:01:00-04:00",'
              '"level":"WARN","api_key":"hidden_value","message":"timeout"}\n'
              'Oct 15 12:01:22 server failure timezone is unknown\n')
        a = call(home, 'artifact_register', {'case_id': case, 'filename': 'first.log'})['artifact_id']
        b = call(home, 'artifact_register', {'case_id': case, 'filename': 'second.jsonl'})['artifact_id']
        j = call(home, 'job_submit', {'case_id': case, 'kind': 'build_timeline'})['job_id']
        run(home, 'jobwork.py')
        result = call(home, 'job_result', {'job_id': j})
        assert result['state'] == 'SUCCEEDED' and result['result']['events_indexed'] == 4
        assert result['outcome'] == 'PARTIAL' and result['result']['events_unanchored'] == 1
        q = call(home, 'timeline_query', {'case_id': case, 'include_unanchored': True})
        assert [e['artifact_id'] for e in q['events']] == [a, b, a, b]
        assert q['events'][-1]['timestamp_utc'] is None
        assert len(call(home, 'timeline_sources', {'case_id': case})['sources']) == 2
        stats = call(home, 'timeline_summary', {'case_id': case})
        assert stats['events_unanchored'] == 1 and stats['events_indexed'] == 4
        secret_leak = json.dumps({'query': q, 'result': result, 'stats': stats})
        for forbidden in ('never_emit', 'hidden_value', str(home)):
            assert forbidden not in secret_leak
        stage(home, 'third.log', '2026-10-15T16:02:00Z INFO fresh\n')
        call(home, 'artifact_register', {'case_id': case, 'filename': 'third.log'})
        stale = {'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
                 'params': {**META, 'name': 'timeline_summary', 'arguments': {'case_id': case}}}
        raw = run(home, 'gateway.py', json.dumps(stale) + '\n')
        err = json.loads(raw)
        assert err['result']['isError'] is True  # Case evidence was added after timeline build
        j2 = call(home, 'job_submit', {'case_id': case, 'kind': 'build_timeline'})['job_id']
        run(home, 'jobwork.py')
        assert call(home, 'job_result', {'job_id': j2})['result']['events_indexed'] == 5
        assert call(home, 'timeline_summary', {'case_id': case})['sources_indexed'] == 3
    print('PASS: multi-source timestamp ordering, private JSON redaction, MCP/job persistence, coverage, stale detection, rebuild')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
