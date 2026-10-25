#!/usr/bin/env python3
"""Actual nonroot MCP/worker sensitivity query over declared 40-second skew."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
META = {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                  'io.modelcontextprotocol/clientCapabilities': {}}}


def call(home, name, args):
    wire = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
        'params': {**META, 'name': name, 'arguments': args}}) + '\n'
    result = subprocess.run([sys.executable, '-u', str(ROOT/'gateway.py')], input=wire,
        text=True, capture_output=True, timeout=25, env=os.environ | {'HOME': str(home)})
    if result.returncode or result.stderr:
        raise RuntimeError('Clock model gateway failed')
    reply = json.loads(result.stdout)['result']
    if reply.get('isError'):
        raise RuntimeError('Expected clock model request refused')
    return json.loads(reply['content'][0]['text'])


def job(home, cid, kind):
    jid = call(home, 'job_submit', {'case_id': cid, 'kind': kind})['job_id']
    result = subprocess.run([sys.executable, '-u', str(ROOT/'jobwork.py'), '--once'],
        capture_output=True, text=True, timeout=35, env=os.environ | {'HOME': str(home)})
    if result.returncode or result.stderr or call(home, 'job_result', {'job_id': jid})['state'] != 'SUCCEEDED':
        raise RuntimeError('Clock model prerequisite worker failed')


def main():
    if os.geteuid() == 0:
        raise RuntimeError('A normal nonroot user is required')
    with tempfile.TemporaryDirectory(prefix='eng-clock-model-') as folder:
        home = Path(folder)
        cid = call(home, 'case_open', {})['case_id']
        inbox = home/'.local/share/rocky-mcp-gateway/inbox'
        aids = []
        for name, text in [('anchor.log', '2026-10-18T10:00:00Z ERROR failed password=private\n'),
                           ('skew.log', '2026-10-18T10:00:40Z INFO succeeded\nOct 18 10:00:40 missing context\n')]:
            target = inbox/name; target.write_text(text); target.chmod(0o600)
            aids.append(call(home, 'artifact_register', {'case_id': cid, 'filename': name})['artifact_id'])
        job(home, cid, 'build_timeline'); job(home, cid, 'build_correlation')
        observed = call(home, 'correlation_query', {'case_id': cid, 'artifact_id': aids[0]})
        report = call(home, 'correlation_clock_model', {'case_id': cid,
            'index_revision': observed['index_revision'], 'anchor_event_id': observed['events'][0]['event_id'],
            'source_clocks': [{'artifact_id': aid, 'offset_to_add_ms': shift, 'uncertainty_ms': 0}
                             for aid, shift in zip(aids, (0, -40000))],
            'before_ms': 1000, 'after_ms': 1000})
        if (len(report['events']) != 1 or report['events'][0]['modeled_delta_ms'] != 0 or
                report['events'][0]['source_observed_delta_ms'] != 40000 or
                report['selected_sources_unknown_utc_events'] != 1 or
                report['clock_alignment_verified'] or report['causality_inferred']):
            raise RuntimeError('Declared sensitivity model overstated clock evidence')
        if 'password' in json.dumps(report) or 'private' in json.dumps(report):
            raise RuntimeError('Source text leaked into clock-only report')
    print('PASS: real nonroot MCP/worker declared40-second sensitivity, pinned source locators, unknown time and unverified bounds')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
