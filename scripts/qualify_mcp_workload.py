#!/usr/bin/env python3
"""Opt-in synthetic MCP workload on a new private Linux HOME, never live state."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.qualify_synthetic_scale import make_capture, make_log, digest

META = {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                  'io.modelcontextprotocol/clientCapabilities': {}}}


class Workload:
    def __init__(self, output, profile):
        self.output, self.profile = output, profile
        self.home, self.scratch = output/'home', output/'scratch'
        for p in (self.home, self.scratch, output/'requests', output/'logs'):
            p.mkdir(mode=0o700)
        self.env = {'HOME': str(self.home), 'TMPDIR': str(self.scratch),
                    'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
        self.sequence = 0
        self.checks, self.commands, self.originals, self.workers = [], [], [], []

    def save(self, name, value):
        (self.output/name).write_text(json.dumps(value, indent=2))

    def check(self, name, condition):
        self.checks.append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    def call(self, tool, arguments, error=False):
        self.sequence += 1
        request = {'jsonrpc': '2.0', 'id': self.sequence, 'method': 'tools/call',
                   'params': {**META, 'name': tool, 'arguments': arguments}}
        argv = [sys.executable, '-B', str(ROOT/'gateway.py')]
        start = time.monotonic()
        p = subprocess.run(argv, input=json.dumps(request)+'\n', text=True,
            capture_output=True, env=self.env, cwd=ROOT, timeout=45)
        self.commands.append({'tool': tool, 'argv': argv, 'exit_code': p.returncode,
                              'seconds': round(time.monotonic()-start, 6)})
        self.check('bounded_transport_'+str(self.sequence),
                   p.returncode == 0 and not p.stderr and len(p.stdout) <= 65536)
        reply = json.loads(p.stdout)
        self.save('requests/%04d.json' % self.sequence, {'request': request, 'reply': reply})
        failed = 'error' in reply or reply.get('result', {}).get('isError', False)
        self.check('tool_result_'+str(self.sequence), bool(failed) == error)
        if error:
            return reply
        text = reply['result']['content'][0]['text']
        self.check('tool_text_budget_'+str(self.sequence), len(text) <= 12000)
        return json.loads(text)

    def submit(self, case, kind, artifact=None, filename=None):
        args = {'case_id': case, 'kind': kind}
        if artifact is not None:
            args['artifact_id'] = artifact
        if filename is not None:
            args['filename'] = filename
        return self.call('job_submit', args)['job_id']

    def start_worker(self):
        label = 'worker-%03d' % (len(self.workers)+1)
        stream = (self.output/'logs'/(label+'.log')).open('xb')
        argv = [sys.executable, '-B', str(ROOT/'jobwork.py'), '--once']
        p = subprocess.Popen(argv, cwd=ROOT, env=self.env, stdout=stream,
                             stderr=subprocess.STDOUT)
        # Remain in the outer qualification process group so its hard timeout
        # also terminates every fixed analysis child. Kill one worker by PID
        # for the interruption test, never the containing group.
        self.check(label+'_contained_process_group', os.getpgid(p.pid) == os.getpgrp())
        record = {'process': p, 'stream': stream, 'label': label, 'argv': argv,
                  'start': time.monotonic(), 'finished': False}
        self.workers.append(record)
        return record

    def finish_worker(self, record, expected=0):
        p = record['process']
        try:
            code = p.wait(timeout=300)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=10)
            raise
        record['stream'].close()
        record['finished'] = True
        self.commands.append({'worker': record['label'], 'argv': record['argv'],
                              'exit_code': code, 'seconds': round(time.monotonic()-record['start'], 6)})
        self.check(record['label']+'_exit', code == expected)

    def job(self, case, kind, artifact=None, filename=None, state='SUCCEEDED'):
        jid = self.submit(case, kind, artifact, filename)
        self.finish_worker(self.start_worker())
        result = self.call('job_result', {'job_id': jid})
        self.check('job_'+kind+'_'+state, result['state'] == state)
        return result['result'] if state == 'SUCCEEDED' else result

    @property
    def inbox(self):
        return self.home/'.local/share/rocky-mcp-gateway/inbox'

    def register(self, case, name):
        original_hash = digest(self.inbox/name)
        item = self.job(case, 'import_staged', filename=name)
        self.check('intake_'+name, item['sha256'] == original_hash)
        self.originals.append((case, item['artifact_id'], original_hash))
        return item['artifact_id']

    def query_bound(self, tool, case):
        value = self.call(tool, {'case_id': case, 'offset': 10000, 'limit': 20})
        self.check(tool+'_explicit_page_bound', value['status'] == 'PARTIAL'
            and value['next_offset'] is None and not value['has_more']
            and value['pagination_bound_reached']
            and value['more_matching_events_outside_pagination_bound'])
        self.call(tool, {'case_id': case, 'offset': 10001}, error=True)

    def mixed(self):
        case = self.call('case_open', {})['case_id']
        count, packets = (100000, 200000) if self.profile == 'full' else (1000, 2000)
        make_log(self.inbox/'mixed.txt', count)
        text = self.register(case, 'mixed.txt')
        self.job(case, 'index_log', text)
        search = self.call('log_search', {'case_id': case, 'artifact_id': text, 'query': 'NEEDLELAST'})
        self.check('last_log_line', [m['line'] for m in search['matches']] == [count])
        peer_text = ('2024-07-03T11:46:39+02:00 synthetic peer start\n'
                     '2024-07-03T09:46:40Z synthetic peer retry password=private-synthetic\n'
                     '2024-07-03T05:46:41-04:00 synthetic peer completed\n'
                     'Oct 24 12:00:00 synthetic unknown year\n'
                     '{"timestamp":"2024-07-03T09:46:42Z","message":"synthetic JSON peer","token":"private-synthetic"}\n')
        (self.inbox/'peer.txt').write_text(peer_text)
        peer = self.register(case, 'peer.txt')
        retained = 0
        for fmt in ('pcap', 'pcapng'):
            make_capture(self.inbox/('mixed.'+fmt), fmt, packets)
            aid = self.register(case, 'mixed.'+fmt)
            self.job(case, 'decode_pcap', aid)
            view = self.call('pcap_protocol_report', {'case_id': case, 'artifact_id': aid})
            self.check(fmt+'_frame_count', view['packets_examined'] == packets)
            self.check(fmt+'_known_signals', all(view['counters'][name] == packets//1000
                for name in ('tcp_rst', 'dns_rcode_3', 'tls_alert_40', 'smb2_access_denied')))
            self.check(fmt+'_bounded_observations', view['diagnostic_observations'] <= 512)
            if self.profile == 'full':
                self.check(fmt+'_omission_is_partial', view['status'] == 'PARTIAL' and view['observations_omitted'] > 0)
            self.check(fmt+'_no_complete_capture', not view['claim_boundaries']['capture_complete'])
            retained += view['diagnostic_observations']
        self.job(case, 'build_timeline')
        summary = self.call('timeline_summary', {'case_id': case})
        self.check('timeline_complete_count', summary['events_indexed'] == count+5)
        self.check('timeline_unknown_count', summary['events_unanchored'] == (count+1)//3+1)
        self.check('timeline_partial', summary['status'] == 'PARTIAL')
        query = self.call('timeline_query', {'case_id': case, 'artifact_id': peer, 'include_unanchored': True})
        self.check('normalized_peer_order', [r['line_no'] for r in query['events']] == [1, 2, 3, 5, 4])
        self.check('unknown_peer_time', query['events'][-1]['timestamp_utc'] is None)
        self.job(case, 'build_correlation')
        summary = self.call('correlation_summary', {'case_id': case})
        self.check('cross_source_counts', summary['event_count'] == count+5+retained and summary['source_count'] == 4)
        self.check('correlation_partial', summary['status'] == 'PARTIAL')
        query = self.call('correlation_query', {'case_id': case, 'artifact_id': peer, 'include_unknown': True})
        self.check('correlated_peer_order', [r['locator_number'] for r in query['events']] == [1, 2, 3, 5, 4])
        self.check('no_inferred_cause_identity_clock', not query['causality_inferred']
            and not query['cross_source_identity_inferred'] and not query['clock_offsets_applied']
            and query['clock_alignment'] == 'UNVERIFIED')
        all_query = self.call('correlation_query', {'case_id': case, 'include_unknown': True})
        anchor = all_query['events'][0]
        selected = [peer, next(a for c, a, _ in self.originals if c == case and a not in (text, peer))]
        model = self.call('correlation_clock_model', {'case_id': case, 'index_revision': summary['index_revision'],
            'anchor_event_id': anchor['event_id'], 'source_clocks': [
                {'artifact_id': aid, 'offset_to_add_ms': 100 if i == 0 else -50,
                 'uncertainty_ms': 250 if i == 0 else 100} for i, aid in enumerate(selected)],
            'before_ms': 2000, 'after_ms': 2000})
        self.check('declared_clock_model_not_verified', not model['original_source_times_modified']
            and not model['declared_uncertainty_verified'] and not model['clock_alignment_verified']
            and not model['causality_inferred'])
        if self.profile == 'full':
            for tool in ('timeline_query', 'correlation_query'):
                self.query_bound(tool, case)
        report = self.call('case_evidence_report', {'case_id': case, 'index_revision': summary['index_revision']})
        hashes = {a: h for c, a, h in self.originals if c == case}
        self.check('bounded_report_sample', len(report['observations']) == 6
            and report['observation_sample_omitted'] == summary['event_count']-6)
        self.check('report_provenance', all(row['source_sha256'] == hashes[row['artifact_id']]
            and row['locator_type'] in ('line', 'packet') and row['locator_number'] > 0 for row in report['observations']))
        self.check('report_no_cause', report['status'] == 'PARTIAL'
            and 'root_cause_not_established' in report['unknowns'] and report['hypotheses'] == [])
        self.check('no_raw_selected_secrets', all(secret not in json.dumps((query, report))
            for secret in ('private-synthetic', 'synthetic-private', 'secret.local', '10.1.2.3')))
        self.save('mixed-report.json', report)
        (self.inbox/'not-indexed.pcap').write_bytes(b'\xd4\xc3\xb2\xa1'+b'\0'*20)
        self.register(case, 'not-indexed.pcap')
        self.call('correlation_summary', {'case_id': case}, error=True)
        self.job(case, 'build_correlation')
        new = self.call('correlation_summary', {'case_id': case})
        self.call('case_evidence_report', {'case_id': case, 'index_revision': summary['index_revision']}, error=True)
        missing = self.call('case_evidence_report', {'case_id': case, 'index_revision': new['index_revision']})
        self.check('missing_index_visible', missing['status'] == 'PARTIAL' and missing['facts']['missing_indexes'] == 1)
        self.save('missing-index-report.json', missing)
        return case

    def queue(self, case):
        ids = [self.submit(case, 'verify_case') for _ in range(16)]
        before = self.call('job_list', {})['total_jobs']
        self.call('job_submit', {'case_id': case, 'kind': 'verify_case'}, error=True)
        self.check('queue_refusal_no_hidden_record', self.call('job_list', {})['total_jobs'] == before)
        self.check('queued_cancel', self.call('job_cancel', {'job_id': ids.pop(0)})['state'] == 'CANCELLED')
        ids.append(self.submit(case, 'verify_case'))
        for jid in ids:
            self.check('queue_cancel_'+jid, self.call('job_cancel', {'job_id': jid})['state'] == 'CANCELLED')
        self.finish_worker(self.start_worker())
        self.check('queue_history_preserved', self.call('job_list', {})['total_jobs'] == before+1)

    def wait_running(self, jid, record):
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            status = self.call('job_status', {'job_id': jid})
            if status['state'] == 'RUNNING':
                return
            if record['process'].poll() is not None:
                break
            time.sleep(0.02)
        raise AssertionError('worker_did_not_enter_running')

    def faults_and_capacity(self):
        case = self.call('case_open', {})['case_id']
        make_log(self.inbox/'million.txt', 1000000)
        aid = self.register(case, 'million.txt')
        jid = self.submit(case, 'index_log', aid)
        worker = self.start_worker()
        self.wait_running(jid, worker)
        cancel = self.call('job_cancel', {'job_id': jid})
        self.check('running_cancel_requested', cancel['cancel_requested'])
        self.finish_worker(worker)
        self.check('running_cancelled', self.call('job_result', {'job_id': jid})['state'] == 'CANCELLED')
        indexes = self.home/'.local/share/rocky-mcp-gateway/cases'/case/'indexes'
        self.check('cancel_no_index', not (indexes/(aid+'.sqlite3')).exists())
        jid = self.submit(case, 'index_log', aid)
        worker = self.start_worker()
        self.wait_running(jid, worker)
        deadline = time.monotonic()+10
        while time.monotonic() < deadline and not list(indexes.glob('.tmp-*.sqlite3')):
            time.sleep(0.01)
        self.check('index_transaction_before_kill', bool(list(indexes.glob('.tmp-*.sqlite3'))))
        worker['process'].kill()
        self.finish_worker(worker, -signal.SIGKILL)
        self.finish_worker(self.start_worker())
        result = self.call('job_result', {'job_id': jid})
        self.check('interrupted_job_visible', result['state'] == 'INTERRUPTED' and result['failure_code'] == 'worker_interrupted')
        self.check('interruption_no_published_index', not (indexes/(aid+'.sqlite3')).exists())
        # Index recovery has a separate explicit helper API, not an MCP approval
        # tool. Exercise it only on this synthetic state and record its receipt.
        from casework import CaseStore, CaseError
        import index_recovery
        store = CaseStore(self.home)
        ids = index_recovery.list_interrupted(store, case)['index_work_ids']
        self.check('one_interrupted_transaction', len(ids) == 1)
        try:
            index_recovery.recover(store, case, ids[0])
        except CaseError:
            self.check('recent_recovery_refused', True)
        else:
            self.check('recent_recovery_refused', False)
        future = time.time_ns()+25*3600*1000000000
        plan = index_recovery.recover(store, case, ids[0], now_ns=future)
        done = index_recovery.recover(store, case, ids[0], now_ns=future, confirm=True,
                                      plan_sha256=plan['plan_sha256'])
        self.save('synthetic-recovery-receipt.json', {'preview': plan, 'confirmed': done})
        self.check('recovery_preserves_registered_state', done['registered_originals_removed'] == 0 and done['committed_indexes_removed'] == 0)
        result = self.job(case, 'index_log', aid)
        self.check('interrupted_job_retry', result['lines_indexed'] == 1000000)
        self.job(case, 'build_timeline')
        summary = self.call('timeline_summary', {'case_id': case})
        self.check('million_timeline_count', summary['events_indexed'] == 1000000)
        self.query_bound('timeline_query', case)
        failed = self.job(case, 'build_correlation', state='FAILED')
        self.check('correlation_capacity_refused', 'capacity' in failed['failure_code'].lower())
        self.call('correlation_summary', {'case_id': case}, error=True)
        self.call('case_evidence_report', {'case_id': case, 'index_revision': '0'*32}, error=True)
        self.save('capacity-refusal.json', failed)

    def run(self):
        case = self.mixed()
        print('MIXED_WORKLOAD_PASS', flush=True)
        self.queue(case)
        print('QUEUE_SATURATION_PASS', flush=True)
        if self.profile == 'full':
            self.faults_and_capacity()
            print('CANCELLATION_INTERRUPTION_CAPACITY_PASS', flush=True)
        for cid, aid, sha in self.originals:
            path = self.home/'.local/share/rocky-mcp-gateway/cases'/cid/'originals'/aid
            self.check('original_rehash_'+aid, digest(path) == sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=('smoke', 'full'), default='full')
    args = parser.parse_args()
    if os.geteuid() == 0 or not args.output.is_absolute():
        raise RuntimeError('Nonroot and absolute new output required')
    if any(p.is_symlink() for p in args.output.parents):
        raise RuntimeError('Output ancestor symlink refused')
    if shutil.disk_usage(args.output.parent).free < 8*1024**3:
        raise RuntimeError('Insufficient qualification headroom')
    args.output.mkdir(mode=0o700)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
    workload = Workload(args.output, args.profile)
    result = {'profile': args.profile, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'uid': os.getuid(), 'python': sys.version}
    try:
        workload.run()
        result['status'] = 'PASS'
    except Exception as error:
        result.update(status='FAIL', error=type(error).__name__+': '+str(error))
    finally:
        for row in workload.workers:
            if not row['finished']:
                if row['process'].poll() is None:
                    row['process'].kill()
                row['process'].wait(timeout=10)
                row['stream'].close()
        result.update(checks=workload.checks, commands=workload.commands,
            finished_utc=datetime.now(timezone.utc).isoformat(),
            peak_child_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            retained_bytes=sum(p.stat().st_size for p in args.output.rglob('*') if p.is_file()),
            skipped_full_scenarios=[] if args.profile == 'full' else ['running_cancel','SIGKILL_recovery','million_line_capacity'])
        workload.save('RESULT.json', result)
    print(json.dumps({'status': result['status'], 'checks': len(workload.checks), 'error': result.get('error')}), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
