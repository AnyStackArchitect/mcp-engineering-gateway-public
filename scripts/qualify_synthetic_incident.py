#!/usr/bin/env python3
"""Opt-in incident integration: synthetic inputs plus one pinned public EVTX.

Only a new private nonroot Linux HOME is used. Library attestation below is a
fixture simulation, not human approval or execution/signing authority.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import resource
import shutil
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.qualify_mcp_workload import Workload, make_capture, digest
from scripts.qualify_real_evtx import UPSTREAM_FIXTURE_SHA256, UPSTREAM_FIXTURE_BYTES, _fixture_metadata
import casework
import librarywork


class Incident(Workload):
    def __init__(self, output, fixture, provider):
        super().__init__(output, 'synthetic-incident-with-public-evtx')
        self.fixture = fixture
        self.env['PYTHONPATH'] = str(provider)

    def run(self):
        case = self.call('case_open', {})['case_id']
        (self.inbox/'incident.txt').write_text(
            '2026-10-24T12:00:00Z synthetic operation started\n'
            '2026-10-24T12:00:01Z synthetic retry password=fixture-private\n'
            '2026-10-24T12:00:02Z synthetic operation completed\n'
            'unknown-time synthetic retry reference\n')
        log = self.register(case, 'incident.txt')
        self.job(case, 'index_log', log)
        make_capture(self.inbox/'incident.pcap', 'pcap', 2000)
        packet = self.register(case, 'incident.pcap')
        self.job(case, 'decode_pcap', packet)
        capture = self.call('pcap_protocol_report', {'case_id':case, 'artifact_id':packet})
        self.check('known_synthetic_packet_signals', capture['packets_examined'] == 2000 and
            all(capture['counters'][k] == 2 for k in ('tcp_rst','dns_rcode_3','tls_alert_40','smb2_access_denied')))
        shutil.copyfile(self.fixture, self.inbox/'public.evtx')
        binary = self.register(case, 'public.evtx')
        direct_count, direct_ids, direct_utc = _fixture_metadata(self.fixture)
        outcome = self.job(case, 'analyze_evtx', binary)
        self.check('real_provider_integration', outcome['records_examined'] == direct_count and
                   outcome['records_skipped'] == 0 and outcome['records_without_utc'] == direct_count-direct_utc)
        summary = self.call('evtx_summary', {'case_id':case, 'artifact_id':binary})
        self.check('real_provider_id_counts', {r['event_id']:r['count'] for r in summary['event_id_counts']} == direct_ids)
        events = self.call('evtx_events', {'case_id':case, 'artifact_id':binary})
        rules = self.call('windows_rule_report', {'case_id':case, 'artifact_id':binary})
        self.check('windows_metadata_limits', events['payloads_excluded'] and rules['status'] == 'PARTIAL'
            and not rules['malicious_activity_established'] and not rules['eventdata_evaluated'])
        before, after = ('{"mode":"auto","password":"fixture-before","items":[1,2]}',
                         '{"mode":false,"password":"fixture-after","items":[2,1]}')
        configs = []
        for name, text in (('before.json',before),('after.json',after)):
            (self.inbox/name).write_text(text)
            configs.append(self.register(case, name))
        args = {'case_id':case, 'before_artifact_id':configs[0], 'after_artifact_id':configs[1]}
        drift = self.call('config_drift_report', args)
        self.check('config_known_changes', drift['change_totals'] ==
            {'ARRAY_ORDER_CHANGED':1,'TYPE_CHANGED':1,'VALUE_CHANGED':1})
        self.check('config_not_diagnosis', not drift['causality_established'] and not drift['change_time_verified']
                   and drift['array_order_semantically_significant'] is None)
        reverse = self.call('config_drift_report', args|{'before_artifact_id':configs[1], 'after_artifact_id':configs[0]})
        self.check('reverse_drift_not_chronology', not reverse['change_time_verified'])
        # Explicit local attestation simulation in this new test HOME only.
        store = casework.CaseStore(self.home)
        log_sha = next(h for c,a,h in self.originals if a == log)
        note = dict(kind='reference', product='synthetic-lab', version='1.0',
            title='Synthetic retry reference', summary='Fixture only; no diagnosis or compatibility proof',
            source_case_id=case, source_artifact_id=log, source_sha256=log_sha, source_line=4,
            reference_uri='', reference_date='2020-01-01', rights_confirmed=True)
        review = librarywork.prepare(store, note)
        with patch.object(librarywork.time, 'time', return_value=1):
            accepted = librarywork.accept(store, note, review['review_sha256'], interactive=True)
        search = {'query':'retry', 'product':'synthetic-lab', 'version':'1.0'}
        reference = self.call('knowledge_search', search)
        self.check('reference_exact_version_and_stale_warning', len(reference['matches']) == 1
            and reference['matches'][0]['stale_age_warning']
            and reference['matches'][0]['stale_reference_date_warning']
            and not reference['automatic_reuse_or_execution_authorized'])
        different = self.call('knowledge_search', search|{'version':'2.0'})
        self.check('no_cross_version_inference', different['matches'] == [])
        self.save('attestation-simulation.json', {'fixture_simulation_only':True,
            'real_human_authorization':False, 'acceptance':accepted})
        self.job(case, 'build_timeline')
        self.job(case, 'build_correlation')
        joined = self.call('correlation_summary', {'case_id':case})
        locators = set()
        for kind, locator in (('text','line'),('pcap','packet'),('evtx','record')):
            rows = self.call('correlation_query', {'case_id':case, 'kind':kind, 'include_unknown':True})
            self.check(kind+'_source_locators', bool(rows['events']) and
                all(r['locator_type'] == locator and r['locator_number'] > 0 for r in rows['events']))
            self.check(kind+'_no_causal_clock_claim', not rows['causality_inferred'] and not rows['clock_offsets_applied'])
            locators.update(r['locator_type'] for r in rows['events'])
        self.check('all_three_source_classes', locators == {'line','packet','record'})
        report = self.call('case_evidence_report', {'case_id':case, 'index_revision':joined['index_revision']})
        self.check('report_root_cause_unknown', report['status'] == 'PARTIAL'
            and 'root_cause_not_established' in report['unknowns'] and report['hypotheses'] == [])
        visible = json.dumps((events, rules, drift, reverse, reference, report))
        self.check('no_raw_event_or_secret_values', all(s not in visible for s in
            ('<Event','EventData','TargetUserName','fixture-private','fixture-before','fixture-after')))
        self.save('combined-report.json', report)
        self.save('scope.json', {'synthetic_inputs':['text','pcap','configuration','reference note'],
            'public_binary_fixture_sha256':UPSTREAM_FIXTURE_SHA256, 'public_binary_records':direct_count,
            'provider_version':version('python-evtx'), 'independent_parser_accuracy_proven':False,
            'customer_or_live_inputs':False, 'signing_or_execution_authority':False})
        # A signature-only/truncated file must never produce successful coverage.
        bad_case = self.call('case_open', {})['case_id']
        (self.inbox/'truncated.evtx').write_bytes(self.fixture.read_bytes()[:4096])
        truncated = self.register(bad_case, 'truncated.evtx')
        partial = self.job(bad_case, 'analyze_evtx', truncated)
        self.check('truncated_binary_not_successful_coverage', partial['status'] == 'PARTIAL'
                   and partial['records_examined'] == 0)
        self.save('truncated-binary.json', partial)
        for cid, aid, sha in self.originals:
            original = self.home/'.local/share/rocky-mcp-gateway/cases'/cid/'originals'/aid
            self.check('original_unchanged_'+aid, digest(original) == sha)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--fixture', type=Path, required=True)
    p.add_argument('--provider-path', type=Path, required=True)
    args = p.parse_args()
    if os.geteuid() == 0 or not args.output.is_absolute():
        raise RuntimeError('Nonroot and new absolute output required')
    for target in (args.output, args.fixture, args.provider_path):
        if not target.is_absolute() or any(x.is_symlink() for x in (target,*target.parents)):
            raise RuntimeError('Absolute nonsymlink paths required')
    if args.fixture.stat().st_size != UPSTREAM_FIXTURE_BYTES or digest(args.fixture) != UPSTREAM_FIXTURE_SHA256:
        raise RuntimeError('Public binary provenance mismatch')
    sys.path.insert(0, str(args.provider_path))
    if version('python-evtx') != '0.8.1':
        raise RuntimeError('Pinned provider required')
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(300,300))
    workload = Incident(args.output, args.fixture, args.provider_path)
    result = {'started_utc':datetime.now(timezone.utc).isoformat(),'uid':os.getuid(),'python':sys.version}
    try:
        workload.run()
        result['status'] = 'PASS'
    except Exception as error:
        result.update(status='FAIL',error=type(error).__name__+': '+str(error))
    finally:
        for row in workload.workers:
            if not row['finished']:
                if row['process'].poll() is None:
                    row['process'].kill()
                row['process'].wait(timeout=10)
                row['stream'].close()
        result.update(checks=workload.checks,commands=workload.commands,
            finished_utc=datetime.now(timezone.utc).isoformat())
        workload.save('RESULT.json', result)
    print(json.dumps({'status':result['status'],'checks':len(workload.checks),'error':result.get('error')}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
