"""Synthetic semantic incident contracts; controlled XML is not EVTX binary proof."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import casework
import configdelta
import evtxwork
import librarywork
import test_evtxwork as event_fixtures
import test_windowsrules as rule_fixtures
import windowsrules


class WindowsIncidentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = event_fixtures.EVTXTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def analyze(self, rows):
        f = self.fixture
        with f.provider(rows):
            return evtxwork.analyze_evtx(f.jobs.cases, f.case, f.aid)

    def test_failure_then_success_is_observation_not_compromise_or_recovery(self):
        self.analyze([rule_fixtures.record(number=1),
                      rule_fixtures.record('4624', number=2)])
        f = self.fixture
        out = windowsrules.report(f.jobs.cases, f.case, f.aid)
        self.assertEqual([r['matches'] for r in out['rules']], [1, 0, 0, 1])
        self.assertFalse(out['malicious_activity_established'])
        self.assertFalse(out['collection_completeness_verified'])
        self.assertFalse(out['eventdata_evaluated'])
        self.assertEqual(out['status'], 'PARTIAL')

    def test_eventdata_nested_system_and_duplicate_channel_do_not_forge_incident(self):
        valid = rule_fixtures.record().xml()
        rows = [event_fixtures.FakeRecord('<Event><EventData>'+valid+'</EventData></Event>'),
                event_fixtures.FakeRecord(valid.replace('</System>', '<Channel>System</Channel></System>')),
                rule_fixtures.record(provider='Synthetic.Security-Auditing', number=3)]
        self.analyze(rows)
        f = self.fixture
        out = windowsrules.report(f.jobs.cases, f.case, f.aid)
        self.assertEqual(out['records_skipped'], 2)
        self.assertEqual(out['matches'], [])
        self.assertNotIn('Synthetic.Security-Auditing', json.dumps(out))

    def test_malformed_and_unknown_time_are_distinct_coverage_gaps(self):
        xml = event_fixtures.event_xml(rawtime='unknown')
        out = self.analyze([event_fixtures.FakeRecord(xml, 1),
                            event_fixtures.FakeRecord('<Event>', 2)])
        self.assertEqual(out['records_skipped'], 1)
        self.assertEqual(out['records_without_utc'], 1)
        self.assertEqual(out['status'], 'PARTIAL')

    def test_provider_failure_after_valid_record_never_commits_partial_success(self):
        def records():
            yield rule_fixtures.record(number=1)
            raise RuntimeError('synthetic provider stopped')
        f = self.fixture
        with self.assertRaises(evtxwork.EvtxError):
            self.analyze(records())
        with self.assertRaises(evtxwork.EvtxError):
            evtxwork.evtx_summary(f.jobs.cases, f.case, f.aid)


class ConfigurationKnowledgeIncidentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = casework.CaseStore(Path(temporary.name))
        self.case = self.store.open_case()['case_id']

    def add(self, name, text):
        p = self.store.inbox/name
        p.write_text(text)
        p.chmod(0o600)
        return self.store.register(self.case, name)['artifact_id']

    def test_reversed_drift_is_not_verified_chronology_and_preserves_originals(self):
        a = self.add('before.json', '{"password":"synthetic-alpha","mode":"auto","items":[1,2]}')
        b = self.add('after.json', '{"password":"synthetic-beta","mode":false,"items":[2,1]}')
        originals = self.store.cases/self.case/'originals'
        hashes = {aid: hashlib.sha256((originals/aid).read_bytes()).hexdigest() for aid in (a,b)}
        for first, second in ((a,b),(b,a)):
            out = configdelta.report(self.store, self.case, first, second)
            self.assertEqual(out['change_totals'], {'ARRAY_ORDER_CHANGED':1,'TYPE_CHANGED':1,'VALUE_CHANGED':1})
            self.assertFalse(out['change_time_verified'])
            self.assertFalse(out['causality_established'])
            self.assertIsNone(out['array_order_semantically_significant'])
            for secret in ('password','synthetic-alpha','synthetic-beta'):
                self.assertNotIn(secret, json.dumps(out))
        self.assertEqual(hashes, {aid:hashlib.sha256((originals/aid).read_bytes()).hexdigest() for aid in (a,b)})

    def test_comment_only_properties_drift_does_not_create_incident(self):
        a = self.add('a.properties', '# observed failure\nport=443\nmode=auto\n')
        b = self.add('b.properties', '; observed recovery\nmode=auto\nport=443\n')
        out = configdelta.report(self.store, self.case, a, b, fmt='properties')
        self.assertEqual(out['changed_fields'], 0)
        self.assertFalse(out['causality_established'])

    def note(self):
        aid = self.add('reference.txt', 'synthetic retry observation; isolated fixture only\n')
        sha = hashlib.sha256((self.store.cases/self.case/'originals'/aid).read_bytes()).hexdigest()
        return dict(kind='reference', product='synthetic-lab', version='1.0',
            title='Synthetic retry reference', summary='Fixture-only observation, no compatibility claim',
            source_case_id=self.case, source_artifact_id=aid, source_sha256=sha,
            source_line=1, reference_uri='', reference_date='2020-01-01', rights_confirmed=True)

    def test_reference_acceptance_is_exact_review_not_automatic_authority(self):
        note = self.note()
        review = librarywork.prepare(self.store, note)
        for edited in (note|{'version':'2.0'}, note|{'rights_confirmed':False}):
            with self.assertRaises(casework.CaseError):
                librarywork.accept(self.store, edited, review['review_sha256'], interactive=True)
        with self.assertRaises(casework.CaseError):
            librarywork.accept(self.store, note, review['review_sha256'])
        with patch.object(librarywork.time, 'time', return_value=1):
            librarywork.accept(self.store, note, review['review_sha256'], interactive=True)
        out = librarywork.search(self.store, 'retry', 'synthetic-lab', '1.0')
        self.assertTrue(out['matches'][0]['stale_age_warning'])
        self.assertTrue(out['matches'][0]['stale_reference_date_warning'])
        self.assertFalse(out['automatic_reuse_or_execution_authorized'])
        self.assertEqual(librarywork.search(self.store, 'retry', 'synthetic-lab', '2.0')['matches'], [])

    def test_missing_source_retains_history_with_explicit_reference_warning(self):
        note = self.note()
        review = librarywork.prepare(self.store, note)
        librarywork.accept(self.store, note, review['review_sha256'], interactive=True)
        (self.store.cases/self.case/'originals'/note['source_artifact_id']).unlink()
        out = librarywork.search(self.store, 'retry', 'synthetic-lab', '1.0')
        self.assertEqual(out['matches'][0]['source_state'], 'SOURCE_UNAVAILABLE_OR_CHANGED')
        self.assertFalse(out['automatic_reuse_or_execution_authorized'])
        self.assertEqual(out['status'], 'PARTIAL')


if __name__ == '__main__':
    unittest.main()
