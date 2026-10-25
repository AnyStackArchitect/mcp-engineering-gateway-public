"""Known answers for exact channel/provider/EventID matching, never a diagnosis."""
import json
import unittest
from unittest.mock import patch

import casework
import evtxwork
import gateway
import windowsrules
from test_evtxwork import EVTXTests, FakeRecord, event_xml


def record(eid='4625', provider='Microsoft-Windows-Security-Auditing',
           channel='Security', number=42):
    xml = event_xml(eid, provider=provider, secret='private-test-principal')
    if channel is not None:
        xml = xml.replace('</System>', '<Channel>' + channel + '</Channel></System>')
    return FakeRecord(xml, number)


class WindowsRuleTests(EVTXTests):
    # Reuse the existing actual case/worker fixture, not its inherited tests.
    def analyze(self, rows):
        with self.provider(rows):
            evtxwork.analyze_evtx(self.jobs.cases, self.case, self.aid)

    def report(self, **args):
        return windowsrules.report(self.jobs.cases, self.case, self.aid, **args)

    def test_exact_four_rule_vectors_and_metadata_privacy(self):
        self.analyze([record(), record('1102', 'Microsoft-Windows-Eventlog', number=43),
                      record('7031', 'Service Control Manager', 'System', number=44),
                      record('4624', number=45)])
        report = self.report()
        self.assertEqual([r['matches'] for r in report['rules']], [1, 1, 1, 1])
        self.assertEqual([r['record'] for r in report['matches']], [42, 43, 44, 45])
        self.assertEqual(report['pack_version'], '1.1.0')
        self.assertEqual(report['status'], 'PARTIAL')
        self.assertEqual(report['pack_sha256'], windowsrules.pack_digest())
        self.assertFalse(report['collection_completeness_verified'])
        self.assertFalse(report['malicious_activity_established'])
        self.assertNotIn('private-test-principal', json.dumps(report))
        self.assertNotIn('<Event', json.dumps(report))

    def test_event_id_without_expected_provider_or_channel_does_not_match(self):
        self.analyze([record(provider='Service Control Manager'), record(channel='System'),
                      record(provider='private-provider-name'), record(channel='private-channel')])
        report = self.report()
        self.assertEqual(sum(r['matches'] for r in report['rules']), 0)
        self.assertEqual(report['matches'], [])
        self.assertNotIn('private-provider-name', json.dumps(report))
        self.assertNotIn('private-channel', json.dumps(report))
        self.assertEqual(report['records_without_allowlisted_channel'], 1)

    def test_missing_security_channel_never_claims_negative_coverage(self):
        self.analyze([record('7036', 'Service Control Manager', 'System')])
        report = self.report()
        self.assertEqual(report['rules'][0]['state'], 'CHANNEL_NOT_OBSERVED')
        self.assertEqual(report['rules'][2]['state'], 'NO_MATCHES_OBSERVED')
        self.assertEqual(report['status'], 'PARTIAL')

    def test_missing_or_malformed_records_are_explicit(self):
        self.analyze([record(channel=None), FakeRecord('<invalid>')])
        report = self.report()
        self.assertEqual(report['records_without_allowlisted_channel'], 1)
        self.assertEqual(report['records_skipped'], 1)
        self.assertTrue(all(r['state'] == 'CHANNEL_NOT_OBSERVED' for r in report['rules']))

    def test_nested_or_duplicate_system_metadata_cannot_forge_match(self):
        good = record().xml()
        nested = '<Event><EventData>' + good + '</EventData></Event>'
        duplicate = good.replace('</System>', '<Channel>System</Channel></System>')
        self.analyze([FakeRecord(nested), FakeRecord(duplicate)])
        report = self.report()
        self.assertEqual(report['records_skipped'], 2)
        self.assertEqual(report['matches'], [])

    def test_pagination_keeps_source_record_references(self):
        self.analyze([record(number=n) for n in range(45)])
        pages = [self.report(offset=n) for n in (0, 20, 40)]
        self.assertEqual([len(p['matches']) for p in pages], [20, 20, 5])
        self.assertEqual([m['record'] for p in pages for m in p['matches']], list(range(45)))
        self.assertEqual([p['next_offset'] for p in pages], [20, 40, None])
        self.assertTrue(all(p['rules'][0]['matches'] == 45 for p in pages))

    def test_unknown_rule_pack_invalid_controls_and_stale_source_refused(self):
        self.analyze([record()])
        for kw in ({'pack': 'sigma'}, {'pack': True}, {'offset': True}, {'offset': -1}, {'offset': 500000}):
            with self.subTest(kw=kw), self.assertRaises(evtxwork.EvtxError):
                self.report(**kw)
        original = self.jobs.cases.cases/self.case/'originals'/self.aid
        original.write_bytes(b'BADFILE' + original.read_bytes()[7:])
        with self.assertRaises(evtxwork.EvtxError):
            self.report()

    def test_gateway_read_only_and_arbitrary_rule_input_refused(self):
        self.analyze([record()])
        gw = gateway.Gateway(gateway.Config({}, (), self.home))
        spec = next(s for s in gw.tools() if s['name'] == 'windows_rule_report')
        self.assertTrue(spec['annotations']['readOnlyHint'])
        self.assertFalse(spec['annotations']['destructiveHint'])
        args = {'case_id': self.case, 'artifact_id': self.aid}
        self.assertEqual(gw.call('windows_rule_report', args)['rules'][0]['matches'], 1)
        with self.assertRaises(gateway.GatewayError):
            gw.call('windows_rule_report', args | {'rule': 'arbitrary code'})

    def test_legacy_index_requires_rebuild(self):
        self.analyze([record()])
        import sqlite3
        path = self.jobs.cases.cases/self.case/'indexes'/('evtx-' + self.aid + '.sqlite3')
        with sqlite3.connect(path) as db:
            db.execute("UPDATE facts SET value='1' WHERE key='schema'")
        with self.assertRaises(evtxwork.EvtxError):
            self.report()

    def test_continuation_after_ten_thousand_matches_remains_reachable(self):
        self.analyze([record(number=n) for n in range(10021)])
        page = self.report(offset=10000)
        self.assertEqual(len(page['matches']), 20)
        self.assertEqual(page['next_offset'], 10020)
        tail = self.report(offset=page['next_offset'])
        self.assertEqual([r['record'] for r in tail['matches']], [10020])
        self.assertIsNone(tail['next_offset'])


# Avoid counting inherited baseline tests as new rule-pack proof.
for _name in tuple(EVTXTests.__dict__):
    if _name.startswith('test_') and _name not in WindowsRuleTests.__dict__:
        setattr(WindowsRuleTests, _name, None)
del EVTXTests

if __name__ == '__main__':
    unittest.main()
