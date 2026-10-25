"""Declared 40-second skew and uncertainty must not become clock/causal truth."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest

import casework
import clockwork
import correlationwork
import gateway
import timelinework


class ClockSensitivityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.store = casework.CaseStore(self.home)
        self.cid = self.store.open_case()['case_id']
        self.first = self.add('a.log', '2026-10-18T10:00:00Z ERROR failed password=private\n')
        self.second = self.add('b.log', '2026-10-18T10:00:40Z INFO succeeded\n'
                               '2026-10-18T10:00:42.500Z WARN later\n'
                               'Oct 18 10:00:40 missing UTC context\n')
        self.rebuild()

    def add(self, name, text):
        p = self.store.inbox/name
        p.write_text(text); p.chmod(0o600)
        return self.store.register(self.cid, name)['artifact_id']

    def rebuild(self):
        timelinework.build_timeline(self.store, self.cid)
        correlationwork.build_correlation(self.store, self.cid)
        q = correlationwork.correlation_query(self.store, self.cid, include_unknown=True)
        self.revision = q['index_revision']
        self.anchor = next(r['event_id'] for r in q['events'] if r['artifact_id'] == self.first)
        self.unknown = next(r['event_id'] for r in q['events'] if r['utc'] is None)

    def models(self, *, a=0, b=-40000, ua=0, ub=0):
        return [{'artifact_id': self.first, 'offset_to_add_ms': a, 'uncertainty_ms': ua},
                {'artifact_id': self.second, 'offset_to_add_ms': b, 'uncertainty_ms': ub}]

    def query(self, **kwargs):
        return clockwork.adjusted_window(self.store, self.cid, index_revision=self.revision,
            anchor_event_id=self.anchor, source_clocks=self.models(), before_ms=1000,
            after_ms=1000, **kwargs)

    def test_known_40_second_offset_keeps_original_and_modeled_time_separate(self):
        original = self.store.cases/self.cid/'originals'/self.second
        before = hashlib.sha256(original.read_bytes()).hexdigest()
        report = self.query()
        self.assertEqual(len(report['events']), 1)
        event = report['events'][0]
        self.assertEqual(event['source_observed_delta_ms'], 40000)
        self.assertEqual(event['modeled_delta_ms'], 0)
        self.assertEqual(event['locator_number'], 1)
        self.assertEqual(event['artifact_id'], self.second)
        self.assertEqual(report['selected_sources_unknown_utc_events'], 1)
        self.assertFalse(report['clock_alignment_verified'])
        self.assertFalse(report['causality_inferred'])
        self.assertFalse(report['original_source_times_modified'])
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), before)
        self.assertNotIn('private', json.dumps(report))
        self.assertNotIn('succeeded', json.dumps(report))

    def test_zero_offsets_leave_skewed_source_outside_nominal_window(self):
        report = clockwork.adjusted_window(self.store, self.cid, index_revision=self.revision,
            anchor_event_id=self.anchor, source_clocks=self.models(b=0), before_ms=1000, after_ms=1000)
        self.assertEqual(report['events'], [])
        self.assertEqual(report['status'], 'PARTIAL')

    def test_declared_uncertainty_overlap_does_not_imply_verified_bound(self):
        report = clockwork.adjusted_window(self.store, self.cid, index_revision=self.revision,
            anchor_event_id=self.anchor, source_clocks=self.models(ua=1000, ub=1000),
            before_ms=1000, after_ms=1000)
        self.assertEqual(len(report['events']), 2)
        later = report['events'][1]
        self.assertEqual(later['membership'], 'DECLARED_UNCERTAINTY_OVERLAP_ONLY')
        self.assertEqual(later['declared_delta_uncertainty_ms'], 2000)
        self.assertFalse(report['declared_uncertainty_verified'])

    def test_model_digest_stable_for_declaration_order_and_pages(self):
        first = clockwork.adjusted_window(self.store, self.cid, index_revision=self.revision,
            anchor_event_id=self.anchor, source_clocks=self.models(), before_ms=5000, after_ms=5000, limit=1)
        second = clockwork.adjusted_window(self.store, self.cid, index_revision=self.revision,
            anchor_event_id=self.anchor, source_clocks=list(reversed(self.models())),
            before_ms=5000, after_ms=5000, limit=1, offset=first['next_offset'])
        self.assertEqual(first['model_sha256'], second['model_sha256'])
        self.assertNotEqual(first['events'][0]['event_id'], second['events'][0]['event_id'])
        self.assertIsNone(second['next_offset'])

    def test_unknown_anchor_and_stale_revision_refused(self):
        with self.assertRaises(casework.CaseError):
            clockwork.adjusted_window(self.store, self.cid, index_revision=self.revision,
                anchor_event_id=self.unknown, source_clocks=self.models())
        old = self.revision
        self.rebuild()
        with self.assertRaises(casework.CaseError):
            clockwork.adjusted_window(self.store, self.cid, index_revision=old,
                anchor_event_id=self.anchor, source_clocks=self.models())

    def test_declaration_controls_strict_and_cross_case_source_refused(self):
        bad = [None, [], self.models()[:1], self.models()*5,
               [self.models()[0], self.models()[0]],
               self.models()[:1] + [{'artifact_id': self.second, 'offset_to_add_ms': True, 'uncertainty_ms': 0}],
               self.models()[:1] + [{'artifact_id': self.second, 'offset_to_add_ms': 3600001, 'uncertainty_ms': 0}],
               self.models()[:1] + [{'artifact_id': self.second, 'offset_to_add_ms': 0, 'uncertainty_ms': -1}],
               self.models()[:1] + [{'artifact_id': 'f'*32, 'offset_to_add_ms': 0, 'uncertainty_ms': 0}]]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(casework.CaseError):
                clockwork.adjusted_window(self.store, self.cid, index_revision=self.revision,
                    anchor_event_id=self.anchor, source_clocks=value)

    def test_gateway_read_only_model_rejects_extra_approval_claim(self):
        gw = gateway.Gateway(gateway.Config({}, (), self.home))
        args = {'case_id': self.cid, 'index_revision': self.revision,
                'anchor_event_id': self.anchor, 'source_clocks': self.models()}
        self.assertFalse(gw.call('correlation_clock_model', args)['clock_alignment_verified'])
        with self.assertRaises(gateway.GatewayError):
            gw.call('correlation_clock_model', args | {'verified': True})

    def test_page_bound_is_explicit_and_never_advertises_unreachable_next_page(self):
        many = self.add('many.log', '2026-10-18T10:00:00Z INFO known\n' * 10021)
        timelinework.build_timeline(self.store, self.cid)
        correlationwork.build_correlation(self.store, self.cid)
        anchor = correlationwork.correlation_query(self.store, self.cid, artifact_id=self.first)
        models = [{'artifact_id': aid, 'offset_to_add_ms': 0, 'uncertainty_ms': 0}
                  for aid in (self.first, many)]
        report = clockwork.adjusted_window(self.store, self.cid, index_revision=anchor['index_revision'],
            anchor_event_id=anchor['events'][0]['event_id'], source_clocks=models, offset=10000)
        self.assertEqual(report['matching_events_in_declared_model'], 10021)
        self.assertEqual(len(report['events']), 20)
        self.assertTrue(report['pagination_bound_reached'])
        self.assertTrue(report['more_matching_events_outside_pagination_bound'])
        self.assertFalse(report['has_more'])
        self.assertIsNone(report['next_offset'])


if __name__ == '__main__':
    unittest.main()
