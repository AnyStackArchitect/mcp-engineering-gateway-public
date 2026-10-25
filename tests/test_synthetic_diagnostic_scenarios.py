"""Multi-source synthetic incidents; no vendor compatibility or cause asserted.

Failure, successful retry and unaffected-peer records are deliberately separate
sources. Expected marker IDs are fixture answers, not generated from rule tables.
All data is synthetic and stays in temporary case storage.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from casework import CaseError
import correlationwork
import jobwork
import recipework
import reportwork
import timelinework


SCENARIOS = {
    'vmware': ('vpxa disconnected during task synth-01', 'vcenter_host_agent',
               'vpxa connected; task synth-01 retry completed'),
    'veeam': ('failed to create vm snapshot for task synth-01', 'snapshot_failure',
              'VM snapshot created; task synth-01 retry completed'),
    'hyperv': ('live migration failed for task synth-01', 'live_migration',
               'live migration completed for task synth-01 retry'),
    'nutanix': ('foundation heartbeat timeout for task synth-01', 'foundation_heartbeat',
                'foundation heartbeat received; task synth-01 retry completed'),
    'proxmox': ('cluster not ready - no quorum for task synth-01', 'cluster_no_quorum',
                'cluster ready with quorum; task synth-01 retry completed'),
    'linux': ('start operation timed out for task synth-01', 'service_start_timeout',
              'service started; task synth-01 retry completed'),
    'storage': ('NFS server not responding for task synth-01', 'nfs_server_not_responding',
                'NFS server responding; task synth-01 retry completed'),
    'openshift': ('Velero backup failed for task synth-01', 'velero_backup_failure',
                  'Velero backup completed for task synth-01 retry'),
    'identity': ('DNS returned SERVFAIL for task synth-01', 'dns_servfail',
                 'DNS returned NOERROR for task synth-01 retry'),
}


class SyntheticDiagnosticScenarios(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.jobs = jobwork.JobStore(Path(temporary.name))
        self.store = self.jobs.cases
        self.cid = self.store.open_case()['case_id']
        self.originals = {}

    def register(self, name, text, cid=None):
        cid = self.cid if cid is None else cid
        path = self.store.inbox / name
        raw = text.encode('utf-8')
        path.write_bytes(raw)
        path.chmod(0o600)
        aid = self.store.register(cid, name)['artifact_id']
        self.originals[(cid, aid)] = hashlib.sha256(raw).hexdigest()
        return aid

    def fixed_job(self, kind, cid=None):
        submitted = self.jobs.submit(kind, self.cid if cid is None else cid)
        self.assertEqual(self.jobs.work_once()['state'], 'SUCCEEDED')
        return self.jobs.result(submitted['job_id'])

    def incident(self, family, unknown_time=False):
        failure, _, recovered = SCENARIOS[family]
        # Reverse source registration/time order to challenge chronology.
        retry = self.register('retry.txt', '2026-10-24T12:00:30Z '+recovered+'\n')
        peer = self.register('peer.txt',
            '2026-10-24T12:00:00Z unaffected peer completed independent task synth-02\n')
        stamp = 'Oct 24 12:00:10' if unknown_time else '2026-10-24T12:00:10Z'
        failed = self.register('failure.txt',
            '2026-10-24T12:00:05Z starting task synth-01\n'+stamp+' '+failure+
            ' password=synthetic-private-value\n')
        self.fixed_job('build_timeline')
        self.fixed_job('recipe_'+family)
        self.fixed_job('build_correlation')
        return failed, retry, peer

    def rehash(self):
        for (cid, aid), digest in self.originals.items():
            raw = (self.store.cases/cid/'originals'/aid).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)

    def scenario_recovery(self, family):
        failed, retry, peer = self.incident(family)
        recipe = recipework.report(self.store, self.cid, family)
        self.assertEqual([f['marker_id'] for f in recipe['findings']], [SCENARIOS[family][1]])
        self.assertEqual(recipe['findings'][0]['observed'], 1)
        evidence = recipe['findings'][0]['evidence']
        self.assertEqual([(e['artifact_id'], e['line_no']) for e in evidence], [(failed, 2)])
        self.assertEqual(evidence[0]['source_sha256'], self.originals[(self.cid, failed)])
        self.assertFalse(recipe['root_cause_established'])
        self.assertFalse(recipe['candidate_explanations_validated'])
        self.assertTrue(recipe['falsification_checks'])
        self.assertEqual(recipe['platform_version_support'], 'UNVERIFIED')
        query = correlationwork.correlation_query(self.store, self.cid)
        events = query['events']
        self.assertEqual(len(events), 4)
        self.assertEqual([e['artifact_id'] for e in events], [peer, failed, failed, retry])
        self.assertFalse(query['causality_inferred'])
        self.assertFalse(query['cross_source_identity_inferred'])
        self.assertEqual(query['clock_alignment'], 'UNVERIFIED')
        revision = correlationwork.correlation_summary(self.store, self.cid)['index_revision']
        report = reportwork.build(self.store, self.cid, revision)
        self.assertIn('root_cause_not_established', report['unknowns'])
        self.assertEqual({e['artifact_id'] for e in report['observations']}, {failed, retry, peer})
        public = json.dumps((recipe, query, report))
        self.assertNotIn('synthetic-private-value', public)
        self.rehash()

    def scenario_success_only(self, family):
        self.register('success.txt', '2026-10-24T12:00:30Z '+SCENARIOS[family][2]+'\n')
        self.fixed_job('build_timeline')
        self.fixed_job('recipe_'+family)
        recipe = recipework.report(self.store, self.cid, family)
        self.assertEqual(recipe['findings'], [])
        self.assertEqual(recipe['status'], 'PARTIAL')
        self.assertTrue(recipe['no_markers_does_not_mean_healthy'])
        self.assertFalse(recipe['root_cause_established'])
        self.rehash()

    def scenario_case_isolation(self, family):
        self.incident(family)
        other = self.store.open_case()['case_id']
        self.register('other.txt', '2026-10-24T12:01:00Z independent task completed\n', other)
        self.fixed_job('build_timeline', other)
        self.fixed_job('recipe_'+family, other)
        self.assertEqual(recipework.report(self.store, other, family)['findings'], [])
        self.assertEqual(recipework.report(self.store, self.cid, family)['markers_found'], 1)
        self.rehash()

    def scenario_version_mismatch(self, family):
        self.incident(family)
        aid = self.register('version.json', json.dumps({
            'schema': 1, 'family': family, 'product': 'synthetic-service',
            'version': '1.0', 'recipe_sha256': recipework.recipe_digest(family)}))
        # New input requires refreshing both indexes before testing identity gates.
        self.fixed_job('build_timeline')
        self.fixed_job('recipe_'+family)
        result = recipework.report(self.store, self.cid, family, product='synthetic-service',
                                   platform_version='2.0', version_artifact_id=aid)
        self.assertEqual(result['status'], 'NOT_APPLICABLE_TO_REQUESTED_DECLARATION')
        self.assertNotIn('findings', result)
        self.assertFalse(result['version_applicability']['vendor_compatibility_verified'])
        matched = recipework.report(self.store, self.cid, family, product='synthetic-service',
                                    platform_version='1.0', version_artifact_id=aid)
        self.assertEqual(matched['version_applicability']['status'],
                         'DECLARATION_MATCH_COMPATIBILITY_UNVERIFIED')
        self.assertFalse(matched['root_cause_established'])
        self.rehash()

    def scenario_stale_after_peer_added(self, family):
        self.incident(family)
        self.register('late-peer.txt', '2026-10-24T12:00:12Z peer retry completed\n')
        with self.assertRaises(CaseError):
            recipework.report(self.store, self.cid, family)
        with self.assertRaises(CaseError):
            correlationwork.correlation_query(self.store, self.cid)
        self.fixed_job('build_timeline')
        with self.assertRaisesRegex(CaseError, 'stale'):
            recipework.report(self.store, self.cid, family)
        self.fixed_job('recipe_'+family)
        self.assertEqual(recipework.report(self.store, self.cid, family)['markers_found'], 1)
        self.rehash()

    def scenario_unknown_failure_time(self, family):
        failed, _, _ = self.incident(family, unknown_time=True)
        recipe = recipework.report(self.store, self.cid, family)
        self.assertFalse(recipe['scan_complete'])
        self.assertEqual(recipe['status'], 'PARTIAL')
        query = correlationwork.correlation_query(self.store, self.cid, include_unknown=True)
        self.assertEqual(len(query['events']), 4)
        self.assertIsNone(query['events'][-1]['utc'])
        self.assertEqual(query['events'][-1]['artifact_id'], failed)
        self.assertFalse(query['causality_inferred'])
        self.assertEqual(query['clock_alignment'], 'UNVERIFIED')
        self.rehash()


def install_test(family, scenario):
    def test(self):
        getattr(self, 'scenario_'+scenario)(family)
    test.__name__ = 'test_'+family+'_'+scenario
    test.__doc__ = family+' synthetic '+scenario.replace('_', ' ')
    setattr(SyntheticDiagnosticScenarios, test.__name__, test)


for _family in SCENARIOS:
    for _scenario in ('recovery', 'success_only', 'case_isolation', 'version_mismatch',
                      'stale_after_peer_added', 'unknown_failure_time'):
        install_test(_family, _scenario)


if __name__ == '__main__':
    unittest.main()
