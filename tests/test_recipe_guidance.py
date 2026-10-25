"""Known engineering markers are source-linked leads with falsification checks."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import casework
import gateway
import jobwork
import recipework
import timelinework


VECTORS = {
    'proxmox': (
        'cluster not ready - no quorum; Corosync token retransmit timeout; migration failed',
        {'cluster_no_quorum', 'corosync_token_timeout', 'migration_failure'}),
    'linux': (
        'Quadlet generator failed; pull image failed; start operation timed out; memory cgroup out of memory',
        {'quadlet_generator', 'container_image_pull', 'service_start_timeout', 'cgroup_memory_kill'}),
    'storage': (
        'XFS metadata corruption detected; multipath path failed; NFS server not responding; iSCSI connection failed',
        {'xfs_metadata_corruption', 'multipath_path_failure', 'nfs_server_not_responding', 'iscsi_connection_failure'}),
    'openshift': (
        'Velero backup failed; Kasten action failed; snapshot CSI operation failed',
        {'velero_backup_failure', 'kasten_action_failure', 'csi_snapshot_failure'}),
    'identity': (
        'KRB_AP_ERR_MODIFIED; KRB_AP_ERR_SKEW; DNS returned SERVFAIL; domain controller could not be contacted',
        {'kerberos_ticket_modified', 'kerberos_clock_skew', 'dns_servfail', 'domain_controller_unavailable'}),
}


class RecipeGuidanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.store = casework.CaseStore(self.home)
        self.cid = self.store.open_case()['case_id']

    def build(self, text):
        source = self.store.inbox/'synthetic.log'
        source.write_text('2026-10-18T01:02:03Z ' + text + '\n')
        source.chmod(0o600)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        aid = self.store.register(self.cid,source.name)['artifact_id']
        timelinework.build_timeline(self.store,self.cid)
        return aid,digest

    def test_five_new_family_known_answers_and_source_identity(self):
        aid,digest = self.build(' '.join(v[0] for v in VECTORS.values()))
        # Text previews are bounded; keep each family in a separate short source.
        # The initial combined preview must not be mistaken for complete coverage.
        first = recipework.evaluate(self.store,self.cid,'identity')
        self.assertFalse(first['scan_complete'])
        for number,(family,(text,expected)) in enumerate(VECTORS.items()):
            source = self.store.inbox/f'part{number}.log'
            source.write_text('2026-10-18T01:03:00Z '+text+' password=private-value\n')
            source.chmod(0o600)
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            source_id = self.store.register(self.cid,source.name)['artifact_id']
            timelinework.build_timeline(self.store,self.cid)
            report = recipework.evaluate(self.store,self.cid,family)
            self.assertEqual({f['marker_id'] for f in report['findings']},expected)
            self.assertEqual(report['status'],'PARTIAL')
            self.assertFalse(report['candidate_explanations_validated'])
            self.assertEqual(report['platform_version_support'],'UNVERIFIED')
            self.assertTrue(report['falsification_checks'])
            self.assertTrue(report['required_evidence'])
            self.assertEqual(report['recipe_sha256'],recipework.recipe_digest(family))
            for finding in report['findings']:
                self.assertTrue(any(e['artifact_id']==source_id and
                    e['source_sha256']==source_hash and e['line_no']==1 for e in finding['evidence']))
            self.assertNotIn('private-value',json.dumps(report))

    def test_benign_sources_do_not_produce_markers_or_health_verdict(self):
        self.build('startup completed and normal session ended')
        for family in recipework.FAMILIES:
            report = recipework.evaluate(self.store,self.cid,family)
            self.assertEqual(report['findings'],[])
            self.assertTrue(report['scan_complete'])
            self.assertEqual(report['status'],'PARTIAL')
            self.assertTrue(report['no_markers_does_not_mean_healthy'])

    def test_catalog_job_and_gateway_schemas_share_fixed_family_set(self):
        data = recipework.catalog()
        self.assertEqual(len(data['families']),9)
        self.assertLess(len(json.dumps(data)),gateway.MAX_RESPONSE_TEXT)
        self.assertTrue(all('recipe_'+family in jobwork.TEMPLATES for family in recipework.FAMILIES))
        gw = gateway.Gateway(gateway.Config({},(),self.home))
        spec = next(t for t in gw.tools() if t['name']=='diagnostic_report')
        self.assertEqual(set(spec['inputSchema']['properties']['family']['enum']),set(recipework.FAMILIES))
        for invalid in (None,True,[],{},'../../host'):
            with self.subTest(invalid=invalid),self.assertRaises(casework.CaseError):
                recipework.evaluate(self.store,self.cid,invalid)

    def test_report_recipe_identity_mismatch_requires_rebuild(self):
        self.build('Quadlet generator failed')
        recipework.evaluate(self.store,self.cid,'linux')
        path=self.store.cases/self.cid/'indexes/recipe-linux.json'
        report=json.loads(path.read_text())
        report['recipe_sha256']='0'*64
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(casework.CaseError,'version'):
            recipework.report(self.store,self.cid,'linux')
