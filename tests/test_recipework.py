"""Evidence and safety checks for nine approved diagnostic recipe families."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import casework, recipework, timelinework, gateway, jobwork


class RecipeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home=Path(temp.name)
        self.store=casework.CaseStore(self.home)
        self.cid=self.store.open_case()['case_id']

    def add_text(self, text, name='host.log'):
        p=self.store.inbox / name
        p.write_text(text)
        p.chmod(0o600)
        return self.store.register(self.cid,name)['artifact_id']

    def build(self, text, name='host.log'):
        aid=self.add_text(text,name)
        timelinework.build_timeline(self.store,self.cid)
        return aid

    def test_catalog_covers_all_four_including_vmware_vcf(self):
        data=recipework.catalog()
        self.assertEqual({v['family'] for v in data['families']},
                         {'veeam','vmware','hyperv','nutanix','proxmox','linux','storage','openshift','identity'})
        vm=next(v for v in data['families'] if v['family']=='vmware')
        self.assertIn('VMware Cloud Foundation',vm['components'])
        self.assertFalse(data['root_cause_established'])

    def test_vmware_esxi_vcenter_snapshot_and_vcf_patterns(self):
        aid=self.build('''2026-10-15T16:01:00Z vmkernel: All Paths Down for datastore
2026-10-15T16:01:01Z hostd is not responding
2026-10-15T16:01:02Z virtual machine disks consolidation is needed
2026-10-15T16:01:03Z VCF precheck failed in lifecycle workflow
''')
        result=recipework.evaluate(self.store,self.cid,'vmware')
        self.assertEqual(result['status'],'PARTIAL')
        markers={v['marker_id'] for v in result['findings']}
        self.assertTrue({'esxi_storage_paths','esxi_hostd','snapshot_consolidation','vcf_lifecycle'} <= markers)
        self.assertFalse(result['root_cause_established'])
        self.assertEqual(result['findings'][0]['evidence'][0]['artifact_id'],aid)
        self.assertEqual(recipework.report(self.store,self.cid,'vmware')['markers_found'],len(markers))

    def test_other_three_family_markers(self):
        self.build('''2026-10-15T16:00:00Z failed to create vm snapshot
2026-10-15T16:00:01Z cluster node was removed
2026-10-15T16:00:02Z foundation heartbeat timeout
''')
        expected={'veeam':'snapshot_failure','hyperv':'cluster_node_removed','nutanix':'foundation_heartbeat'}
        for family,marker in expected.items():
            data=recipework.evaluate(self.store,self.cid,family)
            self.assertIn(marker,{x['marker_id'] for x in data['findings']})

    def test_no_match_is_not_a_health_declaration(self):
        self.build('2026-10-15T16:00:00Z healthy-looking startup\n')
        r=recipework.evaluate(self.store,self.cid,'vmware')
        self.assertEqual(r['markers_found'],0)
        self.assertTrue(r['no_markers_does_not_mean_healthy'])
        self.assertFalse(r['root_cause_established'])

    def test_unrelated_generic_precheck_failure_does_not_match_vcf(self):
        self.build('2026-10-15T16:00:00Z hyperv upgrade precheck failed\n')
        self.assertEqual(recipework.evaluate(self.store,self.cid,'vmware')['markers_found'],0)

    def test_unknown_family_rejected(self):
        self.build('2026-10-15T16:00:00Z issue\n')
        with self.assertRaises(casework.CaseError):
            recipework.evaluate(self.store,self.cid,'unknown-platform')
        with self.assertRaises(casework.CaseError):
            recipework.report(self.store,self.cid,';cat')

    def test_requires_fresh_timeline(self):
        self.add_text('2026-10-15T16:00:00Z failed to create vm snapshot\n')
        with self.assertRaisesRegex(casework.CaseError,'not built'):
            recipework.evaluate(self.store,self.cid,'veeam')

    def test_reports_become_stale_after_index_rebuild(self):
        self.build('2026-10-15T16:00:00Z vpxa disconnected\n')
        recipework.evaluate(self.store,self.cid,'vmware')
        timelinework.build_timeline(self.store,self.cid)
        with self.assertRaisesRegex(casework.CaseError,'stale'):
            recipework.report(self.store,self.cid,'vmware')

    def test_stale_source_rejected(self):
        aid=self.build('2026-10-15T16:00:00Z vpxa disconnected\n')
        recipework.evaluate(self.store,self.cid,'vmware')
        path=self.store.cases/self.cid/'originals'/aid
        os.utime(path,None)
        with self.assertRaises(casework.CaseError):
            recipework.report(self.store,self.cid,'vmware')

    def test_rollback_preserves_prior_report_on_cancel(self):
        self.build('2026-10-15T16:00:00Z vpxa disconnected\n')
        original=recipework.evaluate(self.store,self.cid,'vmware')
        def cancel():
            raise jobwork.JobCancelled('test_requested')
        with self.assertRaises(jobwork.JobCancelled):
            recipework.evaluate(self.store,self.cid,'vmware',should_cancel=cancel)
        self.assertEqual(recipework.report(self.store,self.cid,'vmware')['built_at'],original['built_at'])

    def test_unknown_time_and_truncated_preview_are_partial(self):
        self.build('Oct 15 10:01:02 vpxa disconnected\n'+
                   '2026-10-15T16:00:00Z '+('x'*450)+' vpxa disconnected\n')
        r=recipework.evaluate(self.store,self.cid,'vmware')
        self.assertEqual(r['status'],'PARTIAL')
        self.assertGreater(r['coverage']['unanchored_lines'],0)
        self.assertGreater(r['coverage']['truncated_previews'],0)

    def test_private_output_never_includes_original_excerpt(self):
        self.build('2026-10-15T16:00:00Z vpxa disconnected password=bigsecret\n')
        r=recipework.evaluate(self.store,self.cid,'vmware')
        content=json.dumps((r,recipework.report(self.store,self.cid,'vmware')))
        self.assertNotIn('bigsecret',content)
        self.assertNotIn('vpxa disconnected',content)
        self.assertIn('vcenter_host_agent',content)

    def test_symlink_report_refused(self):
        self.build('2026-10-15T16:00:00Z vpxa disconnected\n')
        target=self.home/'elsewhere'
        target.write_text('sensitive')
        (self.store.cases/self.cid/'indexes'/'recipe-vmware.json').symlink_to(target)
        with self.assertRaisesRegex(casework.CaseError,'unsafe'):
            recipework.evaluate(self.store,self.cid,'vmware')
        self.assertEqual(target.read_text(),'sensitive')

    def test_scan_limit_marks_partial(self):
        self.build('2026-10-15T16:00:00Z vmkernel all paths down\n'*5)
        with patch.object(recipework,'MAX_SCAN',2):
            data=recipework.evaluate(self.store,self.cid,'vmware')
        self.assertEqual(data['status'],'PARTIAL')
        self.assertEqual(data['events_examined'],2)
        self.assertIn('scan_cap_reached',data['limitations'])

    def test_job_flow_fixed_vmware_template(self):
        self.build('2026-10-15T16:00:00Z vpxa disconnected\n')
        worker=jobwork.JobStore(self.home)
        job=worker.submit('recipe_vmware',self.cid)
        self.assertEqual(worker.work_once()['state'],'SUCCEEDED')
        result=worker.result(job['job_id'])
        self.assertIn('vcenter_host_agent',json.dumps(result))
        with self.assertRaises(jobwork.JobError):
            worker.submit('recipe_vmware',self.cid,artifact_id='a'*32)

if __name__=='__main__': unittest.main()
