"""Fixed plan/result boundaries; successful-state fixtures are synthetic only."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import casework
import gateway
import outputwork
import providerplans
import sandboxwork


class ProviderPlanTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.home=Path(temporary.name)
        config=self.home/'.config/rocky-mcp-gateway';config.mkdir(parents=True,mode=0o700)
        image=config/'sandbox-image.txt';image.write_text('localhost/test@sha256:'+'a'*64+'\n');image.chmod(0o600)
        self.executions=sandboxwork.ExecutionStore(self.home)
        self.store=self.executions.cases;self.cid=self.store.open_case()['case_id']
        source=self.store.inbox/'fixture.bin';source.write_bytes(b'\x00synthetic source\n');source.chmod(0o600)
        self.aid=self.store.register(self.cid,source.name)['artifact_id']
        self.sha=hashlib.sha256(source.read_bytes()).hexdigest()
        self.config={'provider':'git_bundle','source_sha256':self.sha,'expected_version':'2.43.0'}

    def script(self):return providerplans.script_for(**self.config)

    def plan(self,provider='git_bundle'):
        if provider=='windows_memory_info':return providerplans.plan(self.store,self.cid,self.aid,provider,'2.28.2','c'*64)
        return providerplans.plan(self.store,self.cid,self.aid,provider,'2.43.0')

    def payload(self):
        return {'schema':1,**self.config,'observed_version':'2.43.0','entrypoint_sha256':'b'*64,
            'status':'PASS','exit_code':0,'metrics':{'head_count':1},'root_cause_established':False,
            'raw_output_disclosed':False,'private_raw_output_sha256':hashlib.sha256(b'private principal secret=hidden').hexdigest()}

    def completed_fixture(self,*,script=None,payload=None):
        plan=self.executions.prepare(self.cid,self.script() if script is None else script,[self.aid],
            ['provider-result.json','provider-raw.txt'],timeout_seconds=180)
        details,_=self.executions.inspect_local(plan['execution_id'])
        output=self.home/'synthetic-output';output.mkdir(mode=0o700,exist_ok=True)
        (output/'provider-raw.txt').write_bytes(b'private principal secret=hidden')
        (output/'provider-result.json').write_text(json.dumps(self.payload() if payload is None else payload))
        for source in output.iterdir():source.chmod(0o600)
        outputs=outputwork.register_outputs(self.store,self.cid,plan['execution_id'],plan['plan_sha256'],
            details['plan']['inputs'],output,details['plan']['output_names'],32)
        # Direct state injection is a unit fixture, not signed-job qualification.
        with self.executions._db() as db:
            db.execute("UPDATE plans SET state='SUCCEEDED',result_json=? WHERE id=?",
                (json.dumps({'status':'PASS','outputs':sorted(outputs,key=lambda v:v['name'])}),plan['execution_id']))
            db.commit()
        return plan,outputs

    def test_fixed_source_version_plan_requires_existing_signed_workflow(self):
        for provider in providerplans.PROVIDERS:
            with self.subTest(provider=provider):
                plan=self.plan(provider)
                self.assertEqual(plan['status'],'PLAN_ONLY_REQUIRES_SIGNED_OPERATOR_GRANT')
                args=plan['execution_prepare_arguments']
                self.assertEqual(args['artifact_ids'],[self.aid])
                self.assertLessEqual(args['memory_mib'],1536)
                self.assertEqual(providerplans.checked_script(args['script'])['source_sha256'],self.sha)
                self.assertLess(len(json.dumps(plan)),gateway.MAX_RESPONSE_TEXT)
        self.assertEqual(self.store.status(self.cid)['artifact_count'],1)

    def test_controls_unknown_provider_and_template_mutations_refused(self):
        for change in ({'provider':'shell'},{'provider':[]},{'expected_version':'2; whoami'},
                       {'source_sha256':'../../case'}):
            with self.subTest(change=change),self.assertRaises(casework.CaseError):
                providerplans.script_for(**(self.config|change))
        with self.assertRaises(casework.CaseError):providerplans.checked_script(self.script()+"print('extra')\n")
        with self.assertRaises(casework.CaseError):providerplans.checked_script('CONFIG = __import__("os")\n')

    def test_oversize_policy_refusal_does_not_fresh_hash_or_prepare(self):
        with patch.object(providerplans,'MAX_INPUT_BYTES',1):result=self.plan()
        self.assertEqual(result['status'],'NOT_AVAILABLE_RESOURCE_POLICY')
        self.assertFalse(result['plan_created'])
        self.assertNotIn('execution_prepare_arguments',result)
        self.assertIn('not_freshly_rehashed',result['source_hash_basis'])

    def test_source_change_and_shared_capacity_refusal(self):
        with patch.object(providerplans,'verify_committed_reserve',side_effect=casework.CaseError('reserved')):
            with self.assertRaises(casework.CaseError):self.plan()
        path=self.store.cases/self.cid/'originals'/self.aid;path.write_bytes(b'changed')
        with self.assertRaises(casework.CaseError):self.plan()

    def test_completed_fixed_result_preserves_identity_without_private_text(self):
        plan,outputs=self.completed_fixture()
        result=providerplans.read_result(self.executions,plan['execution_id'])
        self.assertEqual(result['provider_result']['metrics'],{'head_count':1})
        self.assertEqual(result['plan_sha256'],plan['plan_sha256'])
        self.assertEqual(result['status'],'PARTIAL')
        self.assertNotIn('principal',json.dumps(result));self.assertNotIn('hidden',json.dumps(result))

    def test_arbitrary_script_and_not_completed_jobs_never_bless_output(self):
        plan=self.executions.prepare(self.cid,self.script(),[self.aid],['provider-result.json','provider-raw.txt'])
        result=providerplans.read_result(self.executions,plan['execution_id'])
        self.assertEqual(result['status'],'NOT_AVAILABLE')
        plan,_=self.completed_fixture(script="print('arbitrary approved code')\n")
        with self.assertRaises(casework.CaseError):providerplans.read_result(self.executions,plan['execution_id'])

    def test_raw_artifact_change_and_output_lineage_corruption_rejected(self):
        plan,outputs=self.completed_fixture()
        raw=next(v for v in outputs if v['name']=='provider-raw.txt')
        path=self.store.cases/self.cid/'originals'/raw['artifact_id']
        path.write_bytes(b'changed')
        with self.assertRaises(casework.CaseError):providerplans.read_result(self.executions,plan['execution_id'])

    def test_result_schema_cannot_overstate_versions_or_return_arbitrary_prose(self):
        for change in ({'observed_version':'9.0'},{'exit_code':1},{'root_cause_established':True},
            {'raw_output_disclosed':True},{'metrics':{'head_count':'private-user'}},
            {'metrics':{'source_text':'secret'}},{'status':[]}):
            with self.subTest(change=change),self.assertRaises(casework.CaseError):
                providerplans.checked_result(self.payload()|change,self.config)

    def test_memory_banner_result_never_claims_validated_os_or_full_analysis(self):
        config=self.config|{'provider':'volatility_banners'}
        payload=self.payload()|config|{'status':'PARTIAL','metrics':{
            'banner_count':1,'offsets':[256],'offsets_omitted':0,'memory_os_validated':False}}
        self.assertEqual(providerplans.checked_result(payload,config),payload)
        for change in ({'status':'PASS'},{'metrics':payload['metrics']|{'memory_os_validated':True}},
                       {'metrics':payload['metrics']|{'banner_count':2}}):
            with self.subTest(change=change),self.assertRaises(casework.CaseError):
                providerplans.checked_result(payload|change,config)

    def test_xfs_metadata_and_dry_run_cannot_claim_repair(self):
        config=self.config|{'provider':'xfs_geometry'}
        metrics={'magic_number':0x58465342,'block_size':4096,'data_blocks':81920,'allocation_groups':4}
        payload=self.payload()|config|{'metrics':metrics}
        self.assertEqual(providerplans.checked_result(payload,config)['metrics'],metrics)
        for change in ({'magic_number':0},{'block_size':3},{'data_blocks':0},{'allocation_groups':0},{'filename':'private'}):
            with self.subTest(change=change),self.assertRaises(casework.CaseError):
                providerplans.checked_result(payload|{'metrics':metrics|change},config)
        config=self.config|{'provider':'xfs_repair_check'}
        metrics={'readonly_check_completed':True,'modifications_requested':False,'filesystem_repaired':False}
        payload=self.payload()|config|{'status':'PARTIAL','metrics':metrics}
        providerplans.checked_result(payload,config)
        for change in ({'status':'PASS'},{'metrics':metrics|{'filesystem_repaired':True}},{'metrics':metrics|{'modifications_requested':True}}):
            with self.subTest(change=change),self.assertRaises(casework.CaseError):
                providerplans.checked_result(payload|change,config)

    def test_tsk_address_ranges_do_not_claim_actual_inode_count(self):
        config=self.config|{'provider':'tsk_fsstat'}
        payload=self.payload()|config|{'metrics':{'filesystem':'ext4','inode_address_range_count':4097}}
        providerplans.checked_result(payload,config)
        with self.assertRaises(casework.CaseError):
            providerplans.checked_result(payload|{'metrics':{'filesystem':'ext4','inode_count':4097}},config)

    def test_catalog_explicit_provider_input_tiers(self):
        catalog=providerplans.catalog()
        self.assertEqual(catalog['source_limit_bytes'],4*1024**3)
        for item in catalog['providers']:
            expected=4096 if item['provider']=='windows_memory_info' else 352 if item['provider']=='xfs_recovery_experiment' else 512 if item['provider'].startswith('xfs_') else 64
            self.assertEqual(item['maximum_source_bytes'],expected*1024**2)

    def test_banner_offsets_must_fit_the_approved_artifact(self):
        self.config=self.config|{'provider':'volatility_banners'}
        payload=self.payload()|{'status':'PARTIAL','metrics':{'banner_count':1,'offsets':[256],'offsets_omitted':0,'memory_os_validated':False}}
        plan,_=self.completed_fixture(payload=payload)
        with self.assertRaises(casework.CaseError):providerplans.read_result(self.executions,plan['execution_id'])
