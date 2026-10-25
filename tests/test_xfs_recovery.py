"""Synthetic program mechanics; real filesystem qualification remains nativeCI."""
import copy,hashlib,json
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import providerplans,xfs_recovery_runner as runner
from casework import CaseError


class XfsExperimentTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        for name in ('output','workspace','usr/sbin'):(self.root/name).mkdir(parents=True)
        self.source=self.root/'workspace'/('a'*32);self.source.write_bytes(b'XFSB'+b'\0'*(4096-4))
        self.original=self.source.read_bytes();(self.root/'workspace/program.py').write_text('synthetic')
        (self.root/'usr/sbin/xfs_repair').write_text('synthetic')
        self.config={'provider':'xfs_recovery_experiment','source_sha256':hashlib.sha256(self.original).hexdigest(),'expected_version':'6.13.0'}

    def execute(self,*,repair_failure=False):
        def command(args,env,**kwargs):
            if '-V' in args:return 0,b'',b'xfs_repair version 6.13.0\n'
            path=Path(args[-1])
            if '-n' in args:
                with path.open('rb') as stream:valid=stream.read(4)==b'XFSB'
                return (0 if valid else 1),b'',b'private synthetic output'
            if repair_failure:return 1,b'',b'private failure'
            with path.open('r+b') as stream:stream.write(b'X')
            return 0,b'',b'private synthetic repair'
        with patch.object(runner,'Path',side_effect=lambda s:self.root/str(s).lstrip('/')),patch.object(runner,'bounded_command',create=True,side_effect=command):
            runner.run(self.config)
        result=json.loads((self.root/'output/provider-result.json').read_text());providerplans.checked_result(result,self.config)
        return result

    def test_template_is_fixed_and_experiment_is_copy_only(self):
        script=providerplans.script_for(**self.config)
        self.assertEqual(providerplans.checked_script(script),self.config);self.assertLess(len(script),providerplans.MAX_SCRIPT)
        self.assertIn('synthetic_fault_injected',script)
        with self.assertRaises(CaseError):providerplans.checked_script(script+'\nprint(1)')

    def test_fault_detected_repair_rechecked_copy_removed_original_unchanged(self):
        result=self.execute();self.assertEqual(result['status'],'PARTIAL')
        self.assertEqual(result['metrics']['fault_detection_exit_code'],1)
        self.assertTrue(result['metrics']['copy_primary_magic_restored']);self.assertFalse(result['metrics']['repair_on_original'])
        self.assertFalse(result['metrics']['filesystem_files_restored'])
        self.assertEqual(self.source.read_bytes(),self.original)
        self.assertEqual({p.name for p in (self.root/'output').iterdir()},{'provider-result.json','provider-raw.txt'})
        self.assertNotIn('private synthetic',json.dumps(result))

    def test_failed_repair_still_removes_working_copy_and_cannot_succeed(self):
        result=self.execute(repair_failure=True);self.assertEqual(result['status'],'FAILED')
        self.assertEqual(self.source.read_bytes(),self.original);self.assertFalse((self.root/'output/experiment-working.img').exists())

    def test_invalid_or_changed_original_refused(self):
        self.source.write_bytes(b'invalid'+b'\0'*4096)
        result=self.execute();self.assertEqual(result['status'],'REJECTED_SOURCE_HASH')
        self.config['source_sha256']=hashlib.sha256(self.source.read_bytes()).hexdigest()
        result=self.execute();self.assertEqual(result['status'],'REJECTED_INPUT')

    def test_provider_reader_rejects_original_repair_and_file_recovery_claim(self):
        result=self.execute()
        for key,value in [('repair_on_original',True),('filesystem_files_restored',True),('synthetic_fault_injected',False),
            ('fault_detection_exit_code',0),('copy_repair_exit_code',1),('repaired_copy_sha256','private'),
            ('repaired_copy_sha256',result['metrics']['faulted_copy_sha256'])]:
            changed=copy.deepcopy(result);changed['metrics'][key]=value
            with self.subTest(key=key),self.assertRaises(CaseError):providerplans.checked_result(changed,self.config)

    def test_generic_scratch_upper_boundary_still_requires_signed_approval(self):
        from test_sandboxwork import ExecutionBoundaryTests
        from sandboxwork import ExecutionError
        fixture=ExecutionBoundaryTests();fixture.setUp()
        try:
            prepared=fixture.plan(disk_mib=512)
            self.assertEqual(prepared['state'],'PREPARED')
            with self.assertRaises((ExecutionError,CaseError)):fixture.plan(disk_mib=513)
        finally:fixture.doCleanups()


if __name__=='__main__':unittest.main()
