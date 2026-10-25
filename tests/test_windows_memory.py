"""Structural/negative tests are not positive real Windows dump qualification."""
import copy,hashlib,json,os
from pathlib import Path
import tempfile,unittest,zipfile
from unittest.mock import patch
import providerplans,windows_memory_runner as runner
from casework import CaseError


def info_rows():
    values={'NtMajorVersion':'10','NtMinorVersion':'0','MachineType':'34404','KeNumberProcessors':'2','Is64Bit':'True',
        'Major/Minor':'15.19041','Symbols':'jar:file:/opt/eng-symbols/windows.zip!windows/ntkrnlmp.pdb/fixture.json.xz',
        'NtSystemRoot':'private-host-path-never-disclosed','SystemTime':'private-time'}
    return [{'Variable':k,'Value':v} for k,v in values.items()]


class WindowsMemoryTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        for name in ('output','workspace','opt/eng-symbols','usr/local/bin'):(self.root/name).mkdir(parents=True)
        self.source=self.root/'workspace'/('a'*32);self.source.write_bytes(b'PAGEDU64'+b'\0'*(4096-8))
        (self.root/'workspace/program.py').write_text('synthetic')
        self.symbols=self.root/'opt/eng-symbols/windows.zip'
        with zipfile.ZipFile(self.symbols,'w') as archive:archive.writestr('windows/fixture.json','{}')
        (self.root/'usr/local/bin/vol').write_text('synthetic entrypoint')
        self.config={'provider':'windows_memory_info','source_sha256':hashlib.sha256(self.source.read_bytes()).hexdigest(),
            'expected_version':'2.28.2','symbols_sha256':hashlib.sha256(self.symbols.read_bytes()).hexdigest()}

    def run_fixture(self,responses=None):
        replies=responses or [(0,b'',b'Volatility 3 Framework 2.28.2\n'),(0,json.dumps(info_rows()).encode(),b'')]
        with patch.object(runner,'Path',side_effect=lambda s:self.root/str(s).lstrip('/')),patch.object(runner,'bounded_command',create=True,side_effect=replies) as command:
            runner.run(self.config)
        result=json.loads((self.root/'output/provider-result.json').read_text())
        providerplans.checked_result(result,self.config)
        return result,command

    def test_fixed_template_binds_exact_tool_source_and_offline_pack(self):
        script=providerplans.script_for(**self.config)
        self.assertLess(len(script.encode()),providerplans.MAX_SCRIPT)
        self.assertEqual(providerplans.checked_script(script),self.config)
        self.assertIn('--offline',script);self.assertIn('windows.info.Info',script)
        self.assertNotIn('windows.hashdump',script)
        with self.assertRaises(CaseError):providerplans.checked_script(script+'\nprint(1)')
        for changes in ({'symbols_sha256':None},{'symbols_sha256':'bad'},{'expected_version':'2.29.0'}):
            with self.assertRaises(CaseError):providerplans.script_for(**(self.config|changes))

    def test_simulated_info_projection_is_numeric_attributed_partial(self):
        result,command=self.run_fixture()
        self.assertEqual(result['status'],'PARTIAL');self.assertEqual(result['metrics']['kernel_debug_minor'],19041)
        self.assertFalse(result['metrics']['process_analysis_performed']);self.assertFalse(result['root_cause_established'])
        self.assertNotIn('private-host-path',json.dumps(result));self.assertNotIn('private-time',json.dumps(result))
        args=command.call_args_list[-1][0][0];self.assertIn('--offline',args);self.assertIn('/tmp/vol-cache',args)

    def test_symbol_or_source_mismatch_refuses_before_tool(self):
        self.config['symbols_sha256']='0'*64
        result,command=self.run_fixture();self.assertEqual(result['status'],'NOT_AVAILABLE_SYMBOLS');self.assertEqual(command.call_count,0)
        self.config['source_sha256']='0'*64
        result,command=self.run_fixture();self.assertEqual(result['status'],'REJECTED_SOURCE_HASH');self.assertEqual(command.call_count,0)

    def test_unqualified_header_and_version_refused(self):
        self.source.write_bytes(b'not-dump'+b'\0'*(4096-8));self.config['source_sha256']=hashlib.sha256(self.source.read_bytes()).hexdigest()
        result,command=self.run_fixture();self.assertEqual(result['status'],'NOT_AVAILABLE_UNQUALIFIED_FORMAT');self.assertEqual(command.call_count,0)

    def test_oversize_source_refused_without_read(self):
        with self.source.open('wb') as stream:stream.truncate(4*1024**3+1)
        result,command=self.run_fixture();self.assertEqual(result['status'],'REJECTED_INPUT');self.assertEqual(command.call_count,0)

    def test_incompatible_kernel_or_unapproved_symbol_origin_refused(self):
        for key,value in [('Major/Minor','15.22621'),('Symbols','file:///unapproved/symbol.json'),('MachineType','332'),('NtMajorVersion','6'),('KeNumberProcessors','0')]:
            rows=info_rows();next(r for r in rows if r['Variable']==key)['Value']=value
            with self.subTest(key=key),self.assertRaises(ValueError):runner._metrics(rows,self.config['symbols_sha256'])

    def test_symbol_archive_bounds_and_paths_refused(self):
        for name in ('../escape.json','/absolute.json','windows\\escape.json'):
            with zipfile.ZipFile(self.symbols,'w') as archive:archive.writestr(name,'{}')
            self.assertFalse(runner._symbols(self.symbols,hashlib.sha256(self.symbols.read_bytes()).hexdigest()))

    def test_result_reader_refuses_false_success_or_raw_fields(self):
        result,command=self.run_fixture()
        for mutate in (lambda r:r.update(status='PASS'),lambda r:r['metrics'].update(process_analysis_performed=True),
            lambda r:r['metrics'].update(symbols_sha256='0'*64),lambda r:r['metrics'].update(raw_path='private')):
            changed=copy.deepcopy(result);mutate(changed)
            with self.assertRaises(CaseError):providerplans.checked_result(changed,self.config)

    def test_failed_metadata_returns_only_fixed_reason_not_exception_prose(self):
        replies=[(0,b'',b'Volatility 3 Framework 2.28.2\n'),(0,b'not JSON private-path',b'')]
        result,command=self.run_fixture(replies)
        self.assertEqual(result['status'],'FAILED')
        self.assertEqual(result['metrics'],{'failure_reason':'invalid_info_json'})
        self.assertNotIn('private-path',json.dumps(result))
        rows=[row for row in info_rows() if row['Variable']!='NtMajorVersion']
        result,command=self.run_fixture([(0,b'',b'Volatility 3 Framework 2.28.2\n'),(0,json.dumps(rows).encode(),b'')])
        self.assertEqual(result['metrics'],{'failure_reason':'missing_nt_major'})

    def test_completed_result_reader_binds_symbol_template_and_output_lineage(self):
        from test_providerplans import ProviderPlanTests
        fixture=ProviderPlanTests();fixture.setUp()
        try:
            result,command=self.run_fixture()
            config=self.config|{'source_sha256':fixture.sha}
            result['source_sha256']=fixture.sha
            private=b'private principal secret=hidden'
            result['private_raw_output_sha256']=hashlib.sha256(private).hexdigest()
            prepared,outputs=fixture.completed_fixture(script=providerplans.script_for(**config),payload=result)
            read=providerplans.read_result(fixture.executions,prepared['execution_id'])
            self.assertEqual(read['provider_result']['metrics']['symbols_sha256'],self.config['symbols_sha256'])
            self.assertNotIn('private principal',json.dumps(read))
        finally:fixture.doCleanups()

    def test_fixed_cache_storage_and_failed_child_diagnostics_are_bounded(self):
        result,command=self.run_fixture()
        self.assertTrue(command.call_args.kwargs['unlimited_file_size'])
        self.assertTrue((self.root/'tmp/vol-cache').is_dir())
        self.assertEqual((self.root/'tmp/vol-cache').stat().st_mode&0o777,0o700)
        for message,reason in [(b'sqlite3.OperationalError: database or disk is full private-path','tool_cache_full'),
                (b'Permission denied private-path','tool_permission_refused'),(b'unknown private-path','tool_exit_unspecified')]:
            result,command=self.run_fixture([(0,b'',b'Volatility 3 Framework 2.28.2\n'),(1,b'',message)])
            self.assertEqual(result['status'],'FAILED');self.assertEqual(result['metrics'],{'failure_reason':reason})
            self.assertNotIn('private-path',json.dumps(result))


if __name__=='__main__':unittest.main()
