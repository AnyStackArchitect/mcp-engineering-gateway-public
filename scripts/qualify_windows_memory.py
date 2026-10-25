#!/usr/bin/env python3
"""Actual offline fixed adapter on a public Windows10x64 crash dump in CI."""
import hashlib,json,os
from pathlib import Path
import re,secrets,shutil,struct,sys,tempfile,time,resource
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from casework import CaseStore
from providerplans import plan,checked_result
from podman_policy import container_run_command,container_exec_command,container_remove_command
from outputcopy import copy_outputs
from qualify_provider_plans import checked

SYMBOLS='abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e'


def main():
    if os.geteuid()==0 or os.environ.get('GITHUB_ACTIONS')!='true' or len(sys.argv)!=3:raise RuntimeError('Hosted unprivileged fixture qualification only')
    image=sys.argv[1];source=Path(sys.argv[2])
    if not re.fullmatch(r'localhost/rocky-ci-sandbox@sha256:[a-f0-9]{64}',image):raise RuntimeError('Immutable disposable image required')
    symbol_probe=checked(['/usr/bin/podman','run','--rm','--network=none','--read-only',
        '--userns=keep-id','--user',str(os.getuid())+':'+str(os.getgid()),
        '--entrypoint','/usr/local/bin/python3',image,'-c',
        'import hashlib;from pathlib import Path;print(hashlib.sha256(Path("/opt/eng-symbols/windows.zip").read_bytes()).hexdigest())'])
    if symbol_probe.strip()!=SYMBOLS.encode():raise RuntimeError('Unprivileged image symbol-pack read/digest preflight failed')
    start=time.monotonic()
    with source.open('rb') as stream:header=stream.read(64)
    if header[:8]!=b'PAGEDU64':raise RuntimeError('Unsupported public header')
    # Independent fixed binary-header fields, not parsed from Volatility output.
    debug_major,debug_minor=struct.unpack_from('<II',header,8)
    machine,processors=struct.unpack_from('<II',header,48)
    if debug_minor!=19041 or machine!=34404 or not 1<=processors<=4096:raise RuntimeError('Public fixture header differs from chosen known format/build')
    with tempfile.TemporaryDirectory(prefix='eng-windows-memory-') as directory:
        root=Path(directory);home=root/'home';home.mkdir(mode=0o700);store=CaseStore(home);cid=store.open_case()['case_id']
        staged=store.inbox/'public-fixture.dmp';shutil.copyfile(source,staged);staged.chmod(0o600)
        aid=store.register(cid,staged.name,worker=True)['artifact_id']
        prepared=plan(store,cid,aid,'windows_memory_info','2.28.2',SYMBOLS)
        if prepared['status']!='PLAN_ONLY_REQUIRES_SIGNED_OPERATOR_GRANT':raise RuntimeError('Selected Windows fixture exceeds validated plan policy')
        args=prepared['execution_prepare_arguments']
        execution={'id':secrets.token_hex(16),'image':image,'memory_mib':args['memory_mib'],'disk_mib':args['disk_mib'],'output_names':args['output_names']}
        ro=root/'readonly';ro.mkdir(mode=0o700);original=store.cases/cid/'originals'/aid
        shutil.copyfile(original,ro/aid);(ro/aid).chmod(0o400)
        (ro/'program.py').write_text(args['script']);(ro/'program.py').chmod(0o400)
        outputs=root/'outputs';outputs.mkdir(mode=0o700)
        try:
            checked(container_run_command(execution,ro),timeout=40)
            checked(container_exec_command(execution['id']),timeout=170)
            copy_outputs(store,execution,outputs)
            data=json.loads((outputs/'provider-result.json').read_text())
            checked_result(data,{'provider':'windows_memory_info','source_sha256':prepared['source_sha256'],'expected_version':'2.28.2','symbols_sha256':SYMBOLS})
            if data['status']!='PARTIAL':
                # CI-only public fixture: emit a fixed exception-class label,
                # never traceback frames, source lines, paths or exception prose.
                private=(outputs/'provider-raw.txt').read_bytes()
                classes=('AttributeError','TypeError','ValueError','KeyError','IndexError','OSError',
                    'PermissionError','FileNotFoundError','ModuleNotFoundError','ImportError','MemoryError',
                    'OverflowError','NotImplementedError','RuntimeError','sqlite3.OperationalError',
                    'sqlite3.DatabaseError','zipfile.BadZipFile','struct.error')
                found=[kind for kind in classes if re.search(rb'(?:^|\n)'+re.escape(kind.encode())+rb':',private)]
                raise RuntimeError('Windows adapter refused selected fixture: '+data['status']+'; bounded diagnostics: '+json.dumps(data['metrics'],sort_keys=True)+'; fixed_exception_classes='+json.dumps(found))
            metrics=data['metrics']
            if metrics['kernel_debug_minor']!=debug_minor or metrics['machine_type']!=machine or metrics['processor_count']!=processors:
                raise RuntimeError('Offline kernel info disagrees with independent crash-dump header')
            if hashlib.sha256((outputs/'provider-raw.txt').read_bytes()).hexdigest()!=data['private_raw_output_sha256']:raise RuntimeError('Private output identity mismatch')
            h=hashlib.sha256()
            with original.open('rb') as stream:
                for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
            if h.hexdigest()!=prepared['source_sha256']:raise RuntimeError('Registered original changed')
            print(json.dumps({'status':'OFF_HOST_WINDOWS_MEMORY_INFO_PASS','provider_version':data['observed_version'],
                'source_bytes':prepared['source_bytes'],'source_sha256':prepared['source_sha256'],'metrics':metrics,
                'entrypoint_sha256':data['entrypoint_sha256'],'memory_mib':execution['memory_mib'],'scratch_mib':execution['disk_mib'],
                'elapsed_seconds':round(time.monotonic()-start,3),'qualifier_maxrss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                'independent_header_agreement':True,'process_or_credential_analysis_performed':False,
                'all_windows_versions_or_formats_qualified':False,'production_image_or_trust_approved':False},sort_keys=True))
        finally:checked(container_remove_command(execution['id']),timeout=30)


if __name__=='__main__':main()
