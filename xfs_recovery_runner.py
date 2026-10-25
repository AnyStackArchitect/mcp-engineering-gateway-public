"""Fixed disposable-copy fault/recovery experiment; never a volume repair API."""
import hashlib,json,os
from pathlib import Path
import re,resource,selectors,signal,subprocess,time


def file_hash(path):
    sha=hashlib.sha256();size=0
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            size+=len(block)
            if size>512*1024**2:raise RuntimeError('source_limit')
            sha.update(block)
    return sha.hexdigest()


def run(config):
    output=Path('/output');workspace=Path('/workspace');working=output/'experiment-working.img';raw=bytearray()
    result={'schema':1,'provider':config['provider'],'source_sha256':config['source_sha256'],
        'expected_version':config['expected_version'],'observed_version':None,'entrypoint_sha256':None,
        'status':'NOT_AVAILABLE','exit_code':None,'metrics':{},'root_cause_established':False,'raw_output_disclosed':False}
    def finish(status):
        working.unlink(missing_ok=True)
        result['status']=status;result['private_raw_output_sha256']=hashlib.sha256(raw).hexdigest()
        (output/'provider-raw.txt').write_bytes(raw)
        (output/'provider-result.json').write_text(json.dumps(result,sort_keys=True))
    def command(args):
        code,a,b=bounded_command(['/usr/sbin/xfs_repair',*args],
            {'PATH':'/usr/sbin:/usr/bin:/bin','HOME':'/tmp','LC_ALL':'C.UTF-8'},unlimited_file_size=True)
        if len(raw)+len(a)+len(b)>131072:raise RuntimeError('total_capture_limit')
        raw.extend(a+b);return code,a,b
    try:
        if os.geteuid()==0:finish('NOT_AVAILABLE_ISOLATION');return
        inputs=[p for p in workspace.iterdir() if p.name!='program.py']
        if len(inputs)!=1 or not re.fullmatch('[a-f0-9]{32}',inputs[0].name):finish('NOT_AVAILABLE_INPUT_LAYOUT');return
        source=inputs[0]
        if source.is_symlink() or not source.is_file() or not 4096<=source.stat().st_size<=352*1024**2:
            finish('REJECTED_INPUT');return
        if file_hash(source)!=config['source_sha256']:finish('REJECTED_SOURCE_HASH');return
        with source.open('rb') as stream:magic=stream.read(4)
        if magic!=b'XFSB':finish('REJECTED_INPUT');return
        tool=Path('/usr/sbin/xfs_repair')
        if not tool.is_file():finish('NOT_AVAILABLE');return
        result['entrypoint_sha256']=hashlib.sha256(tool.read_bytes()).hexdigest()
        code,a,b=command(['-V']);match=re.search(rb'version ([0-9][\w.+!-]*)',a+b)
        if code or not match:finish('NOT_AVAILABLE_VERSION_UNREADABLE');return
        result['observed_version']=match.group(1).decode()
        if result['observed_version']!=config['expected_version']:finish('NOT_AVAILABLE_VERSION_MISMATCH');return
        code,a,b=command(['-n','-f','-m','256',str(source)])
        if code:finish('REJECTED_INPUT');return
        fd=os.open(working,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        copied=0
        with os.fdopen(fd,'wb') as out,source.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):
                copied+=len(block)
                if copied>352*1024**2:raise RuntimeError('working_copy_limit')
                out.write(block)
        if file_hash(working)!=config['source_sha256']:finish('REJECTED_SOURCE_HASH');return
        # This intentional fault affects only the private tmpfs working copy.
        with working.open('r+b') as stream:stream.write(b'\0')
        faulted=file_hash(working)
        fault_code,a,b=command(['-n','-f','-m','256',str(working)])
        if fault_code!=1 or faulted==config['source_sha256']:finish('FAILED');return
        repair_code,a,b=command(['-f','-m','256',str(working)])
        if repair_code:finish('FAILED');return
        post_code,a,b=command(['-n','-f','-m','256',str(working)])
        with working.open('rb') as stream:restored=stream.read(4)==b'XFSB'
        unchanged=file_hash(source)==config['source_sha256']
        if post_code or not restored or not unchanged:finish('FAILED');return
        result['exit_code']=0
        result['metrics']={'original_unchanged':True,'clean_source_check_completed':True,
            'synthetic_fault_injected':True,'fault_detection_exit_code':fault_code,
            'copy_repair_exit_code':repair_code,'post_repair_check_exit_code':post_code,
            'copy_primary_magic_restored':True,'repaired_copy_sha256':file_hash(working),
            'faulted_copy_sha256':faulted,'filesystem_files_restored':False,'repair_on_original':False}
        finish('PARTIAL')
    except (subprocess.TimeoutExpired,RuntimeError):finish('LIMIT_EXCEEDED')
    except (OSError,ValueError,KeyError,TypeError):finish('FAILED')
