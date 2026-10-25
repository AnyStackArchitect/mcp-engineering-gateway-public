"""Fixed stdlib-only program copied into an operator-approved sandbox plan.

Never run this module directly on a host. Runtime paths are container constants.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import time

TOOLS={
    'git_bundle':('/usr/bin/git',['--version'],r'git version ([0-9][\w.+!-]*)'),
    'ansible_syntax':('/usr/bin/ansible-playbook',['--version'],r'\[core ([0-9][\w.+!-]*)\]'),
    'tsk_fsstat':('/usr/bin/fsstat',['-V'],r'ver\s+([0-9][\w.+!-]*)'),
    'volatility_banners':('/usr/local/bin/vol',['-h'],r'Volatility 3 Framework ([0-9][\w.+!-]*)'),
    'xfs_geometry':('/usr/sbin/xfs_db',['-V'],r'version ([0-9][\w.+!-]*)'),
    'xfs_repair_check':('/usr/sbin/xfs_repair',['-V'],r'version ([0-9][\w.+!-]*)'),
}


def bounded_command(argv,env,*,unlimited_file_size=False):
    def limits():
        if not unlimited_file_size:resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536))
        resource.setrlimit(resource.RLIMIT_CPU,(70,70))
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env=env,preexec_fn=limits,start_new_session=True)
    selector=selectors.DefaultSelector();buffers={}
    try:
        for pipe in (process.stdout,process.stderr):
            os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ);buffers[pipe]=bytearray()
        deadline=time.monotonic()+80
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise RuntimeError('command_timeout')
            if not (events:=selector.select(remaining)):raise RuntimeError('command_timeout')
            for key,_ in events:
                block=os.read(key.fileobj.fileno(),65536)
                if not block:selector.unregister(key.fileobj);continue
                buffers[key.fileobj].extend(block)
                if len(buffers[key.fileobj])>=65536:raise RuntimeError('capture_limit')
        code=process.wait(timeout=max(0.1,deadline-time.monotonic()))
        return code,bytes(buffers[process.stdout]),bytes(buffers[process.stderr])
    finally:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait(timeout=10);selector.close()
        for pipe in (process.stdout,process.stderr):
            if pipe is not None:pipe.close()


def run(config):
    output=Path('/output');workspace=Path('/workspace')
    result={'schema':1,'provider':config['provider'],'source_sha256':config['source_sha256'],
        'expected_version':config['expected_version'],'observed_version':None,
        'entrypoint_sha256':None,'status':'NOT_AVAILABLE','exit_code':None,'metrics':{},
        'root_cause_established':False,'raw_output_disclosed':False}
    raw=bytearray()
    def finish(status):
        result['status']=status
        result['private_raw_output_sha256']=hashlib.sha256(raw).hexdigest()
        (output/'provider-raw.txt').write_bytes(raw)
        (output/'provider-result.json').write_text(json.dumps(result,sort_keys=True))
    def command(argv):
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/tmp','LC_ALL':'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE':'1','GIT_CONFIG_NOSYSTEM':'1',
            'GIT_CONFIG_GLOBAL':'/dev/null','ANSIBLE_CONFIG':'/nonexistent',
            'ANSIBLE_LOCAL_TEMP':'/tmp/ansible','ANSIBLE_NOCOLOR':'1'}
        code,a,b=bounded_command(argv,env,unlimited_file_size=config['provider']=='xfs_repair_check')
        if len(raw)+len(a)+len(b)>131072:raise RuntimeError('total_capture_limit')
        raw.extend(a+b)
        return code,a,b
    try:
        if os.geteuid()==0:finish('NOT_AVAILABLE_ISOLATION');return
        inputs=[p for p in workspace.iterdir() if p.name!='program.py']
        if len(inputs)!=1 or not re.fullmatch('[a-f0-9]{32}',inputs[0].name):
            finish('NOT_AVAILABLE_INPUT_LAYOUT');return
        source=inputs[0]
        maximum=(512 if config['provider'].startswith('xfs_') else 64)*1024*1024
        if source.is_symlink() or not source.is_file() or source.stat().st_size>maximum:
            finish('REJECTED_INPUT');return
        hasher=hashlib.sha256()
        with source.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):hasher.update(block)
        sha=hasher.hexdigest()
        if sha!=config['source_sha256']:finish('REJECTED_SOURCE_HASH');return
        executable,probe,pattern=TOOLS[config['provider']]
        path=Path(executable)
        if not path.is_file():finish('NOT_AVAILABLE');return
        result['entrypoint_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        code,a,b=command([executable,*probe])
        match=re.search(pattern,(a+b).decode('utf-8',errors='replace'),re.I)
        if code or match is None:finish('NOT_AVAILABLE_VERSION_UNREADABLE');return
        result['observed_version']=match.group(1)
        if match.group(1)!=config['expected_version']:
            finish('NOT_AVAILABLE_VERSION_MISMATCH');return
        provider=config['provider']
        if provider=='git_bundle':
            repo='/tmp/provider-git'
            code,_,_=command([executable,'init','--bare',repo])
            if code:finish('REJECTED_INPUT');return
            code,a,b=command([executable,'-c','core.hooksPath=/nonexistent','-C',repo,'bundle','verify',str(source)])
            result['exit_code']=code
            if code:finish('REJECTED_INPUT');return
            code,a,b=command([executable,'bundle','list-heads',str(source)])
            result['exit_code']=code
            result['metrics']={'head_count':sum(bool(re.match(rb'^[a-f0-9]{40,64} ',line)) for line in a.splitlines())}
        elif provider=='ansible_syntax':
            code,a,b=command([executable,'--syntax-check','--inventory','localhost,',str(source)])
            result['exit_code']=code
            result['metrics']={'syntax_checked':code==0,'tasks_executed':False}
        elif provider=='tsk_fsstat':
            code,a,b=command([executable,'-i','raw',str(source)])
            result['exit_code']=code
            if code:finish('REJECTED_INPUT');return
            match=re.search(rb'File System Type:\s*(Ext[234])\b',a,re.I)
            if match is None:finish('NOT_AVAILABLE_UNQUALIFIED_FORMAT');return
            result['metrics']={'filesystem':match.group(1).decode().lower()}
            for name,label in [('inode_address_range_count',rb'Inode Range:'),('block_address_range_count',rb'Total Range:')]:
                item=re.search(label+rb'\s*(\d+)\s*-\s*(\d+)',a)
                if item:result['metrics'][name]=int(item.group(2))-int(item.group(1))+1
        elif provider=='xfs_geometry':
            code,a,b=command([executable,'-r','-c','sb','-c','p magicnum blocksize dblocks agcount',str(source)])
            result['exit_code']=code
            if code:finish('REJECTED_INPUT');return
            metrics={}
            for key,label in [('magic_number','magicnum'),('block_size','blocksize'),('data_blocks','dblocks'),('allocation_groups','agcount')]:
                match=re.search(rb'^'+label.encode()+rb' = (0x[a-fA-F0-9]+|[0-9]+)\s*$',a,re.M)
                if match is None:finish('REJECTED_INPUT');return
                text=match.group(1).decode();metrics[key]=int(text,16 if text.startswith('0x') else 10)
            if metrics['magic_number']!=0x58465342:finish('REJECTED_INPUT');return
            result['metrics']=metrics
        elif provider=='xfs_repair_check':
            code,a,b=command([executable,'-n','-f','-m','256',str(source)])
            result['exit_code']=code
            if code:finish('REJECTED_INPUT');return
            result['metrics']={'readonly_check_completed':True,'modifications_requested':False,'filesystem_repaired':False}
            finish('PARTIAL');return
        else:
            code,a,b=command([executable,'--offline','-q','-r','json','-f',str(source),'banners.Banners'])
            result['exit_code']=code
            if code:finish('REJECTED_INPUT');return
            rows=json.loads(a)
            if type(rows) is not list:raise ValueError('invalid_banner_result')
            offsets=[]
            for row in rows:
                value=row.get('Offset')
                if type(value) is str:value=int(value,0)
                if type(value) is not int or not 0<=value<source.stat().st_size:raise ValueError('invalid_banner_offset')
                offsets.append(value)
            result['metrics']={'banner_count':len(offsets),'offsets':offsets[:32],
                'offsets_omitted':max(0,len(offsets)-32),'memory_os_validated':False}
            finish('PARTIAL');return
        finish('PASS' if result['exit_code']==0 else 'REJECTED_INPUT')
    except (subprocess.TimeoutExpired,RuntimeError):finish('LIMIT_EXCEEDED')
    except (OSError,ValueError,KeyError,TypeError):finish('FAILED')
