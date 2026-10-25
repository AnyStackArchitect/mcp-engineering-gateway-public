#!/usr/bin/env python3
"""Real native providers inside exact rootless policy; synthetic inputs only."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from casework import CaseStore
from podman_policy import container_run_command,container_exec_command,container_remove_command
from providerplans import plan,checked_result
from outputcopy import copy_outputs

PROBES={
    'git_bundle':('/usr/bin/git',['--version'],r'git version ([0-9][\w.+!-]*)'),
    'ansible_syntax':('/usr/bin/ansible-playbook',['--version'],r'\[core ([0-9][\w.+!-]*)\]'),
    'tsk_fsstat':('/usr/bin/fsstat',['-V'],r'ver\s+([0-9][\w.+!-]*)'),
    'volatility_banners':('/usr/local/bin/vol',['-h'],r'Volatility 3 Framework ([0-9][\w.+!-]*)'),
    'xfs_geometry':('/usr/sbin/xfs_db',['-V'],r'version ([0-9][\w.+!-]*)'),
    'xfs_repair_check':('/usr/sbin/xfs_repair',['-V'],r'version ([0-9][\w.+!-]*)'),
    'xfs_recovery_experiment':('/usr/sbin/xfs_repair',['-V'],r'version ([0-9][\w.+!-]*)'),
}


def checked(argv,timeout=100,env=None):
    process=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,env=env)
    if process.returncode:raise RuntimeError('Synthetic provider qualification command failed: '+Path(argv[0]).name)
    return process.stdout+process.stderr


def main():
    if os.geteuid()==0 or len(sys.argv)!=2:raise RuntimeError('Run unprivileged with immutable CI image ref')
    image=sys.argv[1]
    if not re.fullmatch(r'localhost/rocky-ci-sandbox@sha256:[a-f0-9]{64}',image):
        raise RuntimeError('Only immutable local disposable CI image accepted')
    versions={}
    for provider,(exe,args,pattern) in PROBES.items():
        output=checked(['/usr/bin/podman','run','--rm','--network=none','--read-only',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=16m','--env','HOME=/tmp','--entrypoint',exe,image,*args])
        match=re.search(pattern,output.decode(errors='replace'),re.I)
        if not match:raise RuntimeError('Actual provider version unreadable: '+provider)
        versions[provider]=match.group(1)
    if versions['volatility_banners']!='2.28.2':raise RuntimeError('Hash-pinned Volatility version mismatch')
    with tempfile.TemporaryDirectory(prefix='eng-provider-real-') as directory:
        root=Path(directory);home=root/'home';home.mkdir(mode=0o700)
        store=CaseStore(home);cid=store.open_case()['case_id']
        repository=root/'synthetic-repo'
        env=os.environ|{'HOME':str(home),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
        checked(['/usr/bin/git','init','-b','fixture',str(repository)],env=env)
        (repository/'synthetic.txt').write_text('controlled fixture\n')
        checked(['/usr/bin/git','-C',str(repository),'add','synthetic.txt'],env=env)
        checked(['/usr/bin/git','-C',str(repository),'-c','user.name=Synthetic CI Fixture',
            '-c','user.email=fixture@example.invalid','-c','core.hooksPath=/nonexistent',
            'commit','-m','synthetic fixture'],env=env)
        bundle=store.inbox/'synthetic.bundle'
        checked(['/usr/bin/git','-C',str(repository),'bundle','create',str(bundle),'--all'],env=env)
        commit=checked(['/usr/bin/git','-C',str(repository),'rev-parse','HEAD'],env=env).strip()
        refs=b''.join(b'create refs/heads/synthetic-'+str(number).zfill(5).encode()+b' '+commit+b'\n' for number in range(2000))
        subprocess.run(['/usr/bin/git','-C',str(repository),'update-ref','--stdin'],input=refs,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,check=True,timeout=20)
        large_bundle=store.inbox/'many-heads.bundle'
        checked(['/usr/bin/git','-C',str(repository),'bundle','create',str(large_bundle),'--all'],env=env)
        playbook=store.inbox/'synthetic.yml'
        playbook.write_text('- hosts: all\n  gather_facts: false\n  tasks:\n    - name: Synthetic debug task\n      ansible.builtin.debug:\n        msg: controlled fixture\n')
        memory=store.inbox/'synthetic-memory.bin'
        memory.write_bytes(b'\x00'*256+b'Linux version 6.8.0-synthetic (fixture@invalid) (gcc version 12.2.0) #1 SMP Thu Oct 15 00:00:00 UTC 2026\n\x00'+b'\x00'*4096)
        filesystems=[]
        for kind in ('ext2','ext3','ext4'):
            path=store.inbox/('synthetic-'+kind+'.img')
            with path.open('wb') as stream:stream.truncate(16*1024*1024)
            checked(['/usr/sbin/mkfs.'+kind,'-F','-q',str(path)])
            filesystems.append(path)
        invalid=store.inbox/'invalid.yml';invalid.write_text('- hosts: [unterminated\n')
        reject=store.inbox/'not-a-filesystem.bin';reject.write_bytes(b'\x00not a filesystem\n')
        empty_memory=store.inbox/'no-banner.bin';empty_memory.write_bytes(b'\x00'*4096)
        xfs=store.inbox/'synthetic-xfs.img'
        with xfs.open('wb') as stream:stream.truncate(320*1024*1024)
        checked(['/usr/sbin/mkfs.xfs','-f','-b','size=4096','-d','agcount=4',str(xfs)])
        vectors=[('git_bundle',bundle,'PASS'),('ansible_syntax',playbook,'PASS'),
            ('tsk_fsstat',filesystems[0],'PASS'),('tsk_fsstat',filesystems[1],'PASS'),('tsk_fsstat',filesystems[2],'PASS'),
            ('volatility_banners',memory,'PARTIAL'),('volatility_banners',empty_memory,'PARTIAL'),('ansible_syntax',invalid,'REJECTED_INPUT'),
            ('tsk_fsstat',reject,'REJECTED_INPUT'),('git_bundle',bundle,'NOT_AVAILABLE_VERSION_MISMATCH'),
            ('xfs_geometry',xfs,'PASS'),('xfs_repair_check',xfs,'PARTIAL'),
            ('xfs_geometry',reject,'REJECTED_INPUT'),('xfs_repair_check',reject,'REJECTED_INPUT'),
            ('git_bundle',large_bundle,'LIMIT_EXCEEDED'),
            ('xfs_recovery_experiment',xfs,'PARTIAL'),('xfs_recovery_experiment',reject,'REJECTED_INPUT')]
        registered={}
        summaries=[]
        for number,(provider,source,status) in enumerate(vectors):
            if source not in registered:
                source.chmod(0o600)
                registered[source]=store.register(cid,source.name,worker=True)['artifact_id']
            aid=registered[source]
            expected=versions[provider] if status!='NOT_AVAILABLE_VERSION_MISMATCH' else '0.0.0'
            prepared=plan(store,cid,aid,provider,expected)
            args=prepared['execution_prepare_arguments']
            execution={'id':secrets.token_hex(16),'image':image,'memory_mib':args['memory_mib'],'disk_mib':args['disk_mib'],'output_names':args['output_names']}
            ro=root/('readonly-'+str(number));ro.mkdir(mode=0o700)
            original=store.cases/cid/'originals'/aid
            shutil.copyfile(original,ro/aid);(ro/aid).chmod(0o400)
            (ro/'program.py').write_text(args['script']);(ro/'program.py').chmod(0o400)
            outputs=root/('outputs-'+str(number));outputs.mkdir(mode=0o700)
            try:
                checked(container_run_command(execution,ro),timeout=35)
                checked(container_exec_command(execution['id']),timeout=170)
                copy_outputs(store,execution,outputs)
                data=json.loads((outputs/'provider-result.json').read_text())
                checked_result(data,{'provider':provider,'source_sha256':prepared['source_sha256'],'expected_version':expected})
                if data['status']!=status:
                    raise RuntimeError('Actual provider status differs: '+provider+' expected '+status+' got '+data['status'])
                if hashlib.sha256((outputs/'provider-raw.txt').read_bytes()).hexdigest()!=data['private_raw_output_sha256']:
                    raise RuntimeError('Private provider output digest mismatch')
                hasher=hashlib.sha256()
                with original.open('rb') as stream:
                    for block in iter(lambda:stream.read(1024*1024),b''):hasher.update(block)
                if hasher.hexdigest()!=prepared['source_sha256']:
                    raise RuntimeError('Original source changed during isolated analysis')
                if provider=='volatility_banners' and (data['metrics']['banner_count']!=(1 if source==memory else 0) or
                        data['metrics']['offsets']!=([256] if source==memory else [])):
                    raise RuntimeError('Volatility synthetic banner known answer mismatch')
                if provider=='tsk_fsstat' and status=='PASS' and data['metrics']['filesystem']!=source.stem.split('-')[-1]:
                    raise RuntimeError('Native filesystem known answer mismatch')
                if provider=='xfs_geometry' and status=='PASS' and data['metrics']!={'magic_number':0x58465342,'block_size':4096,'data_blocks':81920,'allocation_groups':4}:
                    raise RuntimeError('Native XFS geometry known answer mismatch')
                if provider=='xfs_recovery_experiment' and status=='PARTIAL' and (data['metrics']['fault_detection_exit_code']!=1 or data['metrics']['copy_repair_exit_code']!=0 or data['metrics']['post_repair_check_exit_code']!=0 or not data['metrics']['original_unchanged']):
                    raise RuntimeError('Native disposable XFS experiment failed known transitions')
                summaries.append({'provider':provider,'status':status,'version':data['observed_version'],
                    'entrypoint_sha256':data['entrypoint_sha256'],'metrics':data['metrics']})
            finally:checked(container_remove_command(execution['id']),timeout=30)
        print(json.dumps({'status':'OFF_HOST_FIXED_PROVIDER_QUALIFICATION_PASS','image':image,
            'cases':summaries,'production_image_approved':False,'windows_memory_os_validated':False,
            'rocky_xfs_rea_qualified':False},sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
