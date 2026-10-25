"""Experimental explicit image/public-trust enrollment and worker activation.

Requires a verified disabled preparation and separately approved exact input
digests. Never generates a key, copies SSH credentials or signs a decision.
Failure disables the worker and preserves trust, image and execution state.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import native_prepare as prepare


def public_identity(data):
    """Accept only a canonical Ed25519 SPKI, never private signing material."""
    lines = data.decode('ascii').splitlines()
    prepare.require(len(lines) >= 3 and lines[0] == '-----BEGIN PUBLIC KEY-----' and
                    lines[-1] == '-----END PUBLIC KEY-----', 'public_key_only')
    der = base64.b64decode(''.join(lines[1:-1]), validate=True)
    prepare.require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100'), 'ed25519_spki')
    return prepare.sha(der)


def store(state, record):
    pending = state/'activation.pending'
    with pending.open('x',encoding='utf8') as stream:
        stream.write(json.dumps(record,sort_keys=True,indent=2)+'\n')
        stream.flush(); os.fsync(stream.fileno())
    os.replace(pending,state/'activation.json')


class Activation:
    def __init__(self,state,record,worker):
        self.state,self.record,self.worker=state,record,worker

    def command(self,args,*,stdin=None,accepted=(0,)):
        result=subprocess.run(args,stdin=stdin or subprocess.DEVNULL,capture_output=True,timeout=240,cwd='/')
        number=len(list(self.state.glob('activate-command-*.json')))
        (self.state/('activate-command-%03d.json'%number)).write_text(json.dumps({
            'argv':args,'exit_code':result.returncode,'stdout':result.stdout.decode('utf8',errors='replace'),
            'stderr':result.stderr.decode('utf8',errors='replace')},indent=2)+'\n')
        prepare.require(result.returncode in accepted,'activation_command_failed_'+str(number))
        return result.stdout

    def user(self,args,**kwargs):
        worker=self.worker
        return self.command(['/usr/sbin/runuser','-u',worker['name'],'--','/usr/bin/env','-i',
            'HOME='+worker['home'],'PATH=/usr/bin:/bin','LANG=C.UTF-8',
            'XDG_RUNTIME_DIR=/run/user/'+str(worker['uid']),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(worker['uid'])+'/bus',*args],**kwargs)



def prepare_cold_image(activity, reference, record):
    """Materialize rootless keep-id layers without starting image code."""
    import secrets
    identifier = secrets.token_hex(16)
    name = 'rocky-gw-image-prepare-' + identifier
    activity.user(['/usr/bin/podman','container','exists',name],accepted=(1,))
    record['cold_image_preparation']={'container':name,'started':False,'status':'CREATE_INTENT'}
    store(activity.state,record)
    activity.user(['/usr/bin/podman','create','--name',name,'--pull=never',
        '--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--userns=keep-id','--user',str(activity.worker['uid'])+':'+str(activity.worker['gid']),
        '--pids-limit=64','--cpus=1','--memory=128m','--memory-swap=128m',
        '--ulimit','nofile=64:64','--ulimit','core=0:0',
        '--entrypoint','/usr/bin/python3',reference,'-I','-B','-c','pass'])
    inspection=json.loads(activity.user(['/usr/bin/podman','container','inspect',name]))
    prepare.require(len(inspection)==1 and inspection[0]['Image'].removeprefix('sha256:')==
        record['image']['config_digest'].removeprefix('sha256:') and
        inspection[0]['State']['Status'] in ('created','configured') and
        inspection[0]['State']['Running'] is False and inspection[0]['State']['Pid']==0,
        'cold_preparation_identity_or_state')
    activity.user(['/usr/bin/podman','rm',name])
    activity.user(['/usr/bin/podman','container','exists',name],accepted=(1,))
    record['cold_image_preparation']['status']='REMOVED_ABSENCE_VERIFIED'
    store(activity.state,record)


def probe(activation,journal):
    worker=journal['site']['worker']; gateway=journal['site']['gateway']
    service='engbox-worker-'+journal['site']['site_id']+'.service'
    properties={}
    for _ in range(50):
        text=activation.user(['/usr/bin/systemctl','--user','show',service,
            '--property=MainPID,ActiveState,SubState,UnitFileState,Restart,RestartUSec']).decode()
        properties=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
        if properties.get('ActiveState')=='active' and Path('/run/rocky-eng/execution.sock').exists(): break
        time.sleep(.2)
    prepare.require(properties.get('ActiveState')=='active' and properties.get('SubState')=='running', 'worker_not_active')
    pid=int(properties['MainPID']); prepare.require(pid>1,'worker_pid')
    status=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    prepare.require(set(map(int,status['Uid'].split()))=={worker['uid']} and
        set(map(int,status['Gid'].split()))=={worker['gid']} and
        set(map(int,status['Groups'].split()))=={worker['gid']}, 'worker_effective_identity')
    prepare.require(int(status['CapEff'].strip(),16)==0,'worker_effective_capabilities')
    domain=Path(f'/proc/{pid}/attr/current').read_text().rstrip('\x00\n')
    prepare.require(domain.split(':')[2]=='engbox_worker_t','worker_effective_domain')
    info=Path('/run/rocky-eng/execution.sock').lstat()
    prepare.require(stat.S_ISSOCK(info.st_mode) and info.st_uid==worker['uid'] and
                    info.st_gid==worker['gid'] and stat.S_IMODE(info.st_mode)==0o660,'private_worker_socket')
    denied=activation.command(['/usr/sbin/runuser','-u',gateway['name'],'--','/usr/bin/test','-x',worker['home']],accepted=(1,))
    for path in ('/run/user/'+str(worker['uid']),'/run/user/'+str(worker['uid'])+'/bus'):
        activation.command(['/usr/sbin/runuser','-u',gateway['name'],'--','/usr/bin/test','-r',path],accepted=(1,))
    prepare.require(Path('/sys/fs/selinux/enforce').read_text().strip()=='1','selinux_enforcing')
    limits=activation.command(['/usr/bin/systemctl','show',f'user-{worker["uid"]}.slice',
        '--property=MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec']).decode()
    values=dict(line.split('=',1) for line in limits.splitlines() if '=' in line)
    prepare.require(values.get('MemoryMax')=='4294967296' and values.get('MemoryHigh')=='3221225472'
        and values.get('MemorySwapMax')=='0' and values.get('TasksMax')=='512'
        and values.get('CPUQuotaPerSecUSec')=='2s','effective_aggregate_limits')
    return {'worker_pid':pid,'worker_domain':domain,'properties':properties,'limits':values,
            'gateway_private_home_and_manager_denied':True,'selinux':'Enforcing'}


def activate(args):
    prepare.require(sys.platform=='linux' and os.geteuid()==0,'root_linux_required')
    os.umask(0o077)
    prepare.require(args.enable_at_boot,'explicit_boot_availability_approval_required')
    previous=None
    if args.resume_preserved_activation:
        prepare.trusted_directory(args.state)
        previous=json.loads(prepare.policy_preflight.bounded(args.state/'activation.json'))
        prepare.require(previous['status']=='ACTIVATION_FAILED_STATE_PRESERVED' and
            previous['recovery']==['stop_PASS','disable_PASS','disable-linger_PASS'], 'unconfirmed_activation_recovery')
        journal=json.loads(prepare.policy_preflight.bounded(args.state/'journal.json'))
        prepare.verify_policy_state(journal)
        digest,payload,metadata=prepare.validate_bundle(args.state/'bundle.zip',journal['bundle_sha256'])
        prepare.require(journal['activation_performed'] is True and journal['site']==metadata['site'] and
                        previous['bundle_sha256']==digest,'preserved_activation_binding')
        for relative,data in payload.items():
            path=Path('/'+relative);info=path.lstat()
            prepare.require(prepare.policy_preflight.bounded(path)==data and info.st_gid==0 and
                info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o644,'modified_prepared_payload_preserved')
        original=prepare.policy_preflight.bounded(args.state/'installed-policy.35')
        prepare.require(prepare.sha(Path('/sys/fs/selinux/policy').read_bytes())==prepare.sha(original),
                        'prepared_kernel_policy_changed')
        prepare.require(not Path('/run/rocky-eng/execution.sock').exists(),'active_socket_preserved')
        prepare.require(not (Path('/var/lib/systemd/linger')/journal['site']['worker']['name']).exists(),
                        'linger_changed_since_recovery')
        import pwd,grp
        for role in ('gateway','worker'):
            account=journal['site'][role];entry=pwd.getpwnam(account['name'])
            prepare.require((entry.pw_uid,entry.pw_gid,entry.pw_dir)==(account['uid'],account['gid'],account['home']),
                            'prepared_account_changed')
            expected={account['gid']}
            if role=='gateway':expected.add(journal['site']['worker']['gid'])
            prepare.require(set(os.getgrouplist(account['name'],account['gid']))==expected,'prepared_groups_changed')
            info=Path(account['home']).lstat()
            prepare.require(stat.S_ISDIR(info.st_mode) and info.st_uid==account['uid'] and
                            stat.S_IMODE(info.st_mode)==0o700,'private_home_changed')
    else:
        prepare.require(not (args.state/'activation.json').exists(),'activation_already_recorded')
        prepare.verify(args.state)
        journal,payload=prepare.load(args.state)
    worker=journal['site']['worker']
    public=prepare.policy_preflight.bounded(args.public_key,4096)
    prepare.require(public_identity(public)==args.public_spki_sha256,'approved_public_identity')
    if previous:
        prepare.require(previous['public_spki_sha256']==args.public_spki_sha256 and
                        previous['image']['archive_sha256']==args.archive_sha256,'preserved_inputs_changed')
    # Verification code is in the same reviewed, root-owned source distribution.
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'ci'))
    from image_preparation import verify_oci
    image=verify_oci(args.image)
    prepare.require(image['archive_sha256']==args.archive_sha256 and
        image['manifest_digest']==args.manifest_digest and image['config_digest']==args.config_digest,
        'approved_oci_identity')
    local=args.state/'activation-image.oci.tar'
    if not local.exists():
        with args.image.open('rb') as source,local.open('xb') as target:
            while block:=source.read(1024*1024): target.write(block)
    else:
        prepare.require(previous is not None and not local.is_symlink() and local.stat().st_uid==0,
                        'existing_image_copy_preserved')
    prepare.require(verify_oci(local)==image,'root_owned_oci_copy_identity')
    record={'schema':1,'status':'ENROLLMENT_PENDING','bundle_sha256':journal['bundle_sha256'],
        'source_commit':journal['site']['source_commit'],'public_spki_sha256':args.public_spki_sha256,
        'image':image,'boot_enablement_approved':True,'private_key_generated_or_copied':False,
        'execution_history_deleted':False,'deployment_ready':False}
    record['activation_tool_sha256']=prepare.sha(Path(__file__).read_bytes())
    if previous:
        count=len(list(args.state.glob('activation-failed-before-resume-*.json')))
        (args.state/('activation-failed-before-resume-%03d.json'%count)).write_text(json.dumps(previous,indent=2)+'\n')
    store(args.state,record)
    activity=Activation(args.state,record,worker)
    service='engbox-worker-'+journal['site']['site_id']+'.service'
    # After enrollment begins, prepare rollback must never remove operational state.
    journal['activation_performed']=True; prepare.save(args.state,journal)
    try:
        record['status']='PUBLIC_ENROLLMENT_INTENT';store(args.state,record)
        path=Path('/etc/rocky-eng/approval_ed25519_pub.pem')
        if path.exists():
            prepare.require(previous is not None and prepare.policy_preflight.bounded(path,4096)==public,
                            'existing_public_trust_preserved')
        else:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
            with os.fdopen(fd,'wb') as stream:stream.write(public)
            path.chmod(0o644)
        activity.command(['/usr/sbin/restorecon','-F',str(path)])
        record['status']='USER_MANAGER_ENABLE_INTENT';store(args.state,record)
        activity.command(['/usr/bin/loginctl','enable-linger',worker['name']])
        activity.command(['/usr/bin/systemctl','start','user@'+str(worker['uid'])+'.service'])
        before=json.loads(activity.user(['/usr/bin/podman','images','--format=json']))
        prepare.require(before==[],'nonempty_worker_image_store_requires_review')
        record['status']='ROOTLESS_IMAGE_IMPORT_INTENT';store(args.state,record)
        with local.open('rb') as stream:activity.user(['/usr/bin/podman','load'],stdin=stream)
        reference='localhost/rocky-ci-sandbox@'+args.manifest_digest
        inspect=json.loads(activity.user(['/usr/bin/podman','image','inspect',reference]))
        prepare.require(len(inspect)==1 and inspect[0]['Id'].removeprefix('sha256:')==args.config_digest.removeprefix('sha256:'),
                        'rootless_loaded_image_identity')
        pin=Path(worker['home'])/'.config/rocky-mcp-gateway/sandbox-image.txt'
        fd=os.open(pin,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write((reference+'\n').encode())
        os.chown(pin,worker['uid'],worker['gid']);pin.chmod(0o600)
        activity.command(['/usr/sbin/restorecon','-F',str(pin)])
        prepare_cold_image(activity,reference,record)
        record['status']='WORKER_ENABLE_START_INTENT';store(args.state,record)
        activity.user(['/usr/bin/systemctl','--user','enable',service])
        activity.user(['/usr/bin/systemctl','--user','start',service])
        record['live']=probe(activity,journal)
        record['status']='WORKER_ACTIVE_SIGNED_ACCEPTANCE_REQUIRED';store(args.state,record)
        return record
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        record['failure']=str(error)
        record['recovery']=[]
        for label,action in (
            ('stop',lambda:activity.user(['/usr/bin/systemctl','--user','stop',service])),
            ('disable',lambda:activity.user(['/usr/bin/systemctl','--user','disable',service])),
            ('disable-linger',lambda:activity.command(['/usr/bin/loginctl','disable-linger',worker['name']]))):
            try:action();record['recovery'].append(label+'_PASS')
            except (OSError,ValueError,subprocess.SubprocessError):record['recovery'].append(label+'_UNCONFIRMED')
        record['status']='ACTIVATION_FAILED_STATE_PRESERVED';store(args.state,record)
        raise


def audit_active(state):
    """Observe the installed candidate; write diagnostics only to private state."""
    prepare.trusted_directory(state)
    journal=json.loads(prepare.policy_preflight.bounded(state/'journal.json'))
    prepare.verify_policy_state(journal)
    record=json.loads(prepare.policy_preflight.bounded(state/'activation.json'))
    prepare.require(journal['activation_performed'] is True and
        record['status']=='WORKER_ACTIVE_SIGNED_ACCEPTANCE_REQUIRED','recorded_activation_required')
    digest,payload,metadata=prepare.validate_bundle(state/'bundle.zip',journal['bundle_sha256'])
    prepare.require(journal['site']==metadata['site'] and record['bundle_sha256']==digest,'installed_bundle_binding')
    for relative,data in payload.items():
        path=Path('/'+relative);info=path.lstat()
        prepare.require(prepare.policy_preflight.bounded(path)==data and info.st_gid==0 and
            info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o644,'installed_payload_metadata_or_hash')
    import pwd,sqlite3
    for role in ('gateway','worker'):
        account=journal['site'][role];entry=pwd.getpwnam(account['name'])
        prepare.require((entry.pw_uid,entry.pw_gid,entry.pw_dir)==(account['uid'],account['gid'],account['home']),
                        'installed_account_identity')
        prepare.require(entry.pw_shell==('/usr/sbin/nologin' if role=='worker' else '/bin/bash'),'installed_account_shell')
        groups={account['gid']}
        if role=='gateway':groups.add(journal['site']['worker']['gid'])
        prepare.require(set(os.getgrouplist(account['name'],account['gid']))==groups,'installed_group_membership')
        info=Path(account['home']).lstat()
        prepare.require(stat.S_ISDIR(info.st_mode) and info.st_uid==account['uid'] and
                        stat.S_IMODE(info.st_mode)==0o700,'installed_private_home')
    worker=journal['site']['worker']
    for kind in ('subuid','subgid'):
        rows=[line for line in Path('/etc/'+kind).read_text().splitlines() if line.split(':')[0]==worker['name']]
        prepare.require(rows==[f'{worker["name"]}:{worker["subid_start"]}:{worker["subid_count"]}'],'installed_subordinate_range')
    public=prepare.policy_preflight.bounded(Path('/etc/rocky-eng/approval_ed25519_pub.pem'),4096)
    prepare.require(public_identity(public)==record['public_spki_sha256'],'installed_public_identity')
    info=Path('/etc/rocky-eng/approval_ed25519_pub.pem').lstat()
    prepare.require(info.st_nlink==1 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o644,'installed_public_permissions')
    pin=Path(worker['home'])/'.config/rocky-mcp-gateway/sandbox-image.txt';info=pin.lstat()
    expected='localhost/rocky-ci-sandbox@'+record['image']['manifest_digest']
    prepare.require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==worker['uid'] and
        info.st_gid==worker['gid'] and stat.S_IMODE(info.st_mode)==0o600 and pin.read_text().strip()==expected,'installed_private_image_pin')
    policy_hash=prepare.sha(Path('/sys/fs/selinux/policy').read_bytes())
    prepare.require(policy_hash==prepare.sha(prepare.policy_preflight.bounded(state/'installed-policy.35')),'installed_kernel_policy')
    selected=prepare.policy_preflight.select_modules(Path('/var/lib/selinux/targeted/active/modules'),allow_candidate=True)
    native=journal['native_modules_before']
    candidate={p.stem:p for p in (Path(__file__).parent/'policy').glob('*.cil')}
    prepare.require(set(selected)==set(native)|set(candidate),'installed_module_closure')
    for name,path in selected.items():
        raw=prepare.policy_preflight.bounded(path/'cil')
        if name in native:
            prepare.require(str(path/'cil')==native[name]['path'] and prepare.sha(raw)==native[name]['raw_sha256'],'installed_native_module_identity')
        else:
            prepare.require(prepare.policy_preflight.decode(raw)==candidate[name].read_bytes(),'installed_candidate_module_identity')
    labels={'/opt/rocky-eng':'engbox_worker_code_t','/etc/rocky-eng':'etc_t',
        '/run/rocky-eng':'engbox_worker_run_t','/run/rocky-eng/execution.sock':'engbox_worker_run_t',
        worker['home']+'/.config/rocky-mcp-gateway':'engbox_worker_config_t',
        worker['home']+'/.local/share/rocky-mcp-gateway':'engbox_worker_state_t',
        worker['home']+'/.local/share/rocky-mcp-gateway/tmp':'engbox_worker_tmp_t'}
    for path,label in labels.items():
        context=os.getxattr(path,'security.selinux').decode().rstrip('\x00\n')
        prepare.require(context.split(':')[2]==label,'installed_selinux_label_'+path)
    activity=Activation(state,record,worker)
    live=probe(activity,journal)
    prepare.require(live['properties']['UnitFileState']=='enabled' and live['properties']['Restart']=='always'
        and (Path('/var/lib/systemd/linger')/worker['name']).is_file(),'installed_boot_availability')
    images=json.loads(activity.user(['/usr/bin/podman','images','--format=json']))
    prepare.require(len(images)==1 and images[0]['Id'].removeprefix('sha256:')==record['image']['config_digest'].removeprefix('sha256:'),'installed_worker_image_store')
    containers=json.loads(activity.user(['/usr/bin/podman','ps','-a','--format=json']))
    prepare.require(containers==[],'final_idle_containers_required')
    base=Path(worker['home'])/'.local/share/rocky-mcp-gateway'
    conn=sqlite3.connect('file:'+str(base/'execution.sqlite3')+'?mode=ro',uri=True)
    states=dict(conn.execute('select state,count(*) from plans group by state').fetchall())
    nonces=conn.execute('select count(*),coalesce(sum(consumed),0) from grant_nonces').fetchone();conn.close()
    prepare.require(not any(states.get(k,0) for k in ('QUEUED','RUNNING')),'final_idle_jobs_required')
    prepare.require(not list((base/'execution').iterdir()),'final_workspaces_empty')
    return {'status':'ACTIVE_PRIVATE_PROFILE_AUDIT_PASS','deployment_ready':False,
        'installed_source_commit':journal['site']['source_commit'],'bundle_sha256':digest,
        'audit_tool_sha256':prepare.sha(Path(__file__).read_bytes()),'worker':live,
        'public_spki_sha256':record['public_spki_sha256'],'image_manifest':record['image']['manifest_digest'],
        'kernel_policy_sha256':policy_hash,'native_modules_verified':len(native),'labels_verified':labels,
        'execution_states':states,'nonce_count':nonces[0],'consumed_nonce_count':nonces[1],
        'containers_remaining':0,'workspaces_remaining':0,'host_services_or_configuration_changed':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--image',type=Path)
    parser.add_argument('--archive-sha256')
    parser.add_argument('--manifest-digest')
    parser.add_argument('--config-digest')
    parser.add_argument('--public-key',type=Path)
    parser.add_argument('--public-spki-sha256')
    parser.add_argument('--audit-active',action='store_true')
    parser.add_argument('--enable-at-boot',action='store_true')
    parser.add_argument('--resume-preserved-activation',action='store_true',
                        help='Resume only independently confirmed stopped/disabled recovery with identical inputs')
    args=parser.parse_args()
    try:
        prepare.require(sys.platform=='linux' and os.geteuid()==0,'root_linux_required')
        import fcntl
        fd=os.open('/run/engbox-native-prepare.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+') as lock:
            prepare.require(os.fstat(lock.fileno()).st_uid==0,'unsafe_lock')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.audit_active:record=audit_active(args.state)
            else:
                prepare.require(all(getattr(args,key) is not None for key in
                    ('image','archive_sha256','manifest_digest','config_digest','public_key','public_spki_sha256')),
                    'explicit_activation_inputs_required')
                record=activate(args)
        print(json.dumps({k:v for k,v in record.items() if k!='image'},sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        print(json.dumps({'status':'ACTIVATION_REFUSED_OR_FAILED','error':str(error),'deployment_ready':False}))
        return 2


if __name__=='__main__':raise SystemExit(main())
