"""Experimental fresh Rocky host preparation with conservative recovery.

Creates disabled installation resources only. Never enrolls trust, imports an
image, authorizes SSH, starts a worker or enables boot persistence. Qualify on a
disposable host before considering production use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

import payload_stage
import policy_preflight
import site_inventory
import site_plan


def require(value, error):
    if not value:
        raise ValueError(error)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def trusted_directory(path, *, uid=0):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022,
            'unsafe_directory')


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def save(state, journal):
    pending = state/'journal.pending'
    with pending.open('x', encoding='utf8') as stream:
        stream.write(json.dumps(journal, sort_keys=True, indent=2)+'\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, state/'journal.json')
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Transaction:
    def __init__(self, state, journal, *, fail_after=None):
        self.state, self.journal, self.fail_after = state, journal, fail_after

    def command(self, args):
        number = len(list(self.state.glob('command-*.json')))
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=180)
        record = {'argv':args, 'exit_code':result.returncode,
                  'stdout':result.stdout.decode('utf8', errors='replace'),
                  'stderr':result.stderr.decode('utf8', errors='replace')}
        (self.state/('command-%04d.json'%number)).write_text(json.dumps(record, indent=2)+'\n')
        require(result.returncode == 0, 'native_command_failed_'+str(number))
        return record['stdout']

    def operation(self, record, action):
        record = dict(record, complete=False)
        self.journal['operations'].append(record)
        save(self.state, self.journal)  # Intent precedes mutation, including partial commands.
        action()
        record['complete'] = True
        save(self.state, self.journal)
        if self.fail_after == len(self.journal['operations']):
            raise ValueError('injected_failure')

    def mkdir(self, path, mode=0o755, uid=0, gid=0):
        if not absent(path):
            trusted_directory(path, uid=uid)
            return
        self.mkdir(path.parent) if absent(path.parent) else None
        def create():
            path.mkdir(mode=0o700)
            os.chown(path, uid, gid)
            path.chmod(mode)
        self.operation({'kind':'directory','path':str(path),'uid':uid,'gid':gid,'mode':mode}, create)

    def file(self, path, data):
        require(absent(path), 'occupied_payload')
        self.mkdir(path.parent)
        def create():
            fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            path.chmod(0o644)
        self.operation({'kind':'file','path':str(path),'sha256':sha(data)}, create)

    def policy_operation(self, record, args):
        verify_policy_state(self.journal)
        def apply():
            self.command(args)
            # A failed observation leaves incomplete intent: automatic recovery stops.
            self.journal['policy_current'] = observe_policy(self.journal)
        self.operation(record, apply)


def observe_policy(journal):
    """Bind the exact native sources, owned priority-400 modules and local rules."""
    require('native_modules_before' in journal, 'missing_policy_baseline_preserved')
    kernel = sha(Path('/sys/fs/selinux/policy').read_bytes())
    native = journal['native_modules_before']
    owned = {}
    for op in journal['operations']:
        if op['kind'] == 'modules' and not op.get('undone'):
            owned.update({Path(name).stem:digest for name,digest in op['hashes'].items()})
    root = Path('/var/lib/selinux/targeted/active/modules')
    selected = policy_preflight.select_modules(root, allow_candidate=True)
    require(set(selected) == set(native)|set(owned), 'policy_module_closure_drift_preserved')
    for name,path in selected.items():
        raw = policy_preflight.bounded(path/'cil')
        if name in native:
            require(str(path/'cil') == native[name]['path'] and sha(raw) == native[name]['raw_sha256'],
                    'native_policy_source_drift_preserved')
        else:
            require(path.parent.name == '400' and sha(policy_preflight.decode(raw)) == owned[name],
                    'owned_policy_source_drift_preserved')
            # A hidden lower-priority replacement must not be exposed by deletion.
            require(set(root.glob('*/'+name)) == {path}, 'shadowed_owned_policy_preserved')
    local = Path('/etc/selinux/targeted/contexts/files/file_contexts.local')
    # semanage may leave an empty generated file after its last rule is removed.
    # Preserve rule order and exact regex whitespace: local rules are ordered.
    # Only comments/empty lines and absent versus empty carry no rule semantics.
    text = '' if absent(local) else policy_preflight.bounded(local).decode('utf8')
    records = [line for line in text.splitlines()
               if line.strip() and not line.lstrip().startswith('#')]
    contexts = sha(json.dumps(records).encode())
    require(sha(Path('/sys/fs/selinux/policy').read_bytes()) == kernel, 'policy_changed_during_observation')
    return {'kernel_sha256':kernel, 'local_fcontexts_sha256':contexts}


def verify_policy_state(journal):
    require('policy_current' in journal, 'missing_policy_baseline_preserved')
    observed = observe_policy(journal)
    require(observed == journal['policy_current'], 'policy_state_drift_preserved')
    return observed


def installed_policy_snapshot(state, journal):
    """Create the accepted snapshot once; verification never replaces it."""
    observed = verify_policy_state(journal)
    path = state/'installed-policy.35'
    if absent(path):
        data = Path('/sys/fs/selinux/policy').read_bytes()
        require(sha(data) == observed['kernel_sha256'], 'policy_changed_before_snapshot')
        fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    require(sha(policy_preflight.bounded(path)) == observed['kernel_sha256'],
            'installed_policy_snapshot_drift_preserved')
    return observed['kernel_sha256']


def validate_bundle(bundle, expected):
    digest, payload, metadata = payload_stage.bundle(bundle)
    require(digest == expected, 'approved_bundle_digest')
    runtime = json.loads((Path(__file__).parent/'runtime-manifest.json').read_text())
    require(len(runtime) == 57, 'runtime_manifest')
    runtime_files = {'opt/rocky-eng/'+name: value for name,value in runtime.items()}
    require(all(name in payload and sha(payload[name]) == value for name,value in runtime_files.items()),
            'frozen_runtime_provenance')
    site = metadata['site']
    require(site['paths'] == {'code':'/opt/rocky-eng','config':'/etc/rocky-eng','runtime':'/run/rocky-eng'} and
            site['worker']['home'] == '/home/rocky-eng-worker' and
            site['worker']['name'] == 'rocky-eng-worker', 'supported_native_layout_and_worker_name')
    service = 'engbox-worker-'+site['site_id']+'.service'
    extra = {'etc/rocky-eng/execution-policy.json', 'etc/systemd/user/'+service,
             'etc/systemd/user/'+service+'.d/50-engbox-hardening.conf',
             'etc/systemd/user/'+service+'.d/60-engbox-availability.conf',
             f'etc/systemd/system/user-{site["worker"]["uid"]}.slice.d/50-engbox-limits.conf',
             'etc/tmpfiles.d/rocky-eng-ipc.conf'}
    require(set(payload) == set(runtime_files)|extra, 'exact_native_payload_closure')
    # Re-render generated configuration independently; metadata is not authority.
    base = Path(__file__).parent/'payload'
    policy = {'schema':1,'gateway_uid':site['gateway']['uid'],'worker_uid':site['worker']['uid'],
              'socket_group_gid':site['worker']['gid']}
    require(json.loads(payload['etc/rocky-eng/execution-policy.json']) == policy, 'policy_identity')
    for filename in ('50-engbox-hardening.conf','60-engbox-availability.conf'):
        require(payload['etc/systemd/user/'+service+'.d/'+filename] ==
                (base/'etc/systemd/user/rocky-eng-worker.service.d'/filename).read_bytes(), 'security_dropin_bytes')
    require(payload['etc/systemd/user/'+service] == (base/'etc/systemd/user/rocky-eng-worker.service').read_bytes(),
            'service_bytes')
    require(payload[f'etc/systemd/system/user-{site["worker"]["uid"]}.slice.d/50-engbox-limits.conf'] ==
            (base/'etc/systemd/system/user-1001.slice.d/50-engbox-limits.conf').read_bytes(), 'aggregate_limits_bytes')
    require(payload['etc/tmpfiles.d/rocky-eng-ipc.conf'] ==
            f'd /run/rocky-eng 0750 {site["worker"]["name"]} {site["worker"]["name"]} - -\n'.encode(),
            'tmpfiles_identity')
    with zipfile.ZipFile(bundle) as archive:
        require(all(archive.read('review/policy/'+p.name) == p.read_bytes()
                    for p in (Path(__file__).parent/'policy').glob('*.cil')), 'reviewed_policy_source_identity')
    return digest, payload, metadata


def prepare(bundle, expected, state, *, fail_after=None):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'root_linux_required')
    digest, payload, metadata = validate_bundle(bundle, expected)
    site = metadata['site']
    for role in ('gateway','worker'):
        require(absent(Path('/var/spool/mail')/site[role]['name']), 'preexisting_mailbox_preserved')
    # Collect again immediately before mutation. Never trust a packaged inventory.
    observed = site_inventory.collect(site, ssh_verified=True)
    require(observed['inventory']['complete'], 'fresh_inventory_incomplete')
    require(site_plan.plan(site, observed['inventory'])['status'] == 'OFFLINE_PLAN_REVIEW_REQUIRED', 'fresh_plan_blocked')
    require(state.is_absolute() and absent(state), 'new_private_state_required')
    for parent in state.parents:
        trusted_directory(parent)
    for relative in payload:
        path = Path('/'+relative)
        require(absent(path), 'occupied_payload')
        for parent in path.parents:
            if not absent(parent):
                trusted_directory(parent)
    os.umask(0o077)
    state.mkdir(mode=0o700)
    (state/'bundle.zip').write_bytes(Path(bundle).read_bytes())
    (state/'inventory-before.json').write_text(json.dumps(observed, indent=2)+'\n')
    journal = {'schema':1,'kind':'EXPERIMENTAL_NATIVE_PREPARE','status':'PREFLIGHT',
               'bundle_sha256':digest,'site':site,'operations':[], 'activation_performed':False}
    save(state, journal)
    tx = Transaction(state, journal, fail_after=fail_after)
    # All strict assertions must pass on the actual native policy before loading.
    report = policy_preflight.preflight(state/'policy-review')
    require(report['status'] == 'OFFLINE_POLICY_CANDIDATE_CHECKS_PASS_REVIEW_REQUIRED', 'native_policy_review_blocked')
    journal['native_policy_before'] = report['kernel_policy_sha256']
    journal['native_modules_before'] = report['native_modules']
    journal['policy_original'] = observe_policy(journal)
    require(journal['policy_original']['kernel_sha256'] == report['kernel_policy_sha256'],
            'preflight_policy_changed')
    journal['policy_current'] = dict(journal['policy_original'])
    journal['status'] = 'APPLYING_DISABLED_RESOURCES'
    save(state,journal)
    try:
        for role in ('gateway','worker'):
            account = site[role]
            tx.operation({'kind':'group','account':account}, lambda a=account: tx.command(
                ['/usr/sbin/groupadd','--gid',str(a['gid']),a['name']]))
            shell = '/usr/sbin/nologin' if role == 'worker' else '/bin/bash'
            tx.operation({'kind':'user','account':account,'shell':shell}, lambda a=account,s=shell: tx.command(
                ['/usr/sbin/useradd','--uid',str(a['uid']),'--gid',str(a['gid']),
                 '--home-dir',a['home'],'--shell',s,'--no-create-home','--no-user-group','--no-log-init',
                 '-K','SUB_UID_COUNT=0','-K','SUB_GID_COUNT=0',a['name']]))
            tx.mkdir(Path(account['home']),0o700,account['uid'],account['gid'])
        worker = site['worker']
        interval = str(worker['subid_start'])+'-'+str(worker['subid_start']+worker['subid_count']-1)
        for kind in ('subuids','subgids'):
            tx.operation({'kind':kind,'account':worker,'range':interval}, lambda k=kind: tx.command(
                ['/usr/sbin/usermod','--add-'+k,interval,worker['name']]))
        # Worker has only its primary group. Gateway gets only this IPC group.
        tx.operation({'kind':'membership','account':site['gateway'],'group':worker['name']}, lambda: tx.command(
            ['/usr/sbin/usermod','--append','--groups',worker['name'],site['gateway']['name']]))
        for relative,data in sorted(payload.items()):
            tx.file(Path('/'+relative),data)
        home = Path(worker['home'])
        for relative in ('.config','.config/rocky-mcp-gateway','.local','.local/share',
                         '.local/share/rocky-mcp-gateway','.local/share/rocky-mcp-gateway/tmp'):
            tx.mkdir(home/relative,0o700,worker['uid'],worker['gid'])
        tx.mkdir(Path('/run/rocky-eng'),0o750,worker['uid'],worker['gid'])
        names = sorted(report['candidate_hashes'])
        tx.policy_operation({'kind':'modules','names':[Path(n).stem for n in names],
                      'hashes':report['candidate_hashes']},
            ['/usr/sbin/semodule','-X','400','-i',*[str(Path(__file__).parent/'policy'/n) for n in names]])
        for relative,label in ((r'/\.config/rocky-mcp-gateway(/.*)?','engbox_worker_config_t'),
                               (r'/\.local/share/rocky-mcp-gateway(/.*)?','engbox_worker_state_t'),
                               (r'/\.local/share/rocky-mcp-gateway/tmp(/.*)?','engbox_worker_tmp_t')):
            pattern = str(home)+relative
            tx.policy_operation({'kind':'fcontext','pattern':pattern,'label':label},
                ['/usr/sbin/semanage','fcontext','-a','-s','unconfined_u','-r','s0','-t',label,pattern])
        tx.command(['/usr/sbin/restorecon','-RF',str(home),site['gateway']['home'],'/opt/rocky-eng','/etc/rocky-eng','/run/rocky-eng'])
        tx.command(['/usr/bin/systemctl','daemon-reload'])
        journal['status'] = 'DISABLED_RESOURCES_PREPARED_NOT_DEPLOYMENT_READY'
        save(state,journal)
        return verify(state)
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        journal['failure'] = str(error)
        journal['status'] = 'FAILED_RECOVERY_REQUIRED'
        save(state,journal)
        # Preserve state. Recovery validates every owned resource before removal.
        rollback(state)
        raise


def load(state):
    trusted_directory(state)
    journal = json.loads(policy_preflight.bounded(state/'journal.json'))
    require(journal['schema'] == 1 and journal['kind'] == 'EXPERIMENTAL_NATIVE_PREPARE', 'journal_kind')
    digest,payload,metadata = validate_bundle(state/'bundle.zip',journal['bundle_sha256'])
    require(journal['site'] == metadata['site'] and journal['activation_performed'] is False, 'journal_identity')
    return journal,payload


def verify_resources(journal, *, rollback_check=False):
    files = {Path(op['path']):op for op in journal['operations'] if op['kind']=='file'}
    directories = {Path(op['path']):op for op in journal['operations'] if op['kind']=='directory'}
    for path,op in files.items():
        if absent(path):
            require(rollback_check, 'missing_installed_file')
            continue
        info = path.lstat()
        require(sha(policy_preflight.bounded(path)) == op['sha256'] and info.st_nlink == 1 and
                info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o644,
                'modified_installed_file_preserved')
    for path,op in directories.items():
        if absent(path):
            require(rollback_check, 'missing_installed_directory')
            continue
        trusted_directory(path,uid=op['uid'])
        info = path.lstat()
        require(info.st_gid == op['gid'] and stat.S_IMODE(info.st_mode) == op['mode'], 'changed_directory_metadata')
        require(all(child in files or child in directories for child in path.iterdir()),
                'new_state_or_history_preserved')
    # Refuse to roll back or qualify an installation somebody has activated.
    worker = journal['site']['worker']
    require(absent(Path('/var/lib/systemd/linger')/worker['name']), 'worker_linger_changed')
    require(absent(Path('/etc/rocky-eng/approval_ed25519_pub.pem')), 'enrolled_trust_preserved')
    require(absent(Path('/run/rocky-eng/execution.sock')), 'active_socket_preserved')
    result = subprocess.run(['/usr/bin/systemctl','--global','is-enabled',
        'engbox-worker-'+journal['site']['site_id']+'.service'],capture_output=True,timeout=15)
    require(result.returncode in {1,4} and result.stdout.strip() in {b'disabled',b'not-found',b''}, 'worker_enablement_changed')


def verify(state):
    journal,payload = load(state)
    require(journal['status'] == 'DISABLED_RESOURCES_PREPARED_NOT_DEPLOYMENT_READY', 'prepare_status')
    verify_resources(journal)
    tx = Transaction(state,journal)
    for role in ('gateway','worker'):
        account = journal['site'][role]
        row = tx.command(['/usr/bin/getent','passwd',account['name']]).strip().split(':')
        require((int(row[2]),int(row[3]),row[5]) == (account['uid'],account['gid'],account['home']), 'effective_account')
        require(row[6] == ('/usr/sbin/nologin' if role == 'worker' else '/bin/bash'), 'account_shell')
        groups = set(map(int,tx.command(['/usr/bin/id','-G',account['name']]).split()))
        expected = {account['gid']}
        if role == 'gateway': expected.add(journal['site']['worker']['gid'])
        require(groups == expected, 'exact_group_membership')
    for name in ('subuid','subgid'):
        lines = Path('/etc/'+name).read_text().splitlines()
        worker = journal['site']['worker']
        expected = f'{worker["name"]}:{worker["subid_start"]}:{worker["subid_count"]}'
        require([line for line in lines if line.split(':')[0] == worker['name']] == [expected], 'exact_worker_subids')
    require(Path('/sys/fs/selinux/enforce').read_text().strip()=='1', 'selinux_enforcing')
    kernel_hash = installed_policy_snapshot(state, journal)
    source = Path(__file__).parent
    tx.command(['/usr/bin/python3','-I','-B',str(source/'check_candidate_assertions.py'),
        '--candidate',str(source/'policy/engbox_worker.cil'),'--policy',str(state/'installed-policy.35'),
        '--output',str(state/'installed-candidate-assertions.json')])
    tx.command(['/usr/bin/python3','-I','-B',str(source/'check_global_assertions.py'),
        '--base',str(state/'policy-review/candidate/native-base.cil'),
        '--guard',str(source/'policy/engbox_vendor_assertion_guard.cil'),
        '--policy',str(state/'installed-policy.35'),'--output',str(state/'installed-global-assertions.json')])
    return {'status':'DISABLED_RESOURCES_VERIFIED_NOT_DEPLOYMENT_READY', 'deployment_ready':False,
            'bundle_sha256':journal['bundle_sha256'],'source_commit':journal['site']['source_commit'],
            'worker_started':False,'trust_enrolled':False,'boot_enabled':False,
            'kernel_policy_sha256':kernel_hash}


def rollback(state):
    journal,payload = load(state)
    require(journal['status'] != 'ROLLED_BACK', 'already_rolled_back')
    require(not any(op['kind'] in {'modules','fcontext'} and not op['complete']
                    for op in journal['operations']), 'ambiguous_policy_operation_preserved_for_review')
    verify_resources(journal,rollback_check=True)
    # Preflight the complete policy recovery set before deleting any resource.
    verify_policy_state(journal)
    tx = Transaction(state,journal)
    journal['status'] = 'ROLLING_BACK'
    save(state,journal)
    for operation in reversed(journal['operations']):
        if operation.get('undone'): continue
        kind = operation['kind']
        if kind == 'fcontext':
            if operation['complete']:
                verify_policy_state(journal)
                tx.command(['/usr/sbin/semanage','fcontext','-d',operation['pattern']])
        elif kind == 'modules':
            if operation['complete']:
                verify_policy_state(journal)
                tx.command(['/usr/sbin/semodule','-X','400','-r',*operation['names']])
        elif kind == 'file':
            path = Path(operation['path'])
            if not absent(path): path.unlink()
        elif kind == 'directory':
            path = Path(operation['path'])
            if not absent(path): path.rmdir()
        elif kind == 'membership':
            if operation['complete']:
                tx.command(['/usr/bin/gpasswd','-d',operation['account']['name'],operation['group']])
        elif kind in {'subuids','subgids'}:
            if operation['complete']:
                tx.command(['/usr/sbin/usermod','--del-'+kind,operation['range'],operation['account']['name']])
        elif kind in {'user','group'}:
            account = operation['account']
            import pwd,grp
            try:
                row = pwd.getpwnam(account['name']) if kind == 'user' else grp.getgrnam(account['name'])
            except KeyError:
                row = None
            if row is not None:
                require((row.pw_uid,row.pw_gid,row.pw_dir) == (account['uid'],account['gid'],account['home'])
                        if kind == 'user' else row.gr_gid == account['gid'], 'changed_identity_preserved')
                if kind == 'user':
                    mailbox = Path('/var/spool/mail')/account['name']
                    if not absent(mailbox):
                        info = mailbox.lstat()
                        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                                info.st_uid == account['uid'] and info.st_size == 0, 'mailbox_contents_preserved')
                        mailbox.unlink()
                tx.command(['/usr/sbin/userdel' if kind == 'user' else '/usr/sbin/groupdel',account['name']])
        else:
            raise ValueError('unknown_recovery_operation')
        operation['undone'] = True
        if kind in {'modules','fcontext'}:
            journal['policy_current'] = observe_policy(journal)
        save(state,journal)
    tx.command(['/usr/bin/systemctl','daemon-reload'])
    require(verify_policy_state(journal) == journal.get('policy_original'),
            'original_policy_not_restored_preserved')
    journal['status'] = 'ROLLED_BACK'
    save(state,journal)
    return {'status':'DISABLED_INSTALLATION_ROLLED_BACK','deployment_ready':False,'state_preserved':str(state)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('prepare','verify','rollback'))
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--bundle',type=Path)
    parser.add_argument('--bundle-sha256')
    parser.add_argument('--allow-experimental-prepare',action='store_true')
    parser.add_argument('--fail-after',type=int,help='Disposable qualification: inject failure after an operation')
    args = parser.parse_args()
    try:
        require(sys.platform=='linux' and os.geteuid()==0,'root_linux_required')
        import fcntl
        fd = os.open('/run/engbox-native-prepare.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+') as lock:
            require(os.fstat(lock.fileno()).st_uid==0,'unsafe_lock')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.operation=='prepare':
                require(args.allow_experimental_prepare and args.bundle is not None and args.bundle_sha256 is not None,
                        'explicit_experimental_bundle_approval_required')
                result = prepare(args.bundle,args.bundle_sha256,args.state,fail_after=args.fail_after)
            else:
                result = verify(args.state) if args.operation=='verify' else rollback(args.state)
        print(json.dumps(result,sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        print(json.dumps({'status':'NATIVE_PREPARE_REFUSED_OR_FAILED','deployment_ready':False,'error':str(error)}))
        return 2


if __name__=='__main__': raise SystemExit(main())
