"""Public enrollment input validation; no signing keys or service mutations."""
import base64
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch,MagicMock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/deployment'))
import native_activate as subject


class PublicEnrollmentTests(unittest.TestCase):
    def test_cold_image_preparation_never_starts_image_code(self):
        import json
        image='sha256:'+'a'*64
        activity=MagicMock();activity.worker={'uid':2201,'gid':2201}
        activity.user.side_effect=[b'',b'identifier',json.dumps([{'Image':image,
            'State':{'Status':'created','Running':False,'Pid':0}}]).encode(),b'',b'']
        record={'image':{'config_digest':image}}
        with patch.object(subject,'store'):
            subject.prepare_cold_image(activity,'localhost/synthetic@sha256:'+'b'*64,record)
        commands=[c.args[0] for c in activity.user.call_args_list]
        self.assertEqual([c[1] for c in commands],['container','create','container','rm','container'])
        self.assertTrue({'--pull=never','--network=none','--read-only','--cap-drop=ALL',
            '--security-opt=no-new-privileges','--userns=keep-id'} <= set(commands[1]))
        self.assertFalse(any('start' in c or 'exec' in c or 'run' in c for c in commands))
        self.assertEqual(record['cold_image_preparation']['status'],'REMOVED_ABSENCE_VERIFIED')

    def test_cold_image_preparation_rejects_running_or_wrong_image(self):
        import json
        for state,image in (({'Status':'running','Running':True,'Pid':17},'a'),
                            ({'Status':'created','Running':False,'Pid':0},'b')):
            activity=MagicMock();activity.worker={'uid':2201,'gid':2201}
            activity.user.side_effect=[b'',b'',json.dumps([{'Image':'sha256:'+image*64,'State':state}]).encode()]
            with patch.object(subject,'store'),self.assertRaises(ValueError):
                subject.prepare_cold_image(activity,'synthetic',{'image':{'config_digest':'sha256:'+'a'*64}})
            self.assertEqual(activity.user.call_count,3)

    def test_pre_activation_policy_drift_refused_before_any_enrollment(self):
        args=types.SimpleNamespace(state=Path('/synthetic'),enable_at_boot=True,
                                   resume_preserved_activation=False)
        with patch.object(subject.sys,'platform','linux'), \
             patch.object(subject.os,'geteuid',return_value=0,create=True), \
             patch.object(subject.os,'umask'),patch.object(Path,'exists',return_value=False), \
             patch.object(subject.prepare,'verify',side_effect=ValueError('policy_state_drift_preserved')), \
             patch.object(subject,'public_identity') as public,patch.object(subject.Activation,'command') as command:
            with self.assertRaisesRegex(ValueError,'policy_state_drift'):
                subject.activate(args)
            public.assert_not_called();command.assert_not_called()

    def pem(self,der):
        return b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(der)+b'\n-----END PUBLIC KEY-----\n'

    def test_ed25519_spki_identity_is_the_der_hash(self):
        der=bytes.fromhex('302a300506032b6570032100')+bytes(range(32))
        self.assertEqual(subject.public_identity(self.pem(der)),subject.prepare.sha(der))

    def test_private_key_wrong_algorithm_truncated_and_nonbase64_refused(self):
        valid=bytes.fromhex('302a300506032b6570032100')+bytes(range(32))
        for data in (b'-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----',
                     self.pem(valid[:-1]),self.pem(valid[:8]+b'\x00'+valid[9:]),
                     b'-----BEGIN PUBLIC KEY-----\n!not-base64!\n-----END PUBLIC KEY-----'):
            with self.subTest(data=data[:30]),self.assertRaises(ValueError):subject.public_identity(data)

    def test_cross_identity_commands_do_not_inherit_operator_private_cwd(self):
        def execute(args,**kwargs):
            if kwargs.get('cwd')!='/':raise PermissionError('operator home is inaccessible to worker')
            return types.SimpleNamespace(returncode=0,stdout=b'[]',stderr=b'')
        with tempfile.TemporaryDirectory() as temp,patch.object(subject.subprocess,'run',side_effect=execute):
            a=subject.Activation(Path(temp),{}, {'name':'synthetic','home':'/home/synthetic','uid':2201})
            self.assertEqual(a.user(['/usr/bin/podman','images','--format=json']),b'[]')

    def test_unconfirmed_recovery_blocks_resume_before_commands(self):
        for record in ({'status':'WORKER_ACTIVE_SIGNED_ACCEPTANCE_REQUIRED'},
                       {'status':'ACTIVATION_FAILED_STATE_PRESERVED','recovery':['stop_UNCONFIRMED']}):
            args=types.SimpleNamespace(state=Path('/synthetic'),enable_at_boot=True,resume_preserved_activation=True)
            with patch.object(subject.sys,'platform','linux'), \
                 patch.object(subject.os,'geteuid',return_value=0,create=True),patch.object(subject.os,'umask'), \
                 patch.object(subject.prepare,'trusted_directory'), \
                 patch.object(subject.prepare.policy_preflight,'bounded',return_value=__import__('json').dumps(record).encode()), \
                 patch.object(subject.Activation,'command') as command:
                with self.assertRaisesRegex(ValueError,'unconfirmed_activation_recovery'):subject.activate(args)
                command.assert_not_called()

    def test_active_audit_can_recreate_its_ephemeral_lock_after_boot(self):
        def open_after_boot(path,flags,*args):
            if not flags & subject.os.O_CREAT:raise FileNotFoundError('ephemeral lock is absent after boot')
            return 17
        lock=MagicMock();lock.__enter__.return_value=lock;lock.fileno.return_value=17
        fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *args:None)
        with patch.object(subject.sys,'argv',['native_activate.py','--audit-active','--state','/synthetic']), \
             patch.object(subject.sys,'platform','linux'),patch.dict(subject.sys.modules,{'fcntl':fcntl}), \
             patch.object(subject.os,'geteuid',return_value=0,create=True), \
             patch.object(subject.os,'O_NOFOLLOW',0,create=True),patch.object(subject.os,'open',side_effect=open_after_boot), \
             patch.object(subject.os,'fdopen',return_value=lock), \
             patch.object(subject.os,'fstat',return_value=types.SimpleNamespace(st_uid=0)), \
             patch.object(subject,'audit_active',return_value={'status':'ACTIVE_PRIVATE_PROFILE_AUDIT_PASS'}), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(subject.main(),0)


if __name__=='__main__':unittest.main()
