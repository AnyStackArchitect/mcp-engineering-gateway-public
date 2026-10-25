"""Recovery intent and refusal fixtures. Linux mutation is qualified separately."""
import json
import contextlib
from pathlib import Path
import sys
import types
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/deployment'))
import native_prepare as subject
import site_bundle
from test_site_plan import fixture,NOW


class NativePrepareTests(unittest.TestCase):
    @contextlib.contextmanager
    def policy_fixture(self):
        root=Path('/var/lib/selinux/targeted/active/modules')
        native=root/'100/base'; owned=root/'400/engbox_worker'
        sources={native/'cil':b'native',owned/'cil':b'candidate'}
        selected={'base':native,'engbox_worker':owned}
        local=Path('/etc/selinux/targeted/contexts/files/file_contexts.local')
        sources[local]=b'/home/worker(/.*)? unconfined_u:object_r:engbox_worker_state_t:s0\n'
        journal={'native_modules_before':{'base':{'path':str(native/'cil'),
                    'raw_sha256':subject.sha(b'native')}},
                 'operations':[{'kind':'modules','complete':True,'names':['engbox_worker'],
                                'hashes':{'engbox_worker.cil':subject.sha(b'candidate')}}]}
        with patch.object(subject.policy_preflight,'select_modules',return_value=selected), \
             patch.object(subject.policy_preflight,'bounded',side_effect=lambda path,*args:sources[path]), \
             patch.object(Path,'read_bytes',return_value=b'kernel'), \
             patch.object(subject,'absent',return_value=False), \
             patch.object(Path,'glob',return_value=[owned]):
            journal['policy_current']=subject.observe_policy(journal)
            yield journal,sources,selected,local

    def test_changed_kernel_refused_without_replacing_accepted_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);snapshot=state/'installed-policy.35';snapshot.write_bytes(b'accepted')
            journal={'policy_current':{'kernel_sha256':subject.sha(b'accepted')}}
            with patch.object(subject,'observe_policy',return_value={'kernel_sha256':subject.sha(b'drift')}):
                with self.assertRaisesRegex(ValueError,'policy_state_drift'):
                    subject.installed_policy_snapshot(state,journal)
            self.assertEqual(snapshot.read_bytes(),b'accepted')

    def test_snapshot_is_created_once_and_tamper_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);snapshot=state/'installed-policy.35'
            current={'kernel_sha256':subject.sha(b'kernel')}
            original_read=Path.read_bytes
            def read(path):
                return b'kernel' if str(path).replace('\\','/')=='/sys/fs/selinux/policy' else original_read(path)
            with patch.object(subject,'verify_policy_state',return_value=current), \
                 patch.object(Path,'read_bytes',read), \
                 patch.object(subject.policy_preflight,'bounded',side_effect=lambda path:original_read(path)), \
                 patch.object(subject.os,'O_NOFOLLOW',getattr(subject.os,'O_NOFOLLOW',0),create=True):
                self.assertEqual(subject.installed_policy_snapshot(state,{}),current['kernel_sha256'])
                snapshot.write_bytes(b'preserve rejected evidence')
                with self.assertRaisesRegex(ValueError,'snapshot_drift'):
                    subject.installed_policy_snapshot(state,{})
            self.assertEqual(snapshot.read_bytes(),b'preserve rejected evidence')

    def test_replaced_owned_module_blocks_before_any_rollback_mutation(self):
        with self.policy_fixture() as (journal,sources,selected,local):
            journal['status']='DISABLED_RESOURCES_PREPARED_NOT_DEPLOYMENT_READY'
            sources[selected['engbox_worker']/'cil']=b'administrator replacement'
            with patch.object(subject,'load',return_value=(journal,{})), \
                 patch.object(subject,'verify_resources'),patch.object(subject,'save') as save, \
                 patch.object(subject.Transaction,'command') as command:
                with self.assertRaisesRegex(ValueError,'owned_policy_source_drift'):
                    subject.rollback(Path('/synthetic'))
                command.assert_not_called();save.assert_not_called()

    def test_changed_fcontext_blocks_before_any_rollback_mutation(self):
        with self.policy_fixture() as (journal,sources,selected,local):
            journal['status']='DISABLED_RESOURCES_PREPARED_NOT_DEPLOYMENT_READY'
            sources[local]=b'/home/worker(/.*)? unconfined_u:object_r:administrator_t:s0\n'
            with patch.object(subject,'load',return_value=(journal,{})), \
                 patch.object(subject,'verify_resources'),patch.object(subject.Transaction,'command') as command:
                with self.assertRaisesRegex(ValueError,'policy_state_drift'):
                    subject.rollback(Path('/synthetic'))
                command.assert_not_called()

    def test_native_drift_and_extra_module_are_refused_even_with_same_kernel(self):
        with self.policy_fixture() as (journal,sources,selected,local):
            base=selected['base']/'cil';sources[base]=b'changed native'
            with self.assertRaisesRegex(ValueError,'native_policy_source_drift'):
                subject.verify_policy_state(journal)
            sources[base]=b'native';selected['unrelated']=Path('/synthetic/unrelated')
            with self.assertRaisesRegex(ValueError,'module_closure_drift'):
                subject.verify_policy_state(journal)

    def test_local_rule_reordering_and_regex_whitespace_are_not_normalized_away(self):
        with self.policy_fixture() as (journal,sources,selected,local):
            records=[b'/home/worker(/.*)? system_u:object_r:parent_t:s0',
                     b'/home/worker/tmp(/.*)? system_u:object_r:child_t:s0']
            sources[local]=b'\n'.join(records)
            journal['policy_current']=subject.observe_policy(journal)
            sources[local]=b'\n'.join(reversed(records))
            with self.assertRaisesRegex(ValueError,'policy_state_drift'):
                subject.verify_policy_state(journal)
            sources[local]=b'/home/escaped\\  name(/.*)? system_u:object_r:parent_t:s0'
            journal['policy_current']=subject.observe_policy(journal)
            sources[local]=b'/home/escaped\\ name(/.*)? system_u:object_r:parent_t:s0'
            with self.assertRaisesRegex(ValueError,'policy_state_drift'):
                subject.verify_policy_state(journal)

    def test_undone_module_is_not_required_on_recovery_resume(self):
        with self.policy_fixture() as (journal,sources,selected,local):
            journal['operations'][0]['undone']=True
            selected.pop('engbox_worker')
            journal['policy_current']=subject.observe_policy(journal)
            self.assertEqual(subject.verify_policy_state(journal),journal['policy_current'])

    def test_rollback_does_not_claim_success_when_original_policy_is_not_restored(self):
        journal={'status':'ROLLING_BACK','operations':[],
                 'policy_original':{'kernel_sha256':'original'}}
        with patch.object(subject,'load',return_value=(journal,{})), \
             patch.object(subject,'verify_resources'),patch.object(subject,'save') as save, \
             patch.object(subject,'verify_policy_state',return_value={'kernel_sha256':'different'}), \
             patch.object(subject.Transaction,'command'):
            with self.assertRaisesRegex(ValueError,'original_policy_not_restored'):
                subject.rollback(Path('/synthetic'))
            self.assertEqual(journal['status'],'ROLLING_BACK')
            self.assertEqual(save.call_count,1)

    def test_policy_mutation_failure_retains_incomplete_intent(self):
        journal={'operations':[],'policy_current':{'kernel_sha256':'old'}}
        with patch.object(subject,'verify_policy_state'),patch.object(subject,'save'), \
             patch.object(subject.Transaction,'command'), \
             patch.object(subject,'observe_policy',side_effect=ValueError('drift after command')):
            with self.assertRaisesRegex(ValueError,'drift after command'):
                subject.Transaction(Path('/synthetic'),journal).policy_operation(
                    {'kind':'modules'},['synthetic'])
        self.assertFalse(journal['operations'][0]['complete'])
        self.assertEqual(journal['policy_current'],{'kernel_sha256':'old'})

    def test_validating_review_bundle_never_probes_live_target_state(self):
        root=Path(__file__).resolve().parents[1]
        site,inventory=fixture()
        release={'/opt/rocky-eng/'+name:(root/name).read_bytes()
                 for name in json.loads((root/'ops/deployment/runtime-manifest.json').read_text())}
        metadata,payload=site_bundle.render(site,inventory,release,ssh_alias='synthetic',now=NOW)
        reviews={'review/policy/'+p.name:p.read_bytes() for p in (root/'ops/deployment/policy').glob('*.cil')}
        metadata['review_policy_sha256']={k:subject.sha(v) for k,v in reviews.items()}
        with tempfile.TemporaryDirectory() as temp:
            bundle=Path(temp)/'bundle.zip'
            with zipfile.ZipFile(bundle,'w') as archive:
                members={'bundle.json':json.dumps(metadata).encode(),**reviews,
                         **{'payload'+name:row['data'] for name,row in payload.items()}}
                for name,data in members.items():
                    info=zipfile.ZipInfo(name); info.create_system=3; info.external_attr=0o100644<<16
                    archive.writestr(info,data)
            with patch.object(subject,'absent',side_effect=AssertionError('live state is not bundle validation')):
                digest,files,actual=subject.validate_bundle(bundle,subject.sha(bundle.read_bytes()))
            self.assertEqual(actual['site'],site)
            self.assertEqual(len(files),63)

    def test_intent_is_durable_before_mutation_and_failure_is_recoverable(self):
        journal = {'operations':[]}
        saved = []
        def save(state, value): saved.append(json.loads(json.dumps(value)))
        def action():
            self.assertEqual(saved[-1]['operations'],[{'kind':'synthetic','complete':False}])
        with patch.object(subject,'save',side_effect=save):
            tx = subject.Transaction(Path('/synthetic'),journal,fail_after=1)
            with self.assertRaisesRegex(ValueError,'injected_failure'):
                tx.operation({'kind':'synthetic'},action)
        self.assertTrue(saved[-1]['operations'][0]['complete'])

    def test_action_failure_keeps_pending_intent(self):
        journal={'operations':[]}
        with patch.object(subject,'save') as save:
            tx=subject.Transaction(Path('/synthetic'),journal)
            with self.assertRaises(OSError):
                tx.operation({'kind':'synthetic'},lambda: (_ for _ in ()).throw(OSError('failed')))
        self.assertFalse(journal['operations'][0]['complete'])
        self.assertEqual(save.call_count,1)

    def test_ambiguous_policy_command_blocks_before_any_recovery_mutation(self):
        journal={'status':'FAILED_RECOVERY_REQUIRED','operations':[{'kind':'modules','complete':False}]}
        with patch.object(subject,'load',return_value=(journal,{})), \
             patch.object(subject,'verify_resources') as verify, patch.object(subject.Transaction,'command') as command:
            with self.assertRaisesRegex(ValueError,'ambiguous_policy_operation'):
                subject.rollback(Path('/synthetic'))
            verify.assert_not_called(); command.assert_not_called()

    def test_unknown_history_blocks_recovery_before_first_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); own=root/'known'; own.write_text('known'); extra=root/'execution.sqlite3'; extra.write_text('synthetic')
            journal={'operations':[{'kind':'directory','path':str(root),'uid':0,'gid':0,'mode':0o700}]}
            with patch.object(subject,'trusted_directory'), \
                 patch.object(subject.stat,'S_IMODE',return_value=0o700), \
                 patch.object(Path,'lstat',return_value=type('Info',(),{'st_gid':0,'st_mode':0o40700})()):
                with self.assertRaisesRegex(ValueError,'new_state_or_history_preserved'):
                    subject.verify_resources(journal,rollback_check=True)
            self.assertTrue(own.exists()); self.assertEqual(extra.read_text(),'synthetic')

    def test_busy_account_leaves_an_explicit_partial_rollback_state(self):
        account={'name':'synthetic','uid':2200,'gid':2200,'home':'/home/synthetic'}
        journal={'status':'DISABLED_RESOURCES_PREPARED_NOT_DEPLOYMENT_READY',
                 'operations':[{'kind':'user','account':account,'complete':True}]}
        saved=[]
        pwd=types.SimpleNamespace(getpwnam=lambda name:types.SimpleNamespace(pw_uid=2200,pw_gid=2200,pw_dir='/home/synthetic'))
        grp=types.SimpleNamespace()
        with patch.object(subject,'load',return_value=(journal,{})),patch.object(subject,'verify_resources'), \
             patch.object(subject,'verify_policy_state'), \
             patch.dict(sys.modules,{'pwd':pwd,'grp':grp}),patch.object(subject,'absent',return_value=True), \
             patch.object(subject,'save',side_effect=lambda state,value:saved.append(json.loads(json.dumps(value)))), \
             patch.object(subject.Transaction,'command',side_effect=ValueError('busy account')):
            with self.assertRaisesRegex(ValueError,'busy account'):subject.rollback(Path('/synthetic'))
        self.assertEqual(saved[-1]['status'],'ROLLING_BACK')
        self.assertFalse(saved[-1]['operations'][0].get('undone',False))


if __name__=='__main__': unittest.main()
