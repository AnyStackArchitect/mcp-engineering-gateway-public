import importlib.util,json,shutil,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import doctor,lifecycle,image
class Distribution(unittest.TestCase):
 def fixture(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);root=Path(t.name)
  (root/'.engineering-gateway-offline-fixture').write_text('synthetic-only\n')
  code=root/'code';code.mkdir();state=root/'state';state.mkdir();(state/'nonce.sqlite3').write_bytes(b'synthetic preserved ledger')
  manifest=json.loads((ROOT/'ops/deployment/runtime-manifest.json').read_text())
  for name in manifest:shutil.copyfile(ROOT/name,code/name)
  return root,code,state,manifest
 def test_unsupported_os_and_arch(self):
  observed={'system':'Linux','machine':'aarch64','os':{'ID':'ubuntu','VERSION_ID':'24.04'}}
  r=doctor.evaluate(observed);self.assertEqual(r['status'],'BLOCKED');self.assertFalse(r['checks']['architecture']);self.assertFalse(r['checks']['os'])
 def test_valid_prerequisites(self):
  r=doctor.evaluate({'kernel':doctor.QUALIFIED_KERNEL,'libsepol_cil':True,'python_setools':True,'system':'Linux','machine':'x86_64','os':{'ID':'rocky','VERSION_ID':'10.2'},'selinux':'1','controllers':['cpu','memory','pids'],'tools':dict.fromkeys(doctor.REQUIRED,True),'versions':{'python3':'Python 3.12.13','podman':'podman version 5.8.2','systemctl':'systemd 257'}})
  self.assertEqual(r['status'],'PASS_PREREQUISITES')
 def test_only_exact_running_kernel_is_qualified(self):
  observed={'libsepol_cil':True,'python_setools':True,'system':'Linux','machine':'x86_64','os':{'ID':'rocky','VERSION_ID':'10.2'},'selinux':'1','controllers':['cpu','memory','pids'],'tools':dict.fromkeys(doctor.REQUIRED,True),'versions':{'python3':'Python 3.12.13','podman':'podman version 5.8.2','systemctl':'systemd 257'}}
  for kernel in (None,'6.12.0-211.16.1.el10_2.0.1.x86_64','6.12.0-211.99.1.el10_2.x86_64'):
   with self.subTest(kernel=kernel):
    observed['kernel']=kernel;r=doctor.evaluate(observed)
    self.assertEqual(r['status'],'BLOCKED');self.assertFalse(r['checks']['qualified_running_kernel'])
  observed['kernel']=doctor.QUALIFIED_KERNEL
  self.assertEqual(doctor.evaluate(observed)['status'],'PASS_PREREQUISITES')
 def test_native_cil_library_is_required(self):
  observed={'kernel':doctor.QUALIFIED_KERNEL,'libsepol_cil':False,'python_setools':True,'system':'Linux','machine':'x86_64','os':{'ID':'rocky','VERSION_ID':'10.2'},'selinux':'1','controllers':['cpu','memory','pids'],'tools':dict.fromkeys(doctor.REQUIRED,True),'versions':{'python3':'Python 3.12.13','podman':'podman version 5.8.2','systemctl':'systemd 257'}}
  observed['tools']['secilc']=False
  self.assertEqual(doctor.evaluate(observed)['status'],'BLOCKED')
  observed['libsepol_cil']=True
  self.assertEqual(doctor.evaluate(observed)['status'],'PASS_PREREQUISITES')
 def test_cil_probe_rejects_missing_library(self):
  import subprocess
  prefix="import ctypes; ctypes.CDLL=lambda _: (_ for _ in ()).throw(OSError('synthetic missing library'));"
  r=subprocess.run([sys.executable,'-I','-B','-c',prefix+doctor.CIL_PROBE],capture_output=True,timeout=10)
  self.assertNotEqual(r.returncode,0)
 def test_cil_probe_rejects_missing_symbols(self):
  import subprocess
  prefix="import ctypes,types; ctypes.CDLL=lambda _: types.SimpleNamespace(cil_db_init=lambda:None);"
  r=subprocess.run([sys.executable,'-I','-B','-c',prefix+doctor.CIL_PROBE],capture_output=True,timeout=10)
  self.assertNotEqual(r.returncode,0)
 def test_update_preserves_state(self):
  root,code,state,m=self.fixture();p=lifecycle.plan('update',code,m);lifecycle.offline_apply(p,root)
  self.assertEqual((state/'nonce.sqlite3').read_bytes(),b'synthetic preserved ledger')
  for row in p['files']:self.assertEqual(lifecycle.digest(code/row['name']),row['candidate_sha256'])
 def test_uninstall_preserves_state(self):
  root,code,state,m=self.fixture();lifecycle.offline_apply(lifecycle.plan('uninstall',code,m),root)
  self.assertEqual(list(code.iterdir()),[]);self.assertTrue((state/'nonce.sqlite3').exists())
 def test_drift_refused_without_removal(self):
  root,code,state,m=self.fixture();(code/'gateway.py').write_text('changed')
  with self.assertRaisesRegex(ValueError,'drift'):lifecycle.plan('uninstall',code,m)
  self.assertEqual(len(list(code.iterdir())),57)
 def test_incomplete_manifest_refused(self):
  root,code,state,m=self.fixture();m.pop('gateway.py')
  with self.assertRaises(ValueError):lifecycle.plan('update',code,m)
 def test_missing_marker_refused(self):
  root,code,state,m=self.fixture();p=lifecycle.plan('uninstall',code,m);(root/'.engineering-gateway-offline-fixture').unlink()
  with self.assertRaises((ValueError,OSError)):lifecycle.offline_apply(p,root)
  self.assertEqual(len(list(code.iterdir())),57)
 def test_image_context_wrong_symbols_and_collision(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);symbols=p/'symbols.zip';symbols.write_bytes(b'unapproved')
   with self.assertRaises(ValueError):image.context(p/'context',symbols)
   self.assertFalse((p/'context').exists())
 def test_no_hosted_workflows(self):self.assertFalse((ROOT/'.github/workflows').exists())

 def test_crafted_lifecycle_plan_cannot_escape(self):
  root,code,state,m=self.fixture();victim=root/'victim.py';victim.write_bytes(b'preserve')
  p=lifecycle.plan('uninstall',code,m);p['files'][0]['name']='../victim.py';p['files'][0]['prior_sha256']=lifecycle.digest(victim)
  with self.assertRaises(ValueError):lifecycle.offline_apply(p,root)
  self.assertEqual(victim.read_bytes(),b'preserve');self.assertEqual(len(list(code.iterdir())),57)
 def test_mutated_lifecycle_candidate_hash_refused(self):
  root,code,state,m=self.fixture();p=lifecycle.plan('update',code,m);p['files'][0]['candidate_sha256']='0'*64
  with self.assertRaises(ValueError):lifecycle.offline_apply(p,root)
  self.assertEqual(len(list(code.iterdir())),57)
 def test_hardlinked_symbol_refused(self):
  import os
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);source=p/'one';source.write_bytes(b'x'*789065);linked=p/'two';os.link(source,linked)
   with self.assertRaises(ValueError):image.context(p/'context',linked)
   self.assertFalse((p/'context').exists())


 def test_context_manifest_names_and_hashes_actual_files(self):
  import hashlib
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);symbols=root/'synthetic-symbol-input';symbols.write_bytes(b'x'*789065)
   with patch.object(image,'SYMBOL_HASH',hashlib.sha256(symbols.read_bytes()).hexdigest()):
    image.context(root/'context',symbols)
   context=root/'context';manifest=json.loads((context/'context-manifest.json').read_text())
   self.assertEqual(set(manifest),{'Containerfile','verify_snapshot.py','provider-requirements.txt','windows.zip'})
   for name,digest in manifest.items():self.assertEqual(hashlib.sha256((context/name).read_bytes()).hexdigest(),digest)
   self.assertEqual(image.verify_context(context)['status'],'PASS_CONTEXT_CLOSURE')
   (context/'Containerfile').write_text('tamper')
   with self.assertRaisesRegex(ValueError,'context_content'):image.verify_context(context)

if __name__=='__main__':unittest.main()
