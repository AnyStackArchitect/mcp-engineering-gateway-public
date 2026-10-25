import hashlib,importlib.util,json,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('public_package',ROOT/'ops/deployment/package.py')
pkg=importlib.util.module_from_spec(spec);spec.loader.exec_module(pkg)
class Packaging(unittest.TestCase):
 def fixture(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);base=Path(t.name);root=base/'source';root.mkdir()
  paths={'LICENSE','tool.py','distribution-files.json','SHA256SUMS.txt'}
  (root/'LICENSE').write_text('Synthetic notice\n');(root/'tool.py').write_text('print("synthetic")\n')
  (root/'distribution-files.json').write_text(json.dumps(sorted(paths))+'\n')
  entries={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths-{'SHA256SUMS.txt'}}
  (root/'SHA256SUMS.txt').write_text(''.join(h+'  '+p+'\n' for p,h in sorted(entries.items())),newline='\n')
  def git(args,**kw):
   if args[1]=='ls-files':return ('\0'.join(sorted(paths))+'\0').encode()
   if args[1]=='rev-parse':return 'a'*40+'\n'
   if args[1]=='status':return b''
   raise AssertionError(args)
  self.enterContext(patch.object(pkg,'ROOT',root));self.enterContext(patch.object(pkg.subprocess,'check_output',side_effect=git))
  # verify's default root binds at definition; direct it to the synthetic root.
  original=pkg.verify;self.enterContext(patch.object(pkg,'verify',side_effect=lambda:original(root,paths)))
  return base,root,paths,entries
 def test_two_packages_equal_and_manifest_matches(self):
  base,root,paths,entries=self.fixture();a=pkg.build(base/'one.zip');b=pkg.build(base/'two.zip')
  self.assertEqual(a['sha256'],b['sha256'])
  with zipfile.ZipFile(base/'one.zip') as z:
   for p,h in entries.items():self.assertEqual(hashlib.sha256(z.read('source/'+p)).hexdigest(),h)
   self.assertEqual(json.loads(z.read('provenance.json'))['repository'],'AnyStackArchitect/Mcp-eng-gw-public')
 def test_post_verify_mutation_refused_before_archive(self):
  base,root,paths,entries=self.fixture()
  def altered():
   (root/'tool.py').write_text('changed after verify');return entries
  with patch.object(pkg,'verify',side_effect=altered),self.assertRaisesRegex(ValueError,'changed during packaging'):pkg.build(base/'one.zip')
  self.assertFalse((base/'one.zip').exists())
 def test_extra_allowlist_path_refused(self):
  base,root,paths,entries=self.fixture();paths.add('unexpected.py')
  with self.assertRaises(ValueError):pkg.verify()
 def test_tampered_file_refused(self):
  base,root,paths,entries=self.fixture();(root/'tool.py').write_text('tampered')
  with self.assertRaises(ValueError):pkg.verify()
if __name__=='__main__':unittest.main()
