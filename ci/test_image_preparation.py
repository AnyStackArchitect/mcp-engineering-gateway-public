"""Offline refusal/integrity tests; never instantiate a builder or run containers."""
import hashlib,io,json,os,tarfile,tempfile,time,unittest,sys,stat
from pathlib import Path
from unittest.mock import patch,Mock,mock_open
from contextlib import ExitStack,redirect_stdout
from types import SimpleNamespace
import image_preparation as build
import verify_snapshot as snapshot

class OCIIntegrity(unittest.TestCase):
 def test_podman_config_identity_forms(self):
  h='a'*64
  self.assertEqual(build.config_identity(h),build.config_identity('sha256:'+h))
  self.assertNotEqual(build.config_identity(h),build.config_identity('b'*64))
 def test_podman_config_identity_invalid(self):
  for value in ['a'*12,'SHA256:'+'a'*64,'sha256:'+'A'*64,None,'sha256:'+'a'*64+'\n']:
   with self.assertRaises(build.PreparationRefusal):build.config_identity(value)
 def archive(self,root,change=None):
  config=json.dumps({'architecture':'amd64','os':'linux'}).encode();layer=b'public synthetic layer'
  blobs={}
  def desc(b):
   h=hashlib.sha256(b).hexdigest();blobs['blobs/sha256/'+h]=b
   return {'digest':'sha256:'+h,'size':len(b)}
  cd=desc(config);ld=desc(layer)
  manifest=json.dumps({'schemaVersion':2,'config':cd,'layers':[ld]}).encode();md=desc(manifest)
  entries={'oci-layout':b'{"imageLayoutVersion":"1.0.0"}','index.json':json.dumps({'schemaVersion':2,'manifests':[md]}).encode(),**blobs}
  if change:change(entries)
  p=root/'test.oci.tar'
  with tarfile.open(p,'w') as t:
   for name,b in entries.items():
    m=tarfile.TarInfo(name);m.size=len(b);t.addfile(m,io.BytesIO(b))
  return p
 def test_exact_archive_pass(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.archive(Path(d));r=build.verify_oci(p)
   self.assertEqual(r['archive_sha256'],build.digest(p));self.assertEqual(len(r['blobs']),3)
 def rejects(self,change):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises((ValueError,KeyError)):build.verify_oci(self.archive(Path(d),change))
 def test_blob_tampering(self):self.rejects(lambda e:e.__setitem__(next(n for n in e if n.startswith('blobs/')),b'bad'))
 def test_extra_file(self):self.rejects(lambda e:e.__setitem__('private.pem',b'never permitted'))
 def test_traversal(self):self.rejects(lambda e:e.__setitem__('../escaped',b'bad'))
 def test_unreferenced_blob(self):self.rejects(lambda e:e.__setitem__('blobs/sha256/'+hashlib.sha256(b'extra').hexdigest(),b'extra'))
 def test_descriptor_size(self):
  def change(e):
   j=json.loads(e['index.json']);j['manifests'][0]['size']+=1;e['index.json']=json.dumps(j).encode()
  self.rejects(change)
 def test_multiple_images(self):
  def change(e):
   j=json.loads(e['index.json']);j['manifests']*=2;e['index.json']=json.dumps(j).encode()
  self.rejects(change)
 def test_duplicate_member(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.archive(Path(d))
   with tarfile.open(p,'a') as t:
    m=tarfile.TarInfo('index.json');m.size=2;t.addfile(m,io.BytesIO(b'{}'))
   with self.assertRaises(ValueError):build.verify_oci(p)
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   p=self.archive(Path(d))
   with tarfile.open(p,'a') as t:
    m=tarfile.TarInfo('link');m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';t.addfile(m)
   with self.assertRaises(ValueError):build.verify_oci(p)
 def test_declared_logical_oversize(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'large.tar';m=tarfile.TarInfo('blobs/sha256/'+'0'*64);m.size=build.MAX_EXPORT+1
   p.write_bytes(m.tobuf()+b'\0'*1024)
   with self.assertRaises(ValueError):build.verify_oci(p)

class SnapshotIntegrity(unittest.TestCase):
 def signed(self,b):return b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'+b+b'-----BEGIN PGP SIGNATURE-----\nsynthetic\n-----END PGP SIGNATURE-----\n'
 def test_payload_dash_unescape(self):self.assertEqual(snapshot.payload(self.signed(b'Field: test\n- -dash\n')),b'Field: test\n-dash\n')
 def test_unsigned_rejected(self):
  with self.assertRaises(ValueError):snapshot.payload(b'unsigned')
 def test_unknown_snapshot_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'one_InRelease').write_bytes(self.signed(b'Unapproved\n'))
   with self.assertRaises(ValueError):snapshot.verify(d)


if __name__=="__main__":unittest.main()
