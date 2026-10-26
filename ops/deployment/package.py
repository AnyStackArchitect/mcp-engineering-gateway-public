"""Verify the tracked source closure and produce a deterministic distribution source package."""
import argparse,hashlib,json,re,subprocess,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()
def tracked():
 return set(subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0'))-{''}
def verify(root=ROOT,paths=None):
 paths=tracked() if paths is None else set(paths)
 entries={}
 for line in (root/'SHA256SUMS.txt').read_text(encoding='utf8').splitlines():
  digest,sep,name=line.partition('  ')
  if not sep or not re.fullmatch('[0-9a-f]{64}',digest) or name in entries:raise ValueError('Invalid source manifest')
  p=PurePosixPath(name)
  if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name:raise ValueError('Unsafe source path')
  entries[name]=digest
 if root == ROOT and paths != set(json.loads((root/'distribution-files.json').read_text())):raise ValueError('Public allowlist differs from tracked files')
 if set(entries)!=paths-{'SHA256SUMS.txt'}:raise ValueError('Manifest does not cover exactly the tracked files')
 for name,digest in entries.items():
  path=root/name
  if path.is_symlink() or any(p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()) for p in (path,*path.parents)) or not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or path.stat().st_nlink!=1 or sha(path.read_bytes())!=digest:raise ValueError('Source identity/type mismatch: '+name)
  if path.name in {'.credentials','.credentials_rsaparams','grant.json','execution.sqlite3'} or path.suffix in {'.key','.pfx','.p12'}:raise ValueError('Secret/state path excluded')
  if re.search(rb'^-----BEGIN (?:ENCRYPTED |RSA |OPENSSH |EC )?PRIVATE KEY-----',path.read_bytes(),re.M):raise ValueError('Private key material excluded')
 return entries
def build(output):
 entries=verify();output=output.resolve()
 if output.is_relative_to(ROOT):raise ValueError('Delivery must be outside the repository')
 if output.exists():raise ValueError('Existing delivery retained')
 commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
 if subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT):raise ValueError('Commit and clean source required')
 # Freeze and verify the exact bytes to be archived; never reread source after validation.
 snapshot={name:(ROOT/name).read_bytes() for name in set(entries)|{'SHA256SUMS.txt'}}
 if any(sha(snapshot[name])!=digest for name,digest in entries.items()):raise ValueError('Source changed during packaging')
 expected=''.join(digest+'  '+name+'\n' for name,digest in sorted(entries.items())).encode()
 if snapshot['SHA256SUMS.txt']!=expected:raise ValueError('Manifest changed or noncanonical')
 if subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT):raise ValueError('Source changed during packaging')
 with output.open('xb') as stream:
  # Stored members and explicit platform metadata make delivery bytes identical
  # on Windows/Linux regardless of their zlib builds or permission defaults.
  with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as z:
   for name in sorted(set(entries)|{'SHA256SUMS.txt'}):
    info=zipfile.ZipInfo('source/'+name,(2026,10,23,0,0,0));info.create_system=3;info.compress_type=zipfile.ZIP_STORED;info.external_attr=0o100644<<16;z.writestr(info,snapshot[name])
   info=zipfile.ZipInfo('provenance.json',(2026,10,23,0,0,0));info.create_system=3;info.external_attr=0o100644<<16;z.writestr(info,json.dumps({'repository':'AnyStackArchitect/mcp-engineering-gateway-public','commit':commit,'source_manifest_sha256':sha(snapshot['SHA256SUMS.txt']),'contains_image_blobs':False,'image_delivery':'operator-build; see docs/IMAGE.md'},sort_keys=True)+'\n')
 return {'status':'DISTRIBUTION_PACKAGE_PASS','commit':commit,'bytes':output.stat().st_size,'sha256':sha(output.read_bytes()),'source_manifest_sha256':sha(snapshot['SHA256SUMS.txt'])}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path);args=p.parse_args()
 print(json.dumps(build(args.output) if args.output else {'status':'SOURCE_CLOSURE_PASS','files':len(verify())},sort_keys=True))
