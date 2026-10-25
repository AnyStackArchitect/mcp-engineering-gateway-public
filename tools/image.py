"""Prepare a public build context or verify an OCI archive. No container execution."""
import argparse,hashlib,json,os,stat,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from image_preparation import verify_oci
SYMBOL_HASH='abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e'
def context(output,symbols):
 output=Path(output);symbols=Path(symbols)
 if output.exists() or output.is_symlink():raise ValueError('new_context_required')
 if symbols.is_symlink() or any(p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()) for p in symbols.parents):raise ValueError('symbol_link_refused')
 fd=os.open(symbols,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size!=789065:raise ValueError('approved_exact_symbols_required')
  symbol_bytes=stream.read(789066)
 if len(symbol_bytes)!=789065 or hashlib.sha256(symbol_bytes).hexdigest()!=SYMBOL_HASH:raise ValueError('approved_exact_symbols_required')
 if output.resolve().is_relative_to(ROOT):raise ValueError('context_outside_source_required')
 inputs={name:(ROOT/'ci'/name).read_bytes() for name in ('verify_snapshot.py','provider-requirements.txt','Containerfile.preparation')}
 expected={}
 for line in (ROOT/'SHA256SUMS.txt').read_text().splitlines():
  digest,sep,name=line.partition('  ')
  if sep:expected[name]=digest
 for name,data in inputs.items():
  if hashlib.sha256(data).hexdigest()!=expected.get('ci/'+name):raise ValueError('recipe_source_manifest_mismatch')
 output.mkdir(mode=0o700)
 for name,data in inputs.items():
  with (output/('Containerfile' if name=='Containerfile.preparation' else name)).open('xb') as stream:stream.write(data)
 inventory={('Containerfile' if name=='Containerfile.preparation' else name):hashlib.sha256(data).hexdigest() for name,data in inputs.items()}
 inventory['windows.zip']=SYMBOL_HASH
 with (output/'context-manifest.json').open('x') as stream:json.dump(inventory,stream,sort_keys=True)
 with (output/'windows.zip').open('xb') as stream:stream.write(symbol_bytes)
 return {'status':'CONTEXT_PREPARED','symbol_sha256':SYMBOL_HASH,'image_acceptance':'NOT_RUN','rights':'Operator must have acquisition/use rights; no redistribution clearance implied.'}
def verify_context(directory):
 directory=Path(directory)
 if directory.is_symlink() or any(p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()) for p in directory.parents):raise ValueError('context_link_refused')
 expected=json.loads((directory/'context-manifest.json').read_text())
 names={'Containerfile','verify_snapshot.py','provider-requirements.txt','windows.zip'}
 if set(expected)!=names or {p.name for p in directory.iterdir()}!=names|{'context-manifest.json'}:raise ValueError('context_closure')
 for name,digest in expected.items():
  p=directory/name
  if p.is_symlink() or not p.is_file() or p.stat().st_nlink!=1 or p.stat().st_size>16*1024**2 or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('context_content')
 return {'status':'PASS_CONTEXT_CLOSURE','context_manifest_sha256':hashlib.sha256((directory/'context-manifest.json').read_bytes()).hexdigest()}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='operation',required=True)
 c=sub.add_parser('context');c.add_argument('--output',type=Path,required=True);c.add_argument('--symbols',type=Path,required=True)
 x=sub.add_parser('verify-context');x.add_argument('--context',type=Path,required=True)
 v=sub.add_parser('verify');v.add_argument('--archive',type=Path,required=True)
 a=p.parse_args()
 print(json.dumps(context(a.output,a.symbols) if a.operation=='context' else verify_context(a.context) if a.operation=='verify-context' else verify_oci(a.archive),sort_keys=True))
