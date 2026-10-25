"""Bounded public package/license metadata from the built image only."""
import hashlib,json
from pathlib import Path
from importlib.metadata import distribution

def main():
 total=0
 def notice(path):
  nonlocal total
  if path.is_symlink() or not path.is_file() or path.stat().st_size>256*1024:
   raise ValueError('License metadata file bound')
  with path.open('rb') as f:b=f.read(256*1024+1)
  total+=len(b)
  if len(b)>256*1024 or total>2*1024*1024:raise ValueError('License metadata aggregate bound')
  return {'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'text':b.decode('utf-8','replace')}
 result={'packages':{p.name:p.read_text() for p in Path('/opt/eng-provenance').iterdir()},
         'debian_copyright_hashes':{},'python_wheel_notices':{},'base_python_notices':{},
         'commercial_or_public_redistribution_cleared':False}
 for p in Path('/usr/share/doc').glob('*/copyright'):
  if p.is_file() and not p.is_symlink():
   if p.stat().st_size>2*1024*1024:raise ValueError('Debian notice bound')
   result['debian_copyright_hashes'][str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
 for name in ['volatility3','pefile']:
  dist=distribution(name);notices={}
  for n in dist.files or []:
   if any(part.endswith('.dist-info') for part in n.parts) and (n.name=='METADATA' or 'license' in n.name.lower() or 'copying' in n.name.lower()):
    notices[str(n)]=notice(Path(dist.locate_file(n)))
  if not notices:raise ValueError('Wheel notices missing')
  result['python_wheel_notices'][name]=notices
 for p in [Path('/usr/local/LICENSE'),Path('/usr/local/lib/python3.12/LICENSE.txt')]:
  if p.exists():result['base_python_notices'][str(p)]=notice(p)
 result['base_python_notice_missing']=not bool(result['base_python_notices'])
 print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
