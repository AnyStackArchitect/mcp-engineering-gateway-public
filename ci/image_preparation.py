"""Offline OCI identity verifier. Does not build, pull, import or execute images."""
import hashlib,json,os,re,shutil,signal,stat,subprocess,sys,tarfile,tempfile,time
from pathlib import Path

BASE='docker.io/library/python@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe'
TAG='localhost/rocky-ci-sandbox:prepared-v052'
GIB=1024**3
MAX_EXPORT=5*GIB

class PreparationRefusal(RuntimeError):
 def __init__(self,code,**details):
  super().__init__(code);self.code=code;self.details=details

def config_identity(value):
 """Podman versions expose Id with or without the sha256 prefix."""
 if not isinstance(value,str) or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}',value):
  raise PreparationRefusal('INVALID_CONFIG_IDENTITY')
 return 'sha256:'+value.removeprefix('sha256:')

def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def verify_oci(path,budget=lambda:None):
 """No extraction/execution. Verify exact inventory and every OCI blob."""
 path=Path(path)
 if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_EXPORT:
  raise ValueError('Invalid OCI archive file')
 with tarfile.open(path,'r:') as archive:
  members=[];names=set();logical=0
  for m in archive:
   budget();n=m.name.rstrip('/')
   if len(members)>=10000 or n in names or m.sparse is not None or m.pax_headers:
    raise ValueError('Duplicate/oversized/extended OCI inventory')
   names.add(n);members.append(m);logical+=m.size
   if m.size<0 or logical>MAX_EXPORT:raise ValueError('OCI logical size bound')
  byname={m.name.rstrip('/'):m for m in members if not m.isdir()}
  for m in members:
   n=m.name.rstrip('/')
   if m.isdir():
    if n not in ['blobs','blobs/sha256']:raise ValueError('Unexpected OCI directory')
   elif not m.isfile() or not (n in ['oci-layout','index.json'] or re.fullmatch(r'blobs/sha256/[a-f0-9]{64}',n)):
    raise ValueError('Unexpected OCI entry')
  def document(name):
   m=byname[name]
   if m.size>8*1024*1024:raise ValueError('OCI metadata too large')
   return json.load(archive.extractfile(m))
  blobs={}
  for n,m in byname.items():
   if n.startswith('blobs/'):
    h=hashlib.sha256()
    with archive.extractfile(m) as f:
     for b in iter(lambda:f.read(1024*1024),b''):budget();h.update(b)
    if h.hexdigest()!=n.rsplit('/',1)[1]:raise ValueError('OCI blob hash mismatch')
    blobs['sha256:'+h.hexdigest()]={'bytes':m.size,'sha256':h.hexdigest()}
  def descriptor(d):
   if not isinstance(d,dict) or d.get('digest') not in blobs or d.get('size')!=blobs[d['digest']]['bytes']:
    raise ValueError('OCI descriptor identity mismatch')
   return 'blobs/sha256/'+d['digest'].split(':')[1]
  if document('oci-layout')!={'imageLayoutVersion':'1.0.0'}:raise ValueError('OCI layout version')
  index=document('index.json')
  if index.get('schemaVersion')!=2 or len(index.get('manifests',[]))!=1:raise ValueError('Ambiguous OCI index')
  md=index['manifests'][0];manifest=document(descriptor(md))
  if manifest.get('schemaVersion')!=2:raise ValueError('OCI manifest version')
  config=document(descriptor(manifest['config']))
  if (config.get('os'),config.get('architecture'))!=('linux','amd64'):raise ValueError('OCI platform mismatch')
  refs={md['digest'],manifest['config']['digest']}
  for layer in manifest['layers']:descriptor(layer);refs.add(layer['digest'])
  if refs!=set(blobs):raise ValueError('Unreferenced OCI blob')
 return {'archive_bytes':path.stat().st_size,'archive_sha256':digest(path),'manifest_digest':md['digest'],
         'config_digest':manifest['config']['digest'],'platform':'linux/amd64','blobs':blobs}

