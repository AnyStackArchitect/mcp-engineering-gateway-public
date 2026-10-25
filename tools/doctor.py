"""Read-only supported-host prerequisite report; never installs or changes trust."""
import argparse,json,os,platform,shutil,subprocess
from pathlib import Path

QUALIFIED_KERNEL='6.12.0-211.68.1.el10_2.x86_64'
TOOLS={'python3':(3,12),'podman':(5,8,2),'systemctl':(257,)}
REQUIRED=['getfacl','setfacl','semanage','semodule','getent','useradd','groupadd','usermod','restorecon','runuser','newuidmap','newgidmap','ssh']

# Match the actual native offline linker; the standalone secilc CLI is unused.
CIL_SYMBOLS=('cil_db_init','cil_db_destroy','cil_add_file','cil_compile','cil_build_policydb',
 'cil_set_mls','cil_set_policy_version','cil_set_multiple_decls','sepol_policydb_to_image','sepol_policydb_free')
CIL_PROBE="import ctypes; lib=ctypes.CDLL('libsepol.so.2'); assert all(callable(getattr(lib,n,None)) for n in "+repr(CIL_SYMBOLS)+")"

def cil_available():
 try:
  return subprocess.run([__import__('sys').executable,'-I','-B','-c',CIL_PROBE],
   capture_output=True,timeout=10).returncode==0
 except (OSError,subprocess.SubprocessError):return False

def evaluate(observed):
 checks={'qualified_running_kernel':observed.get('kernel')==QUALIFIED_KERNEL,'linux':observed.get('system')=='Linux','architecture':observed.get('machine') in ('x86_64','amd64'),
 'os':observed.get('os')=={'ID':'rocky','VERSION_ID':'10.2'},'selinux':observed.get('selinux')=='1',
 'cgroup_v2':set(('cpu','memory','pids'))<=set(observed.get('controllers',[])),
 'tools':all(observed.get('tools',{}).get(t) for t in REQUIRED),'python_setools':observed.get('python_setools') is True,'libsepol_cil':observed.get('libsepol_cil') is True}
 import re
 for name,minimum in TOOLS.items():
  match=re.search(r'\d+(?:\.\d+)*',observed.get('versions',{}).get(name,''))
  version=tuple(map(int,match.group().split('.'))) if match else ()
  checks[name]=version+(0,)*(4-len(version))>=minimum+(0,)*(4-len(minimum))
 return {'status':'PASS_PREREQUISITES' if all(checks.values()) else 'BLOCKED','checks':checks,
 'limits':'Read-only prerequisites only; site inventory, identities, storage, image, trust and actual installation acceptance are separate.'}
def collect():
 def read(p):
  try:return Path(p).read_text().strip()
  except OSError:return ''
 osinfo={}
 for line in read('/etc/os-release').splitlines():
  key,sep,value=line.partition('=')
  if sep and key in ('ID','VERSION_ID'):osinfo[key]=value.strip('"')
 versions={}
 for tool in TOOLS:
  try:versions[tool]=subprocess.run([tool,'--version'],capture_output=True,text=True,timeout=10,check=True).stdout[:512]
  except (OSError,subprocess.SubprocessError):versions[tool]=''
 try:
  setools_ok=subprocess.run([__import__('sys').executable,'-I','-B','-c','import setools'],capture_output=True,timeout=10).returncode==0
 except (OSError,subprocess.SubprocessError):setools_ok=False
 return {'kernel':platform.release(),'libsepol_cil':cil_available(),'python_setools':setools_ok,'system':platform.system(),'machine':platform.machine(),'os':osinfo,'selinux':read('/sys/fs/selinux/enforce'),
 'controllers':read('/sys/fs/cgroup/cgroup.controllers').split(),'tools':{x:bool(shutil.which(x)) for x in REQUIRED},'versions':versions}
if __name__=='__main__':
 result=evaluate(collect());print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result['status']=='PASS_PREREQUISITES' else 2)
