"""Produce deterministic operator-reviewed update/uninstall plans; never mutate a live host.

Offline apply exercises code replacement/removal in a synthetic staging root only.
Live services, accounts, policy and persistent state are handled explicitly by the administrator.
"""
import argparse,hashlib,json,os,stat
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def safe(p):
 for x in (p,*p.parents):
  if x.is_symlink() or (hasattr(x,'is_junction') and x.is_junction()):raise ValueError('link_refused')
 if not p.is_file() or p.stat().st_nlink!=1:raise ValueError('regular_single_link_required')
def plan(operation,installed,expected):
 if operation not in ('update','uninstall'):raise ValueError('operation')
 if type(expected) is not dict or len(expected)!=57:raise ValueError('full_prior_runtime_manifest_required')
 target=json.loads((ROOT/'ops/deployment/runtime-manifest.json').read_text())
 if set(expected)!=set(target):raise ValueError('unsupported_module_closure')
 changes=[]
 for name,old in sorted(expected.items()):
  if Path(name).name!=name or not name.endswith('.py'):raise ValueError('module_name')
  p=installed/name;safe(p)
  if digest(p)!=old:raise ValueError('installed_drift_preserved')
  source=ROOT/name;safe(source)
  if digest(source)!=target[name]:raise ValueError('candidate_runtime_drift')
  changes.append({'name':name,'prior_sha256':old,'candidate_sha256':target[name] if operation=='update' else None})
 return {'schema':1,'operation':operation,'files':changes,'preserve':['case stores','execution and nonce history','keys and public trust','accounts and SELinux policy','image stores','transaction journals'],
 'preconditions':['administrator authorizes maintenance','drain jobs and block gateway SSH sessions','stop and disable the site worker and its boot activation','verify snapshot and rollback files','verify exact source and plan hashes'],
 'live_apply':'manual reviewed maintenance; see docs/LIFECYCLE.md'}
def offline_apply(plan_value,root):
 # A literal marker prevents this fixture operation from targeting an installed code directory.
 marker=root/'.engineering-gateway-offline-fixture'
 safe(marker)
 if marker.read_text()!='synthetic-only\n':raise ValueError('fixture_marker')
 installed=root/'code'
 if type(plan_value) is not dict or plan_value.get('operation') not in ('update','uninstall') or type(plan_value.get('files')) is not list:raise ValueError('invalid_plan')
 rows=plan_value['files']
 if any(type(row) is not dict or set(row)!={'name','prior_sha256','candidate_sha256'} or type(row['name']) is not str or Path(row['name']).name!=row['name'] or '/' in row['name'] or '\\' in row['name'] for row in rows):raise ValueError('invalid_plan_member')
 prior={row['name']:row['prior_sha256'] for row in rows}
 if len(prior)!=len(rows) or plan_value!=plan(plan_value['operation'],installed,prior):raise ValueError('plan_identity_changed')
 replacements={}
 for row in rows:
  if plan_value['operation']=='update':
   source=ROOT/row['name'];safe(source);data=source.read_bytes()
   if hashlib.sha256(data).hexdigest()!=row['candidate_sha256']:raise ValueError('candidate_changed_before_apply')
   replacements[row['name']]=data
 for row in plan_value['files']:
  path=installed/row['name'];safe(path)
  if digest(path)!=row['prior_sha256']:raise ValueError('fixture_changed_before_apply')
 for row in plan_value['files']:
  path=installed/row['name']
  if plan_value['operation']=='uninstall':path.unlink()
  else:
   source=ROOT/row['name'];safe(source)
   if digest(source)!=row['candidate_sha256']:raise ValueError('candidate_changed_before_apply')
   # Exclusive pending file and replace; failure preserves old state plus visible pending file.
   pending=path.with_suffix('.pending')
   with pending.open('xb') as stream:stream.write(replacements[row['name']]);stream.flush();os.fsync(stream.fileno())
   os.replace(pending,path)
 return {'status':'PASS_OFFLINE_FIXTURE','live_host_tested':False,'state_preserved':True}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=('update','uninstall'))
 p.add_argument('--installed-code',type=Path,required=True);p.add_argument('--prior-manifest',type=Path,required=True)
 a=p.parse_args();print(json.dumps(plan(a.operation,a.installed_code,json.loads(a.prior_manifest.read_text())),sort_keys=True))
