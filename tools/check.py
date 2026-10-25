"""Bounded local-only syntax, JSON and selected fixture checks; no service/container execution."""
import argparse,ast,hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists() or a.output.resolve().is_relative_to(ROOT):raise ValueError('new_external_output_required')
 a.output.mkdir(parents=True);results=[]
 for path in sorted(ROOT.rglob('*')):
  if '.git' in path.parts or '__pycache__' in path.parts:continue
  if path.suffix=='.py':ast.parse(path.read_text(encoding='utf8'),filename=str(path))
  elif path.suffix=='.json':json.loads(path.read_text(encoding='utf8'))
 results.append({'gate':'syntax_json','status':'PASS'})
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
 for name,args in [('distribution',[sys.executable,'-B','-m','unittest','discover','-s','distribution_tests','-v']),('installer',[sys.executable,'-B','-m','unittest','discover','-s','ci','-v'])]:
  with (a.output/(name+'.log')).open('wb') as log:
   try:r=subprocess.run(args,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env=env,timeout=300);status='PASS' if r.returncode==0 else 'FAIL'
   except subprocess.TimeoutExpired:status='FAIL_TIMEOUT'
  results.append({'gate':name,'status':status,'log_sha256':hashlib.sha256((a.output/(name+'.log')).read_bytes()).hexdigest()})
 report={'results':results,'platform':sys.platform,'clean_host':'NOT_RUN','hosted':'NOT_RUN','image_build':'NOT_RUN'}
 (a.output/'results.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));return int(any(r['status']!='PASS' for r in results))
if __name__=='__main__':raise SystemExit(main())
