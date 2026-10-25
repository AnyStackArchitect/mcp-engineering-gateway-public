#!/usr/bin/env python3
"""End-to-end non-root, cross-process MCP recipe/semantic diff smoke."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
META={'_meta':{'io.modelcontextprotocol/protocolVersion':'2026-07-28',
               'io.modelcontextprotocol/clientCapabilities':{}}}


def run(home,script,stdin=None):
    proc=subprocess.run([sys.executable,'-u',str(ROOT/script)]+(['--once'] if script=='jobwork.py' else []),
        text=True,input=stdin,capture_output=True,env={**os.environ,'HOME':str(home)},timeout=40)
    if proc.returncode or proc.stderr:
        raise RuntimeError('Controlled child process failed: '+script)
    return proc.stdout


def call(home,tool,args):
    req=json.dumps({'jsonrpc':'2.0','id':8,'method':'tools/call',
        'params':{**META,'name':tool,'arguments':args}})+'\n'
    frames=run(home,'gateway.py',req).splitlines()
    if len(frames)!=1: raise RuntimeError('Unexpected MCP response count')
    result=json.loads(frames[0])
    if result.get('id')!=8 or 'error' in result or result.get('result',{}).get('isError'):
        raise RuntimeError('MCP tool invocation failed: '+tool)
    return json.loads(result['result']['content'][0]['text'])


def main():
    if os.geteuid()==0:
        raise RuntimeError('Run as unprivileged user')
    with tempfile.TemporaryDirectory(prefix='rocky-recipe-smoke-') as temp:
        home=Path(temp)
        cid=call(home,'case_open',{})['case_id']
        inbox=home/'.local/share/rocky-mcp-gateway/inbox'
        lines={
            'vmware.log':'hostd is not responding; vpxa disconnected',
            'veeam.log':'failed to create vm snapshot',
            'hyperv.log':'cluster node was removed',
            'nutanix.log':'foundation heartbeat timeout',
            'proxmox.log':'cluster not ready no quorum',
            'linux.log':'quadlet generator failed',
            'storage.log':'xfs metadata corruption',
            'openshift.log':'velero backup failed',
            'identity.log':'KRB_AP_ERR_MODIFIED',
        }
        for filename,msg in lines.items():
            artifact=inbox/filename
            artifact.write_text('2026-10-15T17:00:00Z '+msg+' password=hidden-secret\n')
            artifact.chmod(0o600)
            call(home,'artifact_register',{'case_id':cid,'filename':filename})
        conf1=inbox/'old.json';conf1.write_text('{"password":"oldhidden","timeout":15,"enabled":true}')
        conf2=inbox/'new.json';conf2.write_text('{"enabled":false,"timeout":30,"password":"newhidden"}')
        for p in (conf1,conf2):p.chmod(0o600)
        a=call(home,'artifact_register',{'case_id':cid,'filename':'old.json'})['artifact_id']
        b=call(home,'artifact_register',{'case_id':cid,'filename':'new.json'})['artifact_id']
        recipes=call(home,'diagnostic_recipes',{})
        declarations={}
        for pack in recipes['families']:
            family=pack['family'];path=inbox/(family+'-version.json')
            path.write_text(json.dumps({'schema':1,'family':family,'product':'fixture-product',
                'version':'1.2.3','recipe_sha256':pack['recipe_sha256']}));path.chmod(0o600)
            declarations[family]=call(home,'artifact_register',{'case_id':cid,'filename':path.name})['artifact_id']
        job=call(home,'job_submit',{'case_id':cid,'kind':'build_timeline'})
        run(home,'jobwork.py')
        if call(home,'job_result',{'job_id':job['job_id']})['state']!='SUCCEEDED':
            raise RuntimeError('Timeline worker failed')
        recipes=call(home,'diagnostic_recipes',{})
        if len(recipes['families'])!=9:raise RuntimeError('Not all approved recipes advertised')
        expected={'vmware':'esxi_hostd','veeam':'snapshot_failure','hyperv':'cluster_node_removed',
                  'nutanix':'foundation_heartbeat','proxmox':'cluster_no_quorum',
                  'linux':'quadlet_generator','storage':'xfs_metadata_corruption',
                  'openshift':'velero_backup_failure','identity':'kerberos_ticket_modified'}
        reports=[]
        for family,marker in expected.items():
            job=call(home,'job_submit',{'case_id':cid,'kind':'recipe_'+family})
            run(home,'jobwork.py')
            if call(home,'job_result',{'job_id':job['job_id']})['state']!='SUCCEEDED':
                raise RuntimeError('Recipe job did not succeed: '+family)
            report=call(home,'diagnostic_report',{'case_id':cid,'family':family})
            if marker not in {f['marker_id'] for f in report['findings']}:
                raise RuntimeError('Known-answer marker absent: '+family)
            if report['root_cause_established'] or report['status'] != 'PARTIAL':raise RuntimeError('Unproven diagnosis emitted')
            if not report['falsification_checks'] or report['platform_version_support'] != 'UNVERIFIED':
                raise RuntimeError('Recipe version or falsification boundaries absent')
            if not all(len(e['source_sha256']) == 64 for f in report['findings'] for e in f['evidence']):
                raise RuntimeError('Source hashes absent')
            reports.append(report)
            controls={'case_id':cid,'family':family,'product':'fixture-product',
                'platform_version':'1.2.3','version_artifact_id':declarations[family]}
            matched=call(home,'diagnostic_report',controls)
            if (matched['version_applicability']['status']!='DECLARATION_MATCH_COMPATIBILITY_UNVERIFIED' or
                    matched['version_applicability']['vendor_compatibility_verified'] or matched['status']!='PARTIAL'):
                raise RuntimeError('Declared version incorrectly promoted to vendor qualification')
            mismatch=call(home,'diagnostic_report',controls|{'platform_version':'2.0'})
            if mismatch['status']!='NOT_APPLICABLE_TO_REQUESTED_DECLARATION' or 'findings' in mismatch:
                raise RuntimeError('Version mismatch did not suppress recipe markers')
        delta=call(home,'config_compare',{'case_id':cid,'before_artifact_id':a,
             'after_artifact_id':b,'format':'json'})
        if delta['changed_fields']!=3:raise RuntimeError('Configuration semantic delta is incorrect')
        visible=json.dumps([reports,delta])
        for secret in ('hidden-secret','oldhidden','newhidden','password=','vmware.log'):
            if secret in visible:raise RuntimeError('Private data leaked: '+secret)
        # Replacing underlying text set makes previously saved reports stale.
        c=inbox/'extra.log';c.write_text('2026-10-15T17:00:00Z new case evidence\n');c.chmod(0o600)
        call(home,'artifact_register',{'case_id':cid,'filename':'extra.log'})
        raw=run(home,'gateway.py',json.dumps({'jsonrpc':'2.0','id':8,'method':'tools/call',
            'params':{**META,'name':'diagnostic_report','arguments':{'case_id':cid,'family':'vmware'}}})+'\n')
        if not json.loads(raw)['result']['isError']:
            raise RuntimeError('Stale recipe report was accepted')
    print('PASS: cross-session nine-family recipe jobs, source-bound version guards, config delta, privacy, stale evidence')

if __name__=='__main__':main()
