#!/usr/bin/env python3
"""Actual MCP plan generation/refusal without provider installation/execution."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from smoke_recipes import call
from providerplans import checked_script


def main():
    if os.geteuid()==0:raise RuntimeError('Run unprivileged')
    with tempfile.TemporaryDirectory(prefix='eng-provider-mcp-') as directory:
        home=Path(directory)
        cid=call(home,'case_open',{})['case_id']
        path=home/'.local/share/rocky-mcp-gateway/inbox/synthetic.bin'
        path.write_bytes(b'\x00synthetic artifact only\n');path.chmod(0o600)
        aid=call(home,'artifact_register',{'case_id':cid,'filename':path.name})['artifact_id']
        catalog=call(home,'analysis_providers',{})
        if len(catalog['providers'])!=8 or not catalog['approval_required']:
            raise RuntimeError('Provider scope advertised incorrectly')
        for provider in ('git_bundle','ansible_syntax','tsk_fsstat','volatility_banners','xfs_geometry','xfs_repair_check','xfs_recovery_experiment'):
            result=call(home,'analysis_provider_plan',{'case_id':cid,'artifact_id':aid,
                'provider':provider,'expected_version':'1.0.0'})
            if result['status']!='PLAN_ONLY_REQUIRES_SIGNED_OPERATOR_GRANT':raise RuntimeError('Plan bypassed approval')
            config=checked_script(result['execution_prepare_arguments']['script'])
            if config['source_sha256']!=hashlib.sha256(path.read_bytes()).hexdigest():raise RuntimeError('Provider source digest changed')
        windows=call(home,'analysis_provider_plan',{'case_id':cid,'artifact_id':aid,'provider':'windows_memory_info',
            'expected_version':'2.28.2','symbols_sha256':'c'*64})
        if checked_script(windows['execution_prepare_arguments']['script'])['symbols_sha256']!='c'*64:
            raise RuntimeError('Windows offline symbol binding lost')
        if (home/'.local/share/rocky-mcp-gateway/execution.sqlite3').exists():
            raise RuntimeError('Read-only plan generation created an execution')
    print('PASS: actual MCP fixed-provider catalog/plans, exact source/version, no execution or approval created; native provider runtime requires separate CI')


if __name__=='__main__':main()
