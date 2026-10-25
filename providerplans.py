"""Fixed provider plans use the existing independently enforced sandbox grants."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re

from capacitywork import admission_lock,verify_committed_reserve
from casework import CaseError,_regular_open
from sandboxwork import MAX_INPUT_BYTES

PROVIDERS={
    'git_bundle':{'memory_mib':256,'disk_mib':32,'reference':'https://git-scm.com/docs/git-bundle','format':'self_contained_git_bundle'},
    'ansible_syntax':{'memory_mib':512,'disk_mib':32,'reference':'https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html','format':'offline_playbook_syntax_only'},
    'tsk_fsstat':{'memory_mib':512,'disk_mib':32,'reference':'https://www.sleuthkit.org/sleuthkit/man/fsstat.html','format':'raw_ext2_ext3_ext4_at_offset_zero'},
    'volatility_banners':{'memory_mib':768,'disk_mib':64,'reference':'https://volatility3.readthedocs.io/en/latest/volatility3.plugins.banners.html','format':'raw_linux_mac_banner_scan_not_memory_os_validation'},
    'xfs_geometry':{'memory_mib':512,'disk_mib':32,'reference':'https://man7.org/linux/man-pages/man8/xfs_db.8.html','format':'raw_xfs_at_offset_zero_readonly_geometry'},
    'xfs_repair_check':{'memory_mib':768,'disk_mib':32,'reference':'https://man7.org/linux/man-pages/man8/xfs_repair.8.html','format':'raw_xfs_readonly_repair_dry_run_no_modification'},
    'windows_memory_info':{'memory_mib':1536,'disk_mib':32,'reference':'https://volatility3.readthedocs.io/en/v2.28.0/getting-started-windows-tutorial.html','format':'windows_x64_PAGEDU64_crash_dump_nt10_kernel_debug_minor19041_only'},
    'xfs_recovery_experiment':{'memory_mib':1536,'disk_mib':384,'reference':'https://man7.org/linux/man-pages/man8/xfs_repair.8.html','format':'clean_xfs_regular_image_disposable_copy_primary_magic_fault_and_repair_experiment'},
}
EXPECTED=re.compile(r'[0-9][A-Za-z0-9.+!-]{0,31}\Z')
MAX_SCRIPT=11000


def script_for(provider,source_sha256,expected_version,symbols_sha256=None):
    if (type(provider) is not str or provider not in PROVIDERS or
            type(source_sha256) is not str or not re.fullmatch('[a-f0-9]{64}',source_sha256) or
            type(expected_version) is not str or not EXPECTED.fullmatch(expected_version)):
        raise CaseError('Unknown provider or invalid exact source/version identity')
    config={'provider':provider,'source_sha256':source_sha256,'expected_version':expected_version}
    source=(Path(__file__).resolve().parent/'provider_runner.py').read_text()
    if provider in ('windows_memory_info','xfs_recovery_experiment'):
        if provider=='windows_memory_info':
            if expected_version!='2.28.2' or type(symbols_sha256) is not str or not re.fullmatch('[a-f0-9]{64}',symbols_sha256):
                raise CaseError('Windows memory requires qualified Volatility2.28.2 and exact offline symbol pack SHA256')
            config['symbols_sha256']=symbols_sha256
        elif symbols_sha256 is not None:raise CaseError('Symbol pack applies only to Windows memory')
        capture=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='bounded_command')
        function='\n'.join(source.splitlines()[capture.lineno-1:capture.end_lineno])
        filename='windows_memory_runner.py' if provider=='windows_memory_info' else 'xfs_recovery_runner.py'
        source=(Path(__file__).resolve().parent/filename).read_text()+'\n'+function+'\n'
    elif symbols_sha256 is not None:raise CaseError('Symbol pack applies only to Windows memory')
    script='CONFIG = '+json.dumps(config,sort_keys=True,separators=(',',':'))+'\n'+source+'\nrun(CONFIG)\n'
    if len(script.encode())>MAX_SCRIPT:raise CaseError('Fixed provider script exceeds policy')
    ast.parse(script)
    return script


def checked_script(script):
    if type(script) is not str or len(script.encode())>MAX_SCRIPT:raise CaseError('Unknown provider script')
    line=script.split('\n',1)[0]
    if not line.startswith('CONFIG = '):raise CaseError('Execution is not a fixed provider plan')
    try:
        config=json.loads(line[len('CONFIG = '):])
        if type(config) is not dict or set(config)!=({'provider','source_sha256','expected_version','symbols_sha256'} if config.get('provider')=='windows_memory_info' else {'provider','source_sha256','expected_version'}):
            raise ValueError()
        expected=script_for(**config)
    except (ValueError,TypeError) as exc:raise CaseError('Invalid fixed provider config') from exc
    if script!=expected:raise CaseError('Provider script differs from current fixed template')
    return config


def catalog():
    return {'status':'PARTIAL','providers':[{'provider':key,**value,
        'maximum_source_bytes':min(MAX_INPUT_BYTES,(4096 if key=='windows_memory_info' else 352 if key=='xfs_recovery_experiment' else 512 if key.startswith('xfs_') else 64)*1024**2),
        'availability':'UNVERIFIED_UNTIL_APPROVED_CONTAINER_RUN','version_policy':'EXACT_OPERATOR_SELECTED_VERSION'} for key,value in PROVIDERS.items()],
        'existing_workflows':{'packet':'decode_pcap; no live capture',
            'podman':'existing signed per-job execution broker',
            'rea':'NOT_AVAILABLE_EXTERNAL_INTEGRATION; separate rea-rocky remains untouched',
        'xfs':'readonly geometry/check plus fixed disposable-copy injected-fault recovery experiment; originals never repaired'},
        'source_limit_bytes':MAX_INPUT_BYTES,'network':'NONE','approval_required':True,
        'windows_memory_process_or_kernel_analysis_qualified':False}


def plan(store,case_id,artifact_id,provider,expected_version,symbols_sha256=None):
    # Validate controls before opening evidence or generating any program.
    script_for(provider,'0'*64,expected_version,symbols_sha256)
    with store._locked(case_id) as (folder,manifest):
        path,item=store._artifact(folder,manifest,artifact_id)
        identity={'artifact_id':artifact_id,'source_sha256':item['sha256'],'source_bytes':item['bytes']}
        maximum=min(MAX_INPUT_BYTES,(4096 if provider=='windows_memory_info' else 352 if provider=='xfs_recovery_experiment' else 512 if provider.startswith('xfs_') else 64)*1024**2)
        if item['bytes']>maximum:
            return {'status':'NOT_AVAILABLE_RESOURCE_POLICY',**identity,
                'source_hash_basis':'registered_manifest_not_freshly_rehashed',
                'maximum_source_bytes':maximum,'plan_created':False,
                'policy_expansion_requires_software_validation':True}
        fd,info=_regular_open(path)
        try:
            if info.st_nlink!=1:raise CaseError('Unsafe provider source hardlink')
            with os.fdopen(fd,'rb') as stream:
                fd=-1
                hasher=hashlib.sha256()
                for block in iter(lambda:stream.read(1024*1024),b''):hasher.update(block)
                actual=hasher.hexdigest()
            after=path.lstat()
            if (actual!=item['sha256'] or info.st_size!=item['bytes'] or
                    (info.st_ino,info.st_dev,info.st_mtime_ns,info.st_size)!=
                    (after.st_ino,after.st_dev,after.st_mtime_ns,after.st_size)):
                raise CaseError('Provider source identity changed')
        finally:
            if fd>=0:os.close(fd)
    specification=PROVIDERS[provider]
    with admission_lock(store):
        verify_committed_reserve(store,extra_bytes=2*item['bytes']+specification['disk_mib']*1024**2)
    script=script_for(provider,item['sha256'],expected_version,symbols_sha256)
    return {'status':'PLAN_ONLY_REQUIRES_SIGNED_OPERATOR_GRANT','provider':provider,**identity,
        'script_sha256':hashlib.sha256(script.encode()).hexdigest(),
        'provider_availability':'UNVERIFIED_UNTIL_CONTAINER_RUN','format_scope':specification['format'],
        'source_hash_basis':'fresh_full_hash_before_plan','disk_check':'current_snapshot_not_reservation',
        'execution_prepare_arguments':{'case_id':case_id,'script':script,'artifact_ids':[artifact_id],
            'output_names':['provider-result.json','provider-raw.txt'],'timeout_seconds':180,
            'memory_mib':specification['memory_mib'],'disk_mib':specification['disk_mib']},
        'limitations':['no_host_provider_install_or_execution','no_execution_approval_created',
            'image_digest_and_per_job_approval_enforced_by_existing_broker',
            'raw_provider_output_stays_in_private_worker_artifacts',
            'other_memory_formats_and_production_volume_repair_unqualified']}


STATUSES=frozenset({'PASS','PARTIAL','NOT_AVAILABLE','NOT_AVAILABLE_ISOLATION',
    'NOT_AVAILABLE_INPUT_LAYOUT','REJECTED_INPUT','REJECTED_SOURCE_HASH',
    'NOT_AVAILABLE_VERSION_UNREADABLE','NOT_AVAILABLE_VERSION_MISMATCH',
    'NOT_AVAILABLE_UNQUALIFIED_FORMAT','NOT_AVAILABLE_SYMBOLS','LIMIT_EXCEEDED','FAILED'})


def checked_result(data,config):
    fields={'schema','provider','source_sha256','expected_version','observed_version',
        'entrypoint_sha256','status','exit_code','metrics','root_cause_established',
        'raw_output_disclosed','private_raw_output_sha256'}
    if (type(data) is not dict or set(data)!=fields or type(data['schema']) is not int or data['schema']!=1 or
            any(data.get(key)!=config[key] for key in ('provider','source_sha256','expected_version')) or
            type(data['status']) is not str or data['status'] not in STATUSES or data['root_cause_established'] is not False or
            data['raw_output_disclosed'] is not False):
        raise CaseError('Invalid bounded provider result identity')
    observed=data['observed_version']
    if observed is not None and (type(observed) is not str or not EXPECTED.fullmatch(observed)):
        raise CaseError('Invalid observed provider version')
    for field in ('entrypoint_sha256','private_raw_output_sha256'):
        value=data[field]
        if value is None and field=='entrypoint_sha256':continue
        if type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value):raise CaseError('Invalid provider output hash')
    code=data['exit_code']
    if code is not None and (type(code) is not int or not -128<=code<=255):raise CaseError('Invalid provider exit code')
    metrics=data['metrics']
    allowed={'git_bundle':{'head_count'},'ansible_syntax':{'syntax_checked','tasks_executed'},
        'tsk_fsstat':{'filesystem','inode_address_range_count','block_address_range_count'},
        'xfs_geometry':{'magic_number','block_size','data_blocks','allocation_groups'},
        'xfs_repair_check':{'readonly_check_completed','modifications_requested','filesystem_repaired'},
        'windows_memory_info':{'nt_major','nt_minor','machine_type','processor_count','kernel_debug_minor','symbols_sha256','kernel_information_parsed','process_analysis_performed','failure_reason'},
        'xfs_recovery_experiment':{'original_unchanged','clean_source_check_completed','synthetic_fault_injected','fault_detection_exit_code','copy_repair_exit_code','post_repair_check_exit_code','copy_primary_magic_restored','repaired_copy_sha256','faulted_copy_sha256','filesystem_files_restored','repair_on_original'},
        'volatility_banners':{'banner_count','offsets','offsets_omitted','memory_os_validated'}}[config['provider']]
    if type(metrics) is not dict or not set(metrics)<=allowed:raise CaseError('Unknown provider metric')
    for key,value in metrics.items():
        if key in ('syntax_checked','tasks_executed','memory_os_validated','readonly_check_completed','modifications_requested','filesystem_repaired','kernel_information_parsed','process_analysis_performed','original_unchanged','clean_source_check_completed','synthetic_fault_injected','copy_primary_magic_restored','filesystem_files_restored','repair_on_original'):
            if type(value) is not bool:raise CaseError('Invalid provider boolean')
        elif key=='filesystem':
            if value not in ('ext2','ext3','ext4'):raise CaseError('Unqualified filesystem result')
        elif key=='offsets':
            if type(value) is not list or len(value)>32 or any(type(v) is not int or not 0<=v<64*1024**2 for v in value):
                raise CaseError('Invalid bounded banner offsets')
        elif key=='symbols_sha256':
            if type(value) is not str or value!=config.get('symbols_sha256'):raise CaseError('Unapproved Windows symbol pack')
        elif key=='failure_reason':
            if value not in ('invalid_info_rows','invalid_info_row','duplicate_info_metadata','kernel_symbols_not_from_approved_pack','missing_kernel_build','unqualified_memory_architecture','unqualified_windows_version','unsupported_numeric_metadata','missing_expected_info_field','missing_nt_major','missing_nt_minor','missing_machine_type','missing_processor_count','invalid_info_json','invalid_symbol_zip','provider_io_refused','invalid_provider_data_or_io','tool_file_limit','tool_cache_full','tool_cache_io','tool_permission_refused','tool_requirements_unsatisfied','tool_internal_error','tool_exit_unspecified') or data['status']!='FAILED':
                raise CaseError('Invalid bounded Windows failure reason')
        elif key in ('faulted_copy_sha256','repaired_copy_sha256'):
            if type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value):raise CaseError('Invalid disposable-copy identity')
        elif type(value) is not int or not 0<=value<=2**48:raise CaseError('Invalid provider numeric metric')
    if data['status'] in ('PASS','PARTIAL'):
        if observed!=config['expected_version'] or data['entrypoint_sha256'] is None or code!=0:
            raise CaseError('Provider success contradicts version or process outcome')
        required={'git_bundle':{'head_count'},'ansible_syntax':allowed,'tsk_fsstat':{'filesystem'},'volatility_banners':allowed,'xfs_geometry':allowed,'xfs_repair_check':allowed,'windows_memory_info':allowed-{'failure_reason'},'xfs_recovery_experiment':allowed}[config['provider']]
        if not required<=set(metrics):raise CaseError('Provider success lacks required metrics')
        if (config['provider']=='ansible_syntax' and (metrics['syntax_checked'] is not True or metrics['tasks_executed'] is not False) or
                config['provider']=='volatility_banners' and (data['status']!='PARTIAL' or metrics['memory_os_validated'] is not False or
                    metrics['banner_count']!=len(metrics['offsets'])+metrics['offsets_omitted'])):
            raise CaseError('Provider result overstates execution or memory proof')
        if config['provider']=='xfs_repair_check' and (data['status']!='PARTIAL' or metrics!={'readonly_check_completed':True,'modifications_requested':False,'filesystem_repaired':False}):
            raise CaseError('Read-only XFS check overstates repair')
        if config['provider']=='xfs_geometry' and (metrics['magic_number']!=0x58465342 or metrics['block_size'] not in (512,1024,2048,4096,8192,16384,32768,65536) or not metrics['data_blocks'] or not metrics['allocation_groups']):
            raise CaseError('Invalid XFS geometry')
        if config['provider']=='windows_memory_info' and (data['status']!='PARTIAL' or metrics['nt_major']!=10 or metrics['nt_minor']!=0 or metrics['machine_type']!=34404 or metrics['kernel_debug_minor']!=19041 or not 1<=metrics['processor_count']<=4096 or metrics['kernel_information_parsed'] is not True or metrics['process_analysis_performed'] is not False):
            raise CaseError('Windows memory result overstates supported kernel interpretation')
        if config['provider']=='xfs_recovery_experiment' and (data['status']!='PARTIAL' or any(metrics[k] is not True for k in ('original_unchanged','clean_source_check_completed','synthetic_fault_injected','copy_primary_magic_restored')) or any(metrics[k] is not False for k in ('filesystem_files_restored','repair_on_original')) or metrics['fault_detection_exit_code']!=1 or metrics['copy_repair_exit_code']!=0 or metrics['post_repair_check_exit_code']!=0 or metrics['faulted_copy_sha256']==config['source_sha256'] or metrics['repaired_copy_sha256']==metrics['faulted_copy_sha256']):
            raise CaseError('XFS experiment overstates original repair or file recovery')
    return data


def read_result(executions,execution_id):
    with executions._db() as db:
        row=executions._row(db,execution_id)
        approved_plan=executions._verified_plan(row)
        config=checked_script(row['script'])
        if len(approved_plan['inputs'])!=1 or approved_plan['inputs'][0]['sha256']!=config['source_sha256']:
            raise CaseError('Provider plan input identity mismatch')
        if row['state']!='SUCCEEDED':
            return {'status':'NOT_AVAILABLE','reason':'provider_job_not_succeeded','execution_id':execution_id}
        if row['result_json'] is None or len(row['result_json'])>16384:raise CaseError('Provider execution result missing or oversized')
        completion=json.loads(row['result_json'])
        plan_sha256=row['digest']
    outputs=completion.get('outputs')
    if type(outputs) is not list or len(outputs)!=2:raise CaseError('Provider output inventory mismatch')
    mapped={value.get('name'):value for value in outputs if type(value) is dict}
    if set(mapped)!={'provider-result.json','provider-raw.txt'}:raise CaseError('Unknown provider output')
    with executions.cases._locked(approved_plan['case_id']) as (folder,manifest):
        lineage=manifest.get('execution_derivatives',{}).get(execution_id)
        if (type(lineage) is not dict or lineage.get('plan_sha256')!=plan_sha256 or lineage.get('outputs')!=outputs):
            raise CaseError('Provider output lineage differs from completed plan')
        content={}
        for name,item in mapped.items():
            path,meta=executions.cases._artifact(folder,manifest,item['artifact_id'])
            maximum=8192 if name=='provider-result.json' else 131072
            fd,info=_regular_open(path)
            with os.fdopen(fd,'rb') as source:
                if info.st_nlink!=1 or info.st_size>maximum or info.st_size!=item['bytes'] or meta['sha256']!=item['sha256']:
                    raise CaseError('Provider output identity or size invalid')
                raw=source.read(maximum+1)
            if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:
                raise CaseError('Provider output changed after registration')
            content[name]=raw
    data=checked_result(json.loads(content['provider-result.json']),config)
    if config['provider']=='volatility_banners' and any(v>=approved_plan['inputs'][0]['bytes'] for v in data['metrics'].get('offsets',[])):
        raise CaseError('Banner offset exceeds approved source length')
    if hashlib.sha256(content['provider-raw.txt']).hexdigest()!=data['private_raw_output_sha256']:
        raise CaseError('Provider private raw-output hash mismatch')
    return {'status':'PARTIAL','execution_id':execution_id,'plan_sha256':plan_sha256,
        'result_artifact_sha256':mapped['provider-result.json']['sha256'],'provider_result':data,
        'basis':'fixed_current_template_output_from_worker_recorded_completed_job',
        'limitations':['sandbox_self_report_not_independent_environment_attestation',
            'entrypoint_hash_not_full_package_dependency_attestation','raw_provider_output_not_disclosed',
            'tool_success_does_not_prove_source_completeness_or_root_cause']}
