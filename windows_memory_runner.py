"""Fixed offline Windows x64 crash-dump information adapter; sandbox only."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import time
import zipfile

# script_for injects the exact current bounded_command function here.


def _number(value):
    if type(value) is int and 0<=value<=2**32:return value
    if type(value) is str and re.fullmatch(r'(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})',value):
        result=int(value,16 if value.startswith('0x') else 10)
        if result<=2**32:return result
    raise ValueError('unsupported_numeric_metadata')


def _metrics(rows,symbols_sha256):
    if type(rows) is not list or not 1<=len(rows)<=64:raise ValueError('invalid_info_rows')
    values={}
    for row in rows:
        if type(row) is not dict or type(row.get('Variable')) is not str:raise ValueError('invalid_info_row')
        key=row['Variable']
        if key in values:raise ValueError('duplicate_info_metadata')
        values[key]=row.get('Value')
    result={'nt_major':_number(values['NtMajorVersion']),'nt_minor':_number(values['NtMinorVersion']),
        'machine_type':_number(values['MachineType']),'processor_count':_number(values['KeNumberProcessors']),
        'symbols_sha256':symbols_sha256,'kernel_information_parsed':True,'process_analysis_performed':False}
    if type(values.get('Symbols')) is not str or not values['Symbols'].startswith('jar:file:/opt/eng-symbols/windows.zip!'):
        raise ValueError('kernel_symbols_not_from_approved_pack')
    build=values.get('Major/Minor')
    if type(build) is not str or not re.fullmatch(r'[0-9]{1,5}\.[0-9]{1,6}',build):raise ValueError('missing_kernel_build')
    result['kernel_debug_minor']=int(build.split('.')[1])
    if values.get('Is64Bit') not in (True,'True') or result['machine_type']!=34404 or not 1<=result['processor_count']<=4096:
        raise ValueError('unqualified_memory_architecture')
    if result['nt_major']!=10 or result['nt_minor']!=0 or result['kernel_debug_minor']!=19041:raise ValueError('unqualified_windows_version')
    # This is a fixed structural info operation, not a dump-health/OS-wide verdict.
    return result


def _symbols(path,expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>16*1024**2:return False
    actual=hashlib.sha256(path.read_bytes()).hexdigest()
    if actual!=expected:return False
    with zipfile.ZipFile(path) as archive:
        members=archive.infolist()
        if not 1<=len(members)<=64 or sum(x.file_size for x in members)>64*1024**2:return False
        for item in members:
            name=item.filename
            if '\\' in name or name.startswith('/') or '..' in name.split('/') or item.flag_bits&1:return False
            if item.file_size>16*1024**2:return False
    return True


def run(config):
    output=Path('/output');workspace=Path('/workspace');raw=bytearray()
    result={'schema':1,'provider':config['provider'],'source_sha256':config['source_sha256'],
        'expected_version':config['expected_version'],'observed_version':None,'entrypoint_sha256':None,
        'status':'NOT_AVAILABLE','exit_code':None,'metrics':{},'root_cause_established':False,'raw_output_disclosed':False}
    def finish(status):
        result['status']=status;result['private_raw_output_sha256']=hashlib.sha256(raw).hexdigest()
        (output/'provider-raw.txt').write_bytes(raw)
        (output/'provider-result.json').write_text(json.dumps(result,sort_keys=True))
    def command(argv):
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/tmp','XDG_CACHE_HOME':'/tmp',
            'LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
        # Volatility builds an offline SQLite symbol cache which may exceed
        # 64KiB. Its explicit writable paths remain private bounded tmpfs:
        # /tmp is 16MiB and /output is 32MiB; capture/CPU/cgroup limits stay.
        code,a,b=bounded_command(argv,env,unlimited_file_size=True)
        if len(raw)+len(a)+len(b)>131072:raise RuntimeError('total_capture_limit')
        raw.extend(a+b);return code,a,b
    try:
        if os.geteuid()==0:finish('NOT_AVAILABLE_ISOLATION');return
        inputs=[p for p in workspace.iterdir() if p.name!='program.py']
        if len(inputs)!=1 or not re.fullmatch('[a-f0-9]{32}',inputs[0].name):finish('NOT_AVAILABLE_INPUT_LAYOUT');return
        source=inputs[0]
        if source.is_symlink() or not source.is_file() or not 4096<=source.stat().st_size<=4*1024**3:finish('REJECTED_INPUT');return
        actual=hashlib.sha256();count=0
        with source.open('rb') as stream:
            header=stream.read(8);stream.seek(0)
            for block in iter(lambda:stream.read(1024*1024),b''):
                count+=len(block)
                if count>4*1024**3:raise RuntimeError('source_limit')
                actual.update(block)
        if actual.hexdigest()!=config['source_sha256']:finish('REJECTED_SOURCE_HASH');return
        if header!=b'PAGEDU64':finish('NOT_AVAILABLE_UNQUALIFIED_FORMAT');return
        symbols=Path('/opt/eng-symbols/windows.zip')
        if not _symbols(symbols,config['symbols_sha256']):finish('NOT_AVAILABLE_SYMBOLS');return
        exe=Path('/usr/local/bin/vol')
        if not exe.is_file():finish('NOT_AVAILABLE');return
        result['entrypoint_sha256']=hashlib.sha256(exe.read_bytes()).hexdigest()
        code,a,b=command([str(exe),'-h'])
        match=re.search(rb'Volatility 3 Framework ([0-9][\w.+!-]*)',a+b)
        if code or not match:finish('NOT_AVAILABLE_VERSION_UNREADABLE');return
        result['observed_version']=match.group(1).decode()
        if result['observed_version']!=config['expected_version']:finish('NOT_AVAILABLE_VERSION_MISMATCH');return
        # Volatility changes CACHE_PATH without creating the supplied directory.
        Path('/tmp/vol-cache').mkdir(mode=0o700,parents=True,exist_ok=True)
        code,a,b=command([str(exe),'--offline','--cache-path','/tmp/vol-cache','-s','/opt/eng-symbols','-q','-r','json','-f',str(source),'windows.info.Info'])
        result['exit_code']=code
        if code:
            diagnostic=(a+b).lower()
            reasons=((b'file too large','tool_file_limit'),(b'database or disk is full','tool_cache_full'),
                (b'no space left','tool_cache_full'),(b'disk i/o error','tool_cache_io'),
                (b'permission denied','tool_permission_refused'),(b'unsatisfied requirement','tool_requirements_unsatisfied'),
                (b'traceback','tool_internal_error'))
            result['metrics']={'failure_reason':next((reason for token,reason in reasons if token in diagnostic),'tool_exit_unspecified')}
            finish('FAILED');return
        result['metrics']=_metrics(json.loads(a),config['symbols_sha256'])
        finish('PARTIAL')
    except (subprocess.TimeoutExpired,RuntimeError):finish('LIMIT_EXCEEDED')
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as exc:
        reasons={'invalid_info_rows','invalid_info_row','duplicate_info_metadata','kernel_symbols_not_from_approved_pack',
            'missing_kernel_build','unqualified_memory_architecture','unqualified_windows_version','unsupported_numeric_metadata'}
        reason=str(exc)
        missing={'NtMajorVersion':'missing_nt_major','NtMinorVersion':'missing_nt_minor',
            'MachineType':'missing_machine_type','KeNumberProcessors':'missing_processor_count'}
        field=exc.args[0] if isinstance(exc,KeyError) and exc.args and type(exc.args[0]) is str else ''
        result['metrics']={'failure_reason':reason if type(exc) is ValueError and reason in reasons else
            missing.get(field,'missing_expected_info_field') if isinstance(exc,KeyError) else
            'invalid_info_json' if isinstance(exc,json.JSONDecodeError) else
            'invalid_symbol_zip' if isinstance(exc,zipfile.BadZipFile) else
            'provider_io_refused' if isinstance(exc,OSError) else 'invalid_provider_data_or_io'}
        finish('FAILED')
