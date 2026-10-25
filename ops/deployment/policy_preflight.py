"""Snapshot and strictly link native SELinux modules with a proposed candidate.

Root Linux observation only; never installs a module or loads a kernel policy.
Reports and intermediate snapshots require a new root-private output directory.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

LIMIT = 32 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded(path, maximum=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe_policy_source')
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('oversized_policy_source')
    return data


def decode(data):
    if data.startswith(b'BZh'):
        decoder = bz2.BZ2Decompressor()
        data = decoder.decompress(data, max_length=LIMIT + 1)
        if not decoder.eof or decoder.unused_data:
            raise ValueError('bounded_decoded_module')
    if len(data) > LIMIT or b'\x00' in data:
        raise ValueError('invalid_decoded_module')
    return data


def select_modules(root, *, allow_candidate=False):
    """Highest-priority instance wins; unknown/disabled states fail closed."""
    if any((root/'disabled').iterdir()):
        raise ValueError('disabled_modules_require_review')
    selected = {}
    for priority in root.iterdir():
        if priority.name == 'disabled':
            continue
        info = priority.lstat()
        if not priority.name.isdigit() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe_module_priority')
        for module in priority.iterdir():
            info = module.lstat()
            if not re.fullmatch(r'[A-Za-z0-9_-]+', module.name) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('unsafe_module_directory')
            current = selected.get(module.name)
            if current is None or int(priority.name) > int(current.parent.name):
                selected[module.name] = module
    if 'base' not in selected or len(selected) > 1024:
        raise ValueError('native_module_count')
    if not allow_candidate and any(name.startswith('engbox_') for name in selected):
        raise ValueError('candidate_already_installed')
    return dict(sorted(selected.items()))


def execute(args, output, label):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=180)
    (output/(label+'.stdout')).write_bytes(result.stdout)
    (output/(label+'.stderr')).write_bytes(result.stderr)
    return {'argv': args, 'exit_code': result.returncode,
            'stdout_sha256': digest(result.stdout), 'stderr_sha256': digest(result.stderr)}


def preflight(output):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('root_linux_observation_required')
    if Path('/sys/fs/selinux/enforce').read_text().strip() != '1':
        raise ValueError('selinux_enforcing_required')
    if not output.is_absolute() or output == Path('/'):
        raise ValueError('new_private_output_required')
    for parent in output.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe_output_ancestor')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    source = Path(__file__).resolve().parent
    for name in ('strict_link.py', 'check_candidate_assertions.py', 'check_global_assertions.py'):
        bounded(source/name)
    original = digest(Path('/sys/fs/selinux/policy').read_bytes())
    modules = select_modules(Path('/var/lib/selinux/targeted/active/modules'))
    decoded = {}
    native = {}
    total = 0
    for name, path in modules.items():
        raw = bounded(path/'cil')
        data = decode(raw)
        total += len(data)
        if total > 128 * 1024 * 1024:
            raise ValueError('aggregate_module_size')
        native[name] = {'path':str(path/'cil'), 'raw_sha256':digest(raw), 'decoded_sha256':digest(data)}
        decoded[name] = data
    candidates = {p.name:bounded(p) for p in sorted((source/'policy').glob('*.cil'))}
    expected = {'engbox_worker.cil', 'engbox_vendor_assertion_guard.cil',
                'engbox_worker_statfs.cil', 'engbox_worker_boot_runtime.cil'}
    if set(candidates) != expected:
        raise ValueError('exact_candidate_closure')
    report = {'schema':1, 'status':'POLICY_PREFLIGHT_BLOCKED', 'deployment_ready':False,
              'host_policy_loaded':False, 'kernel_policy_sha256':original,
              'native_modules':native, 'candidate_hashes':{k:digest(v) for k,v in candidates.items()},
              'runs':{}}
    for variant in ('native', 'candidate'):
        directory = output/variant
        directory.mkdir(mode=0o700)
        inputs = []
        for name,data in decoded.items():
            filename = 'native-'+name+'.cil'
            (directory/filename).write_bytes(data)
            inputs.append(filename)
        if variant == 'candidate':
            for name,data in candidates.items():
                (directory/name).write_bytes(data)
                inputs.append(name)
        (directory/'link-inputs.json').write_text(json.dumps(inputs))
        (directory/'strict_link.py').write_bytes(bounded(source/'strict_link.py'))
        report['runs'][variant] = execute(['/usr/bin/python3','-I','-B',str(directory/'strict_link.py')], directory, 'strict-link')
    candidate = output/'candidate'
    if report['runs']['candidate']['exit_code'] == 0:
        for label, args in (
            ('candidate-assertions', ['check_candidate_assertions.py','--candidate',str(candidate/'engbox_worker.cil')]),
            ('global-assertions', ['check_global_assertions.py','--base',str(candidate/'native-base.cil'),
                                   '--guard',str(candidate/'engbox_vendor_assertion_guard.cil')])):
            script, *rest = args
            report['runs'][label] = execute(['/usr/bin/python3','-I','-B',str(source/script),
                '--policy',str(candidate/'combined-policy.35'),'--output',str(candidate/(label+'.json')),*rest], candidate, label)
        if all(report['runs'][name]['exit_code'] == 0 for name in ('candidate','candidate-assertions','global-assertions')):
            report['status'] = 'OFFLINE_POLICY_CANDIDATE_CHECKS_PASS_REVIEW_REQUIRED'
    report['policy_unchanged'] = digest(Path('/sys/fs/selinux/policy').read_bytes()) == original
    current = select_modules(Path('/var/lib/selinux/targeted/active/modules'))
    report['module_sources_unchanged'] = (set(current) == set(modules) and all(
        str(current[name]/'cil') == native[name]['path'] and
        digest(bounded(current[name]/'cil')) == native[name]['raw_sha256'] for name in current))
    if not report['policy_unchanged'] or not report['module_sources_unchanged']:
        report['status'] = 'POLICY_CHANGED_DURING_OBSERVATION'
    (output/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = preflight(args.output)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'status':'POLICY_PREFLIGHT_BLOCKED','error':type(error).__name__,
                          'host_policy_loaded':False,'deployment_ready':False}))
        return 2
    print(json.dumps({k:v for k,v in report.items() if k not in {'native_modules','runs'}}))
    return 0 if report['status'] == 'OFFLINE_POLICY_CANDIDATE_CHECKS_PASS_REVIEW_REQUIRED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
