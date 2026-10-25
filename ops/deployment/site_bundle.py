"""Generate an inspectable offline payload; not a qualified host installer."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile

import site_plan
import package

ROOT = Path(__file__).resolve().parents[2]
FIXED_PATHS = {'code': '/opt/rocky-eng', 'config': '/etc/rocky-eng', 'runtime': '/run/rocky-eng'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def render(site, inventory, release, *, ssh_alias, now=None):
    report = site_plan.plan(site, inventory, now=now)
    site_plan.require(report['status'] == 'OFFLINE_PLAN_REVIEW_REQUIRED', 'blocked_site_plan')
    site_plan.require(site['paths'] == FIXED_PATHS and site['worker']['home'] == '/home/rocky-eng-worker'
                      and site['worker']['name'] == 'rocky-eng-worker', 'runtime_fixed_layout_and_worker_name')
    site_plan.require(type(ssh_alias) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', ssh_alias), 'ssh_alias')
    gateway, worker = site['gateway'], site['worker']
    payload = {path: {'data': data, 'mode': 0o644} for path, data in release.items()}
    for path in payload:
        site_plan.require(path.startswith('/opt/rocky-eng/') and path.count('/') == 3
                          and path.endswith('.py') and site_plan.linux_path(path), 'release_path')
    policy = {'schema': 1, 'gateway_uid': gateway['uid'], 'worker_uid': worker['uid'], 'socket_group_gid': worker['gid']}
    payload['/etc/rocky-eng/execution-policy.json'] = {'data': (json.dumps(policy, sort_keys=True, indent=2) + '\n').encode(), 'mode': 0o644}
    service_name = report['proposed']['worker_service']
    base = ROOT/'ops/deployment/payload'
    service = (base/'etc/systemd/user/rocky-eng-worker.service').read_text(encoding='utf8')
    # Only the environment home changes. Security directives come verbatim from
    # the accepted hardening and availability drop-ins, not string-wide UID edits.
    service = service.replace('Environment=HOME=/home/rocky-eng-worker', 'Environment=HOME=' + worker['home'])
    payload['/etc/systemd/user/' + service_name] = {'data': service.encode(), 'mode': 0o644}
    for name in ('50-engbox-hardening.conf', '60-engbox-availability.conf'):
        payload['/etc/systemd/user/' + service_name + '.d/' + name] = {'data': (base/'etc/systemd/user/rocky-eng-worker.service.d'/name).read_bytes(), 'mode': 0o644}
    payload[f'/etc/systemd/system/user-{worker["uid"]}.slice.d/50-engbox-limits.conf'] = {
        'data': (base/'etc/systemd/system/user-1001.slice.d/50-engbox-limits.conf').read_bytes(), 'mode': 0o644}
    payload['/etc/tmpfiles.d/rocky-eng-ipc.conf'] = {
        'data': f'd /run/rocky-eng 0750 {worker["name"]} {worker["name"]} - -\n'.encode(), 'mode': 0o644}
    command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-l', gateway['name'], ssh_alias, '/usr/bin/python3', '-B', '-u', '/opt/rocky-eng/gateway.py']
    metadata = {
        'schema': 1, 'kind': 'OFFLINE_REVIEW_PAYLOAD', 'deployment_ready': False,
        'site': site, 'site_sha256': site_plan.digest(site), 'inventory_sha256': site_plan.digest(inventory),
        'source_commit': site['source_commit'],
        'files': {path: {'sha256': sha(row['data']), 'bytes': len(row['data']), 'mode': row['mode'], 'owner': 'root:root'} for path, row in sorted(payload.items())},
        'account_plan': {'gateway': gateway, 'worker': worker,
                         'worker_shell': '/usr/sbin/nologin', 'worker_supplementary_groups': [],
                         'gateway_additional_group': worker['name'], 'home_mode': '0700',
                         'credential_copy_or_generation': False},
        'client': {'type': 'stdio', 'command': command[0], 'args': command[1:],
                   'authentication': 'Existing authorized key and known-host trust; verify access under gateway account separately.'},
        'excluded': ['private keys', 'public trust enrollment', 'SSH keys and authorized_keys', 'case and nonce databases', 'runner registration', 'image blobs'],
        'blockers': ['Exact-candidate fresh-host acceptance still required', 'Native SELinux assertions/vendor guard require host-specific verification',
                     'Native preparation/activation remain experimental and require explicit reviewed execution',
                     'Human public-trust and image enrollment not performed'],
        'operations_available': ['offline payload staging', 'offline payload byte verification', 'offline staging rollback',
                                 'explicit experimental native preparation and public-only activation'],
        'operations_unavailable': ['implicit live host apply', 'unapproved service activation', 'automatic private key enrollment']}
    return metadata, payload


def build(site, inventory, output, *, ssh_alias):
    package.verify()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    site_plan.require(commit == site['source_commit'], 'source_commit_mismatch')
    site_plan.require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT), 'clean_source_required')
    runtime = json.loads((ROOT/'ops/deployment/runtime-manifest.json').read_text())
    release = {'/opt/rocky-eng/' + name: (ROOT/name).read_bytes() for name in runtime}
    site_plan.require(len(release) == 57 and all(sha(data) == runtime[PurePosixPath(path).name] for path, data in release.items()), 'runtime_provenance')
    metadata, payload = render(site, inventory, release, ssh_alias=ssh_alias)
    metadata['source_manifest_sha256'] = sha((ROOT/'SHA256SUMS.txt').read_bytes())
    output = Path(output).resolve()
    site_plan.require(not output.is_relative_to(ROOT), 'output_outside_repository')
    # Exclusive create preserves any existing package. No images or trust are read.
    with output.open('xb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
            members = {'bundle.json': (json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode()}
            members.update({'payload' + path: row['data'] for path, row in payload.items()})
            # Guard bytes are retained for review only. They are not installable
            # payload entries or portable policy acceptance.
            members.update({'review/policy/' + p.name: p.read_bytes() for p in (ROOT/'ops/deployment/policy').glob('*.cil')})
            metadata['review_policy_sha256'] = {name: sha(data) for name, data in members.items() if name.startswith('review/')}
            members['bundle.json'] = (json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode()
            for name, data in sorted(members.items()):
                info = zipfile.ZipInfo(name, (2026, 10, 23, 0, 0, 0))
                info.create_system = 3; info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
    return {'status': 'OFFLINE_REVIEW_BUNDLE_CREATED', 'bytes': output.stat().st_size,
            'sha256': sha(output.read_bytes()), 'source_commit': commit, 'deployment_ready': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--ssh-alias', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build(site_plan.load(args.site), site_plan.load(args.inventory), args.output, ssh_alias=args.ssh_alias)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        print('{"status":"BUNDLE_REFUSED","deployment_ready":false}')
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
