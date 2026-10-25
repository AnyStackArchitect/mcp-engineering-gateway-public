"""Offline fresh-host planning only; never probes or mutates a target host."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

MAX_INPUT = 262144
NAME = r"[a-z][a-z0-9_-]{0,30}"


class InputError(ValueError):
    """Invalid or incomplete nonsecret planning input."""


def require(condition, label):
    if not condition:
        raise InputError(label)


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected.split()), label)


def integer(value, minimum=0, maximum=2**31 - 1):
    return type(value) is int and minimum <= value <= maximum


def name(value):
    return type(value) is str and re.fullmatch(NAME, value) is not None


def linux_path(value):
    return (type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
            and str(PurePosixPath(value)) == value
            and all(p not in {'.', '..'} for p in value.split('/')[1:]))


def overlaps(a, b):
    return a == b or a.startswith(b + '/') or b.startswith(a + '/')


def duplicate_safe(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def load(path):
    # Bounded input; errors never echo raw input or accidental secrets.
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_INPUT + 1)
    require(len(raw) <= MAX_INPUT, 'input_size')
    return json.loads(raw, object_pairs_hook=duplicate_safe,
                      parse_constant=lambda _: require(False, 'nonfinite_json'))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode('utf8')).hexdigest()


def validate_site(site):
    fields = 'schema site_id hostname profile source_commit gateway worker paths min_free_bytes'
    if type(site) is dict and 'min_runtime_free_bytes' in site:
        fields += ' min_runtime_free_bytes'
    keys(site, fields, 'site_fields')
    require(type(site['schema']) is int and site['schema'] == 1, 'site_schema')
    require(name(site['site_id']), 'site_id')
    host = site['hostname']
    require(type(host) is str and 1 <= len(host) <= 253
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in host.split('.')), 'hostname')
    require(site['profile'] == 'rocky10-ssh-rootless-draft', 'profile')
    require(type(site['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', site['source_commit']), 'source_commit')
    require(integer(site['min_free_bytes'], 1024**3, 1024**5), 'min_free_bytes')
    if 'min_runtime_free_bytes' in site:
        require(integer(site['min_runtime_free_bytes'],16*1024**2,1024**3), 'min_runtime_free_bytes')
    for role in ('gateway', 'worker'):
        fields = 'name uid gid home' + (' subid_start subid_count' if role == 'worker' else '')
        account = site[role]
        keys(account, fields, role + '_fields')
        require(name(account['name']), role + '_name')
        require(integer(account['uid'], 1000, 60000) and integer(account['gid'], 1000, 60000), role + '_ids')
        require(linux_path(account['home']) and account['home'].startswith('/home/'), role + '_home')
    require(site['gateway']['name'] != site['worker']['name']
            and site['gateway']['uid'] != site['worker']['uid']
            and site['gateway']['gid'] != site['worker']['gid'], 'distinct_identities')
    worker = site['worker']
    require(integer(worker['subid_start'], 65536) and type(worker['subid_count']) is int
            and worker['subid_count'] == 65536
            and worker['subid_start'] + worker['subid_count'] <= 2**31, 'worker_subids')
    keys(site['paths'], 'code config runtime', 'path_fields')
    for role, prefix in [('code', '/opt/'), ('config', '/etc/'), ('runtime', '/run/')]:
        path = site['paths'][role]
        require(linux_path(path) and path.startswith(prefix) and '/' not in path[len(prefix):], role + '_path')
        require(path != '/run/user', role + '_reserved_path')
    paths = targets(site)
    require(all(not overlaps(a, b) for i, a in enumerate(paths) for b in paths[i + 1:]), 'overlapping_paths')


def targets(site):
    return [site['gateway']['home'], site['worker']['home'], *site['paths'].values()]


def validate_inventory(inv, now):
    keys(inv, 'schema hostname observed_utc complete os selinux cgroup_v2 tools accounts groups subuids subgids services paths ssh_stdio_verified', 'inventory_fields')
    require(type(inv['schema']) is int and inv['schema'] == 1, 'inventory_schema')
    require(type(inv['hostname']) is str, 'inventory_hostname')
    require(inv['complete'] is True, 'inventory_incomplete')
    require(type(inv['observed_utc']) is str, 'inventory_timestamp')
    try:
        observed = dt.datetime.fromisoformat(inv['observed_utc'].replace('Z', '+00:00'))
        require(observed.utcoffset() == dt.timedelta(0), 'inventory_timestamp_timezone')
        require(-300 <= (now - observed).total_seconds() <= 86400, 'inventory_stale_or_future')
    except (ValueError, TypeError):
        raise InputError('inventory_timestamp') from None
    keys(inv['os'], 'id version', 'inventory_os')
    require(all(type(v) is str for v in inv['os'].values()), 'inventory_os_values')
    require(type(inv['selinux']) is str and type(inv['cgroup_v2']) is bool
            and type(inv['ssh_stdio_verified']) is bool, 'inventory_security_values')
    keys(inv['tools'], 'python podman systemd', 'inventory_tools')
    require(all(type(v) is str and re.fullmatch(r'\d+(?:\.\d+){0,3}', v) for v in inv['tools'].values()), 'inventory_tool_versions')
    for field, fields in [('accounts', 'name uid gid'), ('groups', 'name gid'),
                          ('subuids', 'start count'), ('subgids', 'start count')]:
        rows = inv[field]
        require(type(rows) is list and len(rows) <= 10000, field)
        seen_names, seen_ids = set(), set()
        for row in rows:
            keys(row, fields, field + '_row')
            for k, v in row.items():
                require((type(v) is str and bool(v) and len(v) <= 256) if k == 'name' else integer(v), field + '_value')
            if 'name' in row:
                ident = row['uid'] if field == 'accounts' else row['gid']
                require(row['name'] not in seen_names and ident not in seen_ids, field + '_duplicate')
                seen_names.add(row['name']); seen_ids.add(ident)
            else:
                require(row['count'] > 0 and row['start'] + row['count'] <= 2**31, field + '_range')
    require(type(inv['services']) is list and len(inv['services']) <= 10000
            and all(type(x) is str and re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', x) for x in inv['services']), 'inventory_services')
    require(type(inv['paths']) is dict and len(inv['paths']) <= 100, 'inventory_paths')
    for path, row in inv['paths'].items():
        require(linux_path(path), 'inventory_path')
        keys(row, 'state ancestors_safe read_only free_bytes', 'inventory_path_row')
        require(row['state'] in ('absent', 'present', 'symlink', 'unknown')
                and type(row['ancestors_safe']) is bool and type(row['read_only']) is bool
                and integer(row['free_bytes'], 0, 1024**6), 'inventory_path_values')


def plan(site, inventory, *, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    validate_site(site)
    validate_inventory(inventory, now)
    findings = []

    def check(condition, code, correction):
        if not condition:
            findings.append({'code': code, 'correction': correction})

    check(site['hostname'] == inventory['hostname'], 'host_mismatch', 'Collect an inventory for the selected host.')
    check(inventory['os'] == {'id': 'rocky', 'version': '10.2'}, 'os_profile', 'Use the draft Rocky 10.2 profile; qualify other versions separately.')
    check(inventory['selinux'] == 'Enforcing' and inventory['cgroup_v2'], 'security_prerequisites', 'Resolve host prerequisites under separate review; do not relax enforcement.')
    minimums = {'python': (3, 12), 'podman': (5, 8, 2), 'systemd': (257,)}
    for tool, minimum in minimums.items():
        version = tuple(map(int, inventory['tools'][tool].split('.')))
        check(version + (0,) * (4 - len(version)) >= minimum + (0,) * (4 - len(minimum)),
              'tool_' + tool, 'Review the installed ' + tool + ' version; this planner installs nothing.')
    check(inventory['ssh_stdio_verified'], 'ssh_transport', 'Verify existing authorized SSH stdio access without changing credentials or host-key trust.')
    for role in ('gateway', 'worker'):
        account = site[role]
        check(not any(x['name'] == account['name'] or x['uid'] == account['uid'] for x in inventory['accounts']),
              role + '_account_collision', 'Select an unused name and UID; existing identities require a separate migration plan.')
        check(not any(x['name'] == account['name'] or x['gid'] == account['gid'] for x in inventory['groups']),
              role + '_group_collision', 'Select an unused group name and GID; do not repurpose an existing group.')
    worker = site['worker']
    start, end = worker['subid_start'], worker['subid_start'] + worker['subid_count']
    for field in ('subuids', 'subgids'):
        check(not any(start < x['start'] + x['count'] and x['start'] < end for x in inventory[field]),
              field + '_collision', 'Select a nonoverlapping subordinate-ID range after reviewing all allocations.')
    for role in ('gateway', 'worker'):
        for key, field in [('uid', 'subuids'), ('gid', 'subgids')]:
            check(not any(x['start'] <= site[role][key] < x['start'] + x['count'] for x in inventory[field]),
                  role + '_' + key + '_subid_collision', 'Select a primary ID outside every allocated subordinate-ID range.')
    check(not any(start <= x['uid'] < end for x in inventory['accounts'])
          and not any(start <= x['gid'] < end for x in inventory['groups']),
          'subids_primary_collision', 'Select a subordinate range that contains no allocated primary UID or GID.')
    service = 'engbox-worker-' + site['site_id'] + '.service'
    check(service not in inventory['services'] and 'rocky-eng-worker.service' not in inventory['services'],
          'worker_service_collision', 'Preserve the existing worker; use a separately reviewed migration rather than fresh installation.')
    for path in targets(site):
        row = inventory['paths'].get(path)
        check(row is not None, 'path_inventory_missing:' + path, 'Inspect this exact target and its ancestors without following unsafe links.')
        if row is not None:
            check(row['state'] == 'absent' and row['ancestors_safe'] and not row['read_only'],
                  'path_conflict:' + path, 'Select an unused target with trusted directory ancestors and a writable mount; preserve existing contents.')
            budget = site.get('min_runtime_free_bytes',site['min_free_bytes']) if path == site['paths']['runtime'] else site['min_free_bytes']
            check(row['free_bytes'] >= budget, 'storage:' + path,
                  'Provide the declared free-space budget on the target mount; no files are deleted by this planner.')
    return {
        'schema': 1, 'status': 'BLOCKED' if findings else 'OFFLINE_PLAN_REVIEW_REQUIRED',
        'evidence_kind': 'SUPPLIED_INVENTORY_NOT_LIVE_VERIFICATION',
        'site_sha256': digest(site), 'inventory_sha256': digest(inventory),
        'source_commit_selected_not_accepted': site['source_commit'],
        'findings': findings,
        'proposed': {'accounts': {role: site[role] for role in ('gateway', 'worker')},
                     'private_homes_mode': '0700', 'code_owner': 'root',
                     'paths': site['paths'], 'worker_service': service},
        'host_changes_performed': False, 'deployment_ready': False,
        'remaining_gates': ['fresh privileged inventory validation', 'site payload and policy review',
                            'protected public-trust enrollment approval', 'interactive operator key custody',
                            'image provenance and capacity review', 'transactional apply/rollback implementation',
                            'fresh-host isolation and live signed acceptance']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', required=True, type=Path)
    parser.add_argument('--inventory', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = plan(load(args.site), load(args.inventory))
    except (OSError, ValueError, TypeError, RecursionError):
        print(json.dumps({'status': 'INVALID_INPUT', 'host_changes_performed': False,
                          'deployment_ready': False, 'error': 'Use the documented bounded nonsecret schema and a fresh complete inventory.'}))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2 if result['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
