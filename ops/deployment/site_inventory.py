"""Read-only Linux inventory. Unknown/denied observations prevent a complete plan."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import json

import site_plan


def read(path, limit=262144):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('bounded_read')
    return data.decode('utf8')


def command(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=15, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode or len(result.stdout) > 1048576:
        raise ValueError('command_observation_failed')
    return result.stdout.decode('utf8')


def path_observation(path):
    """Inspect without following a link; unknown evidence is never treated as absence."""
    target = Path(path)
    row = {'state': 'unknown', 'ancestors_safe': False, 'read_only': True, 'free_bytes': 0}
    chain = [*reversed(target.parents), target]
    nearest = None
    missing = False
    safe = True
    try:
        for component in chain:
            try:
                info = component.lstat()
            except FileNotFoundError:
                missing = True
                continue
            if missing:
                raise ValueError('inconsistent_path')
            if stat.S_ISLNK(info.st_mode):
                row['state'] = 'symlink' if component == target else 'unknown'
                return row
            if component != target:
                safe = safe and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            if stat.S_ISDIR(info.st_mode):
                nearest = component
            elif component != target:
                raise ValueError('nondirectory_ancestor')
        if nearest is None:
            return row
        row['state'] = 'absent' if missing else 'present'
        row['ancestors_safe'] = bool(safe)
        fs = os.statvfs(nearest)
        row['read_only'] = bool(fs.f_flag & os.ST_RDONLY)
        row['free_bytes'] = fs.f_bavail * fs.f_frsize
    except (OSError, ValueError):
        return {'state': 'unknown', 'ancestors_safe': False, 'read_only': True, 'free_bytes': 0}
    return row


def database(text, group=False):
    rows = []
    homes = []
    for line in text.splitlines():
        fields = line.split(':')
        if len(fields) != (4 if group else 7):
            raise ValueError('identity_row')
        if group:
            rows.append({'name': fields[0], 'gid': int(fields[2])})
        else:
            rows.append({'name': fields[0], 'uid': int(fields[2]), 'gid': int(fields[3])})
            homes.append(fields[5])
    return rows, homes


def subids(text):
    rows = []
    for line in text.splitlines():
        if line.strip() and not line.startswith('#'):
            fields = line.split(':')
            if len(fields) != 3:
                raise ValueError('subid_row')
            rows.append({'start': int(fields[1]), 'count': int(fields[2])})
    return rows


def systemd_identity_sources():
    """Qualify only the empty static/dynamic default systemd 257 configuration.

    Unknown Varlink providers, drop-ins or live dynamic identities require a
    separate review. Do not mistake successful NSS enumeration for completeness.
    No privileged user records are read.
    """
    for name in ('/etc/userdb', '/run/userdb', '/run/host/userdb', '/usr/lib/userdb'):
        path = Path(name)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or any(path.iterdir())):
            raise ValueError('unqualified_userdb_dropins')
        if any(parent.is_symlink() for parent in path.parents):
            raise ValueError('userdb_ancestor_link')
    allowed = {'io.systemd.DropIn', 'io.systemd.DynamicUser',
               'io.systemd.Multiplexer', 'io.systemd.NameServiceSwitch'}
    path = Path('/run/systemd/userdb')
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or
            any(parent.is_symlink() for parent in path.parents)):
        raise ValueError('unsafe_userdb_directory')
    children = list(path.iterdir())
    if {p.name for p in children} != allowed:
        raise ValueError('unqualified_userdb_provider')
    for child in children:
        row = child.lstat()
        if row.st_uid != 0:
            raise ValueError('unsafe_userdb_provider')
        if child.name in {'io.systemd.DropIn', 'io.systemd.NameServiceSwitch'}:
            if not stat.S_ISLNK(row.st_mode) or os.readlink(child) != str(path/'io.systemd.Multiplexer'):
                raise ValueError('unexpected_userdb_alias')
        elif not stat.S_ISSOCK(row.st_mode):
            raise ValueError('unexpected_userdb_endpoint')
    services = command(['/usr/bin/userdbctl', '--no-pager', '--no-legend', 'services'])
    rows = [line.split() for line in services.splitlines()]
    if len(rows) != 4 or {tuple(row) for row in rows} != {(name, 'yes') for name in allowed}:
        raise ValueError('unqualified_userdb_services')
    for kind in ('user', 'group'):
        value = command(['/usr/bin/userdbctl', '-s', 'io.systemd.DynamicUser',
                         '--with-nss=no', '--with-dropin=no', '--synthesize=no',
                         '--json=short', kind])
        if value.strip():
            raise ValueError('live_dynamic_identity_requires_review')


def user_units(homes):
    units = set()
    visited = 0
    for base in ['/etc/systemd/user', '/usr/lib/systemd/user',
                 *(home + '/.config/systemd/user' for home in homes if site_plan.linux_path(home))]:
        path = Path(base)
        # Missing configuration directories are ordinary. Denied access is not.
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError('unit_directory_type')
        for parent in path.parents:
            if parent.is_symlink():
                raise ValueError('unit_directory_ancestor_link')
        def denied(error):
            raise error
        for directory, subdirs, files in os.walk(path, followlinks=False, onerror=denied):
            visited += 1
            if visited > 4096:
                raise ValueError('unit_directory_count')
            if len(Path(directory).relative_to(path).parts) > 4:
                raise ValueError('unit_directory_depth')
            units.update(name for name in files if name.endswith('.service'))
            if len(units) > 10000:
                raise ValueError('unit_count')
    return units


def collect(site, *, ssh_verified=False):
    site_plan.validate_site(site)
    errors = []

    def observe(label, action, fallback):
        try:
            return action()
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            errors.append(label)
            return fallback

    if sys.platform != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        errors.append('root_linux_observation_required')
    release = observe('os_release', lambda: dict(re.findall(r'^([A-Z_]+)=["\']?([^"\'\n]+)', read('/etc/os-release'), re.M)), {})
    passwd = observe('accounts', lambda: database(command(['/usr/bin/getent', 'passwd'])), ([], []))
    groups = observe('groups', lambda: database(command(['/usr/bin/getent', 'group']), True)[0], [])
    # NSS providers can disable enumeration. Do not claim completeness from a
    # successful getent alone. Remote/dynamic providers need separate support.
    nss = observe('nss_configuration', lambda: read('/etc/nsswitch.conf'), '')
    systemd_nss = False
    for kind in ('passwd', 'group'):
        sources = re.findall(r'^' + kind + r':\s*([^\n#]+)', nss, re.M)
        tokens = sources[0].split() if len(sources) == 1 else []
        default = ['files', 'systemd'] if kind == 'passwd' else ['files', '[SUCCESS=merge]', 'systemd']
        if tokens == default:
            systemd_nss = True
        elif tokens != ['files']:
            errors.append('unqualified_nss_' + kind)
    if systemd_nss:
        observe('unqualified_systemd_identity_sources', systemd_identity_sources, None)
    tools = {'python': '.'.join(map(str, sys.version_info[:3])), 'podman': '0', 'systemd': '0'}
    for label, args, pattern in [('podman', ['/usr/bin/podman', '--version'], r'podman version (\d+(?:\.\d+){1,3})'),
                                 ('systemd', ['/usr/bin/systemctl', '--version'], r'systemd (\d+)')]:
        def version(args=args, pattern=pattern):
            match = re.search(pattern, command(args))
            if not match:
                raise ValueError('version')
            return match[1]
        tools[label] = observe(label + '_version', version, '0')
    system = observe('system_units', lambda: command(['/usr/bin/systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager']), '')
    services = set(re.findall(r'^([A-Za-z0-9_.@-]+\.service)\s', system, re.M))
    if not services:
        errors.append('system_units_empty_or_unparsed')
    services.update(observe('user_units', lambda: user_units(passwd[1]), set()))
    paths = {path: path_observation(path) for path in site_plan.targets(site)}
    if any(row['state'] == 'unknown' for row in paths.values()):
        errors.append('unknown_path_observation')
    inventory = {'schema': 1, 'hostname': socket.gethostname(),
                 'observed_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                 'complete': False, 'os': {'id': release.get('ID', 'unknown'), 'version': release.get('VERSION_ID', 'unknown')},
                 'selinux': observe('selinux', lambda: 'Enforcing' if read('/sys/fs/selinux/enforce').strip() == '1' else 'NotEnforcing', 'unknown'),
                 'cgroup_v2': observe('cgroup_v2', lambda: {'cpu', 'memory', 'pids'} <= set(read('/sys/fs/cgroup/cgroup.controllers').split()), False),
                 'tools': tools, 'accounts': passwd[0], 'groups': groups,
                 'subuids': observe('subuids', lambda: subids(read('/etc/subuid')), []),
                 'subgids': observe('subgids', lambda: subids(read('/etc/subgid')), []),
                 'services': sorted(services), 'paths': paths, 'ssh_stdio_verified': ssh_verified}
    inventory['complete'] = not errors
    # Malformed/ambiguous enumeration must not become a planner success.
    if inventory['complete']:
        try:
            site_plan.validate_inventory(inventory, dt.datetime.now(dt.timezone.utc))
        except site_plan.InputError:
            errors.append('inventory_schema_or_ambiguous_enumeration')
            inventory['complete'] = False
    return {'collector_schema': 1, 'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'site_sha256': site_plan.digest(site), 'host_changes_performed': False,
            'status': 'OBSERVED_REVIEW_REQUIRED' if not errors else 'INCOMPLETE',
            'errors': sorted(set(errors)), 'inventory': inventory}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True)
    parser.add_argument('--ssh-verified', action='store_true', help='Attest a separately checked existing SSH stdio connection; does not test or change SSH.')
    args = parser.parse_args(argv)
    try:
        result = collect(site_plan.load(args.site), ssh_verified=args.ssh_verified)
    except (OSError, ValueError, TypeError, RecursionError):
        print('{"status":"INVALID_INPUT","host_changes_performed":false}')
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['status'] == 'OBSERVED_REVIEW_REQUIRED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
