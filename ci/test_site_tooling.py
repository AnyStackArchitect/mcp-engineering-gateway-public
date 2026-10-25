"""Windows-safe collector fixtures and offline bundle/staging transactions."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'ops/deployment'))
import site_inventory as collector
import site_bundle as builder
import payload_stage as staging
from test_site_plan import fixture, NOW


def supported_fixture(now=NOW):
    site, inv = fixture(now)
    site['paths'] = dict(builder.FIXED_PATHS)
    site['worker']['home'] = '/home/rocky-eng-worker'
    inv['paths'] = {p: {'state': 'absent', 'ancestors_safe': True, 'read_only': False,
                        'free_bytes': 10 * 1024**3} for p in builder.site_plan.targets(site)}
    return site, inv


def payload():
    return {'opt/rocky-eng/gateway.py': b'# synthetic\n',
            'etc/rocky-eng/execution-policy.json': b'{"synthetic":true}\n'}


def review_archive(path, mutate=None):
    site, inv = supported_fixture()
    metadata, rows = builder.render(site, inv, {'/opt/rocky-eng/gateway.py': b'# synthetic\n'}, ssh_alias='existing-alias', now=NOW)
    members = {'payload' + name: row['data'] for name, row in rows.items()}
    reviews = {'review/policy/' + p.name: p.read_bytes() for p in (ROOT/'ops/deployment/policy').glob('*.cil')}
    metadata['review_policy_sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in reviews.items()}
    members.update(reviews)
    members['bundle.json'] = json.dumps(metadata).encode()
    if mutate:
        mutate(members)
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3; info.external_attr = 0o100644 << 16
            archive.writestr(info, data)


class CollectorTests(unittest.TestCase):
    def observe(self, *, nss='passwd: files\ngroup: files\n', failure=None):
        site, inv = fixture(dt.datetime.now(dt.timezone.utc))
        reads = {'/etc/os-release': 'ID="rocky"\nVERSION_ID="10.2"\n', '/etc/nsswitch.conf': nss,
                 '/sys/fs/selinux/enforce': '1', '/sys/fs/cgroup/cgroup.controllers': 'cpu memory pids',
                 '/etc/subuid': 'other:100000:65536\n', '/etc/subgid': 'other:100000:65536\n'}
        def read(path):
            if path == failure:
                raise PermissionError('synthetic denial')
            return reads[path]
        def command(args):
            if args[0].endswith('getent'):
                return 'root:x:0:0:root:/root:/bin/bash\n' if args[1] == 'passwd' else 'root:x:0:\n'
            if args[-1] == '--version':
                return 'podman version 5.8.2' if args[0].endswith('podman') else 'systemd 257 (257.1)'
            return 'unrelated.service disabled disabled\n'
        with patch.object(collector.sys, 'platform', 'linux'), patch.object(collector.os, 'geteuid', return_value=0, create=True), \
             patch.object(collector, 'read', side_effect=read), patch.object(collector, 'command', side_effect=command), \
             patch.object(collector.socket, 'gethostname', return_value=site['hostname']), \
             patch.object(collector, 'user_units', return_value=set()), \
             patch.object(collector, 'path_observation', side_effect=lambda path: inv['paths'][path]):
            return collector.collect(site, ssh_verified=True)

    def test_complete_fixture_can_feed_planner_without_claiming_live_acceptance(self):
        result = self.observe()
        self.assertEqual(result['status'], 'OBSERVED_REVIEW_REQUIRED')
        site, inv = fixture()
        report = builder.site_plan.plan(site, result['inventory'])
        self.assertEqual(report['status'], 'OFFLINE_PLAN_REVIEW_REQUIRED')
        self.assertFalse(report['deployment_ready'])

    def test_access_denial_kept_unknown_not_replaced_with_empty_success(self):
        result = self.observe(failure='/etc/subgid')
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertFalse(result['inventory']['complete'])
        self.assertIn('subgids', result['errors'])

    def test_remote_nss_enumeration_never_assumed_complete(self):
        result = self.observe(nss='passwd: files sss systemd\ngroup: files sss\n')
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIn('unqualified_nss_passwd', result['errors'])

    def test_default_systemd_requires_independent_qualification(self):
        nss = 'passwd: files systemd\ngroup: files [SUCCESS=merge] systemd\n'
        with patch.object(collector, 'systemd_identity_sources') as qualify:
            result = self.observe(nss=nss)
        qualify.assert_called_once_with()
        self.assertTrue(result['inventory']['complete'])
        with patch.object(collector, 'systemd_identity_sources', side_effect=ValueError('unknown provider')):
            result = self.observe(nss=nss)
        self.assertFalse(result['inventory']['complete'])
        self.assertIn('unqualified_systemd_identity_sources', result['errors'])

    def test_nonstandard_nss_actions_remain_incomplete(self):
        with patch.object(collector, 'systemd_identity_sources'):
            result = self.observe(nss='passwd: files [NOTFOUND=return] systemd\ngroup: files\n')
        self.assertIn('unqualified_nss_passwd', result['errors'])

    def test_default_systemd_refuses_dropins_unknown_endpoints_and_dynamic_users(self):
        paths = {'/etc/userdb', '/run/userdb', '/run/host/userdb', '/usr/lib/userdb'}
        providers = {'io.systemd.DropIn', 'io.systemd.DynamicUser',
                     'io.systemd.Multiplexer', 'io.systemd.NameServiceSwitch'}
        def info(path):
            if path.as_posix() in paths:
                raise FileNotFoundError()
            mode = stat.S_IFDIR | 0o755
            if path.name in {'io.systemd.DropIn', 'io.systemd.NameServiceSwitch'}:
                mode = stat.S_IFLNK | 0o777
            elif path.name in providers:
                mode = stat.S_IFSOCK | 0o666
            return types.SimpleNamespace(st_mode=mode, st_uid=0)
        def listing(path):
            return iter(Path('/run/systemd/userdb')/name for name in providers)
        def command(args):
            return ''.join(name+' yes\n' for name in sorted(providers)) if args[-1] == 'services' else ''
        with patch.object(Path, 'lstat', info), patch.object(Path, 'is_symlink', return_value=False), \
             patch.object(Path, 'iterdir', listing), patch.object(collector.os, 'readlink', return_value=str(Path('/run/systemd/userdb/io.systemd.Multiplexer'))), \
             patch.object(collector, 'command', side_effect=command):
            collector.systemd_identity_sources()
            with patch.object(collector, 'command', return_value='unexpected'):
                with self.assertRaises(ValueError): collector.systemd_identity_sources()
            with patch.object(collector, 'command', side_effect=lambda args: command(args) if args[-1] == 'services' else '{"userName":"busy"}'):
                with self.assertRaises(ValueError): collector.systemd_identity_sources()
            with patch.object(Path, 'iterdir', return_value=iter([Path('/run/systemd/userdb/unrecognized')])):
                with self.assertRaises(ValueError): collector.systemd_identity_sources()
            with patch.object(Path, 'lstat', return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755, st_uid=0)), \
                 patch.object(Path, 'iterdir', return_value=iter([Path('/etc/userdb/unreviewed.user')])):
                with self.assertRaises(ValueError): collector.systemd_identity_sources()

    def test_database_parsing_never_retains_password_fields(self):
        accounts, homes = collector.database('root:synthetic-sensitive:0:0:root:/root:/bin/bash\n')
        self.assertNotIn('synthetic-sensitive', json.dumps(accounts))
        self.assertEqual(homes, ['/root'])
        with self.assertRaises(ValueError): collector.subids('broken:not-a-number:65536')

    def test_path_denial_and_link_are_not_absent(self):
        with patch.object(Path, 'lstat', side_effect=PermissionError('denied')):
            self.assertEqual(collector.path_observation('/opt/engbox')['state'], 'unknown')
        info = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        with patch.object(Path, 'lstat', return_value=info):
            result = collector.path_observation('/opt/engbox')
            self.assertNotEqual(result['state'], 'absent')
            self.assertFalse(result['ancestors_safe'])

    def test_absent_target_uses_nearest_mount_and_retains_readonly_flag(self):
        def info(path):
            if path.name == 'new-target':
                raise FileNotFoundError('synthetic absent target')
            return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        fs = types.SimpleNamespace(f_flag=1, f_bavail=5, f_frsize=4096)
        with patch.object(Path, 'lstat', info), patch.object(collector.os, 'statvfs', return_value=fs, create=True), \
             patch.object(collector.os, 'ST_RDONLY', 1, create=True):
            result = collector.path_observation('/opt/new-target')
        self.assertEqual(result['state'], 'absent')
        self.assertTrue(result['ancestors_safe'])
        self.assertTrue(result['read_only'])
        self.assertEqual(result['free_bytes'], 20480)

    def test_unsafe_existing_ancestor_not_hidden_by_absent_target(self):
        def info(path):
            if path.name == 'new-target':
                raise FileNotFoundError('synthetic absent target')
            return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=2200)
        fs = types.SimpleNamespace(f_flag=0, f_bavail=100, f_frsize=4096)
        with patch.object(Path, 'lstat', info), patch.object(collector.os, 'statvfs', return_value=fs, create=True), \
             patch.object(collector.os, 'ST_RDONLY', 1, create=True):
            result = collector.path_observation('/opt/new-target')
        self.assertFalse(result['ancestors_safe'])


class BundleTests(unittest.TestCase):
    def test_render_retains_fixed_paths_and_security_dropins(self):
        site, inv = supported_fixture()
        metadata, rows = builder.render(site, inv, {'/opt/rocky-eng/gateway.py': b'# synthetic\n'}, ssh_alias='existing-alias', now=NOW)
        self.assertFalse(metadata['deployment_ready'])
        self.assertEqual(metadata['account_plan']['worker_supplementary_groups'], [])
        policy = json.loads(rows['/etc/rocky-eng/execution-policy.json']['data'])
        self.assertEqual(policy['worker_uid'], 2201)
        self.assertEqual(policy['gateway_uid'], 2200)
        name = '/etc/systemd/user/engbox-worker-example.service.d/50-engbox-hardening.conf'
        self.assertEqual(rows[name]['data'], (ROOT/'ops/deployment/payload/etc/systemd/user/rocky-eng-worker.service.d/50-engbox-hardening.conf').read_bytes())
        self.assertIn('StrictHostKeyChecking=yes', metadata['client']['args'])
        self.assertIn('Exact-candidate fresh-host acceptance still required', metadata['blockers'])

    def test_unsupported_layout_and_ssh_option_injection_refused(self):
        site, inv = fixture()
        site['paths']['config'] = '/etc/other-engbox'
        inv['paths'][site['paths']['config']] = {'state': 'absent', 'ancestors_safe': True, 'read_only': False, 'free_bytes': 10 * 1024**3}
        with self.assertRaises(ValueError): builder.render(site, inv, {}, ssh_alias='existing-alias', now=NOW)
        site,inv = supported_fixture()
        site['worker']['name']='another-worker'
        with self.assertRaises(ValueError): builder.render(site, inv, {}, ssh_alias='existing-alias', now=NOW)
        site, inv = supported_fixture()
        for alias in ('-oProxyCommand=bad', 'host;id', 'host name', 'host\n'):
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                builder.render(site, inv, {}, ssh_alias=alias, now=NOW)

    def test_archive_verification_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'bundle.zip'
            review_archive(path)
            digest, rows, metadata = staging.bundle(path)
            self.assertEqual(len(digest), 64)
            self.assertIn('opt/rocky-eng/gateway.py', rows)
            for mutator in (lambda members: members.update({'payload/opt/rocky-eng/gateway.py': b'drift'}),
                            lambda members: members.update({'../escape': b'x'}),
                            lambda members: members.update({'extra': b'x'})):
                review_archive(path, mutator)
                with self.assertRaises(ValueError): staging.bundle(path)

    def test_symlink_compression_and_duplicate_archive_members_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'bundle.zip'
            for mode, compression, duplicate in [(0o120777, zipfile.ZIP_STORED, False),
                                                  (0o100644, zipfile.ZIP_DEFLATED, False),
                                                  (0o100644, zipfile.ZIP_STORED, True)]:
                with self.subTest(mode=mode, compression=compression, duplicate=duplicate):
                    with zipfile.ZipFile(path, 'w') as archive:
                        info = zipfile.ZipInfo('bundle.json'); info.create_system = 3
                        info.external_attr = mode << 16; info.compress_type = compression
                        archive.writestr(info, b'{}')
                        if duplicate:
                            import warnings
                            with warnings.catch_warnings():
                                warnings.simplefilter('ignore', UserWarning)
                                archive.writestr(info, b'{}')
                    with self.assertRaises(ValueError): staging.bundle(path)

    def test_bundle_source_identity_must_agree_with_site(self):
        def drift(members):
            metadata = json.loads(members['bundle.json'])
            metadata['source_commit'] = 'b' * 40
            members['bundle.json'] = json.dumps(metadata).encode()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'bundle.zip'; review_archive(path, drift)
            with self.assertRaises(ValueError): staging.bundle(path)

    def test_generation_refuses_wrong_commit_and_dirty_source_before_output(self):
        for commit, dirty in [('b'*40, b''), ('a'*40, b' M synthetic')]:
            with self.subTest(dirty=bool(dirty)), tempfile.TemporaryDirectory() as temp:
                site, inv = supported_fixture()
                output = Path(temp)/'retain.zip'
                def git(args, **kwargs):
                    return commit + '\n' if 'rev-parse' in args else dirty
                with patch.object(builder.package, 'verify', return_value={}), \
                     patch.object(builder.subprocess, 'check_output', side_effect=git), self.assertRaises(ValueError):
                    builder.build(site, inv, output, ssh_alias='existing-alias')
                self.assertFalse(output.exists())


class TransactionTests(unittest.TestCase):
    def test_roundtrip_and_existing_root_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'offline'; files = payload()
            self.assertEqual(staging.stage(root, 'a'*64, files)['status'], 'OFFLINE_STAGE_VERIFIED')
            with self.assertRaises(FileExistsError): staging.stage(root, 'a'*64, files)
            self.assertEqual(staging.verify(root, 'a'*64, files)['files'], 2)
            staging.rollback(root, 'a'*64, files)
            self.assertFalse(root.exists())

    def test_injected_failure_rolls_back_only_new_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'offline'
            with self.assertRaises(OSError): staging.stage(root, 'a'*64, payload(), fail_after=1)
            self.assertFalse(root.exists())

    def test_modified_or_foreign_evidence_prevents_any_rollback_deletion(self):
        for foreign in (False, True):
            with self.subTest(foreign=foreign), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)/'offline'; files = payload(); staging.stage(root, 'a'*64, files)
                path = root/'case-history.txt' if foreign else root/'opt/rocky-eng/gateway.py'
                path.write_bytes(b'retain synthetic human change')
                with self.assertRaises(ValueError): staging.rollback(root, 'a'*64, files)
                self.assertEqual(path.read_bytes(), b'retain synthetic human change')
                self.assertTrue((root/'etc/rocky-eng/execution-policy.json').exists())

    def test_wrong_bundle_and_hardlink_metadata_block_verify(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'offline'; files = payload(); staging.stage(root, 'a'*64, files)
            with self.assertRaises(ValueError): staging.verify(root, 'b'*64, files)
            path = root/'opt/rocky-eng/gateway.py'
            real = Path.lstat
            def lstat(value, *args, **kwargs):
                info = real(value, *args, **kwargs)
                if value == path:
                    return types.SimpleNamespace(st_mode=info.st_mode, st_nlink=2)
                return info
            with patch.object(Path, 'lstat', lstat), self.assertRaises(ValueError): staging.verify(root, 'a'*64, files)

    def test_filesystem_roots_and_relative_traversal_refused(self):
        for path in (Path(Path.cwd().anchor), Path.cwd()/'..'/'escape'):
            with self.subTest(path=path), self.assertRaises(ValueError): staging.safe_root(path)
        with tempfile.TemporaryDirectory() as temp:
            for name in ('../escape', '/etc/escape', '.', '.engbox-offline-stage.json'):
                with self.subTest(name=name), self.assertRaises(ValueError): staging.target(Path(temp), name)

    def test_journal_traversal_cannot_delete_outside_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'offline'; files = payload(); staging.stage(root, 'a'*64, files)
            outside = Path(temp)/'preserve.txt'; outside.write_bytes(b'preserve')
            path = root/staging.JOURNAL; journal = json.loads(path.read_text())
            journal['created_dirs'].append('../')
            path.write_text(json.dumps(journal))
            with self.assertRaises(ValueError): staging.rollback(root, 'a'*64, files)
            self.assertEqual(outside.read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
