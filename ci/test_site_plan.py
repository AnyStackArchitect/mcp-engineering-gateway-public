"""Synthetic portability planning; no target-host access or provisioning."""
import contextlib
import copy
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('site_plan', ROOT / 'ops/deployment/site_plan.py')
planner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(planner)
NOW = dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc)


def fixture(now=NOW):
    site = {
        'schema': 1, 'site_id': 'example', 'hostname': 'lab-example',
        'profile': 'rocky10-ssh-rootless-draft', 'source_commit': 'a' * 40,
        'gateway': {'name': 'engbox_gateway', 'uid': 2200, 'gid': 2200, 'home': '/home/engbox_gateway'},
        'worker': {'name': 'rocky-eng-worker', 'uid': 2201, 'gid': 2201, 'home': '/home/rocky-eng-worker',
                   'subid_start': 200000, 'subid_count': 65536},
        'paths': {'code': '/opt/rocky-eng', 'config': '/etc/rocky-eng', 'runtime': '/run/rocky-eng'},
        'min_free_bytes': 1024**3, 'min_runtime_free_bytes':16*1024**2}
    inv = {
        'schema': 1, 'hostname': 'lab-example', 'observed_utc': now.isoformat(), 'complete': True,
        'os': {'id': 'rocky', 'version': '10.2'}, 'selinux': 'Enforcing', 'cgroup_v2': True,
        'tools': {'python': '3.12.11', 'podman': '5.8.2', 'systemd': '257'},
        'accounts': [{'name': 'root', 'uid': 0, 'gid': 0}], 'groups': [{'name': 'root', 'gid': 0}],
        'subuids': [{'start': 100000, 'count': 65536}], 'subgids': [{'start': 100000, 'count': 65536}],
        'services': ['unrelated.service'], 'ssh_stdio_verified': True,
        'paths': {p: {'state': 'absent', 'ancestors_safe': True, 'read_only': False,
                      'free_bytes': 10 * 1024**3} for p in planner.targets(site)}}
    return site, inv


class SitePlanTests(unittest.TestCase):
    def test_clear_fixture_is_review_only_not_live_acceptance(self):
        site, inv = fixture()
        before = copy.deepcopy((site, inv))
        result = planner.plan(site, inv, now=NOW)
        self.assertEqual(result['status'], 'OFFLINE_PLAN_REVIEW_REQUIRED')
        self.assertFalse(result['deployment_ready'])
        self.assertFalse(result['host_changes_performed'])
        self.assertEqual(result['findings'], [])
        self.assertEqual((site, inv), before)
        self.assertEqual(result['inventory_sha256'], planner.digest(inv))
        self.assertIn('fresh-host isolation and live signed acceptance', result['remaining_gates'])

    def test_schema_unknown_fields_and_secret_fields_refused(self):
        for field in ('passphrase', 'private_key', 'unknown'):
            site, inv = fixture()
            site[field] = 'synthetic-do-not-echo'
            with self.subTest(field=field), self.assertRaises(planner.InputError):
                planner.plan(site, inv, now=NOW)

    def test_reserved_ids_boolean_ids_and_duplicate_identities_refused(self):
        for role, field, value in [('gateway', 'uid', 0), ('worker', 'uid', True),
                                   ('worker', 'uid', 2200), ('worker', 'gid', 2200),
                                   ('worker', 'name', 'engbox_gateway')]:
            site, inv = fixture(); site[role][field] = value
            with self.subTest(role=role, field=field, value=value), self.assertRaises(planner.InputError):
                planner.plan(site, inv, now=NOW)

    def test_path_traversal_shell_syntax_reserved_and_overlap_refused(self):
        for path in ('/opt/../etc', '/opt//unsafe', '/opt/x/', '/opt/$(id)', '/opt/x\n', '/etc', '/', 'C:\\x', '/opt/x/y'):
            site, inv = fixture(); site['paths']['code'] = path
            with self.subTest(path=path), self.assertRaises(planner.InputError):
                planner.plan(site, inv, now=NOW)
        site, inv = fixture(); site['worker']['home'] = site['gateway']['home'] + '/child'
        with self.assertRaises(planner.InputError): planner.plan(site, inv, now=NOW)
        site, inv = fixture(); site['paths']['runtime'] = '/run/user'
        with self.assertRaises(planner.InputError): planner.plan(site, inv, now=NOW)

    def test_fresh_host_refuses_existing_accounts_groups_services(self):
        for key, row, expected in [
            ('accounts', {'name': 'other', 'uid': 2201, 'gid': 9}, 'worker_account_collision'),
            ('accounts', {'name': 'engbox_gateway', 'uid': 3300, 'gid': 9}, 'gateway_account_collision'),
            ('groups', {'name': 'other', 'gid': 2201}, 'worker_group_collision'),
            ('groups', {'name': 'engbox_gateway', 'gid': 3300}, 'gateway_group_collision'),
            ('services', 'rocky-eng-worker.service', 'worker_service_collision'),
            ('services', 'engbox-worker-example.service', 'worker_service_collision')]:
            site, inv = fixture(); inv[key].append(row)
            with self.subTest(key=key, row=row):
                result = planner.plan(site, inv, now=NOW)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertIn(expected, [f['code'] for f in result['findings']])

    def test_subordinate_range_overlap_and_adjacent_boundaries(self):
        for key in ('subuids', 'subgids'):
            for start, blocked in ((134464, False), (134465, True), (200000, True), (265535, True), (265536, False)):
                site, inv = fixture(); inv[key] = [{'start': start, 'count': 65536}]
                with self.subTest(key=key, start=start):
                    codes = [x['code'] for x in planner.plan(site, inv, now=NOW)['findings']]
                    self.assertEqual(key + '_collision' in codes, blocked)

    def test_primary_ids_cannot_collide_with_subordinate_allocations(self):
        site, inv = fixture()
        inv['subuids'] = [{'start': 2000, 'count': 65536}]
        inv['subgids'] = [{'start': 2000, 'count': 65536}]
        codes = [x['code'] for x in planner.plan(site, inv, now=NOW)['findings']]
        self.assertIn('gateway_uid_subid_collision', codes)
        self.assertIn('worker_gid_subid_collision', codes)
        site, inv = fixture()
        inv['accounts'].append({'name': 'other', 'uid': 200001, 'gid': 200001})
        codes = [x['code'] for x in planner.plan(site, inv, now=NOW)['findings']]
        self.assertIn('subids_primary_collision', codes)

    def test_hostname_requires_canonical_labels(self):
        for value in ('host..example', '-host', 'host-', 'host;id', 'host\n', 'AHost'):
            site, inv = fixture(); site['hostname'] = value
            with self.subTest(value=value), self.assertRaises(planner.InputError):
                planner.plan(site, inv, now=NOW)

    def test_example_site_matches_documented_fixture_contract(self):
        site, inv = fixture()
        example = planner.load(ROOT / 'ops/deployment/site.example.json')
        self.assertEqual(site, example)
        self.assertEqual(planner.plan(example, inv, now=NOW)['status'], 'OFFLINE_PLAN_REVIEW_REQUIRED')

    def test_existing_symlink_unknown_unsafe_readonly_targets_block(self):
        for key, value in [('state', 'present'), ('state', 'symlink'), ('state', 'unknown'),
                           ('ancestors_safe', False), ('read_only', True), ('free_bytes', 0)]:
            site, inv = fixture(); inv['paths'][site['paths']['code']][key] = value
            with self.subTest(key=key, value=value):
                self.assertEqual(planner.plan(site, inv, now=NOW)['status'], 'BLOCKED')
        site, inv = fixture(); del inv['paths'][site['worker']['home']]
        self.assertEqual(planner.plan(site, inv, now=NOW)['status'], 'BLOCKED')

    def test_wrong_os_security_transport_and_versions_report_corrections(self):
        site, inv = fixture()
        inv.update(hostname='other', os={'id': 'ubuntu', 'version': '24.04'},
                   selinux='Permissive', cgroup_v2=False, ssh_stdio_verified=False,
                   tools={'python': '3.11', 'podman': '5.8.1', 'systemd': '256'})
        result = planner.plan(site, inv, now=NOW)
        self.assertEqual(len(result['findings']), 7)
        self.assertTrue(all(x['correction'] for x in result['findings']))

    def test_explicit_ipc_tmpfs_budget_does_not_reduce_persistent_budget(self):
        site,inv=fixture()
        site.pop('min_runtime_free_bytes')
        runtime=site['paths']['runtime']
        inv['paths'][runtime]['free_bytes']=32*1024**2
        self.assertEqual(planner.plan(site,inv,now=NOW)['status'],'BLOCKED')
        site['min_runtime_free_bytes']=16*1024**2
        self.assertEqual(planner.plan(site,inv,now=NOW)['status'],'OFFLINE_PLAN_REVIEW_REQUIRED')
        inv['paths'][runtime]['free_bytes']=16*1024**2-1
        self.assertEqual(planner.plan(site,inv,now=NOW)['status'],'BLOCKED')
        inv['paths'][runtime]['free_bytes']=32*1024**2
        inv['paths'][site['paths']['code']]['free_bytes']=32*1024**2
        self.assertIn('storage:'+site['paths']['code'],[x['code'] for x in planner.plan(site,inv,now=NOW)['findings']])
        for value in (True,0,16*1024**2-1,1024**3+1):
            site['min_runtime_free_bytes']=value
            with self.assertRaises(planner.InputError): planner.plan(site,inv,now=NOW)

    def test_incomplete_stale_future_and_naive_inventory_refused(self):
        for value in ('2026-10-22T00:00:00Z', '2026-10-25T00:00:00Z', '2026-10-24T00:00:00', 'bad'):
            site, inv = fixture(); inv['observed_utc'] = value
            with self.subTest(timestamp=value), self.assertRaises(planner.InputError):
                planner.plan(site, inv, now=NOW)
        site, inv = fixture(); inv['complete'] = False
        with self.assertRaises(planner.InputError): planner.plan(site, inv, now=NOW)

    def test_malformed_nested_types_ranges_duplicates_refused(self):
        for key, value in [('accounts', None), ('groups', [{'name': 'root', 'gid': False}]),
                           ('subuids', [{'start': 0, 'count': 0}]), ('tools', {}),
                           ('services', ['bad\n.service']), ('paths', []), ('schema', True)]:
            site, inv = fixture(); inv[key] = value
            with self.subTest(key=key), self.assertRaises(planner.InputError):
                planner.plan(site, inv, now=NOW)
        site, inv = fixture(); inv['accounts'].append(dict(inv['accounts'][0]))
        with self.assertRaises(planner.InputError): planner.plan(site, inv, now=NOW)

    def test_bounded_json_duplicate_and_nonfinite_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.json'
            for raw in (b'{"schema":1,"schema":2}', b'{"value":NaN}', b' ' * (planner.MAX_INPUT + 1)):
                path.write_bytes(raw)
                with self.subTest(size=len(raw)), self.assertRaises((ValueError, planner.InputError)):
                    planner.load(path)

    def test_cli_only_reads_inputs_and_emits_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); site, inv = fixture(dt.datetime.now(dt.timezone.utc))
            a, b = root / 'site.json', root / 'inventory.json'
            a.write_text(json.dumps(site)); b.write_text(json.dumps(inv))
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(planner.main(['--site', str(a), '--inventory', str(b)]), 0)
            self.assertEqual(json.loads(output.getvalue())['status'], 'OFFLINE_PLAN_REVIEW_REQUIRED')
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
            b.write_text('{"private_key":"synthetic-sensitive"}')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(planner.main(['--site', str(a), '--inventory', str(b)]), 2)
            self.assertNotIn('synthetic-sensitive', output.getvalue())


if __name__ == '__main__':
    unittest.main()
