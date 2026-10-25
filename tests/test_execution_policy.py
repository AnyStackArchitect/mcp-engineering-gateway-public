"""Fail-closed trusted identity and worker startup policy regressions."""
from __future__ import annotations
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from execution_policy import ExecutionPolicy, IdentityError, _trusted_path
from execworker import _exclusive
from sandboxwork import ExecutionStore, ExecutionError


class ExecutionPolicyTests(unittest.TestCase):
    def test_new_worker_dependencies_are_in_trusted_startup_inventory(self):
        import execution_policy
        policy=ExecutionPolicy(1501,1502,1503)
        for filename in ('capacitywork.py','sharedcapacity.py','providerplans.py','provider_runner.py','outputcopy.py'):
            self.assertIn(filename,execution_policy.MODULE_NAMES)
            seen=[]
            def inspect(path,**kwargs):
                seen.append(path)
                if path.name==filename:raise IdentityError('untrusted new dependency')
            with self.subTest(filename=filename),patch('execution_policy._trusted_path',side_effect=inspect):
                with self.assertRaises(IdentityError):policy.check_worker(uid=1502,gid=1503,module_dir=Path('/trusted'))
            self.assertIn(Path('/trusted')/filename,seen)

    def test_invalid_or_shared_principals_rejected(self):
        for values in [(1001, 1001, 1002), (0, 1002, 1003),
                       (1001, 0, 1003), (1001, 1002, 0),
                       (True, 1002, 1003), (1001, 1002, 100000000000)]:
            with self.assertRaises(IdentityError):
                ExecutionPolicy(*values)

    def test_worker_is_not_authorized_as_gateway(self):
        policy = ExecutionPolicy(1501, 1502, 1503)
        policy.check_gateway(uid=1501)
        for uid in (1502, 0, 1504):
            with self.assertRaises(IdentityError):
                policy.check_gateway(uid=uid)

    def test_wrong_worker_uid_or_gid_rejected_before_file_access(self):
        policy = ExecutionPolicy(1501, 1502, 1503)
        for uid, gid in [(1501, 1503), (1502, 1501), (0, 1503)]:
            with self.assertRaises(IdentityError):
                policy.check_worker(uid=uid, gid=gid)

    def test_untrusted_config_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fake-policy.json"
            path.write_text('{"schema":1,"gateway_uid":1501,"worker_uid":1502,"socket_group_gid":1503}')
            # The test user's writable config path must not be treated as
            # an administrator-controlled policy, regardless of JSON validity.
            with patch("execution_policy.POLICY_FILE", path):
                with self.assertRaises(IdentityError):
                    ExecutionPolicy.load()

    def test_symlinks_and_writable_modules_not_trusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "module.py"
            target.write_text("pass\n")
            redirect = Path(temporary) / "symlink.py"
            redirect.symlink_to(target)
            for item in (redirect, target):
                with self.assertRaises(IdentityError):
                    _trusted_path(item)

    def test_dedicated_worker_lock_cannot_be_acquired_twice(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            store = ExecutionStore(home)
            first = _exclusive(store)
            try:
                with self.assertRaises((OSError, BlockingIOError)):
                    _exclusive(store)
            finally:
                os.close(first)

    def test_worker_lock_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            store = ExecutionStore(home)
            store.cases._ensure_store()
            target = home / "outside"
            target.write_text("x")
            (store.base / "execution.worker.lock").symlink_to(target)
            with self.assertRaises(ExecutionError):
                _exclusive(store)


if __name__ == "__main__":
    unittest.main()
