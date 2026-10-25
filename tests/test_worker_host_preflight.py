"""Read-only host prerequisite evidence cannot be mistaken for platform proof."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import worker_host_preflight as preflight
from execution_policy import IdentityError


class WorkerHostPreflightTests(unittest.TestCase):
    def _mock_host(self, root: Path, release: str, controllers: str, enforcing: str):
        os_release = root / "os-release"
        cgroup = root / "controllers"
        selinux = root / "enforcing"
        os_release.write_text(release)
        cgroup.write_text(controllers)
        selinux.write_text(enforcing)
        return os_release, cgroup, selinux

    def test_missing_operator_policy_never_reports_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = self._mock_host(Path(tmp), 'ID=rocky\nVERSION_ID="10.2"\n',
                                    "cpu memory pids\n", "1\n")
            with patch.object(preflight.ExecutionPolicy, "load",
                              side_effect=IdentityError("missing protected policy")):
                status = preflight.run_checks(os_release=files[0], cgroup=files[1],
                                              selinux=files[2])
            self.assertEqual(status["prerequisite_status"], "BLOCKED")
            self.assertEqual(status["checks"]["trusted_execution_policy"], "BLOCKED")
            self.assertEqual(status["checks"]["worker_user_systemd_bus"], "BLOCKED")
            self.assertEqual(status["ed25519_operator_handoff"], "NOT_TESTED")
            self.assertEqual(status["release_gate"], "OPEN")

    def test_wrong_os_non_enforcing_selinux_and_missing_cgroup_are_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = self._mock_host(Path(tmp), 'ID=ubuntu\nVERSION_ID="24.04"\n',
                                    "cpu pids\n", "0\n")
            with patch.object(preflight.ExecutionPolicy, "load",
                              side_effect=IdentityError("missing protected policy")):
                status = preflight.run_checks(os_release=files[0], cgroup=files[1],
                                              selinux=files[2])
            for label in ("rocky10", "cgroup_v2_controllers", "selinux_enforcing"):
                self.assertEqual(status["checks"][label], "BLOCKED")

    def test_report_cannot_claim_live_worker_or_release_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = self._mock_host(Path(tmp), 'ID=rocky\nVERSION_ID=10.2\n',
                                    "cpu memory pids\n", "1\n")
            with patch.object(preflight.ExecutionPolicy, "load",
                              side_effect=IdentityError("unset")):
                status = preflight.run_checks(os_release=files[0], cgroup=files[1],
                                              selinux=files[2])
            self.assertEqual(status["rootless_podman_execution"], "NOT_TESTED")
            self.assertEqual(status["worker_systemd_install"], "NOT_TESTED")
            self.assertEqual(status["ed25519_operator_handoff"], "NOT_TESTED")

    def test_read_only_command_rejects_client_selectable_policy_location(self):
        with patch.object(preflight.sys, "argv",
                          ["worker_host_preflight.py", "--policy", "/tmp/forged.json"]):
            self.assertEqual(preflight.main(), 2)


if __name__ == "__main__":
    unittest.main()
