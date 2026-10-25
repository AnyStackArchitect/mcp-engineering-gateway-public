"""Development policy regression; live container isolation is tested separately."""
from pathlib import Path
import unittest

from podman_policy import (container_run_command, container_exec_command,
                           container_remove_command)


class ContainerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.id = "a" * 32
        self.image = "registry.example.net/vetted/sandbox@sha256:" + "b" * 64
        self.plan = {"id": self.id, "image": self.image,
                     "memory_mib": 256, "disk_mib": 32}
        self.ro = Path("/var/lib/rocky-eng-exec/readonly")

    def test_rootless_launch_is_bounded_and_offline(self):
        command = container_run_command(self.plan, self.ro, uid=1002, gid=1003)
        self.assertEqual(command[:3], ["/usr/bin/podman", "run", "--detach"])
        self.assertEqual(command[-5:], [self.image, "-I", "-B", "-c",
                                        "import time; time.sleep(1000000)"])
        for forbidden in ("--privileged", "--network=host", "--pid=host",
                          "--security-opt=label=disable"):
            self.assertNotIn(forbidden, command)
        self.assertEqual(command.count("--volume"), 1)
        self.assertIn(str(self.ro) + ":/workspace:ro,Z", command)
        for required in ("--pull=never", "--network=none", "--read-only",
                         "--cap-drop=ALL", "--security-opt=no-new-privileges",
                         "--userns=keep-id", "--user", "1002:1003",
                         "--pids-limit=64", "--cpus=1", "--memory=256m",
                         "--memory-swap=256m", "/output:rw,nosuid,nodev,size=32m",
                         "/tmp:rw,nosuid,nodev,size=16m"):
            self.assertIn(required, command)

    def test_exec_output_collection_and_cleanup_are_fixed(self):
        name = "rocky-gw-job-" + self.id
        self.assertEqual(container_exec_command(self.id),
                         ["/usr/bin/podman", "exec", name,
                          "/usr/bin/python3", "-I", "-B", "/workspace/program.py"])
        self.assertEqual(container_remove_command(self.id),
                         ["/usr/bin/podman", "rm", "--force", "--ignore", name])

    def test_worker_uses_same_tested_command_builder(self):
        source = (Path(__file__).resolve().parents[1] / "sandboxwork.py").read_text()
        for api in ("container_run_command(plan, ro)",
                    "container_exec_command(row[\"id\"])",
                    "container_remove_command(plan_id)",
                    "self._cleanup_container(row[\"id\"])"):
            self.assertIn(api, source)


if __name__ == "__main__":
    unittest.main()
