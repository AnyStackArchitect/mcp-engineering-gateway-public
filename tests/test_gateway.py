from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import gateway


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.calls = []
        self.outputs = {}
        def runner(executable, arguments, home):
            self.calls.append((executable, arguments, home))
            item = self.outputs.get((executable, tuple(arguments)))
            if isinstance(item, Exception):
                raise item
            return item if item is not None else ""
        self.runner = runner
        self.conf = gateway.Config({}, (), self.home)
        self.gateway = gateway.Gateway(self.conf, runner=self.runner)
        self.mcp = gateway.MCPServer(self.gateway)

    def call(self, name, arguments=None):
        return self.gateway.call(name, arguments or {})

    def add_repo(self, alias="ansible"):
        p = self.home / alias
        p.mkdir()
        (p / ".git").mkdir()
        self.conf = replace(self.conf, repos={alias: p})
        self.gateway = gateway.Gateway(self.conf, runner=self.runner)
        self.mcp = gateway.MCPServer(self.gateway)
        return p

    def test_documented_build_version_matches_runtime(self):
        # A reported runtime version must never lag the candidate's README.
        readme=(Path(__file__).resolve().parents[1] / "README.md").read_text()
        expected=re.search(r"\*\*Development build:\*\* `([^`]+)`",readme)
        self.assertIsNotNone(expected)
        self.assertEqual(gateway.VERSION,expected.group(1))

    def test_config_defaults_to_no_repo_or_units(self):
        self.assertEqual(gateway.Config.load(self.home), self.conf)

    def test_config_accepts_only_secure_file_and_in_home_repo(self):
        p = self.add_repo()
        d = self.home / ".config" / "rocky-mcp-gateway"
        d.mkdir(parents=True)
        f = d / "config.json"
        f.write_text(json.dumps({"repos": {"ansible": str(p)}, "user_units": ["nginx.service"]}))
        f.chmod(0o600)
        read = gateway.Config.load(self.home)
        self.assertEqual(read.repos, {"ansible": p})
        self.assertEqual(read.user_units, ("nginx.service",))
        f.chmod(0o644)
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)

    def test_config_rejects_symlink_file(self):
        d = self.home / ".config" / "rocky-mcp-gateway"
        d.mkdir(parents=True)
        target = self.home / "outside.json"
        target.write_text('{"repos":{},"user_units":[]}')
        target.chmod(0o600)
        (d / "config.json").symlink_to(target)
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)

    def test_config_rejects_path_escaping_home_and_unsafe_unit(self):
        d = self.home / ".config" / "rocky-mcp-gateway"
        d.mkdir(parents=True)
        f = d / "config.json"
        f.write_text(json.dumps({"repos": {"bad": "/tmp"}, "user_units": []}))
        f.chmod(0o600)
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)
        f.write_text(json.dumps({"repos": {}, "user_units": ["--evil.service"]}))
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)

    def test_config_rejects_unknown_fields_and_excess(self):
        d = self.home / ".config" / "rocky-mcp-gateway"
        d.mkdir(parents=True)
        f = d / "config.json"
        f.write_text(json.dumps({"repos": {}, "user_units": [], "shell": "/bin/bash"}))
        f.chmod(0o600)
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)

    def test_config_rejects_repository_dotgit_file_or_symlink(self):
        p = self.home / "worktree"
        p.mkdir()
        d = self.home / ".config" / "rocky-mcp-gateway"
        d.mkdir(parents=True)
        f = d / "config.json"
        f.write_text(json.dumps({"repos": {"worktree": str(p)}, "user_units": []}))
        f.chmod(0o600)
        (p / ".git").write_text("gitdir: ../other\n")
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)
        (p / ".git").unlink()
        target = self.home / "other"
        target.mkdir()
        (p / ".git").symlink_to(target)
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)

    def test_config_rejects_symlink_config_ancestor(self):
        target = self.home / "actual_config"
        d = target / "rocky-mcp-gateway"
        d.mkdir(parents=True)
        (d / "config.json").write_text('{"repos": {}, "user_units": []}')
        (d / "config.json").chmod(0o600)
        (self.home / ".config").symlink_to(target)
        with self.assertRaisesRegex(gateway.ConfigurationError, "ancestor"):
            gateway.Config.load(self.home)

    def test_audit_rejects_symlink_ancestor(self):
        target = self.home / "outside"
        target.mkdir()
        (self.home / ".local").symlink_to(target)
        with self.assertRaisesRegex(gateway.GatewayError, "ancestor"):
            self.call("gateway_status")

    def test_tool_list_hides_unconfigured_operations(self):
        names = [x["name"] for x in self.gateway.tools()]
        self.assertEqual(names[:3], ["gateway_status", "host_snapshot", "podman_containers"])
        self.assertEqual(len(names), 44)
        for definition in self.gateway.tools():
            if definition["name"] in ("case_open", "artifact_register", "log_index", "job_submit", "job_cancel", "execution_prepare", "execution_cancel"):
                self.assertFalse(definition["annotations"]["readOnlyHint"])
            else:
                self.assertTrue(definition["annotations"]["readOnlyHint"])
            self.assertFalse(definition["annotations"]["destructiveHint"])
            self.assertFalse(definition["inputSchema"]["additionalProperties"])

    def test_diagnostic_and_config_tools_are_strictly_typed(self):
        names={t['name']:t for t in self.gateway.tools()}
        self.assertTrue({'diagnostic_recipes','diagnostic_report','config_compare'} <= set(names))
        self.assertEqual({x['family'] for x in self.call('diagnostic_recipes')['families']},
                         {'vmware','veeam','hyperv','nutanix','proxmox','linux',
                          'storage','openshift','identity'})
        self.assertTrue(names['config_compare']['annotations']['readOnlyHint'])
        self.assertFalse(names['job_submit']['annotations']['readOnlyHint'])
        for invalid in (
            {'family':'vmware'},
            {'case_id':'a'*32,'family':'unsupported'},
            {'case_id':'a'*32,'family':'vmware','shell':'ls'},
        ):
            with self.assertRaises(gateway.GatewayError):
                self.call('diagnostic_report',invalid)
        for invalid in (
            {'case_id':'a'*32,'before_artifact_id':'a'*32},
            {'case_id':'a'*32,'before_artifact_id':'a'*32,'after_artifact_id':'b'*32,'format':'yaml'},
            {'case_id':'a'*32,'before_artifact_id':'a'*32,'after_artifact_id':'b'*32,'command':'rm'},
        ):
            with self.assertRaises(gateway.GatewayError):
                self.call('config_compare',invalid)

    def test_gateway_status_is_bounded_and_no_paths(self):
        data = self.call("gateway_status")
        self.assertEqual(data["version"], gateway.VERSION)
        self.assertNotIn(str(self.home), json.dumps(data))
        self.assertEqual(data["permissions"], "observe+private-case-analysis")

    def test_host_snapshot_has_no_secret_env(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "SHOULD_NOT_APPEAR"}):
            data = self.call("host_snapshot")
        self.assertIn("uptime_hours", data)
        self.assertGreater(data["memory_total_mib"], 0)
        self.assertNotIn("SHOULD_NOT_APPEAR", json.dumps(data))

    def test_podman_containers_only_allowlisted_fields(self):
        self.outputs[("podman", ("ps", "--format", "json"))] = json.dumps([
            {"Names": ["rocky-web"], "State": "running", "Status": "Up 30 minutes",
             "Image": "private.example.com/customer:secret", "Env": ["TOKEN=topsecret"]}
        ])
        data = self.call("podman_containers")
        self.assertEqual(data["running_containers"], 1)
        self.assertEqual(data["listed"][0]["name"], "rocky-web")
        self.assertNotIn("topsecret", json.dumps(data))
        self.assertNotIn("customer", json.dumps(data))
        self.assertEqual(self.calls[0][0], "podman")

    def test_podman_output_cap_and_invalid_shape(self):
        self.outputs[("podman", ("ps", "--format", "json"))] = '{"foo":"bar"}'
        with self.assertRaisesRegex(gateway.GatewayError, "unexpected"):
            self.call("podman_containers")
        self.outputs[("podman", ("ps", "--format", "json"))] = json.dumps(
            [{"Names": ["x"], "State": "running"} for _ in range(40)])
        data = self.call("podman_containers")
        self.assertEqual(data["running_containers"], 40)
        self.assertEqual(len(data["listed"]), 32)
        self.assertTrue(data["truncated"])

    def test_reject_unapproved_unit_and_repo(self):
        with self.assertRaises(gateway.GatewayError):
            self.call("user_service_status", {"unit": "sshd.service"})
        with self.assertRaises(gateway.GatewayError):
            self.call("git_repo_status", {"repo": "secret"})
        self.assertEqual(self.calls, [])

    def test_service_only_approved_and_field_filtered(self):
        self.conf = replace(self.conf, user_units=("nginx.service",))
        self.gateway = gateway.Gateway(self.conf, runner=self.runner)
        command = ("--user", "show", "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState", "nginx.service")
        self.outputs[("systemctl", command)] = "LoadState=loaded\nActiveState=active\nSubState=running\nSecret=NO\n"
        result = self.call("user_service_status", {"unit": "nginx.service"})
        self.assertEqual(result["properties"]["ActiveState"], "active")
        self.assertNotIn("Secret", json.dumps(result))
        with self.assertRaises(gateway.GatewayError):
            self.call("user_service_status", {"unit": "sshd.service"})

    def test_git_status_is_fixed_commands_and_count_only(self):
        path = self.add_repo()
        prefix = ("-c", "core.fsmonitor=false", "--no-optional-locks", "-C", str(path))
        self.outputs[("git", prefix + ("rev-parse", "--verify", "HEAD"))] = "a"*40 + "\n"
        self.outputs[("git", prefix + ("symbolic-ref", "--quiet", "--short", "HEAD"))] = "main\n"
        self.outputs[("git", prefix + ("status", "--porcelain=v1", "--untracked-files=no"))] = " M secret.txt\nA  normal.py\n"
        data = self.call("git_repo_status", {"repo": "ansible"})
        self.assertEqual(data["head_sha"], "a"*40)
        self.assertEqual(data["tracked_changes"], 2)
        self.assertEqual(data["branch"], "main")
        self.assertNotIn("secret.txt", json.dumps(data))
        self.assertEqual(len(self.calls), 3)
        self.assertTrue(all(item[0] == "git" for item in self.calls))

    def test_git_sha_must_be_hex(self):
        path = self.add_repo()
        prefix = ("-c", "core.fsmonitor=false", "--no-optional-locks", "-C", str(path))
        self.outputs[("git", prefix + ("rev-parse", "--verify", "HEAD"))] = "BAD\n"
        with self.assertRaisesRegex(gateway.GatewayError, "invalid commit"):
            self.call("git_repo_status", {"repo": "ansible"})

    def test_unexpected_arguments_blocked_before_any_command(self):
        for name, args in [
            ("host_snapshot", {"path": "/etc/shadow"}),
            ("podman_containers", {"command": "rm -rf ~"}),
            ("gateway_status", {"verbose": True}),
            ("git_repo_status", {"repo": "ansible", "shell": True}),
        ]:
            with self.assertRaises(gateway.GatewayError):
                self.call(name, args)
        self.assertEqual(self.calls, [])

    def test_rate_limit_blocks_61st_call(self):
        self.gateway = gateway.Gateway(self.conf, runner=self.runner, monotonic=lambda: 1000.)
        for _ in range(60):
            self.gateway.call("gateway_status", {})
        with self.assertRaisesRegex(gateway.GatewayError, "Too many"):
            self.gateway.call("gateway_status", {})

    def test_audit_records_only_tool_and_outcome_not_arguments(self):
        self.call("gateway_status")
        audit = self.home / ".local" / "state" / "rocky-mcp-gateway" / "audit.jsonl"
        self.assertTrue(audit.exists())
        entry = json.loads(audit.read_text().splitlines()[0])
        self.assertEqual(entry["tool"], "gateway_status")
        self.assertEqual(entry["result"], "ok")
        self.assertEqual(set(entry), {"time", "tool", "result"})
        self.assertEqual(audit.stat().st_mode & 0o777, 0o600)

    def test_audit_symlink_is_rejected(self):
        d = self.home / ".local" / "state"
        d.mkdir(parents=True)
        (d / "rocky-mcp-gateway").symlink_to(self.home)
        with self.assertRaisesRegex(gateway.GatewayError, "symlink"):
            self.call("gateway_status")

    def test_mcp_legacy_handshake_notifications_and_capabilities(self):
        self.assertEqual(self.mcp.process({"jsonrpc":"2.0", "id":1,"method":"tools/list"})["error"]["code"], -32000)
        result = self.mcp.process({"jsonrpc":"2.0", "id":2,"method":"initialize", "params":{
            "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"test","version":"1"}}})
        self.assertEqual(result["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(result["result"]["capabilities"]["tools"]["listChanged"], False)
        self.assertIsNone(self.mcp.process({"jsonrpc":"2.0", "method":"notifications/initialized"}))
        tool_list = self.mcp.process({"jsonrpc":"2.0", "id":3,"method":"tools/list"})
        self.assertEqual(len(tool_list["result"]["tools"]), 44)
        response = self.mcp.process({"jsonrpc":"2.0", "id":4,"method":"tools/call", "params":{
            "name":"gateway_status", "arguments":{}}})
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(json.loads(response["result"]["content"][0]["text"])["version"], gateway.VERSION)

    def test_mcp_client_compat_fallback_to_legacy(self):
        # A discovery request missing modern metadata is not an MCP 2026 probe.
        attempt = self.mcp.process({"jsonrpc":"2.0", "id":1,"method":"server/discover", "params":{}})
        self.assertEqual(attempt["error"]["code"], -32602)
        selected = self.mcp.process({"jsonrpc":"2.0", "id":2,"method":"initialize", "params":{
            "protocolVersion":"2099-01-01", "capabilities":{}, "clientInfo":{"name":"test","version":"1"}}})
        self.assertEqual(selected["result"]["protocolVersion"], "2025-11-25")

    @staticmethod
    def modern_meta(version="2026-07-28"):
        return {"_meta": {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": {"name": "gateway-test", "version": "1.0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }}

    def test_mcp_modern_discovery_advertises_both_eras(self):
        response = self.mcp.process({"jsonrpc": "2.0", "id": "discover-1",
                                     "method": "server/discover", "params": self.modern_meta()})
        result = response["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["supportedVersions"][0], "2026-07-28")
        self.assertIn("2025-11-25", result["supportedVersions"])
        self.assertEqual(result["capabilities"], {"tools": {"listChanged": False}})
        self.assertEqual(result["_meta"]["io.modelcontextprotocol/serverInfo"]["version"], gateway.VERSION)
        self.assertFalse(self.mcp.ready)

    def test_mcp_modern_discover_and_tools_list_cache_freshness_private(self):
        for method in ("server/discover", "tools/list"):
            response = self.mcp.process({"jsonrpc":"2.0", "id": 11,
                                         "method":method, "params":self.modern_meta()})
            result = response["result"]
            self.assertEqual(result["ttlMs"], 0)
            self.assertEqual(result["cacheScope"], "private")
            self.assertEqual(result["_meta"]["io.modelcontextprotocol/serverInfo"]["version"], gateway.VERSION)

    def test_modern_client_identity_optional_per_spec(self):
        meta = self.modern_meta()
        del meta["_meta"]["io.modelcontextprotocol/clientInfo"]
        for method in ("server/discover", "tools/list"):
            result = self.mcp.process({"jsonrpc":"2.0", "id": 21,
                                       "method":method, "params":meta})
            self.assertIn("result", result)
        result = self.mcp.process({"jsonrpc":"2.0", "id": 22,
                                   "method":"tools/call",
                                   "params":{**meta, "name":"gateway_status", "arguments":{}}})
        self.assertFalse(result["result"]["isError"])

    def test_modern_tool_errors_still_include_server_identity(self):
        response = self.mcp.process({"jsonrpc":"2.0", "id": 12,
                                     "method":"tools/call", "params":{
                                         **self.modern_meta(), "name":"invalid", "arguments":{},
                                     }})
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"], gateway.VERSION)

    def test_mcp_modern_stateless_tool_flow_requires_no_initialize(self):
        response = self.mcp.process({"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list", "params": self.modern_meta()})
        self.assertEqual(response["result"]["resultType"], "complete")
        self.assertEqual(len(response["result"]["tools"]), 44)
        params = {**self.modern_meta(), "name": "gateway_status", "arguments": {}}
        response = self.mcp.process({"jsonrpc": "2.0", "id": 2,
                                     "method": "tools/call", "params": params})
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(response["result"]["resultType"], "complete")
        self.assertEqual(json.loads(response["result"]["content"][0]["text"])["version"], gateway.VERSION)
        self.assertFalse(self.mcp.initialized)

    def test_modern_errors_are_result_type_complete_and_subsequent_works(self):
        bad = self.mcp.process({"jsonrpc":"2.0", "id": 10, "method":"tools/call",
                                "params": {**self.modern_meta(), "name": "not_approved", "arguments": {}}})
        self.assertEqual(bad["result"]["resultType"], "complete")
        self.assertTrue(bad["result"]["isError"])
        ok = self.mcp.process({"jsonrpc":"2.0", "id": 11, "method":"tools/list",
                               "params": self.modern_meta()})
        self.assertEqual(len(ok["result"]["tools"]), 44)

    def test_modern_wrong_version_fails_with_negotiation_hint(self):
        response = self.mcp.process({"jsonrpc": "2.0", "id": 5,
                                     "method": "tools/list", "params": self.modern_meta("2099-01-01")})
        self.assertEqual(response["error"]["code"], -32022)
        self.assertEqual(response["error"]["data"]["requested"], "2099-01-01")
        self.assertIn("2026-07-28", response["error"]["data"]["supported"])
        self.assertEqual(self.calls, [])

    def test_modern_missing_or_invalid_identity_rejected(self):
        invalid = [
            {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
            {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                       "io.modelcontextprotocol/clientInfo": {},
                       "io.modelcontextprotocol/clientCapabilities": []}},
        ]
        for params in invalid:
            response = self.mcp.process({"jsonrpc": "2.0", "id": 3, "method": "tools/list",
                                         "params": params})
            self.assertEqual(response["error"]["code"], -32602)
        self.assertEqual(self.calls, [])

    def test_dual_era_support_when_legacy_is_initialized(self):
        # Modern calls should be stateless even when a legacy process was initialized.
        self.mcp.process({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2025-11-25"}})
        self.mcp.process({"jsonrpc": "2.0", "method": "notifications/initialized"})
        modern = self.mcp.process({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                                   "params": self.modern_meta()})
        legacy = self.mcp.process({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        self.assertEqual(modern["result"]["resultType"], "complete")
        self.assertNotIn("resultType", legacy["result"])
        self.assertEqual(modern["result"]["tools"], legacy["result"]["tools"])

    def test_modern_cannot_use_legacy_ping_without_fallback(self):
        request = {"jsonrpc":"2.0", "id": 7, "method":"ping", "params": self.modern_meta()}
        self.assertEqual(self.mcp.process(request)["error"]["code"], -32601)

    def test_mcp_rejects_bad_jsonrpc_and_invalid_params(self):
        self.assertEqual(self.mcp.process({"id":9,"method":"initialize"})["error"]["code"], -32600)
        self.assertEqual(self.mcp.process({"jsonrpc":"2.0","id":True,"method":"initialize"})["error"]["code"], -32600)
        self.assertEqual(self.mcp.process({"jsonrpc":"2.0","id":2,"method":"initialize","params":[]})["error"]["code"], -32602)

    def test_mcp_tool_errors_are_recoverable(self):
        self.mcp.process({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}})
        self.mcp.process({"jsonrpc":"2.0","method":"notifications/initialized"})
        error = self.mcp.process({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"git_repo_status","arguments":{"repo":"invalid"}}})
        self.assertTrue(error["result"]["isError"])
        success = self.mcp.process({"jsonrpc":"2.0","id":3,"method":"ping"})
        self.assertEqual(success["result"], {})

    def test_fixed_subprocess_output_limit_is_enforced_while_streaming(self):
        import sys as system_python
        with patch.dict(gateway.SAFE_EXECUTABLES, {"selftest": system_python.executable}):
            with self.assertRaisesRegex(gateway.GatewayError, "output exceeds"):
                gateway.run_fixed_command(
                    "selftest", ["-c", "import sys;sys.stdout.write('x'*140000)"], self.home)

    def test_fixed_subprocess_timeout_is_enforced(self):
        import sys as system_python
        with patch.dict(gateway.SAFE_EXECUTABLES, {"selftest": system_python.executable}):
            with patch.object(gateway, "COMMAND_TIMEOUT_SECONDS", 0.12):
                with self.assertRaisesRegex(gateway.GatewayError, "timeout"):
                    gateway.run_fixed_command(
                        "selftest", ["-c", "import time;time.sleep(1)"], self.home)

    def test_audit_file_full_fails_closed(self):
        self.call("gateway_status")
        audit = self.home / ".local" / "state" / "rocky-mcp-gateway" / "audit.jsonl"
        with audit.open("r+b") as stream:
            stream.truncate(gateway.MAX_AUDIT_FILE)
        with self.assertRaisesRegex(gateway.GatewayError, "Audit file is full"):
            self.call("gateway_status")

    def test_config_rejects_group_writable_parent(self):
        d = self.home / ".config" / "rocky-mcp-gateway"
        d.mkdir(parents=True)
        f = d / "config.json"
        f.write_text('{"repos":{},"user_units":[]}')
        f.chmod(0o600)
        d.chmod(0o770)
        with self.assertRaises(gateway.ConfigurationError):
            gateway.Config.load(self.home)

    def test_output_limit_logs_output_limited_not_success(self):
        self.outputs[("podman", ("ps", "--format", "json"))] = json.dumps([
            {"Names": ["z"*120], "Status": "y"*120, "State": "x"*40} for _ in range(32)])
        with patch.object(gateway, "MAX_RESPONSE_TEXT", 100):
            with self.assertRaisesRegex(gateway.GatewayError, "safe response limit"):
                self.call("podman_containers")
        audit = self.home / ".local" / "state" / "rocky-mcp-gateway" / "audit.jsonl"
        entry = json.loads(audit.read_text().splitlines()[-1])
        self.assertEqual(entry["result"], "output_limited")

    def test_no_arbitrary_commands_exist(self):
        self.assertEqual(set(gateway.SAFE_EXECUTABLES), {"podman", "systemctl", "git"})
        with self.assertRaises(gateway.GatewayError):
            gateway.run_fixed_command("sh", ["-c", "echo danger"], self.home)

    def test_public_labels_strip_newline_and_control(self):
        self.assertEqual(gateway.public_text("first\nsecond\x01third"), "first?second?third")


if __name__ == "__main__":
    unittest.main()
