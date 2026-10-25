"""End-to-end off-host grant review/export/sign/verify integration tests.

The test signing key is GENERATED within a disposable temp directory and never
shipped as a release asset. This is not proof of Rocky Linux user separation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import approvalwork
import operator_sign
import operator_approve
import sandboxwork

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "localhost/rocky-sandbox@sha256:" + "b" * 64

class OffHostOperatorGrantTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        conf = self.home / ".config" / "rocky-mcp-gateway"
        conf.mkdir(mode=0o700, parents=True)
        (conf / "sandbox-image.txt").write_text(IMAGE + "\n")
        (conf / "sandbox-image.txt").chmod(0o600)
        self.trust = self.home / "public-trust"
        self.trust.mkdir(mode=0o700)
        self.private = self.home / "operator-private.pem"
        self.public = self.trust / approvalwork.KEY_NAME
        subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519",
                        "-out", str(self.private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(self.private),
                        "-pubout", "-out", str(self.public)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.private.chmod(0o600)
        self.public.chmod(0o600)
        self.store = sandboxwork.ExecutionStore(
            self.home, approval_dir=self.trust, trusted_approval_uid=os.getuid())
        self.case = self.store.cases.open_case()["case_id"]
        self.plan = self.store.prepare(self.case, "print('untrusted sample')\n",
                                       [], ["summary.json"])
        self.review = self.home / "review.json"
        self.signed = self.home / "grant.json"

    def export(self):
        details, script = self.store.inspect_local(self.plan["execution_id"])
        argv = ["operator_approve.py", "export",
                self.plan["execution_id"], "--out", str(self.review)]
        with patch.object(sys, "argv", argv), \
             patch("operator_approve.ExecutionBrokerClient") as client:
            client.return_value.export_review.return_value = {**details, "script": script}
            result = operator_approve.main()
        self.assertEqual(result, 0)


    def sign(self, answer):
        argv = ["operator_sign.py", str(self.review), "--private-key",
                str(self.private), "--out", str(self.signed)]
        with patch.object(sys, "argv", argv), \
             patch.object(sys.stdin, "isatty", return_value=True), \
             patch.object(sys.stdout, "isatty", return_value=True), \
             patch.object(sys.stderr, "isatty", return_value=True), \
             patch("builtins.input", return_value=answer):
            return operator_sign.main()

    def test_export_sign_import_then_fail_closed_without_runtime(self):
        self.export()
        self.assertEqual(self.review.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.sign(self.plan["plan_sha256"]), 0)
        envelope = approvalwork.decode(self.signed.read_bytes())
        self.assertEqual(envelope["payload"]["plan_sha256"], self.plan["plan_sha256"])
        self.assertEqual(self.signed.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("PRIVATE KEY", self.review.read_text() + self.signed.read_text())
        result = self.store.import_signed_grant(envelope)
        self.assertEqual(result["state"], "QUEUED")
        with patch.object(self.store, "_stage", side_effect=sandboxwork.ExecutionError("sandbox_runtime_unavailable")):
            outcome = self.store.work_once()
        self.assertEqual(outcome["state"], "FAILED")
        self.assertEqual(self.store.status(self.plan["execution_id"], include_result=True)["failure_code"],
                         "sandbox_runtime_unavailable")

    def test_operator_can_sign_deny_without_queueing_job(self):
        self.export()
        self.assertEqual(self.sign("DENY"), 0)
        self.assertEqual(self.store.import_signed_grant(
            approvalwork.decode(self.signed.read_bytes()))["state"], "DENIED")
        self.assertEqual(self.store.work_once()["processed"], 0)

    def test_modified_review_bundle_cannot_be_signed(self):
        self.export()
        doc = json.loads(self.review.read_text())
        doc["script"] += "import os\n"
        self.review.write_text(json.dumps(doc))
        self.assertEqual(self.sign(self.plan["plan_sha256"]), 2)
        self.assertFalse(self.signed.exists())

    def test_noninteractive_signing_refused(self):
        self.export()
        argv = ["operator_sign.py", str(self.review), "--private-key",
                str(self.private), "--out", str(self.signed)]
        with patch.object(sys, "argv", argv), patch.object(sys.stdin, "isatty", return_value=False):
            self.assertEqual(operator_sign.main(), 2)
        self.assertFalse(self.signed.exists())

    def test_each_redirected_terminal_stream_refuses_before_review_or_key_use(self):
        argv = ["operator_sign.py", str(self.review), "--private-key",
                str(self.private), "--out", str(self.signed)]
        for stream in ("stdin", "stdout", "stderr"):
            with self.subTest(stream=stream), patch.object(sys, "argv", argv), \
                 patch.object(sys.stdin, "isatty", return_value=stream != "stdin"), \
                 patch.object(sys.stdout, "isatty", return_value=stream != "stdout"), \
                 patch.object(sys.stderr, "isatty", return_value=stream != "stderr"), \
                 patch("operator_sign._read_review") as review, \
                 patch("operator_sign._sign_bytes") as sign:
                self.assertEqual(operator_sign.main(), 2)
                review.assert_not_called()
                sign.assert_not_called()
                self.assertFalse(self.signed.exists())

    def test_openssl_prompt_is_visible_and_crypto_timeout_remains_bounded(self):
        def crypto(args, **kwargs):
            self.assertIsNone(kwargs["stderr"])
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 12)
            self.assertNotIn("-passin", args)
            Path(args[args.index("-out") + 1]).write_bytes(b"x" * 64)
            return subprocess.CompletedProcess(args, 0)
        import io
        from contextlib import redirect_stderr
        output = io.StringIO()
        with patch("operator_sign.subprocess.run", side_effect=crypto), redirect_stderr(output):
            self.assertEqual(operator_sign._sign_bytes(self.private, b"test", "/usr/bin/openssl"), b"x" * 64)
        self.assertIn("12 seconds", output.getvalue())
        self.assertIn("input is hidden", output.getvalue())

if __name__ == "__main__":
    unittest.main()
