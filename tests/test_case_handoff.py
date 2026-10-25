"""Private case handoff must verify original bytes and require exact operator approval."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import case_handoff
from case_handoff import handoff
from casework import CaseError, CaseStore, _write_json_atomic


class HandoffTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.home = Path(work.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.payload = b'password=do-not-publish; raw synthetic case\n'
        first = self.store.inbox / "customer-secret-name.log"
        first.write_bytes(self.payload)
        first.chmod(0o600)
        self.artifact = self.store.register(self.case, first.name)
        self.folder = self.store.cases / self.case
        self.exports = self.store.base / case_handoff.OUT_DIR

    def preview(self):
        return handoff(self.store, self.case)

    def confirm(self, statement):
        return handoff(self.store, self.case, confirm=True,
                       plan_sha256=statement["plan_sha256"])

    def test_two_phase_private_manifest_has_opaque_sha_verified_metadata_only(self):
        before = self.preview()
        self.assertEqual(before["status"], "PREVIEW_ONLY")
        self.assertTrue(before["requires_explicit_confirmation"])
        self.assertFalse(self.exports.exists())
        self.assertEqual(before["artifact_count"], 1)
        self.assertEqual(before["original_bytes_verified"], len(self.payload))
        with self.assertRaisesRegex(CaseError, "requires preview SHA-256"):
            handoff(self.store, self.case, confirm=True)
        committed = self.confirm(before)
        self.assertEqual(committed["status"], "PRIVATE_METADATA_EXPORTED")
        self.assertEqual(committed["raw_originals_exported"], 0)
        self.assertFalse(committed["public_disclosure_approved"])
        self.assertEqual(self.exports.stat().st_mode & 0o777, 0o700)
        destination = self.exports / committed["export_name"]
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        encoded = destination.read_bytes()
        self.assertNotIn(self.payload, encoded)
        self.assertNotIn(b"customer-secret-name.log", encoded)
        self.assertNotIn(b"do-not-publish", encoded)
        self.assertNotIn(b"intake_name", encoded)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), before["plan_sha256"])
        document = json.loads(encoded)
        self.assertEqual(document["scope"], "private_metadata_only_no_raw_evidence")
        self.assertEqual(document["artifacts"][0]["artifact_id"], self.artifact["artifact_id"])
        self.assertEqual(document["artifacts"][0]["sha256"], self.artifact["sha256"])
        self.assertEqual(document["artifacts"][0]["bytes"], len(self.payload))
        self.assertEqual(len(list(self.exports.iterdir())), 1)
        with self.assertRaisesRegex(CaseError, "already exists"):
            self.confirm(before)
        self.assertEqual(destination.read_bytes(), encoded)

    def test_altered_original_is_refused_even_if_size_unchanged(self):
        planned = self.preview()
        original = self.folder / "originals" / self.artifact["artifact_id"]
        original.write_bytes(b"Z" * len(self.payload))
        with self.assertRaisesRegex(CaseError, "SHA-256"):
            self.confirm(planned)
        self.assertFalse(self.exports.exists())

    def test_changed_case_plan_is_denied(self):
        planned = self.preview()
        source = self.store.inbox / "another.log"
        source.write_bytes(b"synthetic\n")
        source.chmod(0o600)
        self.store.register(self.case, source.name)
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(planned)
        self.assertFalse(self.exports.exists())

    def test_missing_and_unregistered_originals_refuse(self):
        original = self.folder / "originals" / self.artifact["artifact_id"]
        original.unlink()
        with self.assertRaisesRegex(CaseError, "missing or unregistered"):
            self.preview()
        original.write_bytes(self.payload)
        original.chmod(0o600)
        unknown = self.folder / "originals" / ("a" * 32)
        unknown.write_bytes(b"uncommitted partial output")
        unknown.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "missing or unregistered"):
            self.preview()
        self.assertEqual(unknown.read_bytes(), b"uncommitted partial output")

    def test_dirty_scratch_and_unresolved_index_block_handoff(self):
        scratch = self.folder / "scratch"
        scratch.mkdir(mode=0o700)
        (scratch / "unfinished-work").write_bytes(b"synthetic")
        with self.assertRaisesRegex(CaseError, "unfinished case scratch"):
            self.preview()
        (scratch / "unfinished-work").unlink()
        index = self.folder / "indexes" / ".tmp-unsafe.index.json"
        index.write_bytes(b"{}")
        index.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "unresolved index recovery"):
            self.preview()
        self.assertTrue(index.exists())

    def test_symlink_and_hardlinked_originals_are_refused(self):
        original = self.folder / "originals" / self.artifact["artifact_id"]
        copy = self.home / "preserve"
        copy.write_bytes(self.payload)
        original.unlink()
        original.symlink_to(copy)
        with self.assertRaises((CaseError, OSError)):
            self.preview()
        original.unlink()
        original.write_bytes(self.payload)
        original.chmod(0o600)
        os.link(original, self.home / "alias")
        with self.assertRaisesRegex(CaseError, "identity is unsafe"):
            self.preview()

    def test_lineage_is_allowlisted_and_missing_parent_fails(self):
        second = self.store.inbox / "derived-private.log"
        second.write_bytes(b"only synthetic derived bytes")
        second.chmod(0o600)
        derived = self.store.register(self.case, second.name)
        with self.store._locked(self.case) as (folder, manifest):
            manifest["artifacts"][derived["artifact_id"]]["derived_from"] = self.artifact["artifact_id"]
            manifest["artifacts"][derived["artifact_id"]]["derived_member_name"] = "secret-customer-path"
            _write_json_atomic(folder / "manifest.json", manifest)
        approved = self.confirm(self.preview())
        payload = (self.exports / approved["export_name"]).read_text()
        self.assertNotIn("secret-customer-path", payload)
        document = json.loads(payload)
        children = [a for a in document["artifacts"] if a["artifact_id"] == derived["artifact_id"]]
        self.assertEqual(children[0]["derived_from"], self.artifact["artifact_id"])

        with self.store._locked(self.case) as (folder, manifest):
            manifest["artifacts"][derived["artifact_id"]]["derived_from"] = "f" * 32
            _write_json_atomic(folder / "manifest.json", manifest)
        with self.assertRaisesRegex(CaseError, "source lineage"):
            self.preview()

    def test_cyclic_derived_source_lineage_cannot_be_exported(self):
        source = self.store.inbox / "child.log"
        source.write_bytes(b"cycle-only synthetic\n")
        source.chmod(0o600)
        child = self.store.register(self.case, source.name)
        with self.store._locked(self.case) as (folder, manifest):
            manifest["artifacts"][child["artifact_id"]]["derived_from"] = self.artifact["artifact_id"]
            manifest["artifacts"][self.artifact["artifact_id"]]["derived_from"] = child["artifact_id"]
            _write_json_atomic(folder / "manifest.json", manifest)
        with self.assertRaisesRegex(CaseError, "cycle"):
            self.preview()
        self.assertFalse(self.exports.exists())

    def test_metadata_publication_requires_headroom_beyond_locked_reserve(self):
        plan = self.preview()
        seen = []
        real_gate = case_handoff.verify_committed_reserve
        def deny_extra(store, *, extra_bytes=0):
            seen.append(extra_bytes)
            if extra_bytes:
                raise CaseError("synthetic reserved storage gap")
            return real_gate(store)
        with patch.object(case_handoff, "verify_committed_reserve",
                          side_effect=deny_extra):
            with self.assertRaisesRegex(CaseError, "reserved storage"):
                self.confirm(plan)
        self.assertEqual(seen, [0, case_handoff.MAX_OUTPUT_BYTES])
        self.assertFalse(self.exports.exists())

    def test_published_file_must_pass_readback_hash_before_success(self):
        plan = self.preview()
        genuine_sync = case_handoff._sync_directory
        calls = 0
        def corrupt_after_link(directory):
            nonlocal calls
            calls += 1
            if calls == 3:
                # First sync durably records the source-linked journal;
                # second records scratch; third follows publication link.
                target = directory / (self.case + "-" + plan["plan_sha256"][:24] + ".json")
                target.write_bytes(b"corrupted synthetic private manifest")
            return genuine_sync(directory)
        with patch.object(case_handoff, "_sync_directory", side_effect=corrupt_after_link):
            with self.assertRaisesRegex(CaseError, "Published handoff file identity"):
                self.confirm(plan)
        final = self.exports / (self.case + "-" + plan["plan_sha256"][:24] + ".json")
        self.assertTrue(final.exists())
        self.assertEqual((self.folder / "originals" / self.artifact["artifact_id"]).read_bytes(),
                         self.payload)

    def test_unsafe_export_directory_and_existing_target_are_never_overwritten(self):
        approval = self.preview()
        outside = self.home / "unrelated"
        outside.mkdir(mode=0o700)
        self.exports.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(CaseError):
            self.confirm(approval)
        self.assertEqual(list(outside.iterdir()), [])
        self.exports.unlink()
        self.exports.mkdir(mode=0o700)
        target = self.exports / (self.case + "-" + approval["plan_sha256"][:24] + ".json")
        target.write_bytes(b"do-not-replace")
        target.chmod(0o600)
        with self.assertRaisesRegex(CaseError, "already exists"):
            self.confirm(approval)
        self.assertEqual(target.read_bytes(), b"do-not-replace")

    def test_failure_after_publication_preserves_private_export_and_original(self):
        approved = self.preview()
        real_sync = case_handoff._sync_directory
        calls = 0
        def fail_after_publish(path):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise CaseError("synthetic post-publish sync failure")
            return real_sync(path)
        with patch.object(case_handoff, "_sync_directory", side_effect=fail_after_publish):
            with self.assertRaisesRegex(CaseError, "post-publish"):
                self.confirm(approved)
        target = self.exports / (self.case + "-" + approved["plan_sha256"][:24] + ".json")
        self.assertTrue(target.exists())
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),
                         approved["plan_sha256"])
        self.assertEqual((self.folder / "originals" / self.artifact["artifact_id"]).read_bytes(),
                         self.payload)
        with self.assertRaisesRegex(CaseError, "already exists"):
            self.confirm(approved)
        # Recovery provenance and the second temporary hardlink are retained
        # after an ambiguous post-link failure, never silently discarded.
        entries = list(self.exports.iterdir())
        self.assertEqual(len(entries), 3)
        self.assertEqual(len(list(self.exports.glob(".handoff-work-*.json"))), 1)
        self.assertEqual(len(list(self.exports.glob(".tmp-handoff-*"))), 1)

    def test_cli_two_invocations_and_invalid_external_options(self):
        cli = Path(__file__).resolve().parents[1] / "scripts" / "case_handoff_cli.py"
        env = {**os.environ, "HOME": str(self.home)}
        def invoke(*args):
            return subprocess.run(
                [sys.executable, "-u", str(cli), "--case-id", self.case, *args],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        p = invoke("--preview")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        state = json.loads(p.stdout)
        self.assertFalse(self.exports.exists())
        denied = invoke("--confirm")
        self.assertNotEqual(denied.returncode, 0)
        denied = invoke("--preview", "--plan-sha256", state["plan_sha256"])
        self.assertNotEqual(denied.returncode, 0)
        denied = invoke("--preview", "--include-raw-files")
        self.assertNotEqual(denied.returncode, 0)
        accepted = invoke("--confirm", "--plan-sha256", state["plan_sha256"])
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
        info = json.loads(accepted.stdout)
        self.assertEqual(info["status"], "PRIVATE_METADATA_EXPORTED")
        self.assertNotIn(b"password=do-not-publish", accepted.stdout)
        self.assertTrue((self.exports / info["export_name"]).exists())

    def test_empty_case_is_not_exported(self):
        other = self.store.open_case()["case_id"]
        with self.assertRaisesRegex(CaseError, "registered evidence"):
            handoff(self.store, other)


if __name__ == "__main__":
    unittest.main()
