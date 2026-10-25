"""Operator-only handoff crash recovery must preserve approved metadata and originals."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from casework import CaseStore, CaseError
import case_handoff
import handoff_recovery


class HandoffRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.raw = b"customer-login=NEVER-SHARE; synthetic only\n"
        incoming = self.store.inbox / "customer-private-original.log"
        incoming.write_bytes(self.raw)
        incoming.chmod(0o600)
        self.source = self.store.register(self.case, incoming.name)
        self.plan = case_handoff.handoff(self.store, self.case)
        self.exports = self.store.base / case_handoff.OUT_DIR
        self.final_name = self.case + "-" + self.plan["plan_sha256"][:24] + ".json"

    def interrupted(self, stage: int) -> tuple[str, Path, Path, Path]:
        original_sync = case_handoff._sync_directory
        count = 0

        def fault_after_step(location):
            nonlocal count
            count += 1
            if count == stage:
                raise CaseError("synthetic interrupted fsync")
            return original_sync(location)

        with patch.object(case_handoff, "_sync_directory", side_effect=fault_after_step):
            with self.assertRaisesRegex(CaseError, "interrupted fsync"):
                case_handoff.handoff(self.store, self.case, confirm=True,
                                     plan_sha256=self.plan["plan_sha256"])
        journals = list(self.exports.glob(".handoff-work-*.json"))
        self.assertEqual(len(journals), 1)
        work_id = journals[0].name[len(".handoff-work-"):-len(".json")]
        return (work_id, journals[0], self.exports / (".tmp-handoff-" + work_id),
                self.exports / self.final_name)

    @staticmethod
    def age(*paths):
        old = time.time() - 100 * 3600
        for item in paths:
            if item.exists() and not item.is_symlink():
                os.utime(item, (old, old))

    def recover_preview(self, work_id):
        return handoff_recovery.recover(self.store, self.case, work_id)

    def confirm(self, work_id, preview):
        return handoff_recovery.recover(
            self.store, self.case, work_id, confirm=True,
            recovery_plan_sha256=preview["recovery_plan_sha256"])

    def test_normal_export_leaves_only_private_verified_final(self):
        result = case_handoff.handoff(self.store, self.case, confirm=True,
                                      plan_sha256=self.plan["plan_sha256"])
        self.assertEqual(result["status"], "PRIVATE_METADATA_EXPORTED")
        self.assertEqual([p.name for p in self.exports.iterdir()], [self.final_name])
        self.assertEqual(handoff_recovery.list_interrupted(
            self.store, self.case)["handoff_work_ids"], [])
        final = self.exports / self.final_name
        self.assertEqual(hashlib.sha256(final.read_bytes()).hexdigest(),
                         self.plan["plan_sha256"])

    def test_prepublication_partial_requires_aged_sha_confirm(self):
        work, journal, temp, final = self.interrupted(stage=2)
        self.assertTrue(temp.is_file())
        self.assertFalse(final.exists())
        with self.assertRaisesRegex(CaseError, "too recent"):
            self.recover_preview(work)
        self.age(journal, temp)
        state = self.recover_preview(work)
        self.assertEqual(state["status"], "PREVIEW_ONLY")
        self.assertEqual(state["disposition"], "INTERRUPTED")
        self.assertTrue(temp.exists())
        with self.assertRaisesRegex(CaseError, "needs a preview plan"):
            handoff_recovery.recover(self.store, self.case, work, confirm=True)
        complete = self.confirm(work, state)
        self.assertEqual(complete["status"], "INTERRUPTED_SCRATCH_CLEARED")
        self.assertEqual(complete["registered_originals_removed"], 0)
        self.assertEqual(complete["committed_handoffs_removed"], 0)
        self.assertFalse(journal.exists())
        self.assertFalse(temp.exists())
        self.assertFalse(final.exists())
        self.assertEqual((self.store.cases / self.case / "originals" /
                          self.source["artifact_id"]).read_bytes(), self.raw)

    def test_after_link_keeps_valid_final_and_retires_only_second_link(self):
        work, journal, temp, final = self.interrupted(stage=3)
        self.assertEqual(temp.stat().st_ino, final.stat().st_ino)
        self.assertEqual(temp.stat().st_nlink, 2)
        self.age(journal, temp, final)
        plan = self.recover_preview(work)
        self.assertEqual(plan["disposition"], "COMMITTED")
        final_content = final.read_bytes()
        outcome = self.confirm(work, plan)
        self.assertEqual(outcome["status"], "COMMITTED_JOURNAL_CLEARED")
        self.assertEqual(outcome["committed_handoffs_removed"], 0)
        self.assertFalse(temp.exists())
        self.assertFalse(journal.exists())
        self.assertEqual(final.read_bytes(), final_content)
        self.assertEqual(final.stat().st_nlink, 1)
        self.assertEqual(hashlib.sha256(final_content).hexdigest(),
                         self.plan["plan_sha256"])

    def test_after_temp_unlink_can_retire_only_journal(self):
        work, journal, temp, final = self.interrupted(stage=4)
        self.assertFalse(temp.exists())
        self.assertTrue(final.exists())
        self.age(journal, final)
        state = self.recover_preview(work)
        self.assertEqual(state["disposition"], "COMMITTED")
        self.assertEqual(state["scratch_bytes"], 0)
        recovered = self.confirm(work, state)
        self.assertEqual(recovered["removed_unpublished_files"], 0)
        self.assertTrue(final.exists())
        self.assertFalse(journal.exists())

    def test_recovery_interruption_is_repreviewable_without_deleting_final(self):
        work, journal, temp, final = self.interrupted(stage=3)
        self.age(journal, temp, final)
        planned = self.recover_preview(work)
        with patch.object(handoff_recovery, "_sync_directory",
                          side_effect=CaseError("synthetic recovery interruption")):
            with self.assertRaises(CaseError):
                self.confirm(work, planned)
        self.assertTrue(journal.exists())
        self.assertTrue(final.exists())
        self.assertFalse(temp.exists())
        after = self.recover_preview(work)
        self.assertNotEqual(after["recovery_plan_sha256"],
                            planned["recovery_plan_sha256"])
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(work, planned)
        result = self.confirm(work, after)
        self.assertEqual(result["status"], "COMMITTED_JOURNAL_CLEARED")
        self.assertTrue(final.exists())

    def test_committed_file_mutation_during_recovery_keeps_journal(self):
        work, journal, temp, final = self.interrupted(stage=3)
        self.age(journal, temp, final)
        approved = self.recover_preview(work)
        real_sync = handoff_recovery._sync_directory

        def tamper_after_temp_unlink(directory):
            final.write_bytes(b"synthetic changed during recovery")
            return real_sync(directory)

        with patch.object(handoff_recovery, "_sync_directory",
                          side_effect=tamper_after_temp_unlink):
            with self.assertRaisesRegex(CaseError, "Committed handoff changed"):
                self.confirm(work, approved)
        self.assertFalse(temp.exists())
        self.assertTrue(final.exists())
        self.assertTrue(journal.exists())
        self.assertEqual((self.store.cases / self.case / "originals" /
                          self.source["artifact_id"]).read_bytes(), self.raw)

    def test_journal_mutation_during_recovery_refuses_retirement(self):
        work, journal, temp, final = self.interrupted(stage=3)
        self.age(journal, temp, final)
        approved = self.recover_preview(work)
        real_sync = handoff_recovery._sync_directory

        def tamper_journal_after_temp_unlink(directory):
            journal.write_bytes(journal.read_bytes() + b" ")
            return real_sync(directory)

        with patch.object(handoff_recovery, "_sync_directory",
                          side_effect=tamper_journal_after_temp_unlink):
            with self.assertRaisesRegex(CaseError, "journal changed"):
                self.confirm(work, approved)
        self.assertFalse(temp.exists())
        self.assertTrue(final.exists())
        self.assertTrue(journal.exists())
        self.assertEqual(hashlib.sha256(final.read_bytes()).hexdigest(),
                         self.plan["plan_sha256"])

    def test_stale_plan_and_tampered_partial_do_not_trigger_deletion(self):
        work, journal, temp, final = self.interrupted(stage=2)
        self.age(journal, temp)
        preview = self.recover_preview(work)
        temp.write_bytes(b"modified interrupted metadata")
        # Modification refreshes mtime: an active/recent file must fail
        # before an old approval can authorize any deletion.
        with self.assertRaisesRegex(CaseError, "too recent"):
            self.confirm(work, preview)
        self.age(temp)
        # Even once old enough, its original approval is no longer valid.
        with self.assertRaisesRegex(CaseError, "plan changed"):
            self.confirm(work, preview)
        self.assertTrue(temp.exists())
        self.assertTrue(journal.exists())
        self.assertFalse(final.exists())

    def test_tampered_committed_file_never_removed_by_recovery(self):
        work, journal, temp, final = self.interrupted(stage=3)
        final.write_bytes(b"corrupt after linked")
        self.age(journal, temp, final)
        with self.assertRaisesRegex(CaseError, "incorrect approved"):
            self.recover_preview(work)
        self.assertTrue(final.exists())
        self.assertTrue(journal.exists())
        self.assertTrue(temp.exists())

    def test_journal_symlink_or_hardlink_blocks_without_touching_outside(self):
        work, journal, temp, _ = self.interrupted(stage=2)
        external = self.home / "untouched"
        external.write_bytes(journal.read_bytes())
        journal.unlink()
        journal.symlink_to(external)
        self.age(temp)
        with self.assertRaises((CaseError, OSError)):
            self.recover_preview(work)
        self.assertTrue(external.exists())
        journal.unlink()
        journal.write_bytes(external.read_bytes())
        journal.chmod(0o600)
        os.link(journal, self.home / "alias")
        with self.assertRaisesRegex(CaseError, "links unsafe"):
            self.recover_preview(work)

    def test_unjournaled_legacy_orphan_is_reported_but_never_swept(self):
        self.exports.mkdir(mode=0o700)
        orphan = self.exports / (".tmp-handoff-" + "f" * 32)
        orphan.write_bytes(b"legacy incomplete metadata")
        orphan.chmod(0o600)
        listing = handoff_recovery.list_interrupted(self.store, self.case)
        self.assertEqual(listing["status"], "PARTIAL")
        self.assertEqual(listing["unmatched_temp_entries"], 1)
        self.assertEqual(listing["handoff_work_ids"], [])
        with self.assertRaises((CaseError, FileNotFoundError)):
            self.recover_preview("f" * 32)
        self.assertEqual(orphan.read_bytes(), b"legacy incomplete metadata")

    def test_invalid_journal_is_not_silently_cleaned(self):
        work, journal, temp, _ = self.interrupted(stage=2)
        journal.write_bytes(b"not-a-journal")
        self.age(journal, temp)
        with self.assertRaises(CaseError):
            self.recover_preview(work)
        with self.assertRaises(CaseError):
            handoff_recovery.list_interrupted(self.store, self.case)
        self.assertTrue(journal.exists())
        self.assertTrue(temp.exists())

    def test_different_case_journal_does_not_show_up_in_listing(self):
        work, journal, temp, final = self.interrupted(stage=2)
        other = self.store.open_case()["case_id"]
        state = handoff_recovery.list_interrupted(self.store, other)
        self.assertEqual(state["handoff_work_ids"], [])
        self.assertIn(work, handoff_recovery.list_interrupted(
            self.store, self.case)["handoff_work_ids"])

    def test_operator_cli_two_invocations_and_raw_export_option_refused(self):
        work, journal, temp, final = self.interrupted(stage=2)
        self.age(journal, temp)
        script = Path(__file__).resolve().parents[1] / "scripts/handoff_recovery_cli.py"
        env = {**os.environ, "HOME": str(self.home)}

        def invoke(*args):
            return subprocess.run(
                [sys.executable, "-u", str(script), "--case-id", self.case, *args],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, timeout=25)
        listing = invoke("--list")
        self.assertEqual(listing.returncode, 0, listing.stderr.decode())
        self.assertEqual(json.loads(listing.stdout)["handoff_work_ids"], [work])
        planned = invoke("--work-id", work)
        self.assertEqual(planned.returncode, 0, planned.stderr.decode())
        digest = json.loads(planned.stdout)["recovery_plan_sha256"]
        self.assertNotIn(self.raw, planned.stdout)
        for args in [("--work-id", work, "--confirm"),
                     ("--work-id", work, "--include-raw"),
                     ("--work-id", work, "--confirm",
                      "--recovery-plan-sha256", "a" * 64)]:
            self.assertNotEqual(invoke(*args).returncode, 0)
        approved = invoke("--work-id", work, "--confirm",
                          "--recovery-plan-sha256", digest)
        self.assertEqual(approved.returncode, 0, approved.stderr.decode())
        self.assertEqual(json.loads(approved.stdout)["registered_originals_removed"], 0)
        self.assertFalse(journal.exists())
        self.assertFalse(temp.exists())

    def test_full_capacity_and_bad_age_inputs_are_rejected(self):
        work, journal, temp, final = self.interrupted(stage=2)
        self.age(journal, temp)
        for hours in [0, 23, 8761, -1, True, 1.5]:
            with self.assertRaises(CaseError):
                handoff_recovery.recover(self.store, self.case, work,
                                         older_hours=hours)
        self.assertTrue(journal.exists())


if __name__ == "__main__":
    unittest.main()
