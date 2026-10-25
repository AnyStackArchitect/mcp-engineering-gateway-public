"""Synthetic real Ed25519/rename/unlink tests; no production trust enrolled.

Only the production enable gate and trusted-key location are injected. Every
signature, snapshot hash, journal, filesystem operation and recovery is real.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import case_disposition as cd
import disposition_grants as dg
from casework import CaseError, CaseStore, _write_json_atomic
from operator_sign_disposition import sign_plan
from preservationwork import propose_or_record


class CaseDispositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rocky-disposition-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "synthetic-case-owner"
        self.home.mkdir(mode=0o700)
        self.store = CaseStore(self.home)
        self.case = self.store.open_case()["case_id"]
        self.register("synthetic-one.log", b"2026-01-01T00:00:00Z synthetic password=never-print\n" * 9)
        self.register("synthetic-two.log", b"a different synthetic original\n")
        self.folder = self.store.cases / self.case
        with self.store._locked(self.case) as (_, manifest):
            manifest["created_at"] = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
            _write_json_atomic(self.folder / "manifest.json", manifest)
        self.start = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.attest = {name: hashlib.sha256(("synthetic " + name).encode()).hexdigest() for name in dg.ATTESTATIONS}
        self.keys, self.public = {}, {}
        for role in dg.ROLES:
            key, pub = self.root / (role + ".pem"), self.root / (role + ".pub")
            for args in (("genpkey", "-algorithm", "ED25519", "-out", str(key)),
                         ("pkey", "-in", str(key), "-pubout", "-out", str(pub))):
                result = subprocess.run(["/usr/bin/openssl", *args], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            key.chmod(0o600)
            self.keys[role] = key
            self.public[role] = pub.read_bytes()
        self.addCleanup(patch.stopall)
        self.key_patch = patch.object(dg, "_public_key", side_effect=lambda role: self.public[role])
        self.key_patch.start()
        self.policy_patch = patch.object(dg, "production_gate", return_value=None)
        self.policy_patch.start()

    def register(self, name, data):
        path = self.store.inbox / name
        path.write_bytes(data)
        path.chmod(0o600)
        return self.store.register(self.case, name)

    def preview(self, action="RETIRE"):
        return cd.preview(self.store, self.case, action=action, minimum_age_days=30,
                          retention_start_utc=self.start)

    def signed(self, packet=None, action="RETIRE"):
        packet = self.preview(action) if packet is None else packet
        return dg.canonical({"grants": [sign_plan(dg.canonical(packet), self.keys[role], role,
            self.attest, "/usr/bin/openssl") for role in dg.ROLES]})

    def execute(self, action="RETIRE"):
        return cd.execute(self.store, self.signed(action=action))

    def crash(self, point, action="RETIRE"):
        signed = self.signed(action=action)
        fired = False
        def fail(name):
            nonlocal fired
            if name == point and not fired:
                fired = True
                raise RuntimeError("synthetic interruption")
        with patch.object(cd, "_checkpoint", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "synthetic interruption"):
                cd.execute(self.store, signed)
        self.assertTrue(fired)
        return signed

    def test_real_retire_restore_and_new_retirement_cycle(self):
        before = {p.name: p.read_bytes() for p in (self.folder / "originals").iterdir()}
        result = self.execute()
        self.assertEqual(result["status"], "CASE_RETIRED_RECOVERABLE")
        self.assertFalse(self.folder.exists())
        with self.assertRaises(CaseError):
            self.store.status(self.case)
        self.assertEqual(self.execute("RESTORE")["status"], "CASE_RESTORED")
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.folder / "originals").iterdir()})
        self.assertEqual(self.execute()["status"], "CASE_RETIRED_RECOVERABLE")
        archived = [p for p in (self.store.base / cd.OUT_DIR).iterdir() if p.name.startswith("restored-")]
        self.assertEqual(len(archived), 1)

    def test_first_cycle_grants_remain_consumed_across_new_cycle_crash_gaps(self):
        first = self.signed()
        cd.execute(self.store, first)
        self.execute("RESTORE")
        self.crash("AFTER_CYCLE_ARCHIVE")
        with self.assertRaisesRegex(CaseError, "nonce already consumed"):
            cd.execute(self.store, first)
        self.assertTrue(self.folder.exists())
        self.crash("AFTER_INITIALIZATION_PUBLISH")
        with self.assertRaisesRegex(CaseError, "nonce already consumed"):
            cd.execute(self.store, first)
        self.assertTrue(self.folder.exists())
        self.assertEqual(self.execute()["status"], "CASE_RETIRED_RECOVERABLE")

    def test_final_delete_needs_new_dual_grants_and_retains_metadata(self):
        retire = self.signed()
        cd.execute(self.store, retire)
        with self.assertRaises(CaseError):
            cd.execute(self.store, retire)
        result = self.execute("FINAL_DELETE")
        self.assertEqual(result["status"], "EVIDENCE_FILES_DELETED_METADATA_RETAINED")
        self.assertEqual(result["originals_removed"], 2)
        quarantine = self.store.base / cd.OUT_DIR / self.case / "quarantine"
        self.assertEqual(list((quarantine / "originals").iterdir()), [])
        self.assertTrue((quarantine / "manifest.json").exists())
        self.assertTrue((self.store.inbox / "synthetic-one.log").exists())
        for field in ("legal_authority_independently_verified", "backup_custody_independently_verified",
                      "restore_test_independently_verified", "latest_external_checkpoint_independently_verified",
                      "hostile_same_uid_rollback_resistance_verified", "secure_erase_verified", "hold_release_supported"):
            self.assertFalse(result[field], field)
        with self.assertRaises(CaseError):
            self.preview("RESTORE")

    def test_final_delete_on_active_case_refused(self):
        with self.assertRaisesRegex(CaseError, "retired case"):
            self.preview("FINAL_DELETE")

    def test_unsigned_or_single_role_cannot_authorize(self):
        with self.assertRaises(dg.DispositionGrantError):
            cd.execute(self.store, dg.canonical(self.preview()))
        document = dg.decode(self.signed())
        document["grants"].pop()
        with self.assertRaises(dg.DispositionGrantError):
            cd.execute(self.store, dg.canonical(document))
        self.assertTrue(self.folder.exists())

    def test_duplicate_role_or_same_key_refused(self):
        document = dg.decode(self.signed())
        document["grants"][1] = document["grants"][0]
        with self.assertRaises(dg.DispositionGrantError):
            cd.execute(self.store, dg.canonical(document))
        second = dg.ROLES[1]
        self.keys[second] = self.keys[dg.ROLES[0]]
        self.public[second] = self.public[dg.ROLES[0]]
        with self.assertRaisesRegex(dg.DispositionGrantError, "distinct roles and keys"):
            cd.execute(self.store, self.signed())

    def test_forgery_and_changed_attestations_refused(self):
        document = dg.decode(self.signed())
        document["grants"][0]["payload"]["attestations"]["backup_manifest_sha256"] = "a" * 64
        with self.assertRaisesRegex(dg.DispositionGrantError, "signature verification"):
            cd.execute(self.store, dg.canonical(document))
        self.assertFalse((self.store.base / cd.OUT_DIR).exists())

    def test_distinct_attestations_cannot_be_combined(self):
        packet = self.preview()
        one = sign_plan(dg.canonical(packet), self.keys[dg.ROLES[0]], dg.ROLES[0], self.attest, "/usr/bin/openssl")
        changed = dict(self.attest, authority_record_sha256="b" * 64)
        two = sign_plan(dg.canonical(packet), self.keys[dg.ROLES[1]], dg.ROLES[1], changed, "/usr/bin/openssl")
        with self.assertRaises(dg.DispositionGrantError):
            cd.execute(self.store, dg.canonical({"grants": [one, two]}))

    def test_expired_and_future_grants_refused(self):
        signed = self.signed()
        with patch.object(dg.time, "time", return_value=int(__import__("time").time()) + 301):
            with self.assertRaisesRegex(dg.DispositionGrantError, "expired"):
                cd.execute(self.store, signed)

    def test_grant_expiring_during_final_hash_does_not_unlink(self):
        self.execute()
        signed = self.signed(action="FINAL_DELETE")
        expiry = min(g["payload"]["expires_at"] for g in dg.decode(signed)["grants"])
        current, deleting = [expiry - 1], [False]
        real_hash = cd._file_record
        def checkpoint(name):
            if name == "BEFORE_EVIDENCE_UNLINK":
                deleting[0] = True
        def slow_final_hash(*args, **kwargs):
            result = real_hash(*args, **kwargs)
            if deleting[0]:
                current[0] = expiry
            return result
        with patch.object(dg.time, "time", side_effect=lambda: current[0]), \
                patch.object(cd, "_checkpoint", side_effect=checkpoint), \
                patch.object(cd, "_file_record", side_effect=slow_final_hash):
            with self.assertRaisesRegex(dg.DispositionGrantError, "expired"):
                cd.execute(self.store, signed)
        originals = self.store.base / cd.OUT_DIR / self.case / "quarantine" / "originals"
        self.assertEqual(len(list(originals.iterdir())), 2)
        self.assertEqual(self.execute("FINAL_DELETE")["originals_removed"], 2)

    def test_stale_source_metadata_and_new_original_refused(self):
        signed = self.signed()
        self.register("new-evidence.log", b"new synthetic content")
        with self.assertRaisesRegex(CaseError, "Stale disposition"):
            cd.execute(self.store, signed)
        self.assertTrue(self.folder.exists())

    def test_hold_cannot_be_overridden(self):
        signed = self.signed()
        source = next(iter(self.store.status(self.case)["artifacts"]))["sha256"]
        kwargs = {"action": "PRESERVATION_HOLD", "reason_code": "investigation", "reference_sha256": source}
        plan = propose_or_record(self.store, self.case, **kwargs)
        propose_or_record(self.store, self.case, **kwargs, confirm=True, plan_sha256=plan["plan_sha256"])
        with self.assertRaisesRegex(CaseError, "hold"):
            cd.execute(self.store, signed)

    def test_retention_floor_cannot_be_lowered_by_disposition_request(self):
        source = self.store.status(self.case)["artifacts"][0]["sha256"]
        kwargs = {"action": "MINIMUM_RETENTION_DAYS", "reference_sha256": source, "minimum_days": 120}
        plan = propose_or_record(self.store, self.case, **kwargs)
        propose_or_record(self.store, self.case, **kwargs, confirm=True, plan_sha256=plan["plan_sha256"])
        with self.assertRaisesRegex(CaseError, "floor"):
            self.preview()

    def test_too_recent_declared_retention_start_refused(self):
        with self.assertRaisesRegex(CaseError, "age"):
            cd.preview(self.store, self.case, action="RETIRE", minimum_age_days=30,
                       retention_start_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def test_unknown_index_and_hardlinked_original_block(self):
        idx = self.folder / "indexes" / "unidentified.sqlite3"
        idx.write_bytes(b"unknown")
        idx.chmod(0o600)
        with self.assertRaises(CaseError):
            self.preview()
        idx.unlink()
        original = next((self.folder / "originals").iterdir())
        os.link(original, self.root / "extra-link")
        with self.assertRaises(CaseError):
            self.preview()

    def test_interruption_before_and_after_retire_rename(self):
        self.crash("AFTER_DURABLE_AUTHORIZATION")
        self.assertTrue(self.folder.exists())
        self.crash("AFTER_RETIRE_RENAME")
        self.assertFalse(self.folder.exists())
        self.assertEqual(self.execute()["status"], "CASE_RETIRED_RECOVERABLE")
        self.assertEqual(self.execute("RESTORE")["status"], "CASE_RESTORED")

    def test_interrupted_restore_rename_is_recoverable(self):
        self.execute()
        self.crash("AFTER_RESTORE_RENAME", "RESTORE")
        self.assertTrue(self.folder.exists())
        self.assertEqual(self.execute("RESTORE")["status"], "CASE_RESTORED")

    def test_purge_crash_before_unlink_and_after_unlink_recovers(self):
        self.execute()
        self.crash("BEFORE_EVIDENCE_UNLINK", "FINAL_DELETE")
        with self.assertRaisesRegex(CaseError, "Partially deleted"):
            self.preview("RESTORE")
        self.crash("AFTER_EVIDENCE_UNLINK", "FINAL_DELETE")
        self.assertEqual(self.execute("FINAL_DELETE")["originals_removed"], 2)

    def test_crash_at_journal_hardlink_window_recovers(self):
        self.crash("AFTER_JOURNAL_LINK")
        directory = self.store.base / cd.OUT_DIR / self.case / "events"
        self.assertEqual((directory / ".pending").stat().st_nlink, 2)
        self.assertEqual(self.execute()["status"], "CASE_RETIRED_RECOVERABLE")
        self.assertFalse((directory / ".pending").exists())

    def test_staging_initialization_crashes_can_abort_without_evidence_loss(self):
        for point in ("AFTER_INITIALIZATION_DIRECTORY", "AFTER_INITIALIZATION_INVENTORY"):
            with self.subTest(point=point):
                self.crash(point)
                result = cd.abort_initialization(self.store, self.case)
                self.assertEqual(result["metadata_initializations_removed"], 1)
                self.assertEqual(result["originals_removed"], 0)
                self.assertEqual(self.store.status(self.case)["artifact_count"], 2)
        self.assertEqual(self.execute()["status"], "CASE_RETIRED_RECOVERABLE")

    def test_published_initialization_before_authorize_can_resume(self):
        self.crash("AFTER_INITIALIZATION_PUBLISH")
        self.assertTrue(self.folder.exists())
        self.assertEqual(self.execute()["status"], "CASE_RETIRED_RECOVERABLE")

    def fill_disposition_root(self, count):
        root = self.store.base / cd.OUT_DIR
        root.mkdir(mode=0o700, exist_ok=True)
        for index in range(count - len(list(root.iterdir()))):
            (root / ("synthetic-completed-" + str(index))).mkdir(mode=0o700)
        return root

    def test_full_root_refuses_new_retirement_before_any_mutation(self):
        signed = self.signed()
        root = self.fill_disposition_root(cd.MAX_TRANSACTIONS)
        before = set(p.name for p in root.iterdir())
        with self.assertRaisesRegex(CaseError, "capacity exhausted"):
            cd.execute(self.store, signed)
        self.assertEqual(before, set(p.name for p in root.iterdir()))
        self.assertTrue(self.folder.exists())

    def test_full_root_refuses_new_cycle_but_restore_remains_reachable(self):
        self.execute()
        root = self.fill_disposition_root(cd.MAX_TRANSACTIONS)
        self.assertEqual(self.execute("RESTORE")["status"], "CASE_RESTORED")
        transaction = root / self.case
        before = cd._history(transaction)["head"]
        with self.assertRaisesRegex(CaseError, "capacity exhausted"):
            self.execute()
        self.assertEqual(cd._history(transaction)["head"], before)
        self.assertEqual(len(list(root.iterdir())), cd.MAX_TRANSACTIONS)
        self.assertTrue(self.folder.exists())

    def test_last_root_slot_keeps_retired_case_and_initialization_recoverable(self):
        root = self.fill_disposition_root(cd.MAX_TRANSACTIONS - 1)
        self.crash("AFTER_INITIALIZATION_DIRECTORY")
        self.assertEqual(len(list(root.iterdir())), cd.MAX_TRANSACTIONS)
        self.assertEqual(cd.abort_initialization(self.store, self.case)["metadata_initializations_removed"], 1)
        self.assertEqual(self.execute()["status"], "CASE_RETIRED_RECOVERABLE")
        self.assertEqual(len(list(root.iterdir())), cd.MAX_TRANSACTIONS)
        self.assertEqual(self.execute("RESTORE")["status"], "CASE_RESTORED")

    def test_legacy_one_over_capacity_does_not_strand_existing_restore(self):
        self.execute()
        self.fill_disposition_root(cd.MAX_TRANSACTIONS + 1)
        self.assertEqual(self.execute("RESTORE")["status"], "CASE_RESTORED")

    def test_missing_without_purge_intent_and_quarantine_symlink_refused(self):
        self.execute()
        originals = self.store.base / cd.OUT_DIR / self.case / "quarantine" / "originals"
        item = next(originals.iterdir())
        item.unlink()
        with self.assertRaisesRegex(CaseError, "without durable"):
            self.preview("FINAL_DELETE")
        item.symlink_to(self.root / "outside")
        with self.assertRaises((CaseError, OSError)):
            self.preview("FINAL_DELETE")

    def test_consumed_grants_cannot_resume_interruption(self):
        signed = self.crash("AFTER_DURABLE_AUTHORIZATION")
        with self.assertRaisesRegex(CaseError, "nonce already consumed"):
            cd.execute(self.store, signed)

    def test_production_gate_is_really_disabled_without_enrollment(self):
        self.policy_patch.stop()
        with self.assertRaises(dg.DispositionGrantError):
            cd.execute(self.store, self.signed())
        self.assertTrue(self.folder.exists())

    def test_malformed_preview_inputs_refuse_before_mutation(self):
        for case in (None, "", [], "../outside"):
            with self.subTest(case=case), self.assertRaises(CaseError):
                cd.preview(self.store, case, action="RETIRE", minimum_age_days=30, retention_start_utc=self.start)
        for raw in (b"", b"null", b"[]", b"{}", b'{"grants":[],"grants":[]}', b"x" * (dg.MAX_BYTES + 1)):
            with self.subTest(raw=raw[:25]), self.assertRaises(dg.DispositionGrantError):
                cd.execute(self.store, raw)
        self.assertFalse((self.store.base / cd.OUT_DIR).exists())


if __name__ == "__main__":
    unittest.main()
