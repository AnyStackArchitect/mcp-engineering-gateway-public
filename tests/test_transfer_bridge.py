"""Known-answer tests for SSH/SCP staged-file verification and cleanup."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from casework import CaseError, CaseStore
import transfer_bridge


class TransferTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home=Path(directory.name)
        self.store=CaseStore(self.home)
        self.info=transfer_bridge.prepare(self.store)
        self.temp='.upload-'+'a'*32
        self.body=b'2026-10-15T12:00:00Z ERROR token=local-only\n'
        self.sha=hashlib.sha256(self.body).hexdigest()

    def upload(self,contents=None,mode=0o644):
        p=self.store.inbox/self.temp
        p.write_bytes(self.body if contents is None else contents)
        p.chmod(mode)
        return p

    def finalize(self,destination='bundle.log',sha=None,size=None):
        return transfer_bridge.finalize(self.store,self.temp,destination,
               len(self.body) if size is None else size, self.sha if sha is None else sha)

    def test_prepare_initializes_private_inbox_without_a_listener(self):
        self.assertEqual(self.info['status'],'READY')
        self.assertEqual(stat.S_IMODE(self.store.inbox.stat().st_mode),0o700)
        self.assertEqual(self.info['max_artifact_bytes'],8*1024**3)

    def test_finish_atomic_digest_verified_handoff_to_existing_case(self):
        self.upload()
        result=self.finalize()
        self.assertEqual((result['status'],result['sha256'],result['bytes']),('STAGED',self.sha,len(self.body)))
        self.assertEqual((self.store.inbox/'bundle.log').read_bytes(),self.body)
        self.assertEqual(stat.S_IMODE((self.store.inbox/'bundle.log').stat().st_mode),0o600)
        self.assertFalse((self.store.inbox/self.temp).exists())
        cid=self.store.open_case()['case_id']
        item=self.store.register(cid,'bundle.log')
        self.assertEqual(item['sha256'],self.sha)

    def test_existing_destination_never_overwritten(self):
        target=self.store.inbox/'bundle.log'
        target.write_bytes(b'existing');target.chmod(0o600)
        self.upload()
        with self.assertRaisesRegex(CaseError,'Destination exists'):
            self.finalize()
        self.assertEqual(target.read_bytes(),b'existing')
        self.assertTrue((self.store.inbox/self.temp).exists())

    def test_digest_mismatch_rejects_without_final_name(self):
        self.upload()
        with self.assertRaisesRegex(CaseError,'digest'):
            self.finalize(sha='0'*64)
        self.assertFalse((self.store.inbox/'bundle.log').exists())
        self.assertTrue((self.store.inbox/self.temp).exists())

    def test_size_mismatch_rejects(self):
        self.upload()
        with self.assertRaisesRegex(CaseError,'type, ownership, length'):
            self.finalize(size=1)
        self.assertFalse((self.store.inbox/'bundle.log').exists())

    def test_hardlink_temp_refused_before_chmod(self):
        p=self.upload()
        alias=self.home/'alias'
        os.link(p,alias)
        with self.assertRaisesRegex(CaseError,'ownership'):
            self.finalize()
        self.assertEqual(stat.S_IMODE(alias.stat().st_mode),0o644)

    def test_symlink_temp_refused(self):
        outside=self.home/'personal.txt'
        outside.write_text('private');outside.chmod(0o600)
        (self.store.inbox/self.temp).symlink_to(outside)
        with self.assertRaises((OSError,CaseError)):
            self.finalize(size=7,sha=hashlib.sha256(b'private').hexdigest())
        self.assertEqual(outside.read_text(),'private')

    def test_world_writable_temp_refused(self):
        self.upload(mode=0o666)
        with self.assertRaisesRegex(CaseError,'permissions'):
            self.finalize()

    def test_invalid_temp_and_target_names(self):
        self.upload()
        for temp in ('../bad','temp','a'*32,'.upload-xyz'):
            with self.subTest(temp=temp),self.assertRaises(CaseError):
                transfer_bridge.finalize(self.store,temp,'safe.log',len(self.body),self.sha)
        for target in ('../../etc/passwd','bad/name','bad\\name','.hidden','x y','bad:port','-flag'):
            with self.subTest(target=target),self.assertRaises(CaseError):
                self.finalize(destination=target)

    def test_abort_removes_only_ephemeral_name(self):
        self.upload()
        stable=self.store.inbox/'stable.log'
        stable.write_text('do-not-remove');stable.chmod(0o600)
        self.assertEqual(transfer_bridge.abort(self.store,self.temp)['status'],'TEMPORARY_FILE_REMOVED')
        self.assertEqual(stable.read_text(),'do-not-remove')
        self.assertEqual(transfer_bridge.abort(self.store,self.temp)['status'],'NO_TEMPORARY_FILE')
        with self.assertRaises(CaseError):
            transfer_bridge.abort(self.store,'stable.log')

    def test_abort_symlink_removes_only_link(self):
        target=self.home/'outside'
        target.write_text('safe')
        (self.store.inbox/self.temp).symlink_to(target)
        transfer_bridge.abort(self.store,self.temp)
        self.assertEqual(target.read_text(),'safe')

    def test_unbounded_or_forged_declared_limits_rejected(self):
        self.upload()
        for bogus in (-1,8*1024**3+1):
            with self.assertRaises(CaseError):
                self.finalize(size=bogus)
        for bogus in ('no','G'*64,'a'*63):
            with self.assertRaises(CaseError):
                self.finalize(sha=bogus)

    def test_legacy_scp_writes_reserved_placeholder_and_finalizes_privately(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from casework import FREE_RESERVE
        import resumable_transfer
        from capacitywork import admission_lock, outstanding_reservations

        free = FREE_RESERVE + 4 * len(self.body)
        with patch.object(transfer_bridge.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=free)):
            pre = transfer_bridge.prepare(self.store, proposed_size=len(self.body))
            self.assertEqual(pre["status"], "READY")
            session = resumable_transfer.begin(
                self.store, self.temp, len(self.body), self.sha)
            self.assertEqual(session["status"], "SESSION_CREATED")
            with admission_lock(self.store):
                self.assertEqual(outstanding_reservations(self.store), len(self.body))
            # Simulate SFTP/SCP overwriting its already-reserved 0600
            # placeholder, not a second untracked temporary file.
            stage = self.store.inbox / self.temp
            with open(stage, "wb") as output:
                output.write(self.body[:13])
            with admission_lock(self.store):
                self.assertEqual(outstanding_reservations(self.store),
                                 len(self.body) - 13)
            with open(stage, "ab") as output:
                output.write(self.body[13:])
            complete = self.finalize()
            self.assertEqual(complete["status"], "STAGED")
            self.assertEqual(complete["sha256"], self.sha)
            self.assertFalse((self.store.inbox / (self.temp + ".session")).exists())
            self.assertFalse(stage.exists())
            self.assertEqual((self.store.inbox / "bundle.log").read_bytes(), self.body)
            with admission_lock(self.store):
                self.assertEqual(outstanding_reservations(self.store), 0)

    def test_failed_legacy_scp_abort_releases_durable_reservation(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from casework import FREE_RESERVE
        import resumable_transfer
        from capacitywork import admission_lock, outstanding_reservations

        free = FREE_RESERVE + 2 * len(self.body)
        with patch.object(transfer_bridge.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=free)):
            resumable_transfer.begin(self.store, self.temp, len(self.body), self.sha)
            with open(self.store.inbox / self.temp, "wb") as output:
                output.write(self.body[:8])
            with admission_lock(self.store):
                self.assertEqual(outstanding_reservations(self.store),
                                 len(self.body) - 8)
            with self.assertRaisesRegex(CaseError, "length"):
                self.finalize()
            self.assertFalse((self.store.inbox / "bundle.log").exists())
            result = transfer_bridge.abort(self.store, self.temp)
            self.assertEqual(result["status"], "TEMPORARY_FILE_REMOVED")
            self.assertFalse((self.store.inbox / (self.temp + ".session")).exists())
            self.assertFalse((self.store.inbox / self.temp).exists())
            with admission_lock(self.store):
                self.assertEqual(outstanding_reservations(self.store), 0)

    def test_existing_session_rejects_duplicate_scp_reservation_without_touching_prefix(self):
        import resumable_transfer
        resumable_transfer.begin(self.store, self.temp, len(self.body), self.sha)
        with (self.store.inbox / self.temp).open("wb") as stream:
            stream.write(self.body[:9])
        with self.assertRaises((FileExistsError, CaseError)):
            resumable_transfer.begin(self.store, self.temp, len(self.body), self.sha)
        self.assertEqual((self.store.inbox / self.temp).read_bytes(), self.body[:9])

    def test_local_powershell_helper_has_explicit_scoping(self):
        code=(Path(__file__).resolve().parents[1]/'windows'/'Send-RockyEvidence.ps1').read_text()
        for keyword in ('Get-FileHash','StrictHostKeyChecking=yes',"'finalize'",'Get-Item',"'abort'",'DestinationName',"'prepare'",'& scp'):
            self.assertIn(keyword,code)
        self.assertNotIn('Invoke-Expression',code)
        self.assertNotIn('Start-Process powershell',code)


if __name__=='__main__':
    unittest.main()
