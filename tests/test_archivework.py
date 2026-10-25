"""Adversarial known-answer tests for ZIP, TAR, GZIP expansion and vault hashing."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import archivework
from casework import CaseError, CaseStore, FREE_RESERVE
import resumable_transfer
import capacitywork
import jobwork


class ArchiveWorkTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.home=Path(t.name)
        self.store=CaseStore(self.home)
        self.case=self.store.open_case()['case_id']

    def staged(self, name: str, payload: bytes) -> dict:
        p=self.store.inbox/name
        p.write_bytes(payload)
        p.chmod(0o600)
        return self.store.register(self.case,name)

    def zips(self, members: list[tuple[str,bytes]], special=None) -> bytes:
        fp=io.BytesIO()
        with zipfile.ZipFile(fp,'w',compression=zipfile.ZIP_DEFLATED) as zip:
            for name,payload in members:
                if special is not None:
                    info=zipfile.ZipInfo(name)
                    info.create_system=3
                    info.external_attr=(special << 16)
                    zip.writestr(info,payload)
                else:
                    zip.writestr(name,payload)
        return fp.getvalue()

    def tar(self, members: list[tuple[str,bytes]], *, mode='w', kind=tarfile.REGTYPE):
        fp=io.BytesIO()
        with tarfile.open(fileobj=fp,mode=mode) as tar:
            for name,data in members:
                info=tarfile.TarInfo(name=name)
                info.size=len(data) if kind==tarfile.REGTYPE else 0
                info.type=kind
                tar.addfile(info,io.BytesIO(data) if kind==tarfile.REGTYPE else None)
        return fp.getvalue()

    def unpack(self, item):
        return archivework.unpack_case_archive(self.store,self.case,item['artifact_id'])

    def artifacts(self):
        with self.store._locked(self.case) as (_,manifest):
            return dict(manifest['artifacts'])

    def test_valid_zip_extracts_opaque_case_artifacts_and_supports_log_search(self):
        original=b'2026-10-15T12:00:00Z ERROR token=super_secret\n'
        item=self.staged('bundle.zip',self.zips([('logs/one.log',original),('logs/two.log',b'abc\n')]))
        self.assertEqual(item['type'],'zip')
        results=self.unpack(item)
        self.assertEqual(results['status'],'PASS')
        self.assertEqual(results['derived_artifact_count'],2)
        derived=results['artifact_ids']
        m=self.artifacts()
        self.assertEqual(len(m),3)
        self.assertEqual(m[derived[0]]['derived_from'],item['artifact_id'])
        self.assertEqual(m[derived[0]]['sha256'],hashlib.sha256(original).hexdigest())
        self.assertEqual((self.store.cases/self.case/'originals'/derived[0]).read_bytes(),original)
        self.assertEqual(stat.S_IMODE((self.store.cases/self.case/'originals'/derived[0]).stat().st_mode),0o600)
        self.store.index_log(self.case,derived[0])
        search=self.store.search_log(self.case,derived[0],'ERROR')
        self.assertEqual(len(search['matches']),1)
        self.assertNotIn('super_secret',json.dumps(search))
        self.assertEqual(archivework.verify_case(self.store,self.case)['status'],'PASS')

    def test_valid_gzip_single_file(self):
        payload=b'2026-10-15T10:00:00Z Hello\n'
        item=self.staged('node.log.gz',gzip.compress(payload))
        r=self.unpack(item)
        self.assertEqual(r['derived_artifact_count'],1)
        self.assertEqual(self.artifacts()[r['artifact_ids'][0]]['type'],'text')
        self.assertEqual(self.artifacts()[r['artifact_ids'][0]]['intake_name'],'node.log')

    def test_valid_ustar_and_tar_gzip(self):
        raw=self.tar([('safe/a.log',b'a'),('safe/b.log',b'b')])
        for name,data,expected_type in [('sample.tar',raw,'tar'),('sample.tar.gz',gzip.compress(raw),'gzip')]:
            with self.subTest(name=name):
                item=self.staged(name,data)
                self.assertEqual(item['type'],expected_type)
                self.assertEqual(self.unpack(item)['derived_artifact_count'],2)

    def test_zip_traversal_absolute_backslash_control_and_drive_refused(self):
        for name in ('../escape', '/absolute', 'dir/../escape', 'c:/windows/system', 'a\\b', './local', 'a//b', 'bad\nline'):
            with self.subTest(member=repr(name)):
                item=self.staged('b'+str(len(self.artifacts()))+'.zip',self.zips([(name,b'data')]))
                with self.assertRaises(CaseError):
                    self.unpack(item)
                self.assertEqual(len(self.artifacts()),len([k for k,v in self.artifacts().items() if 'derived_from' not in v]))

    def test_zip_symlink_refused(self):
        item=self.staged('linked.zip',self.zips([('link',b'../secret')],special=stat.S_IFLNK|0o777))
        with self.assertRaisesRegex(CaseError,'special files'):
            self.unpack(item)

    def test_tar_symlink_and_hardlink_refused(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                item=self.staged('tar'+str(len(self.artifacts()))+'.tar',self.tar([('link',b'')],kind=kind))
                with self.assertRaisesRegex(CaseError,'links'):
                    self.unpack(item)

    def test_too_many_members(self):
        item=self.staged('many.zip',self.zips([('1',b'x'),('2',b'y')]))
        with patch.object(archivework,'MAX_MEMBERS',1),self.assertRaisesRegex(CaseError,'members'):
            self.unpack(item)
        self.assertEqual(len(self.artifacts()),1)

    def test_member_too_large_and_total_quota(self):
        item=self.staged('large.zip',self.zips([('large.log',b'0123456789')]))
        with patch.object(archivework,'MAX_MEMBER_BYTES',5),self.assertRaises(CaseError):
            self.unpack(item)
        with patch.object(archivework,'MAX_UNPACKED_BYTES',4),self.assertRaises(CaseError):
            self.unpack(item)
        self.assertEqual(len(self.artifacts()),1)

    def test_ratio_guard_with_repetitive_data(self):
        item=self.staged('bomb.zip',self.zips([('zeros',b'Z'*100_000)]))
        with patch.object(archivework,'MAX_EXPANSION_RATIO',3),self.assertRaisesRegex(CaseError,'ratio'):
            self.unpack(item)
        self.assertEqual(len(self.artifacts()),1)

    def test_empty_archive_fails_without_partial(self):
        item=self.staged('empty.zip',self.zips([]))
        with self.assertRaises(CaseError):
            self.unpack(item)
        self.assertEqual(len(self.artifacts()),1)

    def test_truncated_archive_fails(self):
        item=self.staged('invalid.zip',b'PK\x03\x04garbage')
        with self.assertRaises(CaseError):
            self.unpack(item)

    def test_cancel_rolls_back_staged_expansion(self):
        item=self.staged('good.zip',self.zips([('one',b'abc'),('two',b'def')]))
        called=0
        def cancel():
            nonlocal called
            called+=1
            if called>=4: raise RuntimeError('operator cancelled')
        with self.assertRaises(RuntimeError):
            archivework.unpack_case_archive(self.store,self.case,item['artifact_id'],should_cancel=cancel)
        self.assertEqual(len(self.artifacts()),1)
        self.assertEqual(len(list((self.store.cases/self.case/'scratch').iterdir())),0)

    def test_failed_manifest_commit_rolls_back(self):
        item=self.staged('good.zip',self.zips([('one',b'abc')]))
        with patch.object(archivework,'_write_json_atomic',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.unpack(item)
        self.assertEqual(len(self.artifacts()),1)
        self.assertEqual(len(list((self.store.cases/self.case/'originals').iterdir())),1)

    def test_case_verification_detects_modified_and_missing_and_orphaned(self):
        item=self.staged('one.log',b'first\n')
        cid=item['artifact_id']
        original=self.store.cases/self.case/'originals'/cid
        self.assertEqual(archivework.verify_case(self.store,self.case)['status'],'PASS')
        original.write_bytes(b'other\n')
        r=archivework.verify_case(self.store,self.case)
        self.assertEqual((r['status'],r['digest_mismatch_count']),('PARTIAL',1))
        original.unlink()
        extra=self.store.cases/self.case/'originals'/'stale-temp'
        extra.write_text('stale')
        extra.chmod(0o600)
        r=archivework.verify_case(self.store,self.case)
        self.assertEqual((r['missing_or_unsafe_count'],r['unregistered_entry_count']), (1,1))
        self.assertNotIn(str(self.home),json.dumps(r))

    def test_hash_modified_archive_rejected(self):
        item=self.staged('good.zip',self.zips([('one',b'abc')]))
        path=self.store.cases/self.case/'originals'/item['artifact_id']
        data=bytearray(path.read_bytes());data[3]^=1;path.write_bytes(data)
        with self.assertRaisesRegex(CaseError,'hash changed'):
            self.unpack(item)

    def test_plain_text_is_not_an_archive(self):
        item=self.staged('plain.log',b'hello')
        with self.assertRaisesRegex(CaseError,'Only recognized'):
            self.unpack(item)

    def test_second_unpack_refused_and_does_not_duplicate_evidence(self):
        item=self.staged('one.zip',self.zips([('one.log',b'hello')]))
        self.unpack(item)
        with self.assertRaisesRegex(CaseError,'already expanded'):
            self.unpack(item)
        self.assertEqual(len(self.artifacts()),2)

    def test_symlinked_original_directory_never_redirects_case(self):
        item=self.staged('one.zip',self.zips([('one.log',b'hello')]))
        original=self.store.cases/self.case/'originals'
        original.rename(self.store.cases/self.case/'original-backup')
        outside=self.home/'outside'
        outside.mkdir()
        original.symlink_to(outside)
        with self.assertRaises(CaseError):
            self.unpack(item)
        self.assertEqual(list(outside.iterdir()),[])

    def test_vault_flags_stale_scratch_and_hardlinked_original(self):
        item=self.staged('one.log',b'hello')
        scratch=self.store.cases/self.case/'scratch'
        scratch.mkdir(mode=0o700)
        (scratch/'incomplete').write_bytes(b'partial')
        report=archivework.verify_case(self.store,self.case)
        self.assertEqual((report['status'],report['stale_scratch_entry_count']),('PARTIAL',1))
        (scratch/'incomplete').unlink()
        original=self.store.cases/self.case/'originals'/item['artifact_id']
        extra=self.home/'alias'
        os.link(original,extra)
        report=archivework.verify_case(self.store,self.case)
        self.assertEqual((report['status'],report['missing_or_unsafe_count']),('PARTIAL',1))

    def test_tar_traversal_refused_even_without_os_extract(self):
        item=self.staged('trav.tar',self.tar([('../bad.log',b'text')]))
        with self.assertRaisesRegex(CaseError,'Unsafe'):
            self.unpack(item)
        self.assertEqual(len(self.artifacts()),1)

    def test_archive_pagination_filters_by_parent_without_leaking_member_names(self):
        members=[(f'logs/system-{n}.log',f'entry{n}\n'.encode()) for n in range(26)]
        parent=self.staged('huge.zip',self.zips(members))
        report=self.unpack(parent)
        self.assertEqual(report['derived_artifact_count'],26)
        first=self.store.list_artifacts(self.case,source_artifact_id=parent['artifact_id'])
        self.assertEqual(len(first['artifacts']),20)
        self.assertEqual(first['total'],26)
        second=self.store.list_artifacts(self.case,offset=first['next_offset'],source_artifact_id=parent['artifact_id'])
        self.assertEqual(len(second['artifacts']),6)
        self.assertIsNone(second['next_offset'])
        self.assertNotIn('system-',json.dumps(first)+json.dumps(second))
        self.assertEqual(len(set(x['artifact_id'] for x in first['artifacts']+second['artifacts'])),26)
        with self.assertRaises(CaseError):
            self.store.list_artifacts(self.case,offset=-1)
        with self.assertRaises(CaseError):
            self.store.list_artifacts(self.case,source_artifact_id='0'*32)

    def test_archive_uses_outstanding_upload_reservations_before_writing(self):
        compressed = self.zips([('a.log', b'a' * 4096)])
        item = self.staged('reserved.zip', compressed)
        token = '.upload-' + 'a' * 32
        pending = 1024 * 1024
        resumable_transfer.begin(self.store, token, pending, 'b' * 64)
        # A reserve exists, so the 4 KiB extraction cannot borrow even one
        # byte of space already promised to the pending SSH upload.
        free = FREE_RESERVE + pending + 2000
        with patch.object(archivework.shutil, 'disk_usage',
                          return_value=SimpleNamespace(free=free)):
            with self.assertRaisesRegex(CaseError, 'Insufficient reserved scratch space'):
                self.unpack(item)
        self.assertEqual(len(self.artifacts()), 1)
        self.assertEqual(list((self.store.cases / self.case / 'scratch').iterdir()), [])
        with capacitywork.admission_lock(self.store):
            self.assertEqual(capacitywork.outstanding_reservations(self.store), pending)
        self.assertEqual(archivework.verify_case(self.store, self.case)['status'], 'PASS')

    def test_archive_expands_normally_when_pending_upload_bytes_are_protected(self):
        item = self.staged('capacity-ok.zip', self.zips([('safe.txt', b'S' * 8192)]))
        token = '.upload-' + 'c' * 32
        pending = 1024 * 1024
        resumable_transfer.begin(self.store, token, pending, 'd' * 64)
        free = FREE_RESERVE + pending + 16384
        with patch.object(archivework.shutil, 'disk_usage',
                          return_value=SimpleNamespace(free=free)):
            result = self.unpack(item)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['expanded_bytes'], 8192)
        self.assertEqual(len(self.artifacts()), 2)
        with capacitywork.admission_lock(self.store):
            self.assertEqual(capacitywork.outstanding_reservations(self.store), pending)
        self.assertEqual(archivework.verify_case(self.store, self.case)['status'], 'PASS')

    def test_midmember_free_space_loss_cleans_partial_and_preserves_manifest(self):
        content = os.urandom(2 * archivework.BUFFER + 25)
        item = self.staged('capacity-drop.zip', self.zips([('large.bin', content)]))
        # First call is the initial admission snapshot; then one free-space
        # check for each decoded 1 MiB block. Second block MUST be denied
        # before the filesystem writes it, and no artifact can be published.
        ok = SimpleNamespace(free=FREE_RESERVE + 4 * archivework.BUFFER)
        low = SimpleNamespace(free=FREE_RESERVE + 100)
        with patch.object(archivework.shutil, 'disk_usage',
                          side_effect=[ok, ok, low]):
            with self.assertRaisesRegex(CaseError, 'Insufficient reserved scratch space'):
                self.unpack(item)
        self.assertEqual(len(self.artifacts()), 1)
        self.assertEqual(list((self.store.cases / self.case / 'scratch').iterdir()), [])
        self.assertEqual(archivework.verify_case(self.store, self.case)['status'], 'PASS')

    def test_archive_quota_is_checked_before_next_chunk_allocation(self):
        item = self.staged('quota-first.zip', self.zips([('data', b'X' * 8192)]))
        with patch.object(archivework, 'MAX_CASE_STORAGE', item['bytes'] + 4096):
            with self.assertRaisesRegex(CaseError, 'Case storage quota exceeded'):
                self.unpack(item)
        self.assertEqual(len(self.artifacts()), 1)
        self.assertEqual(archivework.verify_case(self.store, self.case)['status'], 'PASS')

    def test_active_admission_lock_blocks_archive_without_touching_case(self):
        item = self.staged('locked.zip', self.zips([('one', b'present')]))
        self.store._ensure_store()
        lock = self.store.base / '.capacity.lock'
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        import fcntl
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(capacitywork, 'ADMISSION_WAIT_SECONDS', 0.01), \
                 patch.object(capacitywork, 'ADMISSION_POLL_SECONDS', 0.001):
                with self.assertRaisesRegex(CaseError, 'busy'):
                    self.unpack(item)
        finally:
            os.close(fd)
        self.assertEqual(len(self.artifacts()), 1)
        self.assertEqual(archivework.verify_case(self.store, self.case)['status'], 'PASS')

    def test_job_templates_archive_and_verify_are_reachable(self):
        item=self.staged('valid.zip',self.zips([('safe.log',b'hello')]))
        jobs=jobwork.JobStore(self.home)
        jid=jobs.submit('unpack_archive',self.case,item['artifact_id'])['job_id']
        self.assertEqual(jobs.work_once()['state'],'SUCCEEDED')
        result=jobs.result(jid)
        self.assertEqual(result['result']['derived_artifact_count'],1)
        vault_id=jobs.submit('verify_case',self.case)['job_id']
        self.assertEqual(jobs.work_once()['state'],'SUCCEEDED')
        self.assertEqual(jobs.result(vault_id)['result']['verified_count'],2)
        with self.assertRaises(jobwork.JobError):
            jobs.submit('verify_case',self.case,item['artifact_id'])


if __name__=='__main__':
    unittest.main()
