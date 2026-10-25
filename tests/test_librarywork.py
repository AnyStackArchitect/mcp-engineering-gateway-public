"""Accepted-source retrieval, version boundaries and disclosure authority."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import casework
import gateway
import librarywork


class LibraryTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home=Path(temporary.name)
        self.store=casework.CaseStore(self.home)
        self.cid=self.store.open_case()['case_id']
        source=self.store.inbox/'proof.log'
        source.write_text('2026-10-18T01:00:00Z synthetic controlled test\n')
        source.chmod(0o600)
        sha=hashlib.sha256(source.read_bytes()).hexdigest()
        self.aid=self.store.register(self.cid,source.name)['artifact_id']
        self.note={'kind':'case','product':'veeam','version':'12.3',
            'title':'Repository timeout investigation','summary':'Synthetic timeout case; password=do-not-disclose',
            'source_case_id':self.cid,'source_artifact_id':self.aid,'source_sha256':sha,
            'source_line':1,'reference_uri':'https://example.org/owned-note',
            'reference_date':'2026-10-18','rights_confirmed':True,
            'hypothesis':'Repository transport timeout','test':'Controlled replay against disposable endpoint',
            'observed_result':'Failure reproduced with synthetic loss',
            'conclusion':'Lab observation only','applies_to':'Only this tested product and version label'}

    def accept(self,note=None):
        note=self.note if note is None else note
        review=librarywork.prepare(self.store,note)
        return librarywork.accept(self.store,note,review['review_sha256'],interactive=True)

    def search(self,**kwargs):
        return librarywork.search(self.store,kwargs.pop('query','timeout'),kwargs.pop('product','veeam'),kwargs.pop('version','12.3'),**kwargs)

    def test_exact_accepted_note_and_source_provenance_no_raw_source(self):
        accepted=self.accept()
        report=self.search()
        self.assertEqual(len(report['matches']),1)
        row=report['matches'][0]
        self.assertEqual(row['entry_id'],accepted['entry_id'])
        self.assertEqual(row['note']['source_sha256'],self.note['source_sha256'])
        self.assertEqual(row['acceptance_basis'],'local_interactive_operator_attestation')
        self.assertFalse(report['automatic_reuse_or_execution_authorized'])
        self.assertNotIn('do-not-disclose',json.dumps(report))
        self.assertNotIn('synthetic controlled test',json.dumps(report))

    def test_operator_acceptance_and_exact_review_digest_required(self):
        reviewed=librarywork.prepare(self.store,self.note)
        with self.assertRaises(casework.CaseError):
            librarywork.accept(self.store,self.note,reviewed['review_sha256'])
        with self.assertRaises(casework.CaseError):
            librarywork.accept(self.store,self.note|{'conclusion':'changed'},reviewed['review_sha256'],interactive=True)
        self.assertEqual(self.search()['status'],'NOT_AVAILABLE')
        gw=gateway.Gateway(gateway.Config({},(),self.home))
        self.assertFalse(any('accept' in t['name'] or 'library_write' in t['name'] for t in gw.tools()))

    def test_incompatible_versions_excluded_and_stale_age_explicit(self):
        with patch.object(librarywork.time,'time',return_value=1):self.accept()
        self.accept(self.note|{'version':'13.0','summary':'Another timeout lab case'})
        report=self.search()
        self.assertEqual(len(report['matches']),1)
        self.assertEqual(report['incompatible_version_matches_excluded'],1)
        self.assertTrue(report['matches'][0]['stale_age_warning'])
        self.assertEqual(self.search(version='99')['matches'],[])

    def test_source_hash_change_and_nonexistent_line_refused(self):
        for changed in ({'source_sha256':'0'*64},{'source_line':2}):
            with self.subTest(changed=changed),self.assertRaises(casework.CaseError):
                librarywork.prepare(self.store,self.note|changed)
        original=self.store.cases/self.cid/'originals'/self.aid
        original.write_bytes(b'changed source')
        with self.assertRaises(casework.CaseError):librarywork.prepare(self.store,self.note)

    def test_source_absence_retains_historical_note_with_warning(self):
        self.accept()
        original=self.store.cases/self.cid/'originals'/self.aid
        original.unlink()
        report=self.search()
        self.assertEqual(report['matches'][0]['source_state'],'SOURCE_UNAVAILABLE_OR_CHANGED')
        self.assertEqual(report['status'],'PARTIAL')

    def test_reference_notes_require_rights_provenance_and_exact_version(self):
        reference={k:v for k,v in self.note.items() if k not in librarywork.CASE_FIELDS}
        reference['kind']='reference'
        reference['reference_date']='2020-01-01'
        self.accept(reference)
        self.assertEqual(self.search()['matches'][0]['note']['kind'],'reference')
        # This term exists only in original reference bytes, never in the note.
        report=self.search(query='controlled')
        self.assertEqual(len(report['matches']),1)
        self.assertTrue(report['matches'][0]['stale_reference_date_warning'])
        self.assertNotIn('synthetic controlled test',json.dumps(report))
        for change in ({'rights_confirmed':False},{'reference_uri':'https://user:pass@example.org/doc'},
                       {'reference_uri':'https://example.org/doc?token=secret'},{'reference_date':'unknown'}):
            with self.subTest(change=change),self.assertRaises(casework.CaseError):
                librarywork.prepare(self.store,reference|change)

    def test_query_literals_never_become_fts_or_sql_operators(self):
        self.accept()
        self.assertEqual(self.search(query='timeout OR absent')['matches'],[])
        self.assertEqual(self.search(query='timeout"; DROP TABLE notes; --')['matches'],[])
        self.assertEqual(len(self.search(query='timeout')['matches']),1)
        for kwargs in ({'limit':True},{'limit':4},{'query':'*'},{'version':''},{'product':'../case'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(casework.CaseError):self.search(**kwargs)

    def test_lock_database_symlinks_and_corrupt_accepted_identity_refused(self):
        self.accept()
        path=self.store.base/'library/notes.sqlite3'
        with sqlite3.connect(path) as db:db.execute("UPDATE notes SET review_sha256=?",('0'*64,))
        with self.assertRaises(casework.CaseError):self.search()
        path.unlink()
        target=self.home/'outside';target.write_text('private');target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(casework.CaseError):self.search()
        self.assertEqual(target.read_text(),'private')

    def test_budget_failure_rolls_back_and_results_remain_bounded(self):
        self.accept()
        with patch.object(librarywork,'MAX_ENTRIES',1),self.assertRaises(casework.CaseError):self.accept()
        self.assertEqual(len(self.search()['matches']),1)
        for i in range(3):self.accept(self.note|{'title':f'timeout note {i}'})
        report=self.search(limit=2)
        self.assertEqual(len(report['matches']),2)
        self.assertTrue(report['has_more'])
        self.assertLess(len(json.dumps(report)),gateway.MAX_RESPONSE_TEXT)

    def test_reference_budget_and_invalid_utf8_rejected_without_acceptance(self):
        reference={k:v for k,v in self.note.items() if k not in librarywork.CASE_FIELDS}
        reference['kind']='reference'
        with patch.object(librarywork,'MAX_REFERENCE',1),self.assertRaises(casework.CaseError):
            self.accept(reference)
        path=self.store.inbox/'invalid.log'
        path.write_bytes(b'invalid-utf8-\xff\n');path.chmod(0o600)
        item=self.store.register(self.cid,path.name)
        reference['source_artifact_id']=item['artifact_id']
        reference['source_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(casework.CaseError):self.accept(reference)
        self.assertEqual(self.search()['status'],'NOT_AVAILABLE')

    def test_sqlite_page_full_rolls_back_note_and_fts_together(self):
        self.accept()
        source=self.store.inbox/'large-reference.txt'
        source.write_text('capacityprobe '*40000+'\n');source.chmod(0o600)
        aid=self.store.register(self.cid,source.name)['artifact_id']
        reference={k:v for k,v in self.note.items() if k not in librarywork.CASE_FIELDS}
        reference.update(kind='reference',source_artifact_id=aid,
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        current=(self.store.base/'library/notes.sqlite3').stat().st_size
        with patch.object(librarywork,'MAX_DB',current+4096),self.assertRaises(casework.CaseError):
            self.accept(reference)
        self.assertEqual(len(self.search()['matches']),1)
        self.assertEqual(self.search(query='capacityprobe')['matches'],[])
        with sqlite3.connect(self.store.base/'library/notes.sqlite3') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM notes').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM search').fetchone()[0],1)

    def test_unicode_notes_enforce_serialized_output_budget(self):
        for number in range(3):
            self.accept(self.note|{'title':f'timeout Unicode {number}',
                'hypothesis':'\u2603'*350,'test':'\u2603'*350,'observed_result':'\u2603'*350})
        report=self.search()
        self.assertTrue(report['output_bounded'])
        self.assertTrue(report['narrow_query_required_for_more'])
        self.assertLess(len(json.dumps(report)),gateway.MAX_RESPONSE_TEXT)

    def test_shared_capacity_reserve_refusal_precedes_library_write(self):
        with patch.object(librarywork,'verify_committed_reserve',side_effect=casework.CaseError('reserved')) as guard:
            with self.assertRaisesRegex(casework.CaseError,'reserved'):self.accept()
            self.assertEqual(guard.call_args.kwargs['extra_bytes'],2*librarywork.MAX_DB)
        self.assertEqual(self.search()['status'],'NOT_AVAILABLE')
