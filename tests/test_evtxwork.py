"""EVTX metadata-only integration, unavailable provider and adversarial fixtures."""
from __future__ import annotations
from pathlib import Path
import json
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import casework, evtxwork, jobwork


def event_xml(eventid='4625', level='2', provider='Microsoft-Windows-Security-Auditing', rawtime='2026-10-15T20:15:01Z',secret='very-private-token'):
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
      "<System><Provider Name='"+provider+"'/><EventID>"+eventid+"</EventID>"
      "<Level>"+level+"</Level><TimeCreated SystemTime='"+rawtime+"'/></System>"
      "<EventData><Data Name='TargetUserName'>"+secret+"</Data></EventData></Event>")


class FakeRecord:
    def __init__(self,xml,num=42):self._xml,self._num=xml,num
    def xml(self):return self._xml
    def record_num(self):return self._num


class EVTXTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.home=Path(t.name)
        self.jobs=jobwork.JobStore(self.home)
        self.case=self.jobs.cases.open_case()['case_id']
        self.original=b'ElfFile\x00'+b'\x00'*(4096-8)
        self.aid=self.stage('log.evtx',self.original)

    def stage(self,name,data):
        target=self.jobs.cases.inbox/name
        target.write_bytes(data);target.chmod(0o600)
        return self.jobs.cases.register(self.case,name)['artifact_id']

    def provider(self,records):
        class FakeEvtx:
            def __init__(self,file):self.file=file
            def __enter__(self):return self
            def __exit__(self,*args):return None
            def records(self):return iter(records)
        package=types.ModuleType('Evtx');package.__path__=[]
        sub=types.ModuleType('Evtx.Evtx');sub.Evtx=FakeEvtx
        return patch.dict(sys.modules,{'Evtx':package,'Evtx.Evtx':sub})

    def test_signature_registered_as_evtx(self):
        self.assertEqual(self.jobs.cases.status(self.case)['artifact_count'],1)
        self.assertEqual(casework.CaseStore._classify(self.original[:260]),'evtx')

    def test_missing_parser_fails_truthfully_without_index(self):
        j=self.jobs.submit('analyze_evtx',self.case,artifact_id=self.aid)
        r=self.jobs.work_once()
        self.assertEqual(r['state'],'SUCCEEDED')
        outcome=self.jobs.result(j['job_id'])['result']
        self.assertEqual(outcome['status'],'NOT_AVAILABLE')
        self.assertIn('python-evtx',outcome['missing_provider'])
        self.assertNotIn('PASS',json.dumps(outcome))
        self.assertFalse((self.jobs.cases.cases/self.case/'indexes'/('evtx-'+self.aid+'.sqlite3')).exists())

    def test_known_event_metadata_index_and_queries(self):
        with self.provider([FakeRecord(event_xml(secret='username-one'),100),FakeRecord(event_xml('7040','4','Service Control Manager','2026-10-15T20:15:04Z',secret='password-123'),101)]):
            j=self.jobs.submit('analyze_evtx',self.case,artifact_id=self.aid)
            self.assertEqual(self.jobs.work_once()['state'],'SUCCEEDED')
        outcome=self.jobs.result(j['job_id'])['result']
        self.assertEqual(outcome['status'],'PASS')
        self.assertEqual(outcome['records_examined'],2)
        summary=evtxwork.evtx_summary(self.jobs.cases,self.case,self.aid)
        self.assertEqual(summary['event_id_counts'][0]['count'],1)
        found=evtxwork.evtx_events(self.jobs.cases,self.case,self.aid,event_id=4625)
        self.assertEqual(found['total'],1)
        self.assertEqual(found['events'][0]['event_id'],4625)
        self.assertEqual(found['events'][0]['utc'],'2026-10-15T20:15:01.000000+00:00')
        report=json.dumps([summary,found,outcome])
        self.assertNotIn('password-123',report)
        self.assertNotIn('username-one',report)
        self.assertNotIn('TargetUserName',report)

    def test_custom_provider_is_opaque_alias(self):
        with self.provider([FakeRecord(event_xml(provider='Our.Secret.Collector.Node-123'))]):
            evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid)
        docs=json.dumps(evtxwork.evtx_events(self.jobs.cases,self.case,self.aid))
        self.assertIn('provider-',docs)
        self.assertNotIn('Our.Secret',docs)

    def test_invalid_xml_record_is_partial(self):
        with self.provider([FakeRecord(event_xml()),FakeRecord('<Event><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>bad')]):
            report=evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid)
        self.assertEqual(report['status'],'PARTIAL')
        self.assertEqual(report['records_skipped'],1)
        self.assertEqual(evtxwork.evtx_summary(self.jobs.cases,self.case,self.aid)['status'],'PARTIAL')

    def test_naive_windows_time_is_partial(self):
        with self.provider([FakeRecord(event_xml(rawtime='2026-10-15T20:15:01'))]):
            report=evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid)
        self.assertEqual(report['status'],'PARTIAL')
        self.assertEqual(report['records_without_utc'],1)

    def test_huge_event_xml_skipped(self):
        with self.provider([FakeRecord('<Event>'+('A'*(evtxwork.MAX_XML+4))+'</Event>')]):
            report=evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid)
        self.assertEqual(report['status'],'PARTIAL')
        self.assertEqual(report['records_skipped'],1)

    def test_corrupted_source_magic_fails(self):
        original=self.jobs.cases.cases/self.case/'originals'/self.aid
        original.write_bytes(b'BADFILE\x00'+b'\0'*(4096-8))
        with self.assertRaises(casework.CaseError):
            evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid)

    def test_cancel_leaves_no_index(self):
        def stop():raise jobwork.JobCancelled('cancelled')
        with self.provider([FakeRecord(event_xml())]):
            with self.assertRaises(jobwork.JobCancelled):
                evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid,should_cancel=stop)
        self.assertFalse((self.jobs.cases.cases/self.case/'indexes'/('evtx-'+self.aid+'.sqlite3')).exists())

    def test_invalid_offset_and_event_ids(self):
        with self.provider([FakeRecord(event_xml())]):
            evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid)
        for val in (-1,True,10001):
            with self.assertRaisesRegex(evtxwork.EvtxError,'offset'):
                evtxwork.evtx_events(self.jobs.cases,self.case,self.aid,offset=val)
        for val in (-1,True,65536):
            with self.assertRaisesRegex(evtxwork.EvtxError,'identifier'):
                evtxwork.evtx_events(self.jobs.cases,self.case,self.aid,event_id=val)

    def test_evtx_symlink_index_denied(self):
        with self.provider([FakeRecord(event_xml())]):
            evtxwork.analyze_evtx(self.jobs.cases,self.case,self.aid)
        index=self.jobs.cases.cases/self.case/'indexes'/('evtx-'+self.aid+'.sqlite3')
        other=index.with_suffix('.save');index.rename(other);index.symlink_to(other)
        with self.assertRaisesRegex(evtxwork.EvtxError,'symlink'):
            evtxwork.evtx_summary(self.jobs.cases,self.case,self.aid)

    def test_evtx_unapproved_kind_denied(self):
        with self.assertRaisesRegex(jobwork.JobError,'Unknown job'):
            self.jobs.submit('dump_raw_evtx',self.case,artifact_id=self.aid)


if __name__=='__main__':unittest.main()
