"""Pinned source-backed reporting and reviewed metadata-only packages."""
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import casework
import correlationwork
import gateway
import producerwork
import reportwork
import timelinework


class EvidenceReportTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.home=Path(temporary.name);self.store=casework.CaseStore(self.home)
        self.cid=self.store.open_case()['case_id']
        self.aid=self.add('2026-10-18T01:00:00Z ERROR private-customer-name password=secret\nunknown timestamp record\n')
        self.rebuild()

    def add(self,text,name='private-host.log'):
        path=self.store.inbox/name;path.write_text(text);path.chmod(0o600)
        return self.store.register(self.cid,name)['artifact_id']

    def rebuild(self):
        timelinework.build_timeline(self.store,self.cid)
        correlationwork.build_correlation(self.store,self.cid)
        self.revision=correlationwork.correlation_summary(self.store,self.cid)['index_revision']

    def report(self):return reportwork.build(self.store,self.cid,self.revision)

    def test_facts_unknowns_source_hash_and_recorded_producer(self):
        result=self.report()
        self.assertEqual(result['facts']['indexed_events'],2)
        self.assertEqual(result['facts']['events_without_utc'],1)
        self.assertEqual(result['hypotheses'],[])
        self.assertEqual(result['status'],'PARTIAL')
        self.assertEqual(result['observations'][0]['locator_number'],1)
        self.assertEqual(result['observations'][0]['artifact_id'],self.aid)
        original=self.store.cases/self.cid/'originals'/self.aid
        self.assertEqual(result['observations'][0]['source_sha256'],hashlib.sha256(original.read_bytes()).hexdigest())
        producer=result['observed_source_producers'][0]['recorded_producer']
        self.assertEqual(result['observed_source_producers'][0]['analysis_coverage']['unanchored'],1)
        self.assertEqual(result['observed_source_producers'][0]['analysis_coverage']['status'],'PARTIAL')
        self.assertEqual(producer['modules']['timelinework'],hashlib.sha256(Path(timelinework.__file__).read_bytes()).hexdigest())
        for forbidden in ('private-customer-name','private-host.log','password=','unknown timestamp record'):
            self.assertNotIn(forbidden,json.dumps(result))
        copy=dict(result);copy.pop('review_sha256')
        self.assertEqual(result['review_sha256'],hashlib.sha256(reportwork.canonical(copy)).hexdigest())

    def test_stale_revision_source_and_invalid_controls_refused(self):
        old=self.revision;self.rebuild()
        with self.assertRaisesRegex(casework.CaseError,'stale'):reportwork.build(self.store,self.cid,old)
        for invalid in (None,True,'0'*64,'../index'):
            with self.subTest(invalid=invalid),self.assertRaises(casework.CaseError):
                reportwork.build(self.store,self.cid,invalid)
        source=self.store.cases/self.cid/'originals'/self.aid
        os.utime(source,None)
        with self.assertRaises(casework.CaseError):self.report()

    def test_bounded_sample_and_missing_index_coverage(self):
        self.add(''.join(f'2026-10-18T01:01:{n:02d}Z evidence\n' for n in range(20)),'extra.log')
        self.rebuild()
        result=self.report()
        self.assertEqual(len(result['observations']),reportwork.MAX_EVENTS)
        self.assertEqual(result['observation_sample_omitted'],22-reportwork.MAX_EVENTS)
        path=self.store.cases/self.cid/'indexes/timeline.sqlite3';path.unlink()
        correlationwork.build_correlation(self.store,self.cid)
        self.revision=correlationwork.correlation_summary(self.store,self.cid)['index_revision']
        result=self.report()
        self.assertEqual(result['observations'],[])
        self.assertEqual(result['facts']['missing_indexes'],2)
        self.assertEqual(result['facts']['indexed_sources'],0)
        self.assertEqual(result['facts']['registered_sources'],2)
        self.assertIn(b'Missing source indexes: 2',reportwork.markdown(result))
        self.assertEqual(result['source_producers_omitted'],2)

    def test_legacy_producer_missing_is_unknown_not_current_runtime(self):
        path=self.store.cases/self.cid/'indexes/timeline.sqlite3'
        with sqlite3.connect(path) as db:db.execute("DELETE FROM facts WHERE key='producer_identity'")
        correlationwork.build_correlation(self.store,self.cid)
        self.revision=correlationwork.correlation_summary(self.store,self.cid)['index_revision']
        result=self.report()
        self.assertEqual(result['observed_source_producers'][0]['recorded_producer'],
                         {'status':'UNRECORDED_LEGACY_INDEX'})

    def test_corrupt_time_basis_and_producer_metadata_fail_closed(self):
        index=self.store.cases/self.cid/'indexes/correlation.sqlite3'
        with sqlite3.connect(index) as db:db.execute("UPDATE events SET time_basis='VERIFIED'")
        with self.assertRaises(casework.CaseError):self.report()
        self.rebuild()
        timeline=self.store.cases/self.cid/'indexes/timeline.sqlite3'
        with sqlite3.connect(timeline) as db:db.execute("UPDATE facts SET value=? WHERE key='producer_identity'",(json.dumps({'schema':True}),))
        correlationwork.build_correlation(self.store,self.cid)
        self.revision=correlationwork.correlation_summary(self.store,self.cid)['index_revision']
        with self.assertRaises(casework.CaseError):self.report()

    def test_review_required_and_deterministic_verified_zip(self):
        report=self.report()
        with self.assertRaises(casework.CaseError):
            reportwork.package(self.store,self.cid,self.revision,report['review_sha256'])
        with self.assertRaises(casework.CaseError):
            reportwork.package(self.store,self.cid,self.revision,'0'*64,interactive=True)
        first=reportwork.package(self.store,self.cid,self.revision,report['review_sha256'],interactive=True)
        second=reportwork.package(self.store,self.cid,self.revision,report['review_sha256'],interactive=True)
        self.assertEqual(first,second)
        source=self.store.base/'evidence-report-packages'/first['filename']
        raw=source.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),first['package_sha256'])
        self.assertFalse(first['external_disclosure_approved'])
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            self.assertEqual(set(archive.namelist()),{'report.json','report.md','manifest.json'})
            inventory=json.loads(archive.read('manifest.json'))
            for name,sha in inventory['members'].items():self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(),sha)
            content=b' '.join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b'private-customer-name',content)
            self.assertIn(b'external disclosure not approved',content)

    def test_package_capacity_failure_preserves_originals_and_no_package(self):
        report=self.report()
        original=self.store.cases/self.cid/'originals'/self.aid
        prior=original.read_bytes()
        with patch.object(reportwork,'verify_committed_reserve',side_effect=casework.CaseError('reserved')):
            with self.assertRaises(casework.CaseError):
                reportwork.package(self.store,self.cid,self.revision,report['review_sha256'],interactive=True)
        self.assertEqual(original.read_bytes(),prior)
        self.assertFalse((self.store.base/'evidence-report-packages').exists())

    def test_package_collision_symlink_and_interrupted_publication(self):
        report=self.report()
        output=self.store.base/'evidence-report-packages';output.mkdir(mode=0o700)
        target=output/('report-'+report['review_sha256']+'.zip')
        outside=self.home/'outside';outside.write_text('private');outside.chmod(0o600)
        target.symlink_to(outside)
        with self.assertRaises(casework.CaseError):
            reportwork.package(self.store,self.cid,self.revision,report['review_sha256'],interactive=True)
        target.unlink()
        with patch.object(reportwork.os,'replace',side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError):
                reportwork.package(self.store,self.cid,self.revision,report['review_sha256'],interactive=True)
        self.assertEqual(list(output.iterdir()),[])
        self.assertEqual(outside.read_text(),'private')

    def test_producer_identity_rejects_arbitrary_paths_and_metadata(self):
        with self.assertRaises(ValueError):producerwork.record('../private')
        with self.assertRaises(ValueError):producerwork.checked({'schema':True,'python_runtime':'3.12','modules':{}})
        gw=gateway.Gateway(gateway.Config({},(),self.home))
        spec=next(t for t in gw.tools() if t['name']=='case_evidence_report')
        self.assertTrue(spec['annotations']['readOnlyHint'])
        self.assertFalse(any(t['name']=='report_package' for t in gw.tools()))

    def test_evtx_skipped_record_coverage_and_producer_are_preserved(self):
        import evtxwork
        from test_evtxwork import EVTXTests,FakeRecord,event_xml
        source=self.store.inbox/'synthetic.evtx'
        source.write_bytes(b'ElfFile\x00'+b'\x00'*(4096-8));source.chmod(0o600)
        aid=self.store.register(self.cid,source.name)['artifact_id']
        with EVTXTests.provider(self,[FakeRecord(event_xml(),17),FakeRecord('<invalid>')]):
            evtxwork.analyze_evtx(self.store,self.cid,aid)
        correlationwork.build_correlation(self.store,self.cid)
        self.revision=correlationwork.correlation_summary(self.store,self.cid)['index_revision']
        result=self.report()
        source=next(s for s in result['observed_source_producers'] if s['kind']=='evtx')
        self.assertEqual(source['analysis_coverage']['records_examined'],2)
        self.assertEqual(source['analysis_coverage']['records_skipped'],1)
        self.assertEqual(source['analysis_coverage']['status'],'PARTIAL')
        self.assertIn('evtxwork',source['recorded_producer']['modules'])

    def test_corrupt_selected_source_coverage_count_refused(self):
        path=self.store.cases/self.cid/'indexes/timeline.sqlite3'
        with sqlite3.connect(path) as db:db.execute("UPDATE sources SET skipped=-1")
        correlationwork.build_correlation(self.store,self.cid)
        self.revision=correlationwork.correlation_summary(self.store,self.cid)['index_revision']
        with self.assertRaises(casework.CaseError):self.report()

    def test_packet_truncation_coverage_and_producer_are_preserved(self):
        import protocolwork
        from test_packet_coverage import quality_binary
        source=self.store.inbox/'synthetic.pcap'
        source.write_bytes(quality_binary());source.chmod(0o600)
        aid=self.store.register(self.cid,source.name)['artifact_id']
        protocolwork.analyze_capture(self.store,self.cid,aid)
        correlationwork.build_correlation(self.store,self.cid)
        self.revision=correlationwork.correlation_summary(self.store,self.cid)['index_revision']
        source=next(s for s in self.report()['observed_source_producers'] if s['kind']=='pcap')
        self.assertEqual(source['analysis_coverage']['packets_examined'],8)
        self.assertEqual(source['analysis_coverage']['snaplen_truncated_packets'],1)
        self.assertEqual(source['analysis_coverage']['status'],'PARTIAL')
        self.assertIn('packettruth',source['recorded_producer']['modules'])
