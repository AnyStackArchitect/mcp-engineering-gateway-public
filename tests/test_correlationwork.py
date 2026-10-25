"""Known-answer cross-format timestamp and privacy regression tests."""
from __future__ import annotations
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import casework, correlationwork, evtxwork, gateway, jobwork, protocolwork, timelinework
from test_protocolwork import ipv4, tcp, udp, pcap
from test_evtxwork import FakeRecord, event_xml


def fake_provider(events):
    class FakeEvtx:
        def __init__(self,path): pass
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def records(self): return iter(events)
    pkg=types.ModuleType('Evtx');pkg.__path__=[]
    sub=types.ModuleType('Evtx.Evtx');sub.Evtx=FakeEvtx
    return patch.dict(sys.modules,{'Evtx':pkg,'Evtx.Evtx':sub})


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home=Path(temporary.name)
        self.jobs=jobwork.JobStore(self.home)
        self.store=self.jobs.cases
        self.cid=self.store.open_case()['case_id']
        self.base=self.store.cases/self.cid

    def reg(self,name,data):
        path=self.store.inbox/name
        path.write_bytes(data);path.chmod(0o600)
        return self.store.register(self.cid,name)['artifact_id']

    def text(self, naive=False):
        stamp='2024-07-03T09:46:41+00:00'
        contents=(stamp+' failed transfer password: topsecret\n'+
                  '2024-07-03T09:46:44Z recovered token=hidden\n').encode()
        if naive:
            contents+=b'Oct 15 10:12:32 host warning\n'
        aid=self.reg('failure.log',contents)
        self.assertIn(self.store.index_log(self.cid,aid)['status'],('PASS','PARTIAL'))
        timelinework.build_timeline(self.store,self.cid)
        return aid

    def pcap(self):
        client=b'\x0a\x01\x02\x03';server=b'\x0a\x01\x02\x04'
        syn=ipv4(client,server,6,tcp(51515,443,flags=0x02))
        reset=ipv4(server,client,6,tcp(443,51515,flags=0x04))
        q=b'\x06secret\x05local\x00\x00\x01\x00\x01'
        dns=struct.pack('!HHHHHH',7,0x8183,1,0,0,0)+q
        dnse=ipv4(server,client,17,udp(53,55555,dns))
        aid=self.reg('error.pcap',pcap([syn,reset,dnse]))
        report=protocolwork.analyze_capture(self.store,self.cid,aid)
        self.assertEqual(report['packets_examined'],3)
        self.assertEqual(report['counters']['tcp_rst'],1)
        return aid

    def evtx(self):
        aid=self.reg('windows.evtx',b'ElfFile\x00'+b'\0'*(4096-8))
        stamp=datetime.fromtimestamp(1720000001,timezone.utc).isoformat()
        with fake_provider([FakeRecord(event_xml(eventid='7023',provider='Private.Customer.host',rawtime=stamp,secret='confidential-data'),44)]):
            self.assertEqual(evtxwork.analyze_evtx(self.store,self.cid,aid)['status'],'PASS')
        return aid

    def test_full_three_format_cross_source_query(self):
        text_id=self.text(naive=True)
        packet_id=self.pcap()
        evtx_id=self.evtx()
        output=correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(output['status'],'PARTIAL')
        self.assertEqual(output['sources'],3)
        self.assertEqual(output['missing_indexes'],0)
        self.assertEqual(output['events'],2+1+3+1)
        summary=correlationwork.correlation_summary(self.store,self.cid)
        self.assertEqual(summary['event_count'],7)
        self.assertEqual(summary['events_without_utc'],1)
        self.assertEqual({r['kind'] for r in summary['by_kind']},{'text','evtx','pcap'})
        query=correlationwork.correlation_query(self.store,self.cid,include_unknown=True)
        self.assertEqual(len(query['events']),7)
        timestamps=[x['utc'] for x in query['events'] if x['utc']]
        self.assertEqual(timestamps,sorted(timestamps))
        self.assertIsNone(query['events'][-1]['utc'])
        self.assertEqual({e['locator_type'] for e in query['events']},{'line','packet','record'})
        self.assertEqual(len(correlationwork.correlation_query(self.store,self.cid,kind='evtx')['events']),1)
        self.assertEqual(len(correlationwork.correlation_query(self.store,self.cid,artifact_id=packet_id)['events']),3)
        self.assertEqual(len(correlationwork.correlation_query(self.store,self.cid,artifact_id=text_id)['events']),2)
        self.assertEqual(len(correlationwork.correlation_query(self.store,self.cid,artifact_id=evtx_id)['events']),1)
        content=json.dumps((output,summary,query))
        for secret in ('topsecret','confidential-data','Private.Customer.host','secret.local','10.1.2.3','10.1.2.4','token=hidden'):
            self.assertNotIn(secret,content)
        self.assertFalse(query['cross_source_identity_inferred'])
        self.assertFalse(query['causality_inferred'])
        self.assertEqual(query['clock_alignment'],'UNVERIFIED')

    def test_empty_case_is_not_applicable(self):
        result=correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(result['status'],'NOT_APPLICABLE')
        self.assertEqual(correlationwork.correlation_summary(self.store,self.cid)['source_count'],0)

    def test_missing_timeline_and_packet_index_are_partial(self):
        self.reg('log.txt',b'2024-07-03T09:46:41Z message\n')
        self.reg('cap.pcap',pcap([ipv4(b'\x01'*4,b'\x02'*4,6,tcp(1,2,flags=2))]))
        result=correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(result['status'],'PARTIAL')
        self.assertEqual(result['missing_indexes'],2)
        self.assertEqual(result['events'],0)
        source=correlationwork.correlation_sources(self.store,self.cid)
        self.assertTrue(all(x['coverage']=='MISSING_INDEX' for x in source['sources']))

    def test_unavailable_real_evtx_parser_not_credited(self):
        self.reg('events.evtx',b'ElfFile\x00'+b'\0'*(4096-8))
        result=correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(result['missing_indexes'],1)
        self.assertIn('evtx_provider_not_indexed',result['limitations'])

    def test_json_redaction_and_query_offsets(self):
        self.text()
        correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(len(correlationwork.correlation_query(self.store,self.cid,limit=1)['events']),1)
        self.assertTrue(correlationwork.correlation_query(self.store,self.cid,limit=1)['has_more'])
        self.assertEqual(len(correlationwork.correlation_query(self.store,self.cid,offset=1)['events']),1)
        self.assertEqual(len(correlationwork.correlation_query(self.store,self.cid,offset=9)['events']),0)

    def test_time_filter_requires_timezone_and_keeps_order(self):
        self.text(True)
        correlationwork.build_correlation(self.store,self.cid)
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_query(self.store,self.cid,start_utc='2024-07-03T09:00:00')
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_query(self.store,self.cid,start_utc='2024-07-04T00:00:00Z',end_utc='2024-07-03T00:00:00Z')
        result=correlationwork.correlation_query(self.store,self.cid,start_utc='2024-07-03T09:46:42Z',include_unknown=True)
        self.assertEqual(len(result['events']),1)
        self.assertTrue(result['timestamp_filter_excludes_unknown'])

    def test_invalid_parameters_and_sql_injection_fail_closed(self):
        correlationwork.build_correlation(self.store,self.cid)
        for bad in (True,-1,10001,'5'):
            with self.assertRaises(casework.CaseError):
                correlationwork.correlation_query(self.store,self.cid,offset=bad)
        for bad in (0,21,False,'20'):
            with self.assertRaises(casework.CaseError):
                correlationwork.correlation_query(self.store,self.cid,limit=bad)
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_query(self.store,self.cid,artifact_id="abc' OR 1=1--")
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_query(self.store,self.cid,kind="pcap'; DROP TABLE events;--")
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_query(self.store,self.cid,include_unknown='true')

    def test_original_file_change_rejects_query(self):
        aid=self.text()
        correlationwork.build_correlation(self.store,self.cid)
        file=self.base/'originals'/aid
        file.write_bytes(file.read_bytes()+b'changed')
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_query(self.store,self.cid)

    def test_new_evidence_invalidates_combined_index(self):
        self.text()
        correlationwork.build_correlation(self.store,self.cid)
        self.reg('more.log',b'2024-07-03T09:00:00Z new line\n')
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_sources(self.store,self.cid)

    def test_new_upstream_timeline_invalidates_combined_index(self):
        self.text()
        correlationwork.build_correlation(self.store,self.cid)
        timelinework.build_timeline(self.store,self.cid)
        with self.assertRaises(casework.CaseError):
            correlationwork.correlation_summary(self.store,self.cid)

    def test_cancel_does_not_replace_previous_index(self):
        self.text()
        correlationwork.build_correlation(self.store,self.cid)
        initial=correlationwork.correlation_summary(self.store,self.cid)
        def cancel():raise jobwork.JobCancelled('cancelled')
        with self.assertRaises(jobwork.JobCancelled):
            correlationwork.build_correlation(self.store,self.cid,should_cancel=cancel)
        self.assertEqual(correlationwork.correlation_summary(self.store,self.cid),initial)
        self.assertFalse(list((self.base/'indexes').glob('.tmp-correlate-*')))

    def test_index_symlink_refused(self):
        self.text()
        dest=self.base/'indexes'/'correlation.sqlite3'
        dest.symlink_to('/etc/hosts')
        with self.assertRaises(casework.CaseError):
            correlationwork.build_correlation(self.store,self.cid)

    def test_bad_sanitized_provider_is_never_echoed(self):
        self.evtx()
        with self.store._locked(self.cid) as (folder,manifest):
            aid=next(iter(manifest['artifacts']))
            db=folder/'indexes'/('evtx-'+aid+'.sqlite3')
            import sqlite3
            conn=sqlite3.connect(db)
            conn.execute("UPDATE records SET provider='user=private.name' ")
            conn.commit();conn.close()
        result=correlationwork.build_correlation(self.store,self.cid)
        self.assertNotIn('private.name',json.dumps(correlationwork.correlation_query(self.store,self.cid)))
        self.assertEqual(result['sources'],1)

    def test_bad_pcap_signal_refused(self):
        aid=self.pcap()
        path=self.base/'indexes'/('protocol-'+aid+'.json')
        report=json.loads(path.read_text())
        report['observations'][0]['signal']='drop all secrets'
        path.write_text(json.dumps(report));path.chmod(0o600)
        with self.assertRaises(casework.CaseError):
            correlationwork.build_correlation(self.store,self.cid)

    def test_duplicate_signal_observations_are_bounded_and_partial(self):
        aid=self.pcap()
        path=self.base/'indexes'/('protocol-'+aid+'.json')
        report=json.loads(path.read_text())
        report['observations']*=500
        path.write_text(json.dumps(report));path.chmod(0o600)
        with self.assertRaises(casework.CaseError):
            correlationwork.build_correlation(self.store,self.cid)

    def test_repeated_packet_signal_is_not_causality(self):
        aid=self.pcap()
        obs=protocolwork._checked_report(self.store,self.cid,aid)['observations']
        self.assertIn('tcp_syn',{x['signal'] for x in obs})
        self.assertIn('tcp_rst',{x['signal'] for x in obs})
        self.assertIn('dns_error',{x['signal'] for x in obs})
        source=json.dumps(obs)
        self.assertNotIn('secret.local',source)
        self.assertNotIn('10.1.',source)

    def test_packet_observation_limit_is_partial_not_silent(self):
        client=b'\x0a\x01\x02\x03'; server=b'\x0a\x01\x02\x04'
        frame=ipv4(client,server,6,tcp(50000,443,flags=0x02))
        aid=self.reg('many.pcap',pcap([frame]*513))
        decoded=protocolwork.analyze_capture(self.store,self.cid,aid)
        self.assertEqual(decoded['status'],'PARTIAL')
        self.assertGreater(protocolwork.protocol_report(self.store,self.cid,aid)['observations_omitted'],0)
        obs=protocolwork._checked_report(self.store,self.cid,aid)['observations']
        self.assertEqual(len(obs),512)
        combined=correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(combined['status'],'PARTIAL')
        self.assertIn('pcap_source_partial',combined['limitations'])
        self.assertEqual(combined['events'],512)

    def test_untrusted_text_index_excerpts_are_redacted_again(self):
        self.text()
        import sqlite3
        t=self.base/'indexes'/'timeline.sqlite3'
        db=sqlite3.connect(t)
        db.execute("UPDATE events SET excerpt='error password=not-visible',level_hint='private-message' WHERE line_no=1")
        db.commit();db.close()
        correlationwork.build_correlation(self.store,self.cid)
        query=correlationwork.correlation_query(self.store,self.cid)
        self.assertNotIn('not-visible',json.dumps(query))
        self.assertIsNone(query['events'][0]['signal'])

    def test_excluded_archive_is_reported_as_incomplete_coverage(self):
        self.reg('bundle.zip',b'PK\x03\x04' + b'\0'*100)
        result=correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(result['status'],'PARTIAL')
        self.assertEqual(result['excluded_artifacts'],1)
        self.assertIn('non_log_capture_evtx_artifacts_not_correlated',result['limitations'])

    def test_approval_is_case_only_not_arbitrary_job(self):
        with self.assertRaises(jobwork.JobError):
            self.jobs.submit('build_correlation',self.cid,artifact_id='a'*32)
        j=self.jobs.submit('build_correlation',self.cid)
        self.assertEqual(self.jobs.work_once()['state'],'SUCCEEDED')
        self.assertEqual(self.jobs.result(j['job_id'])['result']['status'],'NOT_APPLICABLE')

    def test_gateway_exposes_three_tools_without_shell(self):
        gw=gateway.Gateway(gateway.Config({},(),self.home))
        names={x['name'] for x in gw.tools()}
        self.assertIn('correlation_query',names)
        self.assertIn('correlation_sources',names)
        self.assertIn('correlation_summary',names)
        self.assertNotIn('shell',names)
        with self.assertRaises(gateway.GatewayError):
            gw.call('correlation_query',{'case_id':self.cid,'limit':True})
        job=gw.call('job_submit',{'case_id':self.cid,'kind':'build_correlation'})
        self.assertEqual(self.jobs.work_once()['state'],'SUCCEEDED')
        self.assertEqual(gw.call('correlation_summary',{'case_id':self.cid})['status'],'NOT_APPLICABLE')
        self.assertEqual(self.jobs.result(job['job_id'])['state'],'SUCCEEDED')


if __name__=='__main__': unittest.main()
