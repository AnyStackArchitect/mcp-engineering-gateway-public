"""Byte-known answers, source-frame lineage and explicit ambiguity/budgets."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from streamwork import StreamTracker,MAX_BYTES,MAX_SEGMENTS,MAX_STREAMS
import casework,protocolwork
from test_protocolwork import pcap,pcapng,ipv4
from test_packet_coverage import segment,A,B


def stream_frames(order=(0,1),seq=100,payloads=(b'ABCD',b'EFGH')):
    data=[ipv4(A,B,6,segment(42001,443,seq,0,0x02))]
    for n in order:data.append(ipv4(A,B,6,segment(42001,443,(seq+1+4*n)&0xffffffff,0,0x18,payloads[n])))
    data.append(ipv4(A,B,6,segment(42001,443,(seq+9)&0xffffffff,0,0x11)))
    return data


class StreamTrackerTests(unittest.TestCase):
    def run_stream(self,segments):
        tracker=StreamTracker()
        for frame,(seq,flags,payload) in enumerate(segments,1):tracker.observe('flow-1',seq,flags,payload,frame)
        return tracker.summary()['streams'][0]

    def test_reordering_wrap_duplicate_bytes_and_source_contributions(self):
        r=self.run_stream([(0xfffffffc,2,b''),(1,0x18,b'EFGH'),(0xfffffffd,0x18,b'ABCD'),(1,0x18,b'EFGH'),(5,0x11,b'')])
        self.assertEqual(r['unique_payload_bytes'],8);self.assertEqual(r['overlap_byte_observations'],4)
        self.assertEqual(r['contributing_frames'],[2,3]);self.assertEqual(r['fin_frame'],5)
        self.assertTrue(r['syn_to_fin_payload_covered']);self.assertEqual(r['unobserved_ranges'],[])
        self.assertEqual(r['private_contiguous_sha256'],hashlib.sha256(b'ABCDEFGH').hexdigest())

    def test_holes_and_conflicting_overlap_withhold_unambiguous_hash(self):
        r=self.run_stream([(100,2,b''),(101,0x18,b'ABCD'),(109,0x18,b'IJKL'),(113,0x11,b'')])
        self.assertEqual(r['unobserved_ranges'],[{'start':4,'end':8}]);self.assertFalse(r['syn_to_fin_payload_covered'])
        self.assertIsNone(r['private_contiguous_sha256'])
        r=self.run_stream([(100,2,b''),(101,0x18,b'ABCD'),(103,0x18,b'XXEF'),(107,0x11,b'')])
        self.assertEqual(r['conflicting_byte_observations'],2);self.assertIsNone(r['private_contiguous_sha256'])

    def test_no_syn_rebases_earlier_observed_bytes_but_does_not_claim_start(self):
        r=self.run_stream([(105,0x18,b'EFGH'),(101,0x18,b'ABCD'),(109,0x11,b'')])
        self.assertEqual(r['private_contiguous_sha256'],hashlib.sha256(b'ABCDEFGH').hexdigest())
        self.assertFalse(r['captured_syn']);self.assertFalse(r['syn_to_fin_payload_covered'])

    def test_syn_data_and_fin_data_sequence_consumption(self):
        r=self.run_stream([(100,2,b'AB'),(103,0x19,b'CD')])
        self.assertEqual(r['observed_extent_bytes'],4);self.assertTrue(r['syn_to_fin_payload_covered'])
        self.assertEqual(r['private_contiguous_sha256'],hashlib.sha256(b'ABCD').hexdigest())

    def test_tuple_reuse_creates_separate_epochs_and_syn_repeats_do_not(self):
        t=StreamTracker()
        for n,seq in enumerate((100,100,10000),1):t.observe('flow-1',seq,2,b'',n)
        r=t.summary();self.assertEqual(len(r['streams']),2)
        self.assertEqual([s['epoch'] for s in r['streams']],[1,2])

    def test_window_segment_and_stream_budgets_report_omission(self):
        t=StreamTracker();t.observe('flow-1',100,2,b'',1)
        t.observe('flow-1',101+MAX_BYTES,0x18,b'outside',2)
        for n in range(MAX_SEGMENTS):t.observe('flow-1',101,0x10,b'',3+n)
        for n in range(MAX_STREAMS):t.observe('flow-'+str(n+2),100,2,b'',1000+n)
        r=t.summary();self.assertEqual(len(r['streams']),MAX_STREAMS);self.assertEqual(r['omitted_segments'],1)
        self.assertEqual(r['streams'][0]['limits'],['byte_window_budget','segment_budget'])
        self.assertIsNone(r['streams'][0]['private_contiguous_sha256'])

    def test_truncation_and_conflicting_fin_are_explicit(self):
        t=StreamTracker();t.observe('flow-1',100,2,b'',1)
        t.observe('flow-1',101,0x19,b'ABCD',2,True);t.observe('flow-1',106,0x11,b'',3)
        r=t.summary()['streams'][0];self.assertEqual(r['truncated_frames'],1)
        self.assertIn('conflicting_fin',r['limits']);self.assertFalse(r['syn_to_fin_payload_covered'])

    def test_no_syn_rebase_keeps_existing_fin_inside_window(self):
        r=self.run_stream([(100,0x10,b''),(100+MAX_BYTES,0x11,b''),(99,0x18,b'A')])
        self.assertEqual(r['observed_extent_bytes'],MAX_BYTES)
        self.assertEqual(r['fin_relative_end'],MAX_BYTES)
        self.assertIn('sequence_outside_window',r['limits']);self.assertFalse(r['syn_to_fin_payload_covered'])

    def test_epoch_limit_tombstones_tuple_instead_of_filling_old_stream_hole(self):
        tracker=StreamTracker()
        tracker.observe('flow-1',100,2,b'',1);tracker.observe('flow-1',101,0x18,b'AB',2)
        tracker.observe('flow-1',105,0x11,b'',3)
        for n in range(15):tracker.observe('flow-'+str(n+2),100,2,b'',4+n)
        tracker.observe('flow-1',102,2,b'',20);tracker.observe('flow-1',103,0x18,b'CD',21)
        r=tracker.summary();old=r['streams'][0]
        self.assertEqual(old['unobserved_ranges'],[{'start':2,'end':4}])
        self.assertFalse(old['syn_to_fin_payload_covered']);self.assertIn('later_epoch_omitted',old['limits'])
        self.assertEqual(old['contributing_frames'],[2]);self.assertEqual(r['omitted_segments'],2)


class StreamCaptureTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.store=casework.CaseStore(Path(temp.name));self.cid=self.store.open_case()['case_id']

    def analyze(self,fmt='pcap',order=(1,0),seq=100):
        path=self.store.inbox/('fixture.'+fmt);path.write_bytes((pcap if fmt=='pcap' else pcapng)(stream_frames(order,seq)));path.chmod(0o600)
        aid=self.store.register(self.cid,path.name)['artifact_id'];protocolwork.analyze_capture(self.store,self.cid,aid)
        return aid,protocolwork.protocol_stream_coverage(self.store,self.cid,aid)

    def test_real_formats_reconstruct_and_mcp_projection_hides_payload_and_hash(self):
        for fmt in ('pcap','pcapng'):
            aid,r=self.analyze(fmt)
            self.assertTrue(r['streams'][0]['syn_to_fin_payload_covered']);self.assertEqual(r['streams'][0]['contributing_frames'],[2,3])
            self.assertEqual(r['streams'][0]['observed_ranges'],[{'start':0,'end':8}])
            self.assertEqual(r['status'],'PARTIAL');self.assertFalse(r['packet_loss_proven'])
            raw=json.dumps(r);self.assertNotIn('ABCDEFGH',raw);self.assertNotIn('private_contiguous_sha256',raw)
            self.assertNotIn(hashlib.sha256(b'ABCDEFGH').hexdigest(),raw);self.assertNotIn('10.1.2.3',raw)
            doc=protocolwork._checked_report(self.store,self.cid,aid)
            self.assertEqual(doc['tcp_reconstruction']['streams'][0]['private_contiguous_sha256'],hashlib.sha256(b'ABCDEFGH').hexdigest())

    def test_legacy_report_unavailable_and_stale_source_refusal(self):
        aid,r=self.analyze();doc=protocolwork._checked_report(self.store,self.cid,aid)
        path=self.store.cases/self.cid/'indexes'/('protocol-'+aid+'.json');doc.pop('tcp_reconstruction');path.write_text(json.dumps(doc))
        self.assertEqual(protocolwork.protocol_stream_coverage(self.store,self.cid,aid)['status'],'NOT_AVAILABLE')
        os.utime(self.store.cases/self.cid/'originals'/aid,None)
        with self.assertRaises(casework.CaseError):protocolwork.protocol_stream_coverage(self.store,self.cid,aid)

    def test_corrupt_claims_private_fields_locators_counts_and_controls_refused(self):
        aid,r=self.analyze();original=protocolwork._checked_report(self.store,self.cid,aid)
        import copy
        mutations=[lambda row:row.update(syn_to_fin_payload_covered='true'),lambda row:row.update(unique_payload_bytes=9),
            lambda row:row.update(flow_id='private-host'),lambda row:row.update(contributing_frames=[0]),
            lambda row:row.update(raw='private'),lambda row:row.update(observed_ranges=[{'start':0,'end':MAX_BYTES+1}]),
            lambda row:row.update(private_contiguous_sha256='private'),lambda row:row.update(conflicting_byte_observations=1)]
        for mutate in mutations:
            doc=copy.deepcopy(original);mutate(doc['tcp_reconstruction']['streams'][0])
            with self.subTest(doc=doc),patch('protocolwork._checked_report',return_value=doc),self.assertRaises(casework.CaseError):
                protocolwork.protocol_stream_coverage(self.store,self.cid,aid)
        for offset in (True,-1,16):
            with self.assertRaises(casework.CaseError):protocolwork.protocol_stream_coverage(self.store,self.cid,aid,offset=offset)


if __name__=='__main__':unittest.main()
