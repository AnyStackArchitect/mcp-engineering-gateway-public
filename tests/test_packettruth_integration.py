"""Stage B CAND-04: packet-local DNS/TLS/SMB2 and provenance regressions."""
from __future__ import annotations
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import casework, correlationwork, jobwork, protocolwork, timelinework
from test_protocolwork import ipv4, tcp, udp, pcap, pcapng
from test_packettruth import SMB2TruthTests


def frames():
    a=b"\x0a\x01\x02\x03";b=b"\x0a\x01\x02\x04"
    qname=b"\x06secret\x05local\x00\x00\x01\x00\x01"
    q=struct.pack("!HHHHHH",0x1234,0x0100,1,0,0,0)+qname
    r=struct.pack("!HHHHHH",0x1234,0x8183,1,0,0,0)+qname
    return [
        ipv4(a,b,17,udp(50201,53,q)),
        ipv4(b,a,17,udp(53,50201,r)),
        ipv4(b,a,6,tcp(445,50202,flags=0x18,data=SMB2TruthTests.frame())),
        ipv4(a,b,6,tcp(50203,443,flags=0x18,
                        data=b"\x15\x03\x03\x00\x02\x02\x28")),
        ipv4(b,a,6,tcp(443,50203,flags=0x04)),
    ]


class PacketTruthEndToEnd(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home=Path(tmp.name)
        self.jobs=jobwork.JobStore(self.home)
        self.store=self.jobs.cases
        self.cid=self.store.open_case()["case_id"]

    def reg(self,name,bytestring):
        src=self.store.inbox/name
        src.write_bytes(bytestring)
        src.chmod(0o600)
        return self.store.register(self.cid,name)["artifact_id"]

    def test_pcap_and_pcapng_share_packet_local_known_answers(self):
        outputs=[]
        for extension,doc in (("pcap",pcap(frames())),
                              ("pcapng",pcapng(frames()))):
            aid=self.reg("proof."+extension,doc)
            res=protocolwork.analyze_capture(self.store,self.cid,aid)
            view=protocolwork.protocol_report(self.store,self.cid,aid)
            self.assertEqual(res["packets_examined"],5)
            self.assertEqual(view["counters"]["dns_tuple_id_match_candidates"],1)
            self.assertEqual(view["counters"]["dns_rcode_3"],1)
            self.assertEqual(view["counters"]["smb2_access_denied"],1)
            self.assertEqual(view["counters"]["smb2_response_error"],1)
            self.assertEqual(view["counters"]["tls_alert_40"],1)
            self.assertEqual(view["counters"]["tcp_rst"],1)
            self.assertEqual(view["status"],"PASS")
            self.assertFalse(view["claim_boundaries"]["capture_complete"])
            self.assertFalse(view["claim_boundaries"]["tcp_stream_reassembled"])
            self.assertFalse(view["claim_boundaries"]["dns_transaction_identity_proven"])
            self.assertFalse(view["claim_boundaries"]["clock_alignment_verified"])
            self.assertFalse(view["claim_boundaries"]["smb2_session_complete"])
            self.assertNotIn("secret.local",json.dumps(view))
            outputs.append(view["counters"])
        self.assertEqual(outputs[0],outputs[1])

    def test_smb2_error_is_correlation_signal_without_payload(self):
        aid=self.reg("packet.pcap",pcap(frames()))
        protocolwork.analyze_capture(self.store,self.cid,aid)
        cross=correlationwork.build_correlation(self.store,self.cid)
        self.assertEqual(cross["missing_indexes"],0)
        q=correlationwork.correlation_query(self.store,self.cid)
        self.assertIn("smb2_error",{e["signal"] for e in q["events"]})
        for value in ("secret.local","10.1.2.3","user=","SubjectUserName"):
            self.assertNotIn(value,json.dumps(q))

    def test_fragmented_smb2_and_tls_fail_to_claim_complete_parsing(self):
        a=b"\x0a\x00\x00\x01";b=b"\x0a\x00\x00\x02"
        short=SMB2TruthTests.frame()[:12]
        tlsfragment=b"\x15\x03\x03\x00\x30\x02"
        aid=self.reg("fragment.pcap",pcap([
            ipv4(a,b,6,tcp(40001,445,data=short)),
            ipv4(a,b,6,tcp(40002,443,data=tlsfragment))]))
        view=protocolwork.analyze_capture(self.store,self.cid,aid)
        self.assertEqual(view["status"],"PARTIAL")
        self.assertIn("smb2_header_fragment_no_reassembly",view["limitations"])
        self.assertIn("tls_record_crosses_packet_boundary",view["limitations"])
        counts=protocolwork.protocol_report(self.store,self.cid,aid)["counters"]
        self.assertNotIn("smb2_response_error",counts)
        self.assertNotIn("tls_alert_40",counts)

    def test_unpaired_response_does_not_prove_failure(self):
        a=b"\x0a\x01\x02\x03";b=b"\x0a\x01\x02\x04"
        pkt=struct.pack("!HHHHHH",0x55,0x8180,0,0,0,0)
        aid=self.reg("one-sided.pcap",pcap([ipv4(b,a,17,udp(53,50000,pkt))]))
        got=protocolwork.analyze_capture(self.store,self.cid,aid)
        self.assertEqual(got["status"],"PASS")
        report=protocolwork.protocol_report(self.store,self.cid,aid)
        self.assertEqual(report["counters"]["dns_response_without_seen_query_candidates"],1)
        self.assertFalse(report["claim_boundaries"]["dns_transaction_identity_proven"])

    def test_source_mutation_refuses_protocol_and_joined_results(self):
        aid=self.reg("bytes.pcap",pcap(frames()))
        protocolwork.analyze_capture(self.store,self.cid,aid)
        correlationwork.build_correlation(self.store,self.cid)
        with self.store._locked(self.cid) as (folder, manifest):
            original=folder/"originals"/aid
            original.write_bytes(original.read_bytes()+b"\x00")
        for run in (lambda:protocolwork.protocol_report(self.store,self.cid,aid),
                    lambda:correlationwork.correlation_summary(self.store,self.cid)):
            with self.assertRaises(casework.CaseError):
                run()


if __name__=="__main__":
    unittest.main()
