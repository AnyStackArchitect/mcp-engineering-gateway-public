"""Known-answer packet-local truth and refusal boundaries."""
from __future__ import annotations
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import packettruth


class DnsTruthTests(unittest.TestCase):
    def test_tuple_transaction_id_pairing_is_only_candidate(self):
        s=b"\x0a\x01\x02\x03"; d=b"\x0a\x01\x02\x04"
        p=struct.pack("!HHHHHH",0x1234,0x0100,1,0,0,0)
        r=struct.pack("!HHHHHH",0x1234,0x8183,1,0,0,0)
        tracker=packettruth.DnsCandidateTracker()
        tracker.observe(s,55000,d,53,p,"query")
        tracker.observe(s,55000,d,53,p,"query")
        self.assertEqual(tracker.collisions,1)
        tracker.observe(d,53,s,55000,r,"response")
        tracker.observe(d,53,s,55000,r,"response")
        o=tracker.summary()
        self.assertEqual(o["dns_tuple_id_match_candidates"],1)
        self.assertEqual(o["dns_response_without_seen_query_candidates"],1)
        self.assertEqual(o["dns_query_without_seen_response_candidates"],0)

    def test_no_cross_client_port_or_direction_guess(self):
        a=b"AAAA";b=b"BBBB";q=b"\x04\x01"+b"\x00"*10
        t=packettruth.DnsCandidateTracker()
        t.observe(a,50000,b,53,q,"query")
        t.observe(b,53,a,50001,q,"response")
        self.assertEqual(t.matched,0)
        self.assertEqual(t.orphan_responses,1)
        self.assertEqual(len(t.pending),1)

    def test_pending_tracker_resource_cap_is_explicit(self):
        tracker=packettruth.DnsCandidateTracker()
        old=packettruth.MAX_PENDING_DNS
        packettruth.MAX_PENDING_DNS=1
        try:
            tracker.observe(b"a",100,b"b",53,b"\x00\x01"+b"x"*10,"query")
            tracker.observe(b"a",100,b"b",53,b"\x00\x02"+b"x"*10,"query")
            self.assertTrue(tracker.summary()["dns_pending_tracker_overflow"])
            self.assertEqual(len(tracker.pending),1)
        finally:
            packettruth.MAX_PENDING_DNS=old


class SMB2TruthTests(unittest.TestCase):
    @staticmethod
    def frame(*, response=True, status=0xc0000022, command=5,
              protocol=b"\xfeSMB", length=64):
        hdr=bytearray(64)
        hdr[0:4]=protocol
        hdr[4:6]=(64).to_bytes(2,"little")
        hdr[8:12]=status.to_bytes(4,"little")
        hdr[12:14]=command.to_bytes(2,"little")
        hdr[16:20]=(1 if response else 0).to_bytes(4,"little")
        return bytes([0,0,(length>>8)&255,length&255])+bytes(hdr)

    def test_access_denied_is_metadata_not_identity(self):
        d=packettruth.smb2_header(self.frame())
        self.assertEqual(d["command"],5)
        self.assertEqual(d["status_label"],"access_denied")
        self.assertTrue(d["response"])
        self.assertTrue(d["error"])
        self.assertTrue(d["message_complete_in_segment"])
        self.assertNotIn("user",str(d).lower())

    def test_request_status_bytes_not_read_as_error(self):
        d=packettruth.smb2_header(self.frame(response=False))
        self.assertEqual(d["status_label"],"request")
        self.assertFalse(d["error"])

    def test_unknown_malformed_incomplete_never_claimed_decoded(self):
        for bad in (
            b"short", self.frame(protocol=b"\xffSMB"),
            self.frame(command=65535),
            self.frame()[:67],
            b"\xff"+self.frame()[1:],
        ):
            self.assertIsNone(packettruth.smb2_header(bad))
        self.assertFalse(packettruth.smb2_header(self.frame(length=70))["message_complete_in_segment"])


if __name__=="__main__":
    unittest.main()
