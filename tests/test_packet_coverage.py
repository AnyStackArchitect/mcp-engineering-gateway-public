"""Known-answer capture-quality and source-linked packet signal coverage."""
from pathlib import Path
import json
import struct
import tempfile
import unittest

import casework
import correlationwork
import gateway
import protocolwork
from test_protocolwork import ipv4, tcp, pcap, pcapng

A = b'\x0a\x01\x02\x03'
B = b'\x0a\x01\x02\x04'


def segment(sp, dp, seq, ack, flags=0x10, payload=b'', window=8192):
    data = bytearray(tcp(sp, dp, seq=seq, flags=flags, data=payload))
    data[8:12] = ack.to_bytes(4, 'big')
    data[14:16] = window.to_bytes(2, 'big')
    return bytes(data)


def quality_frames():
    return [
        ipv4(A, B, 6, segment(42001, 443, 100, 0, 0x02)),
        ipv4(B, A, 6, segment(443, 42001, 500, 101, 0x12)),
        ipv4(A, B, 6, segment(42001, 443, 101, 501)),
        ipv4(A, B, 6, segment(42001, 443, 101, 501, 0x18, b'ABCD')),
        ipv4(A, B, 6, segment(42001, 443, 109, 501, 0x18, b'WXYZ')),
        ipv4(A, B, 6, segment(42001, 443, 109, 501, 0x18, b'WXYZ')),
        ipv4(B, A, 6, segment(443, 42001, 501, 113, window=0)),
    ]


def quality_binary(fmt='pcap'):
    frames = quality_frames()
    truncated = ipv4(A, B, 6, segment(42001, 443, 113, 501, 0x18, b'private-payload'))
    cap = truncated[:16]
    if fmt == 'pcap':
        return pcap(frames) + struct.pack('<IIII', 1720000007, 0, len(cap), len(truncated)) + cap
    binary = pcapng(frames)
    body = struct.pack('<IIIII', 0, (1720000007 * 1000000) >> 32,
                       (1720000007 * 1000000) & 0xffffffff, len(cap), len(truncated)) + cap
    n = len(body) + 12
    return binary + struct.pack('<II', 6, n) + body + struct.pack('<I', n)


class PacketCoverageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.store = casework.CaseStore(self.home)
        self.cid = self.store.open_case()['case_id']

    def register(self, data, name='known.pcap'):
        target = self.store.inbox/name
        target.write_bytes(data); target.chmod(0o600)
        return self.store.register(self.cid, name)['artifact_id']

    def analyze(self, data, name='known.pcap'):
        aid = self.register(data, name)
        protocolwork.analyze_capture(self.store, self.cid, aid)
        return aid

    def test_pcap_and_pcapng_known_frame_signals_and_quality(self):
        for fmt in ('pcap', 'pcapng'):
            aid = self.analyze(quality_binary(fmt), 'known.' + fmt)
            summary = protocolwork.protocol_report(self.store, self.cid, aid)
            c = summary['counters']
            self.assertEqual(c['tcp_forward_sequence_gap_candidates'], 1)
            self.assertEqual(c['tcp_retransmit_candidates'], 1)
            self.assertEqual(c['tcp_zero_window_advertised'], 1)
            self.assertEqual(summary['capture_quality']['snaplen_truncated_frames'], 1)
            self.assertEqual(summary['status'], 'PARTIAL')
            self.assertFalse(summary['claim_boundaries']['packet_loss_proven'])
            view = protocolwork.protocol_observations(self.store, self.cid, aid)
            got = {row['signal']: row['packet_no'] for row in view['observations']}
            self.assertEqual(got['tcp_forward_sequence_gap_candidate'], 5)
            self.assertEqual(got['tcp_repeated_seq_candidate'], 6)
            self.assertEqual(got['tcp_zero_window_advertised'], 7)
            self.assertEqual(got['capture_frame_truncated'], 8)
            flow_ids = {f['flow_id'] for f in protocolwork.protocol_flows(self.store, self.cid, aid)['flows']}
            self.assertTrue(all(r['flow_id'] in flow_ids for r in view['observations'] if r['flow_id']))
            self.assertNotIn('private-payload', json.dumps(view))
            self.assertNotIn('10.1.2.3', json.dumps(view))

    def test_sequence_wrap_and_reordered_old_segment_do_not_add_gap(self):
        aid = self.analyze(pcap([
            ipv4(A, B, 6, segment(1, 2, 0xfffffffc, 0, 0x18, b'ABCD')),
            ipv4(A, B, 6, segment(1, 2, 0, 0, 0x18, b'EFGH')),
            ipv4(A, B, 6, segment(1, 2, 0xfffffffc, 0, 0x18, b'ABCD'))]))
        report = protocolwork.protocol_report(self.store, self.cid, aid)
        self.assertEqual(report['counters'].get('tcp_forward_sequence_gap_candidates', 0), 0)
        self.assertFalse(report['claim_boundaries']['packet_loss_proven'])

    def test_new_syn_resets_capture_local_tuple_sequence_space(self):
        aid = self.analyze(pcap([
            ipv4(A, B, 6, segment(1, 2, 100, 0, 0x18, b'ABCD')),
            ipv4(A, B, 6, segment(1, 2, 10000, 0, 0x02)),
            ipv4(A, B, 6, segment(1, 2, 10001, 0, 0x18, b'EFGH'))]))
        self.assertEqual(protocolwork.protocol_report(self.store, self.cid, aid)['counters'].get('tcp_forward_sequence_gap_candidates', 0), 0)

    def test_zero_window_rst_or_syn_is_not_advertised_stall_observation(self):
        aid = self.analyze(pcap([ipv4(A, B, 6, segment(1, 2, 1, 0, f, window=0))
                                 for f in (0x04, 0x02, 0x12, 0x11)]))
        self.assertEqual(protocolwork.protocol_report(self.store, self.cid, aid)['counters'].get('tcp_zero_window_advertised', 0), 0)

    def test_bounded_observation_pagination_and_omitted_coverage(self):
        frame = ipv4(A, B, 6, segment(1, 2, 1, 0, 0x04))
        aid = self.analyze(pcap([frame] * 530))
        page = protocolwork.protocol_observations(self.store, self.cid, aid, offset=500)
        self.assertEqual(len(page['observations']), 12)
        self.assertEqual(page['observations_omitted'], 18)
        self.assertEqual(page['status'], 'PARTIAL')
        self.assertFalse(page['has_more'])
        self.assertIsNone(page['next_offset'])
        for invalid in (True, -1, 512):
            with self.assertRaises(protocolwork.ProtocolError):
                protocolwork.protocol_observations(self.store, self.cid, aid, offset=invalid)

    def test_new_signals_join_common_timeline_with_source_frames(self):
        aid = self.analyze(quality_binary())
        correlationwork.build_correlation(self.store, self.cid)
        rows = correlationwork.correlation_query(self.store, self.cid)['events']
        relevant = {r['signal']: r for r in rows}
        self.assertEqual(relevant['capture_frame_truncated']['locator_number'], 8)
        self.assertEqual(relevant['tcp_zero_window_advertised']['artifact_id'], aid)

    def test_gateway_strict_read_only_query_and_stale_refusal(self):
        aid = self.analyze(quality_binary())
        gw = gateway.Gateway(gateway.Config({}, (), self.home))
        args = {'case_id': self.cid, 'artifact_id': aid}
        self.assertTrue(gw.call('pcap_observations', args)['observations'])
        with self.assertRaises(gateway.GatewayError):
            gw.call('pcap_observations', args | {'display_filter': 'payload'})
        path = self.store.cases/self.cid/'originals'/aid
        path.write_bytes(path.read_bytes() + b'X')
        with self.assertRaises(gateway.GatewayError):
            gw.call('pcap_observations', args)

    def test_timestamp_fraction_outside_capture_precision_is_refused(self):
        raw = bytearray(pcap(quality_frames()[:1]))
        raw[28:32] = (1000000).to_bytes(4, 'little')
        with self.assertRaisesRegex(protocolwork.ProtocolError, 'precision'):
            self.analyze(bytes(raw))

    def test_pcapng_enhanced_capture_must_obey_interface_snaplen(self):
        raw = bytearray(pcapng(quality_frames()[:1]))
        raw[40:44] = (16).to_bytes(4, 'little')
        with self.assertRaisesRegex(protocolwork.ProtocolError, 'snap length'):
            self.analyze(bytes(raw), 'bad.pcapng')

    def test_pcapng_simple_packet_padding_is_not_evidence_bytes(self):
        def block(kind, body):
            body += b'\0' * ((-len(body)) % 4)
            size = len(body) + 12
            return struct.pack('<II', kind, size) + body + struct.pack('<I', size)
        prefix = (block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)) +
                  block(1, struct.pack('<HHI', 1, 0, 1)))
        raw = prefix + block(3, struct.pack('<I', 100) + b'X')
        aid = self.analyze(raw, 'simple.pcapng')
        report = protocolwork.protocol_report(self.store, self.cid, aid)
        self.assertEqual(report['capture_quality']['snaplen_truncated_frames'], 1)
        self.assertEqual(report['capture_quality']['frames_without_timestamp'], 1)
        from io import BytesIO
        self.assertEqual(list(protocolwork._frames(BytesIO(raw), len(raw), 'pcapng'))[0][1], b'X')


if __name__ == '__main__':
    unittest.main()
