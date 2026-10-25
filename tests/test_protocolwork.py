"""Known-answer offline protocol fixtures and hostile/corrupt input boundaries."""
from __future__ import annotations

from pathlib import Path
import json
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import casework, gateway, jobwork, protocolwork


def ipv4(src: bytes, dst: bytes, protocol: int, data: bytes, *, fragmented: bool=False) -> bytes:
    total = len(data)+20
    header = struct.pack('!BBHHHBBH4s4s',0x45,0,total,1,0x2000 if fragmented else 0,64,protocol,0,src,dst)
    return b'\x00'*12 + b'\x08\x00' + header + data


def tcp(sp: int, dp: int, *, seq: int=1,flags: int=0x18,data: bytes=b'') -> bytes:
    return struct.pack('!HHIIBBHHH',sp,dp,seq,0,0x50,flags,8192,0,0)+data


def udp(sp: int, dp: int, data: bytes) -> bytes:
    return struct.pack('!HHHH',sp,dp,len(data)+8,0)+data


def pcap(frames: list[bytes], *, dlt: int=1, broken: bool=False) -> bytes:
    result = bytearray(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII',2,4,0,0,65535,dlt))
    for i, frame in enumerate(frames):
        result += struct.pack('<IIII',1720000000+i,i*100,len(frame),len(frame))+frame
    if broken:
        result += struct.pack('<IIII',1720000050,0,50000,50000)+b'only-four-bytes'
    return bytes(result)


def pcapng(frames: list[bytes]) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        padded = body + b'\0' * ((-len(body)) % 4)
        n=len(padded)+12
        return struct.pack('<II',kind,n)+padded+struct.pack('<I',n)
    out=bytearray()
    out += block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    # Interface time resolution default microseconds
    out += block(1,struct.pack('<HHI',1,0,65535)+struct.pack('<HH',0,0))
    for i, f in enumerate(frames):
        t=1720000000*1_000_000+i*10_000
        out += block(6,struct.pack('<IIIII',0,t>>32,t&0xffffffff,len(f),len(f))+f)
    return bytes(out)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.store = jobwork.JobStore(self.home)
        self.cid = self.store.cases.open_case()['case_id']

    def reg(self, name: str, data: bytes) -> str:
        file=self.store.cases.inbox/name
        file.write_bytes(data)
        file.chmod(0o600)
        return self.store.cases.register(self.cid,name)['artifact_id']

    def traffic(self):
        client=b'\x0a\x01\x02\x03';server=b'\x0a\x01\x02\x04'
        syn=ipv4(client,server,6,tcp(51515,443,flags=0x02))
        ack=ipv4(server,client,6,tcp(443,51515,flags=0x12))
        hello=ipv4(client,server,6,tcp(51515,443,seq=2,data=b'\x16\x03\x03\x00\x04\x01\x00\x00\x00'))
        reset=ipv4(server,client,6,tcp(443,51515,flags=0x04))
        name=b'\x06secret\x05local\x00\x00\x01\x00\x01'
        dns_query=struct.pack('!HHHHHH',7,0x0100,1,0,0,0)+name
        dns_reply=struct.pack('!HHHHHH',7,0x8183,1,0,0,0)+name
        dnsq=ipv4(client,server,17,udp(45678,53,dns_query))
        dnsr=ipv4(server,client,17,udp(53,45678,dns_reply))
        return [syn,ack,hello,hello,reset,dnsq,dnsr]

    def test_pcap_traffic_dns_tls_tcp(self):
        aid=self.reg('traffic.pcap',pcap(self.traffic()))
        j=self.store.submit('decode_pcap',self.cid,artifact_id=aid)
        self.assertEqual(self.store.work_once()['state'],'SUCCEEDED')
        result=self.store.result(j['job_id'])['result']
        self.assertEqual(result['packets_examined'],7)
        self.assertEqual(result['counters']['tcp_rst'],1)
        self.assertEqual(result['counters']['dns_response'],1)
        self.assertEqual(result['counters']['dns_rcode_3'],1)
        self.assertEqual(result['counters']['tls_client_hello'],2)
        self.assertGreaterEqual(result['counters']['tcp_retransmit_candidates'],1)
        report=protocolwork.protocol_report(self.store.cases,self.cid,aid)
        self.assertEqual(report['flow_count'],4)
        self.assertEqual(report['status'],'PASS')
        flow=protocolwork.protocol_flows(self.store.cases,self.cid,aid)
        self.assertEqual(len(flow['flows']),4)
        disclosed=json.dumps([result,report,flow])
        for secret in ('10.1.2.3','secret.local','credential','abcdefg'):
            self.assertNotIn(secret,disclosed)
        self.assertIn('host-1',disclosed)

    def test_pcapng_matches_classic_known_answer(self):
        aid=self.reg('traffic.pcapng',pcapng(self.traffic()))
        result=protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertEqual(result['packets_examined'],7)
        self.assertEqual(result['counters']['dns_rcode_3'],1)
        self.assertTrue(protocolwork.protocol_flows(self.store.cases,self.cid,aid)['flows'])

    def test_pcapng_endian_and_trailer_rejected(self):
        bad=bytearray(pcapng(self.traffic()))
        bad[-1]^=0x11
        aid=self.reg('bad.pcapng',bytes(bad))
        with self.assertRaisesRegex(protocolwork.ProtocolError,'trailer'):
            protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertFalse((self.store.cases.cases/self.cid/'indexes'/('protocol-'+aid+'.json')).exists())

    def test_pcapng_unsupported_linktype_partial(self):
        frame=ipv4(b'\x0a\x00\x00\x01',b'\x0a\x00\x00\x02',6,tcp(1,2))
        v=bytearray(pcapng([frame]))
        # Modify IDB linktype at offset 28: SHB is 28 bytes, block header 8
        v[36:38] = (999).to_bytes(2,'little')
        aid=self.reg('unknown.pcapng',bytes(v))
        got=protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertEqual(got['status'],'PARTIAL')
        self.assertIn('unsupported_datalink',got['limitations'])

    def test_truncated_record_fails_and_keeps_prior_report(self):
        aid=self.reg('broken.pcap',pcap(self.traffic(),broken=True))
        with self.assertRaisesRegex(protocolwork.ProtocolError,'truncated'):
            protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertFalse((self.store.cases.cases/self.cid/'indexes'/('protocol-'+aid+'.json')).exists())

    def test_ipv4_fragment_no_fake_tcp(self):
        frame=ipv4(b'\x0a\x00\x00\x01',b'\x0a\x00\x00\x02',6,tcp(1,2),fragmented=True)
        aid=self.reg('fragment.pcap',pcap([frame]))
        res=protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertEqual(res['status'],'PARTIAL')
        self.assertIn('unsupported_or_fragmented_transport',res['limitations'])

    def test_unsupported_capture_kind_denied(self):
        art=self.reg('a.log',b'hello\n')
        with self.assertRaisesRegex(protocolwork.ProtocolError,'Capture artifact required'):
            protocolwork.analyze_capture(self.store.cases,self.cid,art)

    def test_flow_result_stale_on_original_mutation(self):
        aid=self.reg('change.pcap',pcap(self.traffic()))
        protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        original=self.store.cases.cases/self.cid/'originals'/aid
        original.write_bytes(pcap(self.traffic()[:3]))
        with self.assertRaisesRegex(casework.CaseError,'integrity|stale'):
            protocolwork.protocol_report(self.store.cases,self.cid,aid)

    def test_report_symlink_refused(self):
        aid=self.reg('symlink.pcap',pcap(self.traffic()))
        protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        report=self.store.cases.cases/self.cid/'indexes'/('protocol-'+aid+'.json')
        temp=report.with_suffix('.held')
        report.rename(temp)
        report.symlink_to(temp)
        with self.assertRaisesRegex(protocolwork.ProtocolError,'symlink'):
            protocolwork.protocol_flows(self.store.cases,self.cid,aid)

    def test_cancellation_no_report(self):
        aid=self.reg('cancel.pcap',pcap(self.traffic()))
        def halt():raise jobwork.JobCancelled('operator_cancelled')
        with self.assertRaises(jobwork.JobCancelled):
            protocolwork.analyze_capture(self.store.cases,self.cid,aid,should_cancel=halt)
        self.assertFalse((self.store.cases.cases/self.cid/'indexes'/('protocol-'+aid+'.json')).exists())

    def test_untrusted_dns_body_never_disclosed(self):
        content=bytearray(self.traffic()[5]);content+=b'PASSWORD=somethingsecret'
        aid=self.reg('dns.cap',pcap([bytes(content)]))
        protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        output=json.dumps(protocolwork.protocol_flows(self.store.cases,self.cid,aid))
        self.assertNotIn('somethingsecret',output)
        self.assertNotIn('secret.local',output)

    def test_reject_offset_bool_and_oversized(self):
        aid=self.reg('simple.pcap',pcap(self.traffic()[:1]))
        protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        for offset in (-1,True,10001):
            with self.assertRaisesRegex(protocolwork.ProtocolError,'offset'):
                protocolwork.protocol_flows(self.store.cases,self.cid,aid,offset=offset)

    def test_empty_capture_partial_not_clean(self):
        aid=self.reg('empty.pcap',pcap([]))
        report=protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertEqual(report['status'],'PARTIAL')
        self.assertIn('capture_has_no_packets',report['limitations'])

    def test_snaplen_truncated_packet_partial(self):
        full=pcap(self.traffic()[:1])
        part=full[:24]+struct.pack('<IIII',1720000000,0,16,54)+full[40:56]
        aid=self.reg('snap.pcap',part)
        report=protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertEqual(report['status'],'PARTIAL')
        self.assertIn('capture_packet_truncated',report['limitations'])

    def test_short_dns_question_is_not_valid_dns(self):
        short=struct.pack('!HHHHHH',7,0,1,0,0,0)+b'\x07verybad'
        aid=self.reg('shortdns.pcap',pcap([ipv4(b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02',17,udp(45678,53,short))]))
        report=protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertIn('unparseable_dns_message',report['limitations'])

    def test_truncated_tls_record_not_client_hello(self):
        data=b'\x16\x03\x03\x00\x20\x01\x00'
        aid=self.reg('tlsfrag.pcap',pcap([ipv4(b'\x0a\x00\x00\x01',b'\x0a\x00\x00\x02',6,tcp(50505,443,data=data))]))
        report=protocolwork.analyze_capture(self.store.cases,self.cid,aid)
        self.assertNotIn('tls_client_hello',report['counters'])
        self.assertEqual(report['counters']['tls_record_fragment'],1)

    def test_registered_type_detect(self):
        self.assertEqual(casework.CaseStore._classify(pcapng([])[:260]),'pcapng')
        self.assertEqual(casework.CaseStore._classify(pcap([])[:260]),'pcap')

    def test_job_admission_remains_allowlist(self):
        aid=self.reg('approved.cap',pcap(self.traffic()))
        self.assertEqual(self.store.submit('decode_pcap',self.cid,artifact_id=aid)['status'],'QUEUED')
        with self.assertRaisesRegex(jobwork.JobError,'Unknown job'):
            self.store.submit('run_tshark_shell',self.cid,artifact_id=aid)

    def test_gateway_tool_registration(self):
        conf=gateway.Config(repos={},user_units=(),home=self.home)
        gw=gateway.Gateway(conf)
        names={x['name'] for x in gw.tools()}
        self.assertTrue({'pcap_flows','pcap_protocol_report','evtx_events','evtx_summary'}.issubset(names))
        self.assertIn('decode_pcap',next(x for x in gw.tools() if x['name']=='job_submit')['inputSchema']['properties']['kind']['enum'])


if __name__ == '__main__':unittest.main()
