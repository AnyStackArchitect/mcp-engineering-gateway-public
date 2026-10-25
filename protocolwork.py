#!/usr/bin/env python3
"""Bounded offline capture decoding, with sanitized endpoint identities.

No live capture, credential extraction, application-payload disclosure, packet
reassembly, or network access. Parsing failures never produce a false PASS.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import stat
import struct
from typing import Any, Iterator

from casework import CaseError, CaseStore, _regular_open, PCAP_MAGIC
from packettruth import DnsCandidateTracker, smb2_header
from streamwork import StreamTracker,MAX_STREAMS,MAX_BYTES as STREAM_BYTES,MAX_SEGMENTS,MAX_RANGES,MAX_PROVENANCE
from producerwork import record as producer_identity

MAX_FRAME = 1024 * 1024
MAX_BLOCK = 16 * 1024 * 1024
MAX_FRAMES = 300_000
MAX_FLOWS = 2_000
MAX_REPORT = 1024 * 1024
MAX_RESULTS = 20
MAX_OBSERVATIONS = 512
PACKET_SIGNALS = frozenset({
    'tcp_rst', 'tcp_syn', 'tcp_syn_ack', 'tcp_fin',
    'tcp_repeated_seq_candidate', 'dns_error', 'tls_alert', 'smb2_error',
    'capture_frame_truncated', 'tcp_forward_sequence_gap_candidate',
    'tcp_zero_window_advertised',
})
SUPPORTED_DLT = (1, 101, 113)


class ProtocolError(CaseError):
    """Sanitized error for structurally corrupt or unsupported captures."""


def _time(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec='microseconds')
    except (ValueError, OSError, OverflowError):
        return None


def _frames(fp, size: int, kind: str, cancelled=None) -> Iterator[tuple[int, bytes, str | None, bool]]:
    """Stream bounded Ethernet/raw/SLL frames from PCAP or PCAPNG."""
    if kind == 'pcap':
        header = fp.read(24)
        if len(header) != 24 or header[:4] not in PCAP_MAGIC:
            raise ProtocolError('Invalid PCAP file header')
        endian, precision = PCAP_MAGIC[header[:4]]
        major, minor, _, _, snaplen, dlt = struct.unpack(endian + 'HHIIII', header[4:24])
        if major != 2 or minor not in (4, 3) or not 0 < snaplen <= MAX_FRAME:
            raise ProtocolError('Unsupported PCAP header or snap length')
        for i in range(MAX_FRAMES + 1):
            if cancelled is not None and i % 256 == 0:
                cancelled()
            rec = fp.read(16)
            if not rec:
                return
            if len(rec) != 16:
                raise ProtocolError('Truncated PCAP record header')
            sec, frac, caplen, wirelen = struct.unpack(endian + 'IIII', rec)
            if frac >= (10**9 if precision == 'nanosecond' else 10**6):
                raise ProtocolError('PCAP timestamp fraction outside declared precision')
            if caplen > snaplen or caplen > wirelen or caplen > MAX_FRAME or caplen > size - fp.tell():
                raise ProtocolError('PCAP record size invalid or truncated')
            frame = fp.read(caplen)
            yield dlt & 0xffff, frame, _time(sec + frac / (10**9 if precision == 'nanosecond' else 10**6)), caplen < wirelen
        raise ProtocolError('PCAP packet count exceeds fixed analysis limit')

    if kind != 'pcapng':
        raise ProtocolError('Artifact is not a recognized packet capture')
    endian: str | None = None
    interfaces: list[tuple[int, float, int, int]] = []
    records = 0
    while fp.tell() < size:
        if cancelled is not None and records % 256 == 0:
            cancelled()
        start = fp.tell()
        header = fp.read(8)
        if len(header) != 8:
            raise ProtocolError('Truncated PCAPNG block header')
        rawtype, rawlen = header[:4], header[4:]
        if rawtype == b'\x0a\x0d\x0d\x0a':
            bom = fp.read(4)
            if bom == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise ProtocolError('PCAPNG byte-order marker invalid')
            blocklen = struct.unpack(endian + 'I', rawlen)[0]
            fp.seek(start + 8)
        elif endian is None:
            raise ProtocolError('PCAPNG requires initial section header')
        else:
            blocklen = struct.unpack(endian + 'I', rawlen)[0]
        if blocklen % 4 or blocklen < 12 or blocklen > MAX_BLOCK or blocklen > size - start:
            raise ProtocolError('PCAPNG block size invalid')
        body = fp.read(blocklen - 12)
        trailer = fp.read(4)
        if len(body) != blocklen - 12 or len(trailer) != 4 or struct.unpack(endian + 'I', trailer)[0] != blocklen:
            raise ProtocolError('PCAPNG truncated or mismatched block trailer')
        kindcode = struct.unpack(endian + 'I', rawtype)[0]
        if kindcode == 0x0A0D0D0A:
            if len(body) < 16 or struct.unpack(endian + 'I', body[:4])[0] != 0x1A2B3C4D:
                raise ProtocolError('PCAPNG section body invalid')
            interfaces = []
        elif kindcode == 1:
            if len(body) < 8:
                raise ProtocolError('PCAPNG interface block invalid')
            dlt = struct.unpack(endian + 'H', body[:2])[0]
            snaplen = struct.unpack(endian + 'I', body[4:8])[0]
            resolution, offset = 1e-6, 0
            options = body[8:]
            index = 0
            while index + 4 <= len(options):
                opt, length = struct.unpack(endian + 'HH', options[index:index + 4])
                index += 4
                if opt == 0:
                    break
                padded = (length + 3) & ~3
                if index + padded > len(options):
                    raise ProtocolError('Malformed PCAPNG interface option')
                value = options[index:index + length]
                if opt == 9 and length == 1:
                    n = value[0]
                    resolution = 2.0 ** -(n & 0x7f) if n & 0x80 else 10.0 ** -n
                elif opt == 14 and length == 8:
                    offset = struct.unpack(endian + 'q', value)[0]
                index += padded
            interfaces.append((dlt, resolution, offset, snaplen))
        elif kindcode == 6:
            if len(body) < 20:
                raise ProtocolError('PCAPNG enhanced packet block invalid')
            iface, high, low, captured, wire = struct.unpack(endian + 'IIIII', body[:20])
            if iface >= len(interfaces) or captured > wire or captured > MAX_FRAME or captured > len(body) - 20:
                raise ProtocolError('PCAPNG enhanced packet length/interface invalid')
            dlt, precision, offset, snaplen = interfaces[iface]
            if snaplen and captured > snaplen:
                raise ProtocolError('PCAPNG captured packet exceeds declared snap length')
            ts = _time(((high << 32) | low) * precision + offset)
            records += 1
            if records > MAX_FRAMES:
                raise ProtocolError('PCAPNG packet count exceeds fixed analysis limit')
            yield dlt, body[20:20 + captured], ts, captured < wire
        elif kindcode == 3:  # simple packet block has no timestamp
            if len(body) < 4 or not interfaces:
                raise ProtocolError('PCAPNG simple packet block invalid')
            wire = struct.unpack(endian + 'I', body[:4])[0]
            snaplen = interfaces[0][3]
            captured = min(wire, snaplen) if snaplen else wire
            if len(body) - 4 != ((captured + 3) & ~3):
                raise ProtocolError('PCAPNG simple packet length/padding invalid')
            if captured > MAX_FRAME:
                raise ProtocolError('PCAPNG simple packet exceeds frame limit')
            records += 1
            if records > MAX_FRAMES:
                raise ProtocolError('PCAPNG packet count exceeds fixed analysis limit')
            yield interfaces[0][0], body[4:4 + captured], None, captured < wire


def _ip_payload(dlt: int, frame: bytes) -> tuple[bytes, bytes, int, bytes] | None:
    if dlt == 1:
        if len(frame) < 14:
            return None
        kind = int.from_bytes(frame[12:14], 'big')
        p = 14
        for _ in range(2):
            if kind not in (0x8100, 0x88a8):
                break
            if len(frame) < p + 4:
                return None
            kind = int.from_bytes(frame[p+2:p+4], 'big')
            p += 4
        payload = frame[p:]
    elif dlt == 113:  # Linux cooked capture v1
        if len(frame) < 16:
            return None
        kind = int.from_bytes(frame[14:16], 'big')
        payload = frame[16:]
    elif dlt == 101:  # raw IP
        if not frame:
            return None
        kind = 0x0800 if frame[0] >> 4 == 4 else 0x86dd if frame[0] >> 4 == 6 else 0
        payload = frame
    else:
        return None
    if kind == 0x0800:
        if len(payload) < 20 or payload[0] >> 4 != 4:
            return None
        hlen = (payload[0] & 0x0f) * 4
        total = int.from_bytes(payload[2:4], 'big')
        if hlen < 20 or total < hlen or len(payload) < hlen:
            return None
        fragment = int.from_bytes(payload[6:8], 'big')
        if fragment & 0x3fff or len(payload) < total:
            return payload[12:16], payload[16:20], -1, b''
        return payload[12:16], payload[16:20], payload[9], payload[hlen:min(total, len(payload))]
    if kind == 0x86dd:
        if len(payload) < 40 or payload[0] >> 4 != 6:
            return None
        protocol = payload[6]
        length = int.from_bytes(payload[4:6], 'big')
        data = payload[40:40 + length]
        if protocol in (0, 43, 44, 50, 51, 60) or len(data) < length:
            return payload[8:24], payload[24:40], -1, b''
        return payload[8:24], payload[24:40], protocol, data
    return None


def _dns(packet: bytes) -> tuple[str, str] | None:
    if len(packet) < 12:
        return None
    flags = int.from_bytes(packet[2:4], 'big')
    qd = int.from_bytes(packet[4:6], 'big')
    if qd > 50 or flags & 0x7800:  # unsupported DNS opcode
        return None
    if qd:  # require a bounded, syntactically present first DNS question
        pos = 12
        for _ in range(128):
            if pos >= len(packet):
                return None
            label = packet[pos]
            if label == 0:
                pos += 1
                break
            if label & 0xc0 == 0xc0:
                if pos + 1 >= len(packet):
                    return None
                pos += 2
                break
            if label > 63 or pos + 1 + label > len(packet):
                return None
            pos += 1 + label
        else:
            return None
        if pos + 4 > len(packet):
            return None
    role = 'response' if flags & 0x8000 else 'query'
    return role, ('rcode_' + str(flags & 0xf)) if role == 'response' else 'query'


def _tls(payload: bytes) -> tuple[str, int | None] | None:
    if len(payload) < 5:
        return None
    typ, major, minor = payload[0], payload[1], payload[2]
    if typ not in (20, 21, 22, 23) or major != 3 or minor > 4:
        return None
    recordlen = int.from_bytes(payload[3:5], 'big')
    if recordlen > 18432:
        return None
    if len(payload) < recordlen + 5:
        return 'record_fragment', None
    if typ == 21 and len(payload) >= 7:
        return 'alert', payload[6]
    if typ == 22 and len(payload) >= 6:
        return {1:'client_hello',2:'server_hello',11:'certificate',20:'finished'}.get(payload[5], 'handshake_other'), payload[5]
    return ('application_data' if typ == 23 else 'change_cipher_spec' if typ == 20 else 'handshake_partial'), None


def _write_report(path: Path, doc: dict[str, Any]) -> None:
    data = json.dumps(doc, ensure_ascii=True, separators=(',', ':')).encode()
    if len(data) > MAX_REPORT:
        raise ProtocolError('Capture report exceeds bounded storage limit')
    tmp = path.parent / ('.tmp-pcap-' + secrets.token_hex(12))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            fd = -1
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)


def _checked_report(store: CaseStore, case_id: str, artifact_id: str) -> dict[str, Any]:
    with store._locked(case_id) as (folder, manifest):
        source, item = store._artifact(folder, manifest, artifact_id)
        if item['type'] not in ('pcap','pcapng'):
            raise ProtocolError('Capture artifact required')
        path = folder / 'indexes' / ('protocol-' + artifact_id + '.json')
        if path.is_symlink():
            raise ProtocolError('Capture report symlink refused')
        try:
            sinfo = source.lstat()
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > MAX_REPORT):
                raise ProtocolError('Capture report permissions or size invalid')
            fd, _ = _regular_open(path)
            with os.fdopen(fd, 'rb') as stream:
                report = json.loads(stream.read(MAX_REPORT + 1))
            facts = report.get('source')
            if (not isinstance(facts, dict) or facts.get('sha256') != item['sha256'] or
                    facts.get('mtime_ns') != sinfo.st_mtime_ns or facts.get('device') != sinfo.st_dev or
                    facts.get('inode') != sinfo.st_ino or facts.get('bytes') != sinfo.st_size):
                raise ProtocolError('Capture report is stale; rerun protocol analysis')
            return report
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ProtocolError('Capture report unreadable or invalid') from exc


def analyze_capture(store: CaseStore, case_id: str, artifact_id: str, *, should_cancel=None) -> dict[str, Any]:
    with store._locked(case_id) as (folder, manifest):
        source, item = store._artifact(folder, manifest, artifact_id)
        if item['type'] not in ('pcap','pcapng'):
            raise ProtocolError('Capture artifact required')
        if item['bytes'] > 8 * 1024**3:
            raise ProtocolError('Capture exceeds worker limit')
        dest = folder / 'indexes' / ('protocol-' + artifact_id + '.json')
        if dest.is_symlink():
            raise ProtocolError('Capture report symlink refused')
        fd, pre = _regular_open(source)
        if pre.st_nlink != 1:
            os.close(fd)
            raise ProtocolError('Capture original must not be hardlinked')
        digest = hashlib.sha256()
        counters = Counter()
        flow_packets: dict[tuple[bytes,int,bytes,int,int], dict[str, Any]] = {}
        endpoints: dict[bytes, str] = {}
        seen_tcp: set[tuple[bytes,int,bytes,int,int,int]] = set()
        next_tcp: dict[tuple[bytes,int,bytes,int,int], int] = {}
        earliest: str | None = None
        latest: str | None = None
        partial: set[str] = set()
        observations: list[dict[str, Any]] = []
        dns_candidates = DnsCandidateTracker()
        tcp_streams=StreamTracker()
        flow_ref: str | None = None
        def mark(signal: str, packet_no: int, utc: str | None) -> None:
            # Only fixed signal labels, never packet payloads or identifying names.
            if len(observations) < MAX_OBSERVATIONS:
                observations.append({'packet_no': packet_no, 'utc': utc, 'signal': signal,
                                     'flow_id': flow_ref})
            else:
                counters['observations_omitted'] += 1
                partial.add('diagnostic_observations_truncated')
        try:
            with os.fdopen(fd, 'rb') as f:
                fd = -1
                for chunk in iter(lambda: f.read(1024*1024), b''):
                    if should_cancel is not None:
                        should_cancel()
                    digest.update(chunk)
                if digest.hexdigest() != item['sha256']:
                    raise ProtocolError('Capture source changed since registration')
                f.seek(0)
                for i, (dlt, frame, stamp, snap_truncated) in enumerate(_frames(f, pre.st_size, item['type'], should_cancel), 1):
                    flow_ref = None
                    counters['packets_examined'] += 1
                    if snap_truncated:
                        counters['snaplen_truncated_packets'] += 1
                        partial.add('capture_packet_truncated')
                        mark('capture_frame_truncated', i, stamp)
                    if stamp is None:
                        counters['packets_without_timestamp'] += 1
                        partial.add('packet_timestamp_unavailable')
                    else:
                        earliest = min(earliest, stamp) if earliest else stamp
                        latest = max(latest, stamp) if latest else stamp
                    if dlt not in SUPPORTED_DLT:
                        counters['unsupported_link_type'] += 1
                        partial.add('unsupported_datalink')
                        continue
                    packet = _ip_payload(dlt, frame)
                    if packet is None:
                        counters['unparsed_l2_or_l3'] += 1
                        partial.add('unsupported_or_truncated_network_frame')
                        continue
                    src, dst, proto, data = packet
                    if proto not in (6,17):
                        counters['unsupported_transport'] += 1
                        partial.add('unsupported_or_fragmented_transport')
                        continue
                    if len(data) < (20 if proto == 6 else 8):
                        counters['truncated_transport'] += 1
                        partial.add('truncated_transport')
                        continue
                    src_port, dst_port = struct.unpack('!HH', data[:4])
                    key = (src, src_port, dst, dst_port, proto)
                    if key not in flow_packets:
                        if len(flow_packets) >= MAX_FLOWS:
                            counters['flows_omitted'] += 1
                            partial.add('flow_limit')
                            continue
                        if src not in endpoints:
                            endpoints[src] = 'host-' + str(len(endpoints) + 1)
                        if dst not in endpoints:
                            endpoints[dst] = 'host-' + str(len(endpoints) + 1)
                        flow_packets[key] = {'flow_id': 'flow-' + str(len(flow_packets) + 1),
                                             'source': endpoints[src], 'destination': endpoints[dst],
                                             'source_port': src_port, 'destination_port': dst_port,
                                             'transport': 'TCP' if proto == 6 else 'UDP',
                                             'packets': 0, 'capture_bytes': 0,
                                             'first_utc': stamp, 'last_utc': stamp, 'tcp_resend_candidates': 0}
                    flow = flow_packets[key]
                    flow_ref = flow['flow_id']
                    flow['packets'] += 1
                    flow['capture_bytes'] += len(frame)
                    if stamp is not None:
                        flow['first_utc'] = min(flow['first_utc'], stamp) if flow['first_utc'] else stamp
                        flow['last_utc'] = max(flow['last_utc'], stamp) if flow['last_utc'] else stamp
                    counters['decoded_transport_packets'] += 1
                    if proto == 6:
                        offset = (data[12] >> 4) * 4
                        if offset < 20 or len(data) < offset:
                            partial.add('truncated_tcp_header')
                            counters['malformed_tcp'] += 1
                            continue
                        flags = data[13]
                        for mask,label in ((0x02,'tcp_syn'),(0x10,'tcp_ack'),(0x04,'tcp_rst'),(0x01,'tcp_fin')):
                            if flags & mask:
                                counters[label] += 1
                        if flags & 0x04:
                            mark('tcp_rst', i, stamp)
                        if flags & 0x02:
                            mark('tcp_syn_ack' if flags & 0x10 else 'tcp_syn', i, stamp)
                        if flags & 0x01:
                            mark('tcp_fin', i, stamp)
                        seg = data[offset:]
                        seq = int.from_bytes(data[4:8], 'big')
                        tcp_streams.observe(flow_ref,seq,flags,seg,i,snap_truncated)
                        if (flags & 0x10 and not flags & (0x02 | 0x04 | 0x01)
                                and data[14:16] == b'\0\0'):
                            counters['tcp_zero_window_advertised'] += 1
                            mark('tcp_zero_window_advertised', i, stamp)
                        advance = len(seg) + int(bool(flags & 0x02)) + int(bool(flags & 0x01))
                        if advance:
                            end = (seq + advance) & 0xffffffff
                            expected = next_tcp.get(key)
                            # SYN can indicate a new use of the same capture-local
                            # tuple. Do not bridge its sequence space to old traffic.
                            if expected is None or flags & 0x02:
                                next_tcp[key] = end
                            else:
                                distance = (seq - expected) & 0xffffffff
                                if 0 < distance < 0x80000000:
                                    counters['tcp_forward_sequence_gap_candidates'] += 1
                                    partial.add('tcp_sequence_gap_without_stream_reassembly')
                                    mark('tcp_forward_sequence_gap_candidate', i, stamp)
                                if ((end - expected) & 0xffffffff) < 0x80000000:
                                    next_tcp[key] = end
                        seg_id = (src, src_port, dst, dst_port, seq, len(seg) + int(bool(flags & 0x02)))
                        if seg_id in seen_tcp and (seg or flags & 0x02):
                            counters['tcp_retransmit_candidates'] += 1
                            flow['tcp_resend_candidates'] += 1
                            mark('tcp_repeated_seq_candidate', i, stamp)
                        if len(seen_tcp) < 100_000:
                            seen_tcp.add(seg_id)
                        elif 'sequence_memory_limit' not in partial:
                            partial.add('sequence_memory_limit')
                        tls = _tls(seg)
                        if tls:
                            counters['tls_' + tls[0]] += 1
                            if tls[0] == 'alert':
                                counters['tls_alert_' + str(tls[1])] += 1
                                mark('tls_alert', i, stamp)
                            elif tls[0] == 'record_fragment':
                                # Normal TCP segmentation is expected; no
                                # stream reassembly is performed in this mode.
                                partial.add('tls_record_crosses_packet_boundary')
                        if src_port == 445 or dst_port == 445:
                            smb = smb2_header(seg)
                            if smb is not None:
                                counters['smb2_contiguous_header'] += 1
                                counters['smb2_' + smb['status_label']] += 1
                                if smb['error']:
                                    counters['smb2_response_error'] += 1
                                    mark('smb2_error', i, stamp)
                                if not smb['message_complete_in_segment']:
                                    partial.add('smb2_message_fragmented_no_reassembly')
                            elif len(seg) >= 8 and seg[0] == 0 and seg[4:8] == b'\xfeSMB':
                                # Recognized SMB2 prefix but no complete
                                # 64-byte contiguous header.
                                counters['smb2_incomplete_header_candidate'] += 1
                                partial.add('smb2_header_fragment_no_reassembly')
                    else:
                        udplen = int.from_bytes(data[4:6], 'big')
                        if udplen < 8 or udplen > len(data):
                            counters['malformed_udp'] += 1
                            partial.add('truncated_udp_payload')
                            continue
                        if src_port == 53 or dst_port == 53:
                            dns = _dns(data[8:udplen])
                            if dns:
                                counters['dns_' + dns[0]] += 1
                                dns_candidates.observe(src,src_port,dst,dst_port,
                                                       data[8:udplen],dns[0])
                                if dns[0] == 'response':
                                    counters['dns_' + dns[1]] += 1
                                    if dns[1] != 'rcode_0':
                                        mark('dns_error', i, stamp)
                            else:
                                counters['dns_unparseable'] += 1
                                partial.add('unparseable_dns_message')
        finally:
            if fd >= 0:
                os.close(fd)
        dns_counts = dns_candidates.summary()
        for key, value in dns_counts.items():
            if value:
                counters[key] = int(value)
        if dns_counts['dns_pending_tracker_overflow']:
            partial.add('dns_transaction_candidate_memory_limit')
        post = source.lstat()
        if (post.st_ino != pre.st_ino or post.st_dev != pre.st_dev or
                post.st_size != pre.st_size or post.st_mtime_ns != pre.st_mtime_ns):
            raise ProtocolError('Capture source changed during analysis')
        if not counters['packets_examined']:
            partial.add('capture_has_no_packets')
        flows = sorted(flow_packets.values(), key=lambda x: (-x['packets'], x['source'], x['source_port']))
        facts = {'sha256': item['sha256'], 'bytes': pre.st_size, 'device': pre.st_dev,
                 'inode': pre.st_ino, 'mtime_ns': pre.st_mtime_ns}
        report = {'case_id': case_id, 'artifact_id': artifact_id, 'source': facts,
                  'producer_identity': producer_identity('protocolwork','packettruth','casework','streamwork'),
                  'status': 'PARTIAL' if partial else 'PASS',
                  'first_utc': earliest, 'last_utc': latest,
                  'counters': dict(counters), 'limitations': sorted(partial),
                  'flows': flows,
                  'tcp_reconstruction': tcp_streams.summary(),
                  'observations': observations,
                  'observations_omitted': counters['observations_omitted'],
                  'observations_policy': 'Selected packet-level diagnostic signals only; not complete capture decoding',
                  'disclosure': 'IP addresses, packet payloads, DNS names and TLS SNI intentionally suppressed',
                  'interpretation': 'TCP sequence repeats and DNS tuple/ID matches are candidates, not proven delivery, loss, transaction identity or causality; SMB2 is packet-local only; no TCP stream reassembly',
                  'claim_boundaries': {
                      'clock_alignment_verified': False,
                      'capture_complete': False,
                      'tcp_retransmission_proven': False,
                      'dns_transaction_identity_proven': False,
                      'tcp_stream_reassembled': False,
                      'smb2_session_complete': False,
                      'tls_decrypted': False,
                      'packet_loss_proven': False,
                  }}
        if should_cancel is not None:
            should_cancel()
        _write_report(dest, report)
        return {'status': report['status'], 'case_id': case_id, 'artifact_id': artifact_id,
                'packets_examined': counters['packets_examined'], 'flows': len(flows),
                'counters': {k:v for k,v in counters.items() if k.startswith(('tcp_','dns_','tls_'))},
                'limitations': sorted(partial),
                'note': 'Use pcap_protocol_report and pcap_flows for source-linked sanitized details'}


def protocol_report(store: CaseStore, case_id: str, artifact_id: str) -> dict[str, Any]:
    doc = _checked_report(store, case_id, artifact_id)
    return {'case_id': case_id, 'artifact_id': artifact_id, 'status': doc['status'],
            'sha256': doc['source']['sha256'], 'first_utc': doc['first_utc'], 'last_utc': doc['last_utc'],
            'packets_examined': doc['counters'].get('packets_examined',0),
            'flow_count': len(doc['flows']), 'counters': doc['counters'],
            'diagnostic_observations': len(doc.get('observations', [])),
            'observations_omitted': doc.get('observations_omitted', 0),
            'capture_quality': {
                'snaplen_truncated_frames': doc['counters'].get('snaplen_truncated_packets', 0),
                'frames_without_timestamp': doc['counters'].get('packets_without_timestamp', 0),
                'unsupported_datalink_frames': doc['counters'].get('unsupported_link_type', 0),
                'sequence_tracking_limited': 'sequence_memory_limit' in doc['limitations'],
                'capture_completeness': 'UNVERIFIED',
                'packet_loss': 'NOT_DETERMINABLE_FROM_CAPTURE_ALONE'},
            'limitations': doc['limitations'], 'disclosure': doc['disclosure'],
            'interpretation': doc['interpretation'],
            'claim_boundaries': doc.get('claim_boundaries', {
                'clock_alignment_verified':False,'capture_complete':False,
                'tcp_retransmission_proven':False,'dns_transaction_identity_proven':False,
                'tcp_stream_reassembled':False,'smb2_session_complete':False,
                'tls_decrypted':False})}


def protocol_observations(store: CaseStore, case_id: str, artifact_id: str, *,
                          offset: int = 0) -> dict[str, Any]:
    if type(offset) is not int or not 0 <= offset < MAX_OBSERVATIONS:
        raise ProtocolError('Invalid packet observation offset')
    doc = _checked_report(store, case_id, artifact_id)
    observations = doc.get('observations', [])
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise ProtocolError('Packet observation inventory invalid')
    visible = []
    for row in observations[offset:offset + MAX_RESULTS]:
        if (not isinstance(row, dict) or row.get('signal') not in PACKET_SIGNALS or
                type(row.get('packet_no')) is not int or not 1 <= row['packet_no'] <= MAX_FRAMES):
            raise ProtocolError('Packet observation identity invalid')
        flow = row.get('flow_id')
        if flow is not None:
            if (type(flow) is not str or not 6 <= len(flow) <= 9 or not flow.startswith('flow-') or
                    not flow[5:].isdigit() or not 1 <= int(flow[5:]) <= MAX_FLOWS or
                    flow != 'flow-' + str(int(flow[5:]))):
                raise ProtocolError('Packet observation flow reference invalid')
        utc = row.get('utc')
        if utc is not None:
            try:
                parsed = datetime.fromisoformat(utc)
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise ValueError('Unanchored time')
                utc = parsed.astimezone(timezone.utc).isoformat(timespec='microseconds')
            except (TypeError, ValueError, OverflowError) as exc:
                raise ProtocolError('Packet observation timestamp invalid') from exc
        visible.append({'artifact_id': artifact_id, 'locator_type': 'packet',
            'packet_no': row['packet_no'], 'signal': row['signal'],
            'utc': utc, 'flow_id': flow})
    omitted = doc.get('observations_omitted', 0)
    if type(omitted) is not int or not 0 <= omitted <= MAX_FRAMES * len(PACKET_SIGNALS):
        raise ProtocolError('Packet observation coverage invalid')
    return {'case_id': case_id, 'artifact_id': artifact_id,
            'status': 'PASS' if doc.get('status') == 'PASS' and not omitted else 'PARTIAL',
            'total_sampled_observations': len(observations), 'observations_omitted': omitted,
            'offset': offset, 'observations': visible,
            'next_offset': offset + MAX_RESULTS if offset + MAX_RESULTS < len(observations) else None,
            'has_more': offset + MAX_RESULTS < len(observations),
            'source_sha256': doc['source']['sha256'], 'flow_references_are_capture_local': True,
            'complete_capture_verified': False, 'packet_loss_proven': False,
            'tcp_stream_reassembled': False, 'clock_alignment_verified': False,
            'coverage': 'BOUNDED_PACKET_SIGNAL_SAMPLE', 'root_cause_established': False}


def protocol_flows(store: CaseStore, case_id: str, artifact_id: str, *, offset: int = 0) -> dict[str, Any]:
    if type(offset) is not int or not 0 <= offset <= 10000:
        raise ProtocolError('Invalid flow offset')
    doc = _checked_report(store, case_id, artifact_id)
    return {'case_id': case_id, 'artifact_id': artifact_id, 'status': doc['status'],
            'total_flows': len(doc['flows']), 'offset': offset,
            'flows': doc['flows'][offset:offset+MAX_RESULTS],
            'has_more': len(doc['flows']) > offset + MAX_RESULTS,
            'aliases_are_capture_local': True}


def protocol_stream_coverage(store,case_id,artifact_id,*,offset=0):
    if type(offset) is not int or not 0<=offset<MAX_STREAMS:raise ProtocolError('Invalid reconstruction offset')
    doc=_checked_report(store,case_id,artifact_id)
    source=doc.get('tcp_reconstruction')
    if source is None:return {'status':'NOT_AVAILABLE','reason':'rebuild_capture_for_bounded_reconstruction'}
    if (type(source) is not dict or type(source.get('schema')) is not int or source['schema']!=1 or
            type(source.get('streams')) is not list or len(source['streams'])>MAX_STREAMS or
            type(source.get('omitted_segments')) is not int or not 0<=source['omitted_segments']<=MAX_FRAMES):
        raise ProtocolError('Invalid reconstruction inventory')
    visible=[]
    for row in source['streams']:
        fields={'flow_id','epoch','first_frame','last_frame','captured_syn','captured_fin','fin_frame','fin_relative_end',
            'observed_extent_bytes','unique_payload_bytes','segments_examined','overlap_byte_observations','conflicting_byte_observations',
            'truncated_frames','limits','observed_ranges','observed_ranges_omitted','unobserved_ranges','unobserved_ranges_omitted',
            'contributing_frames','contributing_frames_omitted','contiguous_observed_range_reconstructed','syn_to_fin_payload_covered','private_contiguous_sha256'}
        if type(row) is not dict or set(row)!=fields:raise ProtocolError('Invalid reconstruction fields')
        if type(row['flow_id']) is not str or not re.fullmatch(r'flow-[1-9][0-9]{0,3}',row['flow_id']) or row['flow_id'] not in {f['flow_id'] for f in doc['flows']}:
            raise ProtocolError('Invalid reconstruction flow')
        numbers={'epoch':MAX_STREAMS,'first_frame':MAX_FRAMES,'last_frame':MAX_FRAMES,'observed_extent_bytes':STREAM_BYTES,
            'unique_payload_bytes':STREAM_BYTES,'segments_examined':MAX_FRAMES,'overlap_byte_observations':MAX_SEGMENTS*STREAM_BYTES,
            'conflicting_byte_observations':MAX_SEGMENTS*STREAM_BYTES,'truncated_frames':MAX_FRAMES,
            'observed_ranges_omitted':STREAM_BYTES,'unobserved_ranges_omitted':STREAM_BYTES,'contributing_frames_omitted':MAX_SEGMENTS}
        if any(type(row[k]) is not int or not 0<=row[k]<=maximum for k,maximum in numbers.items()):raise ProtocolError('Invalid reconstruction counts')
        if (not 1<=row['epoch'] or not 1<=row['first_frame']<=row['last_frame']<=doc['counters']['packets_examined'] or
                row['unique_payload_bytes']>row['observed_extent_bytes'] or row['conflicting_byte_observations']>row['overlap_byte_observations']):
            raise ProtocolError('Contradictory reconstruction counts')
        for key in ('captured_syn','captured_fin','contiguous_observed_range_reconstructed','syn_to_fin_payload_covered'):
            if type(row[key]) is not bool:raise ProtocolError('Invalid reconstruction claim')
        if row['captured_fin']:
            if (type(row['fin_frame']) is not int or not row['first_frame']<=row['fin_frame']<=row['last_frame'] or
                    type(row['fin_relative_end']) is not int or not 0<=row['fin_relative_end']<=STREAM_BYTES):raise ProtocolError('Invalid FIN evidence')
        elif row['fin_frame'] is not None or row['fin_relative_end'] is not None:raise ProtocolError('Unexpected FIN evidence')
        allowed_limits={'segment_budget','sequence_outside_window','byte_window_budget','conflicting_fin','later_epoch_omitted'}
        if type(row['limits']) is not list or any(type(v) is not str or v not in allowed_limits for v in row['limits']) or len(row['limits'])!=len(set(row['limits'])):
            raise ProtocolError('Invalid reconstruction limits')
        for key in ('observed_ranges','unobserved_ranges'):
            ranges=row[key]
            if type(ranges) is not list or len(ranges)>MAX_RANGES:raise ProtocolError('Invalid reconstruction range budget')
            end=-1
            for span in ranges:
                if type(span) is not dict or set(span)!={'start','end'} or any(type(span[k]) is not int for k in span) or not 0<=span['start']<span['end']<=row['observed_extent_bytes'] or span['start']<=end:
                    raise ProtocolError('Invalid reconstruction range')
                end=span['end']
        present_total=sum(s['end']-s['start'] for s in row['observed_ranges'])
        missing_total=sum(s['end']-s['start'] for s in row['unobserved_ranges'])
        if present_total>row['unique_payload_bytes'] or missing_total>row['observed_extent_bytes']-row['unique_payload_bytes']:
            raise ProtocolError('Reconstruction range counts conflict')
        if not row['observed_ranges_omitted'] and not row['unobserved_ranges_omitted']:
            cursor=0
            for span in sorted(row['observed_ranges']+row['unobserved_ranges'],key=lambda s:s['start']):
                if span['start']!=cursor:raise ProtocolError('Reconstruction ranges overlap or omit bytes')
                cursor=span['end']
            if cursor!=row['observed_extent_bytes'] or present_total!=row['unique_payload_bytes']:
                raise ProtocolError('Reconstruction ranges lack coverage')
        frames=row['contributing_frames']
        if (type(frames) is not list or len(frames)>MAX_PROVENANCE or any(type(v) is not int or not row['first_frame']<=v<=row['last_frame'] for v in frames) or frames!=sorted(set(frames))):
            raise ProtocolError('Invalid reconstruction source frames')
        reconstructed=bool(row['observed_extent_bytes']) and row['unique_payload_bytes']==row['observed_extent_bytes'] and not row['conflicting_byte_observations'] and not row['limits'] and not row['truncated_frames']
        if (row['contiguous_observed_range_reconstructed']!=reconstructed or
                row['syn_to_fin_payload_covered']!=(reconstructed and row['captured_syn'] and row['fin_relative_end']==row['observed_extent_bytes'])):
            raise ProtocolError('Reconstruction overstates coverage')
        sha=row['private_contiguous_sha256']
        if (sha is not None and (type(sha) is not str or not re.fullmatch('[a-f0-9]{64}',sha))) or (sha is not None)!=reconstructed:
            raise ProtocolError('Invalid private reconstruction identity')
        visible.append({k:v for k,v in row.items() if k!='private_contiguous_sha256'})
    return {'status':'PARTIAL','case_id':case_id,'artifact_id':artifact_id,'source_sha256':doc['source']['sha256'],
        'streams':visible[offset:offset+1],'total_streams':len(visible),'offset':offset,
        'next_offset':offset+1 if offset+1<len(visible) else None,'omitted_segments':source['omitted_segments'],
        'whole_capture_truncated_frames':doc['counters'].get('snaplen_truncated_packets',0),
        'byte_policy':'FIRST_CAPTURED_BYTE; conflicts are ambiguous; no endpoint overlap policy inferred',
        'range_offsets_are_relative_to_observed_sequence_base':True,
        'coverage':'BOUNDED_CAPTURE_LOCAL_RECONSTRUCTION','raw_payload_or_payload_hash_returned':False,
        'packet_loss_proven':False,'endpoint_delivery_proven':False,'capture_complete':False,'root_cause_established':False}
