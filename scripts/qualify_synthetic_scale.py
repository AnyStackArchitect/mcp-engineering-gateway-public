#!/usr/bin/env python3
"""Opt-in Linux synthetic scale profile; writes only a NEW output directory.

Not a benchmark SLA or vendor support assertion. Originals, indexes, searches,
hashes and process high-water RSS are retained for independent evidence review.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tests'))
from casework import CaseStore
import protocolwork
from test_packettruth_integration import frames
from test_protocolwork import ipv4, udp

PROFILES = {'log-small': 100_000, 'log-large': 1_000_000,
            'pcap': 200_000, 'pcapng': 200_000}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def make_log(path, lines):
    """192 bytes per record, three formats, one exact last-line needle."""
    with path.open('xb') as stream:
        for i in range(1, lines+1):
            marker = 'NEEDLELAST' if i == lines else 'normal-record'
            if i % 3 == 0:
                body = (f'{{"timestamp":"2026-10-24T12:00:00Z","record":{i},'
                        f'"message":"{marker}","password":"synthetic-private"}}')
            elif i % 3 == 1:
                body = f'2026-10-24T12:00:00Z record={i} {marker} password=synthetic-private'
            else:
                body = f'Oct 24 12:00:00 synthetic record={i} {marker} token=synthetic-private'
            stream.write(body.encode().ljust(191, b' ')+b'\n')


def block(kind, body):
    body += b'\0' * (-len(body) % 4)
    length = len(body)+12
    return struct.pack('<II', kind, length)+body+struct.pack('<I', length)


def make_capture(path, fmt, count):
    signal_frames = frames()
    noise = ipv4(b'\x0a\x01\x02\x03', b'\x0a\x01\x02\x04', 17,
                 udp(49000, 49001, b'synthetic-noise-'.ljust(512, b'x')))
    with path.open('xb') as stream:
        if fmt == 'pcap':
            stream.write(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1))
        else:
            stream.write(block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)))
            stream.write(block(1, struct.pack('<HHI', 1, 0, 65535)))
        for i in range(count):
            frame = signal_frames[i % 1000] if i % 1000 < 5 else noise
            # Independent synthetic transactions need independent TCP tuples.
            # Identical sequence bytes on one tuple are retransmissions to a
            # stateful reference decoder, not 200 separate SMB/TLS messages.
            cycle, position = divmod(i, 1000)
            if position in (2, 3, 4):
                frame = bytearray(frame)
                port = (50000 if position == 2 else 51000)+cycle
                offset = 34+(0 if position == 3 else 2)
                struct.pack_into('!H', frame, offset, port)
                frame = bytes(frame)
            sec, micro = 1720000000+i//1000, (i % 1000)*1000
            if fmt == 'pcap':
                stream.write(struct.pack('<IIII', sec, micro, len(frame), len(frame))+frame)
            else:
                stamp = sec*1_000_000+micro
                stream.write(block(6, struct.pack('<IIIII', 0, stamp >> 32,
                             stamp & 0xffffffff, len(frame), len(frame))+frame))


def measure(fn):
    start = time.monotonic()
    value = fn()
    return value, round(time.monotonic()-start, 6)


def run(profile, output):
    if os.geteuid() == 0:
        raise RuntimeError('Synthetic qualification refuses root')
    if not output.is_absolute():
        raise RuntimeError('Explicit absolute output required')
    for parent in output.parents:
        if parent.is_symlink():
            raise RuntimeError('Output symlink ancestor refused')
    if shutil.disk_usage(output.parent).free < 5*1024**3:
        raise RuntimeError('At least 5 GiB headroom required')
    output.mkdir(mode=0o700)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (768*1024**2, 768*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512*1024**2, 512*1024**2))
    result = {'profile': profile, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'uid': os.getuid(), 'python': sys.version, 'checks': {}, 'timings': {}}
    home = output/'home'
    home.mkdir(mode=0o700)
    store = CaseStore(home)
    cid = store.open_case()['case_id']
    n = PROFILES[profile]
    path = store.inbox/('mixed.txt' if profile.startswith('log') else 'mixed.'+profile)
    try:
        if profile.startswith('log'):
            _, elapsed = measure(lambda: make_log(path, n))
        else:
            _, elapsed = measure(lambda: make_capture(path, profile, n))
        result['timings']['generate_seconds'] = elapsed
        original_hash = digest(path)
        item, elapsed = measure(lambda: store.register(cid, path.name, worker=True))
        aid = item['artifact_id']
        result['artifact_id'] = aid
        result['case_id'] = cid
        result['input_bytes'] = path.stat().st_size
        result['input_sha256'] = original_hash
        result['timings']['register_seconds'] = elapsed
        checks = result['checks']
        if profile.startswith('log'):
            report, elapsed = measure(lambda: store.index_log(cid, aid, worker=True))
            result['timings']['index_seconds'] = elapsed
            search, elapsed = measure(lambda: store.search_log(cid, aid, 'NEEDLELAST'))
            result['timings']['last_line_search_seconds'] = elapsed
            common, elapsed = measure(lambda: store.search_log(cid, aid, 'record'))
            result['timings']['common_search_seconds'] = elapsed
            checks['all_lines_indexed'] = report['lines_indexed'] == n
            checks['exact_last_line_found'] = [m['line'] for m in search['matches']] == [n]
            checks['bounded_search_results'] = len(common['matches']) == 20 and common['has_more']
            checks['synthetic_secret_redacted'] = 'synthetic-private' not in json.dumps((search, common))
            result['analysis'] = report
            result['search'] = search
            result['common_search'] = common
        else:
            report, elapsed = measure(lambda: protocolwork.analyze_capture(store, cid, aid))
            result['timings']['decode_seconds'] = elapsed
            public = protocolwork.protocol_report(store, cid, aid)
            expected = {'packets_examined': n, 'dns_query': n//1000, 'dns_response': n//1000,
                        'dns_rcode_3': n//1000, 'smb2_access_denied': n//1000,
                        'tls_alert_40': n//1000, 'tcp_rst': n//1000}
            checks['known_counters'] = all(public['counters'].get(k) == v for k, v in expected.items())
            checks['bounded_report'] = len(json.dumps(report)) < protocolwork.MAX_REPORT
            checks['omission_explicit'] = public['status'] == 'PARTIAL' and public['counters']['observations_omitted'] > 0
            checks['no_capture_completeness_claim'] = not public['claim_boundaries']['capture_complete']
            checks['no_raw_payload_disclosure'] = 'synthetic-noise-' not in json.dumps(public)
            result['analysis'] = public
            result['expected_counters'] = expected
        retained = store.cases/cid/'originals'/aid
        checks['originals_unchanged'] = digest(retained) == original_hash == digest(path)
        result['retained_bytes'] = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        checks['per_profile_disk_budget'] = result['retained_bytes'] < 1024**3
        result['status'] = 'PASS' if all(checks.values()) else 'FAIL'
    except Exception as error:
        result.update(status='FAIL', error=type(error).__name__+': '+str(error))
    finally:
        result['peak_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (output/'RESULT.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.profile, args.output))
