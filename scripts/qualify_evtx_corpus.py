#!/usr/bin/env python3
"""Compare real Linux case indexes with independently decoded Windows metadata.

Only pinned public upstream fixtures. Never print raw rows, XML or identities.
Golden digests came from Get-WinEvent file decoding; CI repeats both decoders.
"""
from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualify_real_evtx import _call, _worker

FIXTURES = (
    ('security.evtx', 2166784,
     '5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d', 2261,
     'afaa400724a0f24f1d1d6f59e641b980150063025c44dc62910fd53befa3dc3c', 583),
    ('system.evtx', 1118208,
     'ccb83cfefc9038017224cd97b800b66e248fe14529649ddf47907e5a2021449e', 1601,
     '12c1e80dc2b1c8f1c4c91b6789892c7f0659c1f341640171f122a2c1b2b8229a', 0),
)
UPSTREAM = 'https://raw.githubusercontent.com/williballenthin/python-evtx/c0007441657899c39180de10a2be1a0e43dbeaf9/tests/data/'


def compare_reference(rows, reference):
    normalized = []
    times = []
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    ordered = sorted(rows, key=lambda row: row[0])
    if len({row[0] for row in ordered}) != len(ordered):
        raise RuntimeError('Duplicate corpus record reference')
    for record, event_id, utc, channel, provider in ordered:
        if utc:
            delta = datetime.fromisoformat(utc) - epoch
            millis = (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
        else:
            raise RuntimeError('Native public corpus unexpectedly missing UTC')
        normalized.append(f'{record}|{event_id}|{channel or ""}|{provider or ""}')
        times.append(millis)
    digest = hashlib.sha256(('\n'.join(normalized) + '\n').encode()).hexdigest()
    if digest != reference['identity_sha256']:
        raise RuntimeError('Linux event identity contradicts native Windows file decoder')
    decoder = zlib.decompressobj()
    data = decoder.decompress(base64.b64decode(reference['utc_zlib_base64'], validate=True), 128 * 1024)
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise RuntimeError('Invalid bounded native timestamp reference')
    native = json.loads(data)
    if len(native) != len(times) or any(type(t) is not int for t in native):
        raise RuntimeError('Native timestamp inventory mismatch')
    deltas = [a-b for a,b in zip(times,native)]
    if any(abs(delta) > 1 for delta in deltas):
        raise RuntimeError('Linux event timestamp exceeds one-millisecond decoder tolerance')
    return sum(delta != 0 for delta in deltas)


def main():
    if os.geteuid() == 0 or version('python-evtx') != '0.8.1':
        raise RuntimeError('Run unprivileged with the hash-pinned real EVTX provider')
    references = json.loads((ROOT/'scripts/evtx_native_reference.json').read_text())['fixtures']
    with tempfile.TemporaryDirectory(prefix='public-evtx-corpus-') as directory:
        folder = Path(directory)
        home = folder / 'home'
        home.mkdir()
        cid = _call(home, 'case_open', {})['case_id']
        inbox = home / '.local/share/rocky-mcp-gateway/inbox'
        total = 0
        for name, size, digest, count, native_digest, success_count in FIXTURES:
            staged = inbox / name
            if len(sys.argv) == 2:
                shutil.copyfile(Path(sys.argv[1]) / name, staged)
            elif len(sys.argv) == 1:
                with urllib.request.urlopen(UPSTREAM + name, timeout=35) as response:
                    data = response.read(size + 1)
                staged.write_bytes(data)
            else:
                raise RuntimeError('Expected zero arguments or pinned fixture directory')
            if staged.stat().st_size != size or hashlib.sha256(staged.read_bytes()).hexdigest() != digest:
                raise RuntimeError('Public EVTX source integrity mismatch')
            staged.chmod(0o600)
            aid = _call(home, 'artifact_register', {'case_id': cid, 'filename': name})['artifact_id']
            result = _worker(home, cid, 'analyze_evtx', aid)
            if (result['records_examined'] != count or result['records_skipped'] or
                    result['records_without_utc'] or result['status'] != 'PASS'):
                raise RuntimeError('Real corpus parser coverage mismatch')
            db_path = home / '.local/share/rocky-mcp-gateway/cases' / cid / 'indexes' / ('evtx-' + aid + '.sqlite3')
            with sqlite3.connect(db_path) as db:
                rows = db.execute('SELECT record_num,event_id,utc,channel,provider FROM records').fetchall()
            reference = next(r for r in references if r['fixture'] == name)
            if len(rows) != count or reference['native_metadata_sha256'] != native_digest:
                raise RuntimeError('Native reference identity mismatch')
            timestamp_differences = compare_reference(rows, reference)
            report = _call(home, 'windows_rule_report', {'case_id': cid, 'artifact_id': aid})
            observed = {r['id']: r['matches'] for r in report['rules']}
            if (report['pack_version'] != '1.1.0' or report['status'] != 'PARTIAL' or
                    observed != {'WIN-LOGON-FAILURE': 0, 'WIN-AUDIT-CLEARED': 0,
                                 'WIN-SERVICE-TERMINATION': 0, 'WIN-LOGON-SUCCESS': success_count}):
                raise RuntimeError('Real corpus fixed-rule known answer mismatch')
            if success_count:
                locators = []
                offset = 0
                while True:
                    page = _call(home, 'windows_rule_report', {'case_id': cid, 'artifact_id': aid, 'offset': offset})
                    locators.extend(row['record'] for row in page['matches'])
                    if not page['has_more']:
                        break
                    offset = page['next_offset']
                expected = [row[0] for row in rows if row[1] == 4624 and row[3] == 'Security' and row[4] == 'Microsoft-Windows-Security-Auditing']
                if locators != expected or len(locators) != success_count:
                    raise RuntimeError('Real corpus rule pagination source locator mismatch')
            total += count
            print(json.dumps({'fixture': name, 'records': count,
                'metadata_sha256': native_digest, 'logon_success_records': success_count}))
            print(json.dumps({'timestamp_decoder_differences_ms1': timestamp_differences,
                              'timestamp_tolerance_ms': 1}))
        joined = _worker(home, cid, 'build_correlation')
        if joined['events'] != total or joined['missing_indexes']:
            raise RuntimeError('Real corpus common timeline coverage mismatch')
        print('PASS: 3862 public binary EVTX record identities matched native Windows, UTC within 1ms; 583 source-linked logon-session observations; no actor legitimacy or audit completeness claim')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
