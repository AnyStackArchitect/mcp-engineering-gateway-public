#!/usr/bin/env python3
"""Offline evidence-linked, limited-signal cross-format case correlation.

Correlates previously derived *sanitized* log, packet, and Windows EVTX
metadata. Does not infer clock offsets, endpoint identity, or causality.
Originals never leave the per-case private evidence directory.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
from typing import Any

from casework import CASE_ID, MAX_PREVIEW, CaseError, CaseStore, _clean_line, _regular_open, _utc
from timelinework import _checked_timeline, _valid_range
from evtxwork import SCHEMA as EVTX_SCHEMA
from protocolwork import MAX_REPORT, PACKET_SIGNALS
from eventmodel import (MODEL_VERSION, checked_time_basis, observed_delta_ms,
                        window_bounds, MAX_WINDOW_MS)

SCHEMA = '2'
MAX_CORRELATED_EVENTS = 300_000
MAX_CASE_INPUTS = 512
MAX_QUERY_OFFSET = 10000
MAX_RESULTS = 20
REVISION = re.compile(r'^[0-9a-f]{32}$')
DB_NAME = 'correlation.sqlite3'
SAFE_PROVIDER = re.compile(r'^provider-[0-9a-f]{12}$')
PUBLIC_PROVIDERS = frozenset({
    'Microsoft-Windows-Security-Auditing', 'Microsoft-Windows-Kernel-Boot',
    'Microsoft-Windows-FailoverClustering', 'Service Control Manager',
    'Microsoft-Windows-Hyper-V-Worker', 'Microsoft-Windows-Hyper-V-VMMS',
})
ALLOWED_SIGNALS = PACKET_SIGNALS


def _safe_regular(path: Path, *, max_size: int | None = None) -> os.stat_result:
    if path.is_symlink():
        raise CaseError('Unsafe derived evidence index path')
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise CaseError('Required derived evidence index unavailable') from exc
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
            st.st_uid != os.getuid() or st.st_mode & 0o077 or
            max_size is not None and st.st_size > max_size):
        raise CaseError('Derived evidence index ownership/type/size invalid')
    return st


def _provider(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if value in PUBLIC_PROVIDERS or SAFE_PROVIDER.fullmatch(value):
        return value
    return '[REDACTED_PROVIDER]'


def _evidence_path(folder: Path, aid: str) -> Path:
    return folder / 'originals' / aid


def _validate_source(store: CaseStore, folder: Path, manifest: dict, aid: str) -> os.stat_result:
    source, item = store._artifact(folder, manifest, aid)
    info = _safe_regular(source)
    if info.st_size != item['bytes']:
        raise CaseError('Case evidence size changed; verify original and rebuild')
    return info


def _read_evtx_index(folder: Path, aid: str, item: dict, info: os.stat_result):
    path = folder / 'indexes' / ('evtx-' + aid + '.sqlite3')
    if not path.exists() and not path.is_symlink():
        return None
    _safe_regular(path)
    con = None
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=3)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA trusted_schema=OFF')
        facts = dict(con.execute('SELECT key,value FROM facts'))
        if (facts.get('schema') != EVTX_SCHEMA or facts.get('source_sha256') != item['sha256']
                or facts.get('size') != str(info.st_size)
                or facts.get('mtime_ns') != str(info.st_mtime_ns)
                or facts.get('inode') != str(info.st_ino)
                or facts.get('device') != str(info.st_dev)):
            raise CaseError('Windows event index stale; rerun EVTX analysis')
        return con, facts, path.lstat()
    except (sqlite3.Error, OSError, TypeError, KeyError, ValueError) as exc:
        if con:
            con.close()
        raise CaseError('Windows event metadata index invalid') from exc
    except BaseException:
        if con:
            con.close()
        raise


def _read_pcap_index(folder: Path, aid: str, item: dict, info: os.stat_result):
    path = folder / 'indexes' / ('protocol-' + aid + '.json')
    if not path.exists() and not path.is_symlink():
        return None
    _safe_regular(path, max_size=MAX_REPORT)
    try:
        fd, _ = _regular_open(path)
        with os.fdopen(fd, 'rb') as stream:
            report = json.loads(stream.read(MAX_REPORT + 1))
        source = report['source']
        if (source.get('sha256') != item['sha256'] or source.get('bytes') != info.st_size
                or source.get('inode') != info.st_ino
                or source.get('device') != info.st_dev
                or source.get('mtime_ns') != info.st_mtime_ns):
            raise CaseError('Capture protocol report stale; rerun decode_pcap')
        if not isinstance(report.get('observations'), list):
            raise CaseError('Capture report predates event-level metadata; rerun decode_pcap')
        if len(report['observations']) > 1024:
            raise CaseError('Capture observation index exceeds bounded limit')
        return report, path.lstat()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise CaseError('Capture protocol report invalid') from exc


def _source_signature(path: Path) -> tuple[int, int, int, int]:
    statinfo = _safe_regular(path)
    return statinfo.st_size, statinfo.st_mtime_ns, statinfo.st_ino, statinfo.st_dev


def _checked_correlation(folder: Path, manifest: dict):
    path = folder / 'indexes' / DB_NAME
    _safe_regular(path)
    conn = None
    try:
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=3)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA trusted_schema=OFF')
        facts = dict(conn.execute('SELECT key,value FROM facts'))
        if facts.get('schema') != SCHEMA:
            raise CaseError('Correlation index schema unavailable')
        rows = conn.execute('''SELECT artifact_id, sha256, bytes, mtime_ns, inode, device,
                               index_name, index_size, index_mtime_ns, index_inode, index_device
                               FROM sources''').fetchall()
        expected = {k for k,v in manifest['artifacts'].items() if v.get('type') in ('text','pcap','pcapng','evtx')}
        if {r['artifact_id'] for r in rows} != expected:
            raise CaseError('Correlation stale: case evidence membership changed; rebuild')
        for row in rows:
            aid = row['artifact_id']
            item = manifest['artifacts'][aid]
            original = _evidence_path(folder, aid)
            osig = _source_signature(original)
            if (row['sha256'] != item['sha256'] or osig !=
                    (row['bytes'],row['mtime_ns'],row['inode'],row['device'])):
                raise CaseError('Correlation stale: source evidence changed; rebuild')
            if row['index_name']:
                index_name = row['index_name']
                if index_name not in ('timeline.sqlite3', 'evtx-' + aid + '.sqlite3', 'protocol-' + aid + '.json'):
                    raise CaseError('Correlation index provider identity invalid')
                isign = _source_signature(folder / 'indexes' / index_name)
                if isign != (row['index_size'],row['index_mtime_ns'],row['index_inode'],row['index_device']):
                    raise CaseError('Correlation stale: upstream analyzer changed; rebuild')
        return conn, facts
    except (OSError, TypeError, KeyError, ValueError, sqlite3.Error) as exc:
        if conn: conn.close()
        raise CaseError('Correlation index unavailable or invalid') from exc
    except BaseException:
        if conn: conn.close()
        raise


def build_correlation(store: CaseStore, case_id: str, *, should_cancel=None) -> dict[str, Any]:
    """Join only explicitly indexed evidence. Missing decoders remain gaps."""
    with store._locked(case_id) as (folder, manifest):
        sources = [(aid,item) for aid,item in sorted(manifest['artifacts'].items())
                   if item.get('type') in ('text','pcap','pcapng','evtx')]
        if len(sources) > MAX_CASE_INPUTS:
            raise CaseError('Too many source artifacts for bounded correlation')
        out = folder / 'indexes' / DB_NAME
        if out.exists() or out.is_symlink():
            _safe_regular(out)
        if shutil.disk_usage(folder).free < 64 * 1024 ** 2:
            raise CaseError('Insufficient free space for correlation indexing')
        scratch = folder / 'indexes' / ('.tmp-correlate-' + secrets.token_hex(12) + '.sqlite3')
        fd = os.open(scratch, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os,'O_NOFOLLOW',0),0o600)
        os.close(fd)
        db = None
        text_db = None
        try:
            db = sqlite3.connect(str(scratch),timeout=3)
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE facts(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            db.execute('''CREATE TABLE sources (artifact_id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                sha256 TEXT NOT NULL, bytes INTEGER, mtime_ns INTEGER, inode INTEGER, device INTEGER,
                index_name TEXT, index_size INTEGER, index_mtime_ns INTEGER, index_inode INTEGER,
                index_device INTEGER, coverage TEXT, count INTEGER NOT NULL)''')
            db.execute('''CREATE TABLE events (id INTEGER PRIMARY KEY, artifact_id TEXT NOT NULL,
                kind TEXT NOT NULL, utc TEXT, time_quality TEXT NOT NULL, locator_type TEXT NOT NULL,
                locator_number INTEGER NOT NULL, signal TEXT, excerpt TEXT NOT NULL,
                 time_basis TEXT NOT NULL)''')
            db.execute('CREATE INDEX events_by_utc ON events(utc,kind,artifact_id,locator_number)')
            db.execute('CREATE INDEX events_by_artifact ON events(artifact_id,locator_number)')
            count = 0
            missing = 0
            limitations: set[str] = set()
            by_kind = Counter()
            excluded = len(manifest['artifacts']) - len(sources)
            if excluded:
                limitations.add('non_log_capture_evtx_artifacts_not_correlated')
            text_ids = [aid for aid,item in sources if item['type'] == 'text']
            if text_ids and (folder / 'indexes' / 'timeline.sqlite3').exists():
                text_db = _checked_timeline(folder,manifest)
                text_db.row_factory = sqlite3.Row
            elif text_ids:
                limitations.add('text_timeline_missing')
            for aid,item in sources:
                if should_cancel: should_cancel()
                original = _evidence_path(folder,aid)
                info = _validate_source(store,folder,manifest,aid)
                kind = item['type']
                provider_name = None
                provider_stat = None
                status = 'INDEXED'
                events_this = 0
                if kind == 'text':
                    if text_db is None:
                        status = 'MISSING_INDEX'
                    else:
                        provider_name = 'timeline.sqlite3'
                        provider_stat = _safe_regular(folder / 'indexes' / provider_name)
                        cursor = text_db.execute('''SELECT line_no,timestamp_utc,time_quality,level_hint,excerpt
                                                    FROM events WHERE artifact_id=? ORDER BY line_no''',(aid,))
                        for line, utc, quality, level, excerpt in cursor:
                            if should_cancel and events_this % 256 == 0: should_cancel()
                            if count >= MAX_CORRELATED_EVENTS: raise CaseError('Case correlation event capacity exceeded')
                            if type(line) is not int or line < 1 or not isinstance(excerpt,str):
                                raise CaseError('Log timeline reference invalid')
                            if utc is not None: utc = _valid_range(utc)
                            if level not in ('CRITICAL','ERROR','WARN','INFO','DEBUG','TRACE'):
                                level = None
                            # Derived indexes are still untrusted local data. Redact again.
                            excerpt = _clean_line(excerpt)[:MAX_PREVIEW]
                            db.execute('''INSERT INTO events(artifact_id,kind,utc,time_quality,locator_type,
                                locator_number,signal,excerpt,time_basis) VALUES (?,?,?,?,?,?,?,?,?)''',
                                (aid,kind,utc,quality,'line',line,level,excerpt,
                                  checked_time_basis(utc,quality)))
                            count += 1
                            events_this += 1
                            if utc is None: limitations.add('source_event_timezone_unknown')
                elif kind in ('pcap','pcapng'):
                    loaded = _read_pcap_index(folder,aid,item,info)
                    if loaded is None:
                        status = 'MISSING_INDEX'
                    else:
                        report, provider_stat = loaded
                        provider_name = 'protocol-' + aid + '.json'
                        # The native packet decoder provides bounded diagnostic signal samples,
                        # not comprehensive application traffic or endpoint matching.
                        limitations.add('pcap_diagnostic_signals_only')
                        if report.get('status') != 'PASS': limitations.add('pcap_source_partial')
                        for obs in report['observations']:
                            if not isinstance(obs,dict):raise CaseError('Capture observation index invalid')
                            number, utc, signal = obs.get('packet_no'),obs.get('utc'),obs.get('signal')
                            if type(number) is not int or not 1 <= number <= 300_000 or signal not in ALLOWED_SIGNALS:
                                raise CaseError('Capture observation reference invalid')
                            if utc is not None:
                                utc = _valid_range(utc)
                            else:limitations.add('source_event_timezone_unknown')
                            if count >= MAX_CORRELATED_EVENTS: raise CaseError('Case correlation event capacity exceeded')
                            db.execute('''INSERT INTO events(artifact_id,kind,utc,time_quality,locator_type,
                                locator_number,signal,excerpt,time_basis) VALUES (?,?,?,?,?,?,?,?,?)''',
                                (aid,kind,utc,'OFFSET' if utc else 'NO_TIMESTAMP','packet',number,
                                 signal,'packet signal: ' + signal,
                                  checked_time_basis(utc,'OFFSET' if utc else 'NO_TIMESTAMP')))
                            count += 1
                            events_this += 1
                elif kind == 'evtx':
                    loaded = _read_evtx_index(folder,aid,item,info)
                    if loaded is None:
                        status = 'MISSING_INDEX'
                        limitations.add('evtx_provider_not_indexed')
                    else:
                        conn, facts, provider_stat = loaded
                        provider_name = 'evtx-' + aid + '.sqlite3'
                        try:
                            if int(facts.get('records_skipped','0')) or int(facts.get('records_without_utc','0')):
                                limitations.add('evtx_metadata_partial')
                            for number,eid,provider,level,utc in conn.execute('''SELECT record_num,event_id,provider,level,utc
                                     FROM records ORDER BY ordinal'''):
                                if should_cancel and events_this % 256 == 0:should_cancel()
                                if count >= MAX_CORRELATED_EVENTS:raise CaseError('Case correlation event capacity exceeded')
                                label = _provider(provider)
                                if type(number) is not int or number < 0:raise CaseError('Windows event reference invalid')
                                if eid is not None and (type(eid) is not int or not 0 <= eid <= 65535):
                                    raise CaseError('Windows event ID invalid')
                                if utc is not None: utc = _valid_range(utc)
                                else:limitations.add('source_event_timezone_unknown')
                                db.execute('''INSERT INTO events(artifact_id,kind,utc,time_quality,locator_type,
                                    locator_number,signal,excerpt,time_basis) VALUES (?,?,?,?,?,?,?,?,?)''',
                                    (aid,kind,utc,'OFFSET' if utc else 'NO_TIMESTAMP','record',number,
                                     'event_id_' + str(eid) if eid is not None else None,
                                     'Windows EventID ' + str(eid if eid is not None else 'unknown') +
                                     ' provider ' + (label or 'unknown'),
                                      checked_time_basis(utc,'OFFSET' if utc else 'NO_TIMESTAMP')))
                                count += 1
                                events_this += 1
                        finally:
                            conn.close()
                if status == 'MISSING_INDEX':
                    missing += 1
                    limitations.add('source_index_missing')
                db.execute('''INSERT INTO sources VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (aid,kind,item['sha256'],info.st_size,info.st_mtime_ns,info.st_ino,info.st_dev,
                            provider_name,provider_stat.st_size if provider_stat else None,
                            provider_stat.st_mtime_ns if provider_stat else None,
                            provider_stat.st_ino if provider_stat else None,
                            provider_stat.st_dev if provider_stat else None,status,events_this))
                by_kind[kind] += 1
            if text_db:
                facts = dict(text_db.execute('SELECT key,value FROM facts'))
                if any(int(facts.get(key,'0')) for key in ('events_unanchored','lines_skipped',
                                                           'utf8_decode_errors','previews_truncated')):
                    limitations.add('text_source_partial')
            # Take a final snapshot before publishing an index that could have
            # been invalidated while the bounded worker scanned its inputs.
            for aid,item in sources:
                before=db.execute('''SELECT bytes,mtime_ns,inode,device,index_name,
                                    index_size,index_mtime_ns,index_inode,index_device
                                    FROM sources WHERE artifact_id=?''',(aid,)).fetchone()
                if before is None or _source_signature(_evidence_path(folder,aid)) != tuple(before[:4]):
                    raise CaseError('Case source changed during correlation')
                if before[4] and _source_signature(folder/'indexes'/before[4]) != tuple(before[5:]):
                    raise CaseError('Analyzer index changed during correlation')
            result_status = ('NOT_APPLICABLE' if not sources and not excluded else
                             'PARTIAL' if limitations or missing else 'PASS')
            metadata = {'schema':SCHEMA,'model_version':MODEL_VERSION,
                         'index_revision':secrets.token_hex(16),
                         'built_at':_utc(),'status':result_status,
                        'event_count':str(count),'source_count':str(len(sources)),
                        'missing_indexes':str(missing),'excluded_artifacts':str(excluded),
                        'limitations':json.dumps(sorted(limitations),separators=(',',':'))}
            db.executemany('INSERT INTO facts VALUES (?,?)', metadata.items())
            db.commit()
            db.close()
            db = None
            if should_cancel:should_cancel()
            os.replace(scratch,out)
            return {'case_id':case_id,'status':result_status,'sources':len(sources),
                    'events':count,'missing_indexes':missing,'excluded_artifacts':excluded,
                    'kinds':dict(by_kind),'limitations':sorted(limitations),
                    'built_at':metadata['built_at'],'index_revision':metadata['index_revision'],
                    'note':'Timestamps are unadjusted; no clock-skew/host identity/causal inference'}
        finally:
            if text_db:text_db.close()
            if db:db.close()
            scratch.unlink(missing_ok=True)


def _query_args(start_utc, end_utc, offset, limit, artifact_id, kind, include_unknown):
    if type(offset) is not int or not 0 <= offset <= MAX_QUERY_OFFSET:
        raise CaseError('Invalid correlation offset')
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise CaseError('Invalid correlation limit')
    if type(include_unknown) is not bool:
        raise CaseError('Invalid include_unknown flag')
    if artifact_id is not None and (not isinstance(artifact_id,str) or not CASE_ID.fullmatch(artifact_id)):
        raise CaseError('Invalid source artifact identifier')
    if kind is not None and kind not in ('text','pcap','pcapng','evtx'):
        raise CaseError('Invalid source kind')
    start,end = _valid_range(start_utc),_valid_range(end_utc)
    if start and end and start > end:
        raise CaseError('Correlation start must precede end')
    return start,end


def correlation_query(store:CaseStore,case_id:str,*,start_utc=None,end_utc=None,
                      artifact_id=None,kind=None,include_unknown=False,offset=0,limit=20) -> dict:
    start,end = _query_args(start_utc,end_utc,offset,limit,artifact_id,kind,include_unknown)
    with store._locked(case_id) as (folder,manifest):
        conn,facts=_checked_correlation(folder,manifest)
        try:
            where, args=[],[]
            if kind:where.append('kind=?');args.append(kind)
            if artifact_id:
                if not conn.execute('SELECT 1 FROM sources WHERE artifact_id=?',(artifact_id,)).fetchone():
                    raise CaseError('Correlation source not registered')
                where.append('artifact_id=?');args.append(artifact_id)
            if start or end:
                where.append('utc IS NOT NULL')
                if start:where.append('utc>=?');args.append(start)
                if end:where.append('utc<=?');args.append(end)
            elif not include_unknown:
                where.append('utc IS NOT NULL')
            clause=(' WHERE '+' AND '.join(where)) if where else ''
            records=conn.execute('''SELECT id AS event_id,artifact_id,kind,utc,time_quality,time_basis,
                                          locator_type,locator_number,signal,excerpt
                                   FROM events'''+clause+''' ORDER BY utc IS NULL,utc,kind,artifact_id,locator_number
                                   LIMIT ? OFFSET ?''',(*args,limit+1,offset)).fetchall()
            limitations=json.loads(facts['limitations'])
            more=len(records)>limit
            next_page=offset+limit
            pagination_limited=more and next_page>MAX_QUERY_OFFSET
            return {'case_id':case_id,'status':'PARTIAL' if pagination_limited else facts['status'],
                    'model_version':facts['model_version'],
                    'index_revision':facts['index_revision'],
                    'offset':offset,'limit':limit,'next_offset':next_page if more and not pagination_limited else None,
                    'events':[dict(row) for row in records[:limit]],'has_more':more and not pagination_limited,
                    'pagination_bound_reached':pagination_limited,
                    'more_matching_events_outside_pagination_bound':pagination_limited,
                    'maximum_page_offset':MAX_QUERY_OFFSET,
                    'source_count':int(facts['source_count']),'missing_indexes':int(facts['missing_indexes']),
                    'excluded_artifacts':int(facts['excluded_artifacts']),
                    'limitations':limitations,'clock_alignment':'UNVERIFIED','clock_offsets_applied':False,
                    'cross_source_identity_inferred':False,'causality_inferred':False,
                    'timestamp_filter_excludes_unknown':bool(start or end),
                    'note':'Relative order reflects unadjusted timestamps, not proven causality'}
        except sqlite3.Error as exc:
            raise CaseError('Correlation query index invalid') from exc
        finally:
            conn.close()


def correlation_sources(store:CaseStore,case_id:str,*,offset=0)->dict:
    if type(offset) is not int or not 0 <= offset <= MAX_QUERY_OFFSET:
        raise CaseError('Invalid correlation source offset')
    with store._locked(case_id) as (folder,manifest):
        conn,facts=_checked_correlation(folder,manifest)
        try:
            rows=conn.execute('''SELECT artifact_id,kind,sha256,coverage,count FROM sources
                                 ORDER BY artifact_id LIMIT 21 OFFSET ?''',(offset,)).fetchall()
            return {'case_id':case_id,'status':facts['status'],
                    'index_revision':facts['index_revision'],
                    'sources':[dict(r) for r in rows[:20]],
                    'offset':offset,'next_offset':offset+20 if len(rows)>20 else None,
                    'missing_indexes':int(facts['missing_indexes']),
                    'excluded_artifacts':int(facts['excluded_artifacts']),
                    'clock_alignment':'UNVERIFIED',
                    'limitations':json.loads(facts['limitations'])}
        except sqlite3.Error as exc:
            raise CaseError('Correlation source index invalid') from exc
        finally:conn.close()


def correlation_summary(store:CaseStore,case_id:str)->dict:
    with store._locked(case_id) as (folder,manifest):
        conn,facts=_checked_correlation(folder,manifest)
        try:
            by_type=conn.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind ORDER BY kind').fetchall()
            by_signal=conn.execute('''SELECT COALESCE(signal,'UNCLASSIFIED'),COUNT(*) FROM events
                                      GROUP BY COALESCE(signal,'UNCLASSIFIED') ORDER BY COUNT(*) DESC LIMIT 16''').fetchall()
            untimed=conn.execute('SELECT COUNT(*) FROM events WHERE utc IS NULL').fetchone()[0]
            return {'case_id':case_id,'status':facts['status'],
                    'index_revision':facts['index_revision'],
                    'model_version':facts['model_version'],
                    'event_count':int(facts['event_count']),'source_count':int(facts['source_count']),
                    'missing_indexes':int(facts['missing_indexes']),
                    'excluded_artifacts':int(facts['excluded_artifacts']),
                    'events_without_utc':untimed,
                    'by_kind':[{'kind':k,'count':n} for k,n in by_type],
                    'top_signals':[{'signal':k,'count':n} for k,n in by_signal],
                    'limitations':json.loads(facts['limitations']),
                    'clock_alignment':'UNVERIFIED','causality_inferred':False,
                    'note':'Timestamp proximity is not causal attribution'}
        except sqlite3.Error as exc:
            raise CaseError('Correlation summary index invalid') from exc
        finally:conn.close()


def correlation_window(store: CaseStore, case_id: str, *,
                       index_revision: str, anchor_event_id: int,
                       before_ms: int = 5000, after_ms: int = 5000,
                       cross_source_only: bool = True,
                       offset: int = 0, limit: int = MAX_RESULTS) -> dict:
    """Page timestamp adjacency around a pinned source observation.

    Source clocks may disagree. This cannot establish synchronized clocks,
    a common endpoint, network latency, event order or causality.
    """
    if type(index_revision) is not str or not REVISION.fullmatch(index_revision):
        raise CaseError('Invalid correlation revision')
    if type(anchor_event_id) is not int or not 1 <= anchor_event_id <= MAX_CORRELATED_EVENTS:
        raise CaseError('Invalid correlation anchor event')
    if type(cross_source_only) is not bool:
        raise CaseError('Invalid cross-source filter')
    if type(offset) is not int or not 0 <= offset <= MAX_QUERY_OFFSET:
        raise CaseError('Invalid correlation window offset')
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise CaseError('Invalid correlation window limit')
    if type(before_ms) is not int or type(after_ms) is not int or not (
            0 <= before_ms <= MAX_WINDOW_MS and 0 <= after_ms <= MAX_WINDOW_MS):
        raise CaseError('Invalid correlation window duration')
    with store._locked(case_id) as (folder, manifest):
        conn, facts = _checked_correlation(folder, manifest)
        try:
            if (facts.get('index_revision') != index_revision or
                    facts.get('model_version') != MODEL_VERSION):
                raise CaseError('Correlation event revision stale; refresh event references')
            anchor = conn.execute(
                'SELECT id AS event_id,artifact_id,kind,utc,time_quality,time_basis,'
                'locator_type,locator_number FROM events WHERE id=?',
                (anchor_event_id,)).fetchone()
            if anchor is None:
                raise CaseError('Correlation anchor event not found in pinned index')
            if anchor['utc'] is None:
                raise CaseError('Unanchored event cannot anchor a UTC correlation window')
            if checked_time_basis(anchor['utc'], anchor['time_quality']) != anchor['time_basis']:
                raise CaseError('Correlation anchor clock metadata inconsistent')
            start, end = window_bounds(anchor['utc'], before_ms, after_ms)
            clause = ' AND artifact_id<>?' if cross_source_only else ''
            args = [anchor['event_id'], start, end]
            if cross_source_only:
                args.append(anchor['artifact_id'])
            records = conn.execute(
                '''SELECT id AS event_id,artifact_id,kind,utc,time_quality,time_basis,
                          locator_type,locator_number,signal,excerpt
                   FROM events WHERE id<>? AND utc>=? AND utc<=?''' + clause +
                ''' ORDER BY utc,kind,artifact_id,locator_number,id LIMIT ? OFFSET ?''',
                (*args,limit+1,offset)).fetchall()
            visible = []
            for row in records[:limit]:
                event = dict(row)
                if checked_time_basis(event['utc'], event['time_quality']) != event['time_basis']:
                    raise CaseError('Correlated event clock metadata inconsistent')
                event['observed_delta_ms'] = observed_delta_ms(anchor['utc'], event['utc'])
                visible.append(event)
            unknown = conn.execute('SELECT COUNT(*) FROM events WHERE utc IS NULL').fetchone()[0]
            return {
                'case_id':case_id,'status':facts['status'],
                'model_version':facts['model_version'],
                'index_revision':index_revision,
                'anchor':dict(anchor),
                'window_start_utc':start,'window_end_utc':end,
                'before_ms':before_ms,'after_ms':after_ms,
                'cross_source_only':cross_source_only,
                'offset':offset,'limit':limit,
                'next_offset':offset+limit if len(records)>limit else None,
                'has_more':len(records)>limit,'events':visible,
                'unknown_utc_event_count':unknown,
                'missing_indexes':int(facts['missing_indexes']),
                'excluded_artifacts':int(facts['excluded_artifacts']),
                'limitations':json.loads(facts['limitations']),
                'time_basis':'DECLARED_UTC_CLOCK_UNVERIFIED',
                'clock_alignment':'UNVERIFIED','clock_offsets_applied':False,
                'cross_source_identity_inferred':False,'causality_inferred':False,
                'note':'Timestamp proximity uses source clocks; no verified skew, identity or causality',
            }
        except sqlite3.Error as exc:
            raise CaseError('Correlation window index invalid') from exc
        finally:
            conn.close()
