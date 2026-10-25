#!/usr/bin/env python3
"""Bounded, offline, cross-artifact timeline from owned private text evidence.

No inferred timezone, no clock-skew correction, no claims of causality.
Originals are never written and raw evidence is never returned to MCP clients.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
from producerwork import record as producer_identity
from typing import Any

from casework import (
    CASE_ID, MAX_LINE, MAX_PREVIEW, CaseError, CaseStore, _clean_line,
    _regular_open, _utc, ISO_HEAD,
)

SCHEMA_VERSION = '2'
MAX_TIMELINE_EVENTS = 2_000_000
MAX_TIMELINE_SOURCES = 512
MAX_QUERY = 96
MAX_QUERY_LIMIT = 20
MAX_QUERY_OFFSET = 10000
MAX_SOURCE_OFFSET = 10000
MAX_SOURCE_BYTES = 8 * 1024 ** 3
SOURCE_SQL = 'timeline.sqlite3'
ISO_FULL = re.compile(
    r'^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?$'
)
SYSLOG_HEAD = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)(?:\s|$)'
)
RFC5424_HEAD = re.compile(
    r'^<\d{1,3}>1\s+(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d'
    r'(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s'
)
HINT = re.compile(r'(?i)\b(CRITICAL|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\b')
PRIVATE_FIELD = re.compile(
    r'(?i)(?:password|passwd|passphrase|token|api.?key|secret|authorization|'
    r'credential|cookie|session.?key|client.?secret|private.?key)'
)
LEVELS = {'critical': 'CRITICAL', 'fatal': 'CRITICAL', 'error': 'ERROR',
          'warning': 'WARN', 'warn': 'WARN', 'info': 'INFO',
          'debug': 'DEBUG', 'trace': 'TRACE'}


def _dt(raw: str) -> tuple[str | None, str]:
    """Return normalized UTC or explicit unknown quality; never invent an offset."""
    if not isinstance(raw, str) or not ISO_FULL.fullmatch(raw) or len(raw) > 80:
        return None, 'INVALID'
    try:
        value = datetime.fromisoformat(raw.replace(',', '.').replace('Z', '+00:00'))
        if value.tzinfo is None or value.utcoffset() is None:
            return None, 'NO_TIMEZONE'
        utc = value.astimezone(timezone.utc)
        return utc.isoformat(timespec='microseconds'), 'OFFSET'
    except (ValueError, OverflowError):
        return None, 'INVALID'


def _explicit_epoch(value: object, unit: str) -> tuple[str | None, str]:
    # Only explicitly named UTC epoch fields are supported. No guessing ms/s
    # from the magnitude of a generic JSON 'timestamp' numeric value.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, 'INVALID'
    if not (946684800 <= value / (1000 if unit == 'ms' else 1) <= 4102444800):
        return None, 'INVALID'
    try:
        dt = datetime.fromtimestamp(value / (1000 if unit == 'ms' else 1), timezone.utc)
        return dt.isoformat(timespec='microseconds'), 'EXPLICIT_EPOCH'
    except (ValueError, OSError, OverflowError):
        return None, 'INVALID'


def _sanitize_json(value: Any, depth: int = 0) -> Any:
    if depth > 10:
        return '[DEPTH_LIMIT]'
    if isinstance(value, dict):
        return {str(k)[:60]: ('[REDACTED]' if PRIVATE_FIELD.search(str(k)) else
                _sanitize_json(v, depth + 1)) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return [_sanitize_json(v, depth + 1) for v in value[:20]]
    if isinstance(value, str):
        return _clean_line(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return '[UNSUPPORTED_VALUE]'


def normalize_line(text: str) -> dict[str, str | None]:
    """Bounded known-format normalization. Unrecognized times remain unanchored."""
    text = text.strip('\r\n')
    sample = text.lstrip()
    stamp: str | None = None
    utc: str | None = None
    quality = 'NO_TIMESTAMP'
    fmt = 'plain'
    level: str | None = None
    excerpt = _clean_line(text)
    if sample.startswith('{') and len(text) <= MAX_LINE:
        try:
            event = json.loads(text)
        except (ValueError, RecursionError):
            event = None
        if isinstance(event, dict):
            fmt = 'jsonl'
            excerpt = _clean_line(json.dumps(_sanitize_json(event), ensure_ascii=True,
                                                 separators=(',', ':')))
            for key in ('@timestamp', 'timestamp', 'time', 'ts'):
                if key in event:
                    raw = event[key]
                    if isinstance(raw, str):
                        utc, quality = _dt(raw)
                        stamp = raw[:80] if quality in ('OFFSET', 'NO_TIMEZONE') else '[INVALID_TIMESTAMP]'
                    else:
                        stamp = '[NON_ISO_TIMESTAMP]'
                        quality = 'AMBIGUOUS_NUMERIC'
                    break
            if stamp is None:
                for key, unit in (('timestamp_unix_ms', 'ms'), ('timestamp_unix_s', 's')):
                    if key in event:
                        stamp = key + ':explicit'
                        utc, quality = _explicit_epoch(event[key], unit)
                        break
            raw_level = event.get('level', event.get('severity'))
            if isinstance(raw_level, str):
                level = LEVELS.get(raw_level.strip().lower())
    if fmt == 'plain':
        match = ISO_HEAD.match(text)
        if match:
            fmt = 'iso_prefix'
            stamp = match.group(1)[:80]
            utc, quality = _dt(stamp)
        else:
            match = RFC5424_HEAD.match(text)
            if match:
                fmt = 'syslog5424'
                stamp = match.group(1)[:80]
                utc, quality = _dt(stamp)
            else:
                match = SYSLOG_HEAD.match(text)
                if match:
                    fmt = 'syslog3164'
                    stamp = match.group(1)
                    quality = 'NO_YEAR_OR_TIMEZONE'
        severity = HINT.search(text)
        if severity:
            level = LEVELS.get(severity.group(1).lower())
    return {'utc': utc, 'stamp': stamp, 'time_quality': quality,
            'format': fmt, 'level_hint': level, 'excerpt': excerpt[:MAX_PREVIEW]}


def _index_path(folder: Path) -> Path:
    return folder / 'indexes' / SOURCE_SQL


def _checked_timeline(folder: Path, manifest: dict[str, Any]) -> sqlite3.Connection:
    """Hold the CaseStore lock externally, verify stored input identities and freshness."""
    path = _index_path(folder)
    if path.is_symlink():
        raise CaseError('Timeline index symlink refused')
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise CaseError('Timeline not built; submit build_timeline job') from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077 or info.st_nlink != 1):
        raise CaseError('Timeline index permissions invalid')
    # Prevent accidental creation and treat SQLite corruption as unavailable.
    try:
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=2)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA trusted_schema=OFF')
        facts = dict(conn.execute('SELECT key,value FROM facts'))
        if facts.get('schema_version') != SCHEMA_VERSION:
            raise CaseError('Timeline schema version unavailable')
        sources = conn.execute('SELECT artifact_id,sha256,bytes,mtime_ns,inode,device FROM sources').fetchall()
        source_ids = {r['artifact_id'] for r in sources}
        current = {aid for aid, item in manifest['artifacts'].items() if item.get('type') == 'text'}
        if current != source_ids:
            raise CaseError('Timeline stale: registered text artifact set changed; rebuild')
        for row in sources:
            aid = row['artifact_id']
            item = manifest['artifacts'][aid]
            path_source = folder / 'originals' / aid
            sinfo = path_source.lstat()
            if (path_source.is_symlink() or not stat.S_ISREG(sinfo.st_mode) or
                    sinfo.st_nlink != 1 or sinfo.st_uid != os.getuid() or
                    sinfo.st_mode & 0o077 or sinfo.st_size != row['bytes'] or
                    sinfo.st_mtime_ns != row['mtime_ns'] or sinfo.st_ino != row['inode'] or
                    sinfo.st_dev != row['device'] or item['sha256'] != row['sha256']):
                raise CaseError('Timeline stale: source identity changed; rebuild and verify vault')
        return conn
    except (sqlite3.DatabaseError, OSError, ValueError, KeyError, TypeError) as exc:
        if 'conn' in locals():
            conn.close()
        raise CaseError('Timeline index invalid or unavailable') from exc
    except BaseException:
        if 'conn' in locals():
            conn.close()
        raise


def build_timeline(store: CaseStore, case_id: str, *, should_cancel=None) -> dict[str, Any]:
    """Build an atomic, bounded timeline from all currently registered text artifacts."""
    with store._locked(case_id) as (folder, manifest):
        files = [(aid, item) for aid, item in sorted(manifest['artifacts'].items())
                 if item.get('type') == 'text']
        if len(files) > MAX_TIMELINE_SOURCES:
            raise CaseError('Too many log sources for bounded timeline indexing')
        if any(item['bytes'] > MAX_SOURCE_BYTES for _, item in files):
            raise CaseError('Source exceeds timeline worker capacity')
        path = _index_path(folder)
        if path.is_symlink():
            raise CaseError('Unsafe timeline index path')
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise CaseError('Existing timeline index permissions invalid')
        # Require disk headroom beyond a conservative 2x estimate, without
        # promising support for unbounded source/log materialization.
        total_size = sum(item['bytes'] for _, item in files)
        free = shutil.disk_usage(folder).free
        if free < min(total_size * 2, 8 * 1024 ** 3) + 64 * 1024 ** 2:
            raise CaseError('Insufficient scratch storage for timeline index')
        tmp = folder / 'indexes' / ('.tmp-timeline-' + secrets.token_hex(12) + '.sqlite3')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.close(fd)
        db: sqlite3.Connection | None = None
        try:
            db = sqlite3.connect(str(tmp), timeout=3)
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('CREATE TABLE facts (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute('''CREATE TABLE sources (
                artifact_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL, inode INTEGER NOT NULL, device INTEGER NOT NULL,
                scanned INTEGER NOT NULL, indexed INTEGER NOT NULL, skipped INTEGER NOT NULL,
                unanchored INTEGER NOT NULL, decode_errors INTEGER NOT NULL,
                preview_truncated INTEGER NOT NULL)''')
            db.execute('''CREATE TABLE events (
                id INTEGER PRIMARY KEY, artifact_id TEXT NOT NULL, line_no INTEGER NOT NULL,
                timestamp_utc TEXT, source_timestamp TEXT, time_quality TEXT NOT NULL,
                format TEXT NOT NULL, level_hint TEXT, excerpt TEXT NOT NULL)''')
            db.execute('CREATE INDEX idx_events_time ON events(timestamp_utc,artifact_id,line_no)')
            db.execute('CREATE INDEX idx_events_artifact ON events(artifact_id,line_no)')
            global_count = 0
            global_unanchored = 0
            global_skipped = 0
            global_decode_errors = 0
            global_truncated = 0
            for aid, item in files:
                if should_cancel:
                    should_cancel()
                source, _ = store._artifact(folder, manifest, aid)
                fd, before = _regular_open(source)
                digest = hashlib.sha256()
                examined = 0
                indexed = 0
                skipped = 0
                unanchored = 0
                decode_errors = 0
                previews_truncated = 0
                try:
                    with os.fdopen(fd, 'rb') as inp:
                        fd = -1
                        while True:
                            raw = inp.readline(MAX_LINE + 1)
                            if not raw:
                                break
                            examined += 1
                            if should_cancel is not None and examined % 512 == 1:
                                should_cancel()
                            digest.update(raw)
                            if len(raw) > MAX_LINE:
                                while raw and not raw.endswith(b'\n'):
                                    raw = inp.readline(MAX_LINE + 1)
                                    digest.update(raw)
                                skipped += 1
                                continue
                            if global_count >= MAX_TIMELINE_EVENTS:
                                raise CaseError('Timeline event count exceeds worker capacity')
                            try:
                                parsed = raw.decode('utf-8', errors='strict')
                            except UnicodeDecodeError:
                                parsed = raw.decode('utf-8', errors='replace')
                                decode_errors += 1
                            if len(parsed) > MAX_PREVIEW:
                                previews_truncated += 1
                            event = normalize_line(parsed)
                            db.execute('''INSERT INTO events(artifact_id,line_no,timestamp_utc,source_timestamp,
                                time_quality,format,level_hint,excerpt) VALUES (?,?,?,?,?,?,?,?)''',
                                (aid, examined, event['utc'], event['stamp'], event['time_quality'],
                                 event['format'], event['level_hint'], event['excerpt']))
                            global_count += 1
                            indexed += 1
                            if event['utc'] is None:
                                unanchored += 1
                finally:
                    if fd >= 0:
                        os.close(fd)
                after = source.lstat()
                if (after.st_mtime_ns != before.st_mtime_ns or after.st_ino != before.st_ino or
                        after.st_dev != before.st_dev or after.st_size != before.st_size or
                        digest.hexdigest() != item['sha256']):
                    raise CaseError('Timeline source changed during scan')
                db.execute('INSERT INTO sources VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                           (aid, item['sha256'], item['bytes'], before.st_mtime_ns,
                            before.st_ino, before.st_dev, examined, indexed, skipped, unanchored,
                            decode_errors, previews_truncated))
                global_unanchored += unanchored
                global_skipped += skipped
                global_decode_errors += decode_errors
                global_truncated += previews_truncated
            data = {'schema_version': SCHEMA_VERSION, 'built_at': _utc(),
                    'producer_identity': json.dumps(producer_identity('timelinework','casework'),sort_keys=True),
                    'artifacts_indexed': str(len(files)),
                    'events_indexed': str(global_count),
                    'events_unanchored': str(global_unanchored),
                    'lines_skipped': str(global_skipped),
                    'utf8_decode_errors': str(global_decode_errors),
                    'previews_truncated': str(global_truncated)}
            db.executemany('INSERT INTO facts VALUES (?,?)', data.items())
            db.commit()
            db.close()
            db = None
            if should_cancel:
                should_cancel()
            os.replace(tmp, path)
            quality = _result_status(data)
            return {'status': quality, 'case_id': case_id,
                    'sources_indexed': len(files), 'events_indexed': global_count,
                    'events_unanchored': global_unanchored, 'lines_skipped': global_skipped,
                    'utf8_decode_errors': global_decode_errors,
                    'previews_truncated': global_truncated,
                    'built_at': data['built_at'],
                    'note': 'Timezones/years are never inferred; correlation does not establish causality'}
        finally:
            if db:
                db.close()
            tmp.unlink(missing_ok=True)


def _valid_range(raw: str | None) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or len(raw) > 80:
        raise CaseError('Timeline range must be an ISO-8601 timestamp with timezone')
    utc, quality = _dt(raw)
    if quality != 'OFFSET':
        raise CaseError('Timeline range needs explicit UTC offset or Z')
    return utc


def _result_status(facts: dict[str, str]) -> str:
    if int(facts['artifacts_indexed']) == 0:
        return 'NOT_APPLICABLE'
    if any(int(facts[k]) for k in ('events_unanchored', 'lines_skipped',
                                   'utf8_decode_errors', 'previews_truncated')):
        return 'PARTIAL'
    return 'PASS'


def query_timeline(store: CaseStore, case_id: str, *, text: str | None = None,
                   start_utc: str | None = None, end_utc: str | None = None,
                   artifact_id: str | None = None, include_unanchored: bool = False,
                   offset: int = 0, limit: int = MAX_QUERY_LIMIT) -> dict[str, Any]:
    if (not isinstance(offset, int) or isinstance(offset, bool) or
            not 0 <= offset <= MAX_QUERY_OFFSET):
        raise CaseError('Invalid timeline offset')
    if (not isinstance(limit, int) or isinstance(limit, bool) or
            not 1 <= limit <= MAX_QUERY_LIMIT):
        raise CaseError('Invalid timeline result limit')
    if not isinstance(include_unanchored, bool):
        raise CaseError('include_unanchored must be boolean')
    if artifact_id is not None and (not isinstance(artifact_id, str) or not CASE_ID.fullmatch(artifact_id)):
        raise CaseError('Invalid source artifact identifier')
    if text is not None and (not isinstance(text, str) or not 1 <= len(text) <= MAX_QUERY or
                             not text.isprintable()):
        raise CaseError('Invalid search term')
    start, end = _valid_range(start_utc), _valid_range(end_utc)
    if start and end and start > end:
        raise CaseError('Timeline range start must precede range end')
    with store._locked(case_id) as (folder, manifest):
        db = _checked_timeline(folder, manifest)
        try:
            clauses: list[str] = []
            args: list[Any] = []
            if artifact_id is not None:
                found = db.execute('SELECT 1 FROM sources WHERE artifact_id=?', (artifact_id,)).fetchone()
                if found is None:
                    raise CaseError('Artifact is not an indexed timeline source')
                clauses.append('artifact_id=?')
                args.append(artifact_id)
            if start is not None or end is not None:
                # Unanchored records cannot truthfully be placed inside a UTC range.
                clauses.append('timestamp_utc IS NOT NULL')
                if start:
                    clauses.append('timestamp_utc>=?')
                    args.append(start)
                if end:
                    clauses.append('timestamp_utc<=?')
                    args.append(end)
            elif not include_unanchored:
                clauses.append('timestamp_utc IS NOT NULL')
            if text is not None:
                term = text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                clauses.append("excerpt LIKE ? ESCAPE '\\' COLLATE NOCASE")
                args.append('%' + term + '%')
            where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
            query = ('SELECT artifact_id,line_no,timestamp_utc,source_timestamp,time_quality,'
                     'format,level_hint,excerpt FROM events' + where +
                     ' ORDER BY timestamp_utc IS NULL, timestamp_utc,artifact_id,line_no LIMIT ? OFFSET ?')
            rows = db.execute(query, (*args, limit + 1, offset)).fetchall()
            facts = dict(db.execute('SELECT key,value FROM facts'))
        except sqlite3.DatabaseError as exc:
            raise CaseError('Timeline query index unavailable or invalid') from exc
        finally:
            db.close()
        events = [dict(r) for r in rows[:limit]]
        more = len(rows) > limit
        next_page = offset + limit
        pagination_limited = more and next_page > MAX_QUERY_OFFSET
        return {'status': 'PARTIAL' if pagination_limited else _result_status(facts),
                'case_id': case_id, 'offset': offset,
                'next_offset': next_page if more and not pagination_limited else None,
                'limit': limit, 'events': events, 'has_more': more and not pagination_limited,
                'pagination_bound_reached': pagination_limited,
                'more_matching_events_outside_pagination_bound': pagination_limited,
                'maximum_page_offset': MAX_QUERY_OFFSET,
                'sources_indexed': int(facts['artifacts_indexed']),
                'events_unanchored': int(facts['events_unanchored']),
                'lines_skipped': int(facts['lines_skipped']),
                'utf8_decode_errors': int(facts['utf8_decode_errors']),
                'previews_truncated': int(facts['previews_truncated']),
                'search_redacted_previews_only': text is not None,
                'evidence_excerpts_are_untrusted': True,
                'source_content_rehashed_on_query': False,
                'built_at': facts['built_at'],
                'time_filter_excludes_unanchored': bool(start or end),
                'note': 'Event order is evidence order, not proof of root cause; redaction is best effort'}


def timeline_sources(store: CaseStore, case_id: str, *, offset: int = 0) -> dict[str, Any]:
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_SOURCE_OFFSET:
        raise CaseError('Invalid timeline source offset')
    with store._locked(case_id) as (folder, manifest):
        db = _checked_timeline(folder, manifest)
        try:
            rows = db.execute('''SELECT artifact_id,sha256,bytes,scanned,indexed,skipped,unanchored,
                                        decode_errors,preview_truncated
                                 FROM sources ORDER BY artifact_id LIMIT 21 OFFSET ?''', (offset,)).fetchall()
            facts = dict(db.execute('SELECT key,value FROM facts'))
        except sqlite3.DatabaseError as exc:
            raise CaseError('Timeline source summary unavailable') from exc
        finally:
            db.close()
        return {'case_id': case_id, 'status': _result_status(facts),
                'sources': [dict(r) for r in rows[:20]],
                'next_offset': offset + 20 if len(rows) > 20 else None,
                'events_indexed': int(facts['events_indexed']),
                'events_unanchored': int(facts['events_unanchored']),
                'lines_skipped': int(facts['lines_skipped']),
                'utf8_decode_errors': int(facts['utf8_decode_errors']),
                'previews_truncated': int(facts['previews_truncated']),
                'redaction_best_effort': True}


def timeline_summary(store: CaseStore, case_id: str) -> dict[str, Any]:
    """Bounded aggregate counts; no user-controlled SQL or raw event disclosure."""
    with store._locked(case_id) as (folder, manifest):
        db = _checked_timeline(folder, manifest)
        try:
            facts = dict(db.execute('SELECT key,value FROM facts'))
            by_format = db.execute('SELECT format, COUNT(*) FROM events GROUP BY format ORDER BY format').fetchall()
            by_level = db.execute('''SELECT COALESCE(level_hint,'UNCLASSIFIED'),COUNT(*)
                                     FROM events GROUP BY COALESCE(level_hint,'UNCLASSIFIED')
                                     ORDER BY COUNT(*) DESC''').fetchall()
            # A high event rate is a volume observation, not evidence that the
            # corresponding events were errors or that they caused an incident.
            windows = db.execute('''SELECT substr(timestamp_utc,1,16) AS minute_utc,COUNT(*) AS count
                                    FROM events WHERE timestamp_utc IS NOT NULL
                                    GROUP BY substr(timestamp_utc,1,16)
                                    ORDER BY count DESC, minute_utc LIMIT 10''').fetchall()
        except sqlite3.DatabaseError as exc:
            raise CaseError('Timeline summary unavailable') from exc
        finally:
            db.close()
        return {'status': _result_status(facts),
                'case_id': case_id, 'sources_indexed': int(facts['artifacts_indexed']),
                'events_indexed': int(facts['events_indexed']),
                'events_unanchored': int(facts['events_unanchored']),
                'lines_skipped': int(facts['lines_skipped']),
                'utf8_decode_errors': int(facts['utf8_decode_errors']),
                'previews_truncated': int(facts['previews_truncated']),
                'formats': [{'format': row[0], 'count': row[1]} for row in by_format],
                'level_hints': [{'hint': row[0], 'count': row[1]} for row in by_level],
                'top_minute_volumes': [{'minute_utc': row[0]+'Z', 'count': row[1]} for row in windows],
                'built_at': facts['built_at'],
                'note': 'Lexical level hints and event volume are not a causal diagnosis'}
