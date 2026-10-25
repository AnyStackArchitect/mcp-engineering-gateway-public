#!/usr/bin/env python3
"""Offline Windows EVTX metadata triage via an optional python-evtx parser.

No EventData payload, usernames, hostnames or message strings leave the case.
Missing parser produces NOT_AVAILABLE, never an invented successful analysis.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
from typing import Any
import xml.etree.ElementTree as ET

from casework import CaseError, CaseStore, _regular_open
from producerwork import record as producer_identity

SCHEMA = '2'
MAX_EVTX = 8 * 1024 ** 3
MAX_EVENTS = 500_000
MAX_XML = 1024 * 1024
MAX_OFFSET = 10000


class EvtxError(CaseError):
    pass


def _metadata_and_channel(xml: str) -> tuple[int | None, str | None, str | None, str | None, str | None]:
    """Return *only* System/EventID/Level/Provider alias/SystemTime."""
    if len(xml) > MAX_XML or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():
        raise ValueError('Oversized or unsafe XML event')
    root = ET.fromstring(xml)
    systems = root.findall('{*}System')
    if root.tag.rsplit('}', 1)[-1] != 'Event' or len(systems) != 1:
        raise ValueError('Windows event System element absent')
    system = systems[0]
    if any(len(system.findall('{*}' + name)) > 1 for name in
           ('EventID', 'Level', 'Provider', 'TimeCreated', 'Channel')):
        raise ValueError('Ambiguous Windows event System metadata')
    eventid = system.find('{*}EventID')
    level = system.find('{*}Level')
    provider = system.find('{*}Provider')
    created = system.find('{*}TimeCreated')
    value = int(eventid.text) if eventid is not None and eventid.text and eventid.text.isdigit() else None
    if value is not None and not 0 <= value <= 65535:
        value = None
    leveltxt = level.text[:3] if level is not None and level.text and level.text.isdigit() else None
    name = provider.get('Name', '') if provider is not None else ''
    public_providers = {'Microsoft-Windows-Security-Auditing', 'Microsoft-Windows-Kernel-Boot',
                        'Microsoft-Windows-FailoverClustering', 'Service Control Manager',
                        'Microsoft-Windows-Hyper-V-Worker', 'Microsoft-Windows-Hyper-V-VMMS',
                        'Microsoft-Windows-Eventlog'}
    if name in public_providers:
        provider_label = name
    else:
        provider_label = 'provider-' + hashlib.sha256(name.encode('utf-8', errors='replace')).hexdigest()[:12] if name else None
    raw = created.get('SystemTime', '') if created is not None else ''
    stamp = None
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
            if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                stamp = parsed.astimezone(timezone.utc).isoformat(timespec='microseconds')
        except (ValueError, OverflowError):
            pass
    channel_element = system.find('{*}Channel')
    channel = channel_element.text if channel_element is not None else None
    # Custom channel names can encode private service/customer identities.
    channel = channel if channel in ('System', 'Security', 'Application') else None
    return value, leveltxt, provider_label, stamp, channel


def _metadata(xml: str) -> tuple[int | None, str | None, str | None, str | None]:
    """Compatibility contract used by the independently invoked real parser probe."""
    return _metadata_and_channel(xml)[:4]


def _index_path(folder: Path, artifact_id: str) -> Path:
    return folder / 'indexes' / ('evtx-' + artifact_id + '.sqlite3')


def analyze_evtx(store: CaseStore, case_id: str, artifact_id: str, *, should_cancel=None) -> dict[str, Any]:
    with store._locked(case_id) as (folder, manifest):
        path, item = store._artifact(folder, manifest, artifact_id)
        if item['type'] != 'evtx':
            raise EvtxError('Windows EVTX artifact required')
        if item['bytes'] > MAX_EVTX or item['bytes'] < 4096:
            raise EvtxError('Windows EVTX source size unsupported')
        fd, info = _regular_open(path)
        if info.st_nlink != 1:
            os.close(fd)
            raise EvtxError('Windows EVTX source must not be hardlinked')
        try:
            with os.fdopen(fd, 'rb') as src:
                fd = -1
                if src.read(8) != b'ElfFile\x00':
                    raise EvtxError('Invalid Windows EVTX magic')
                src.seek(0)
                sha = hashlib.sha256()
                for chunk in iter(lambda: src.read(1024 * 1024), b''):
                    if should_cancel is not None:
                        should_cancel()
                    sha.update(chunk)
            if sha.hexdigest() != item['sha256']:
                raise EvtxError('EVTX evidence changed after registration')
        finally:
            if fd >= 0:
                os.close(fd)
        try:
            from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
            from importlib.metadata import version, PackageNotFoundError
            try:
                provider_version = version('python-evtx')
            except PackageNotFoundError:
                provider_version = 'unknown'
        except ImportError:
            return {'status':'NOT_AVAILABLE', 'case_id':case_id, 'artifact_id':artifact_id,
                    'missing_provider':'python-evtx',
                    'note':'EVTX metadata parser unavailable; no records analyzed or success implied'}
        final = _index_path(folder, artifact_id)
        if final.is_symlink():
            raise EvtxError('Unsafe EVTX index symlink')
        temp = folder / 'indexes' / ('.tmp-evtx-' + secrets.token_hex(12) + '.sqlite3')
        filefd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.close(filefd)
        conn = None
        total = skipped = untimed = 0
        try:
            conn = sqlite3.connect(str(temp), timeout=3)
            conn.execute('PRAGMA journal_mode=DELETE')
            conn.execute('PRAGMA trusted_schema=OFF')
            conn.execute('CREATE TABLE records (ordinal INTEGER PRIMARY KEY, record_num INTEGER, event_id INTEGER, provider TEXT, level TEXT, utc TEXT, channel TEXT)')
            conn.execute('CREATE TABLE facts (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            try:
                with Evtx(str(path)) as stream:
                    for row in stream.records():
                        if should_cancel is not None and total % 128 == 0:
                            should_cancel()
                        total += 1
                        if total > MAX_EVENTS:
                            raise EvtxError('EVTX record limit exceeded; cannot claim complete coverage')
                        try:
                            xml = row.xml()
                            if not isinstance(xml, str):
                                raise ValueError('XML output not text')
                            eventid, level, provider, utc, channel = _metadata_and_channel(xml)
                            record_num = int(row.record_num()) if callable(getattr(row, 'record_num', None)) else total
                            if utc is None:
                                untimed += 1
                            conn.execute('INSERT INTO records VALUES (?,?,?,?,?,?,?)',
                                         (total, record_num, eventid, provider, level, utc, channel))
                        except (ValueError, ET.ParseError, OverflowError):
                            skipped += 1
            except EvtxError:
                raise
            except Exception as exc:
                raise EvtxError('EVTX parser failed; no complete index published') from exc
            after = path.lstat()
            if (after.st_dev != info.st_dev or after.st_ino != info.st_ino or
                    after.st_mtime_ns != info.st_mtime_ns or after.st_size != info.st_size):
                raise EvtxError('EVTX evidence changed during analysis')
            facts = {'schema':SCHEMA,'source_sha256':item['sha256'], 'size':str(info.st_size),
                     'producer_identity':json.dumps(producer_identity('evtxwork','casework'),sort_keys=True),
                     'inode':str(info.st_ino), 'device':str(info.st_dev), 'mtime_ns':str(info.st_mtime_ns),
                     'provider_version':provider_version,'records_examined':str(total),
                     'records_skipped':str(skipped),'records_without_utc':str(untimed)}
            conn.executemany('INSERT INTO facts VALUES (?,?)', list(facts.items()))
            conn.commit()
            conn.close()
            conn = None
            if should_cancel is not None:
                should_cancel()
            os.replace(temp, final)
        finally:
            if conn is not None:
                conn.close()
            temp.unlink(missing_ok=True)
        return {'status':'PARTIAL' if skipped or untimed or total == 0 else 'PASS',
                'sha256':item['sha256'], 'case_id':case_id, 'artifact_id':artifact_id,
                'records_examined':total,'records_skipped':skipped,'records_without_utc':untimed,
                'provider':'python-evtx', 'version':provider_version,
                'note':'Windows EventData/UserData, original provider data and host/user identities are not returned'}


def _get_index(store: CaseStore, case_id: str, artifact_id: str) -> tuple[sqlite3.Connection, dict[str,str]]:
    with store._locked(case_id) as (folder, manifest):
        path, item = store._artifact(folder, manifest, artifact_id)
        if item['type'] != 'evtx':
            raise EvtxError('Windows EVTX artifact required')
        target = _index_path(folder, artifact_id)
        if target.is_symlink():
            raise EvtxError('Windows EVTX index symlink refused')
        try:
            info = target.lstat()
        except FileNotFoundError as exc:
            raise EvtxError('EVTX not indexed or parser unavailable') from exc
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise EvtxError('Windows EVTX index permissions unsafe')
        conn = None
        try:
            conn = sqlite3.connect(f'file:{target}?mode=ro', uri=True, timeout=2)
            conn.execute('PRAGMA trusted_schema=OFF')
            data = dict(conn.execute('SELECT key,value FROM facts'))
            sinfo = path.lstat()
            if (data.get('schema') != SCHEMA or data.get('source_sha256') != item['sha256'] or
                    data.get('size') != str(sinfo.st_size) or data.get('inode') != str(sinfo.st_ino) or
                    data.get('device') != str(sinfo.st_dev) or data.get('mtime_ns') != str(sinfo.st_mtime_ns)):
                raise EvtxError('EVTX index stale or source identity changed')
            return conn, data
        except (sqlite3.Error, ValueError, OSError, KeyError) as exc:
            if conn:
                conn.close()
            raise EvtxError('Windows EVTX index invalid or unavailable') from exc
        except BaseException:
            if conn:
                conn.close()
            raise


def evtx_summary(store: CaseStore, case_id: str, artifact_id: str) -> dict[str, Any]:
    db, facts = _get_index(store, case_id, artifact_id)
    try:
        events = db.execute('SELECT event_id,COUNT(*) AS n FROM records GROUP BY event_id ORDER BY n DESC,event_id LIMIT 20').fetchall()
        time = db.execute('SELECT MIN(utc),MAX(utc) FROM records WHERE utc IS NOT NULL').fetchone()
        return {'status':'PARTIAL' if int(facts['records_skipped']) or int(facts['records_without_utc']) or int(facts['records_examined']) == 0 else 'PASS',
                'sha256':facts['source_sha256'], 'case_id':case_id, 'artifact_id':artifact_id, 'records_examined':int(facts['records_examined']),
                'records_skipped':int(facts['records_skipped']), 'records_without_utc':int(facts['records_without_utc']),
                'parser':'python-evtx','parser_version':facts['provider_version'],
                'first_utc':time[0],'last_utc':time[1],
                'event_id_counts':[{'event_id':k,'count':n} for k,n in events],
                'note':'Raw event messages, usernames, hostnames and payloads excluded'}
    finally:
        db.close()


def evtx_events(store: CaseStore, case_id: str, artifact_id: str, *, event_id: int | None = None,
                offset: int = 0) -> dict[str, Any]:
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise EvtxError('Invalid Windows event offset')
    if event_id is not None and (type(event_id) is not int or not 0 <= event_id <= 65535):
        raise EvtxError('Invalid Windows event identifier')
    db, facts = _get_index(store, case_id, artifact_id)
    try:
        where = 'WHERE event_id=?' if event_id is not None else ''
        args = (event_id,) if event_id is not None else ()
        count = db.execute(f'SELECT COUNT(*) FROM records {where}',args).fetchone()[0]
        data = db.execute(f'SELECT record_num,event_id,provider,level,utc FROM records {where} ORDER BY ordinal LIMIT 21 OFFSET ?',args+(offset,)).fetchall()
        return {'case_id':case_id,'artifact_id':artifact_id,'status':'PARTIAL' if int(facts['records_skipped']) or int(facts['records_without_utc']) or int(facts['records_examined']) == 0 else 'PASS',
                'total':count,'offset':offset,'events':[{'record':n,'event_id':eid,'provider':p,'level':l,'utc':u} for n,eid,p,l,u in data[:20]],
                'has_more':len(data)>20,'payloads_excluded':True}
    finally:
        db.close()
