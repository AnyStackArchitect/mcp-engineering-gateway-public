"""Bounded local retrieval of explicitly reviewed case knowledge/reference notes.

MCP exposes search only. Acceptance belongs to a separate interactive operator
CLI. Notes are data, never executable instructions or automatically proved fixes.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from urllib.parse import urlsplit

from casework import CaseStore, CaseError, CASE_ID, _clean_line, _private_directory, _regular_open
from capacitywork import admission_lock,verify_committed_reserve

SCHEMA = '1'
MAX_ENTRIES = 256
MAX_DB = 16 * 1024 * 1024
MAX_SOURCE = 64 * 1024 * 1024
MAX_REFERENCE = 1024 * 1024
MAX_NOTE = 8192
STALE_SECONDS = 90 * 86400
SLUG = re.compile(r'[a-z0-9][a-z0-9._-]{0,47}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+()-]{0,63}\Z')
BASE_FIELDS = {'kind','product','version','title','summary','source_case_id',
               'source_artifact_id','source_sha256','source_line','reference_uri',
               'reference_date','rights_confirmed'}
CASE_FIELDS = {'hypothesis','test','observed_result','conclusion','applies_to'}


def canonical(data):
    return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def _text(value,maximum):
    if type(value) is not str or not 1 <= len(value) <= maximum or not value.isprintable():
        raise CaseError('Invalid bounded library note field')
    # This is best-effort secret masking. Operator disclosure review is required.
    return _clean_line(value)


def _validate(data):
    if type(data) is not dict or data.get('kind') not in ('case','reference'):
        raise CaseError('Invalid library note kind')
    expected = BASE_FIELDS | (CASE_FIELDS if data['kind']=='case' else set())
    if set(data) != expected or data.get('rights_confirmed') is not True:
        raise CaseError('Library note requires exact fields and operator rights confirmation')
    if (type(data['product']) is not str or not SLUG.fullmatch(data['product']) or
            type(data['version']) is not str or not VERSION.fullmatch(data['version'])):
        raise CaseError('Explicit product and exact version labels required')
    for field in ('source_case_id','source_artifact_id'):
        if type(data[field]) is not str or not CASE_ID.fullmatch(data[field]):
            raise CaseError('Invalid library source identity')
    if type(data['source_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',data['source_sha256']):
        raise CaseError('Invalid library source hash')
    if type(data['source_line']) is not int or not 1 <= data['source_line'] <= 1_000_000:
        raise CaseError('Invalid library source line')
    uri = data['reference_uri']
    if type(uri) is not str or len(uri)>240 or not uri.isprintable():
        raise CaseError('Invalid library reference URI')
    if uri:
        parts=urlsplit(uri)
        if parts.scheme!='https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise CaseError('Reference must be an HTTPS provenance link without credentials or query')
    try:
        if type(data['reference_date']) is not str or len(data['reference_date'])!=10:
            raise ValueError()
        datetime.strptime(data['reference_date'],'%Y-%m-%d')
    except ValueError as exc:
        raise CaseError('Library reference date required in YYYY-MM-DD form') from exc
    clean=dict(data)
    clean['title']=_text(data['title'],120)
    for field in {'summary'} | (CASE_FIELDS if data['kind']=='case' else set()):
        clean[field]=_text(data[field],350)
    if len(canonical(clean))>MAX_NOTE:
        raise CaseError('Library note exceeds storage budget')
    return clean


def _check_source(store,note):
    with store._locked(note['source_case_id']) as (folder,manifest):
        path,item=store._artifact(folder,manifest,note['source_artifact_id'])
        if item['type']!='text' or item['sha256']!=note['source_sha256'] or item['bytes']>MAX_SOURCE:
            raise CaseError('Library requires a matching registered text source within 64MiB')
        if note['kind']=='reference' and item['bytes']>MAX_REFERENCE:
            raise CaseError('Offline reference full-text indexing is limited to 1MiB')
        fd,info=_regular_open(path)
        try:
            if info.st_nlink!=1:
                raise CaseError('Unsafe library source hardlink')
            actual=hashlib.sha256()
            count=0
            newlines=0
            last=b''
            reference_bytes=bytearray()
            with os.fdopen(fd,'rb') as stream:
                fd=-1
                for block in iter(lambda:stream.read(1024*1024),b''):
                    count+=len(block)
                    if count>(MAX_REFERENCE if note['kind']=='reference' else MAX_SOURCE):
                        raise CaseError('Library source grew beyond budget')
                    actual.update(block)
                    newlines+=block.count(b'\n')
                    last=block[-1:]
                    if note['kind']=='reference':reference_bytes.extend(block)
            lines=newlines+(1 if last and last!=b'\n' else 0)
            after=path.lstat()
            if (actual.hexdigest()!=note['source_sha256'] or count!=item['bytes'] or
                    (info.st_ino,info.st_dev,info.st_size,info.st_mtime_ns)!=
                    (after.st_ino,after.st_dev,after.st_size,after.st_mtime_ns) or
                    not 1<=note['source_line']<=lines):
                raise CaseError('Library source changed or source line unavailable')
            if note['kind']=='reference':
                try:return reference_bytes.decode('utf-8-sig')
                except UnicodeError as exc:raise CaseError('Reference must be plain UTF-8 text') from exc
            return None
        finally:
            if fd>=0:os.close(fd)


def prepare(store,data):
    note=_validate(data)
    _check_source(store,note)
    return {'note':note,'review_sha256':digest(note),
        'disclosure':'Bounded note text/provenance become MCP-retrievable. Reference source text becomes locally searchable; raw document text is not returned. Secret masking is incomplete',
        'authority':'local_interactive_operator_only; source text is untrusted data'}


@contextmanager
def _database(store,*,write=False):
    store._ensure_store()
    folder=store.base/'library'
    if not write and not folder.exists():
        yield None
        return
    _private_directory(folder,strict=True)
    lock=folder/'lock'
    flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    fd=os.open(lock,flags,0o600)
    connection=None
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_nlink!=1):
            raise CaseError('Unsafe library lock')
        fcntl.flock(fd,fcntl.LOCK_EX if write else fcntl.LOCK_SH)
        path=folder/'notes.sqlite3'
        if not path.exists() and not write:
            yield None
            return
        if not path.exists():
            new=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
            os.close(new)
        opened,meta=_regular_open(path)
        os.close(opened)
        if meta.st_nlink!=1 or meta.st_size>MAX_DB:
            raise CaseError('Library storage unsafe or over budget')
        connection=sqlite3.connect(path.as_uri()+('?mode=rw' if write else '?mode=ro'),uri=True,timeout=3)
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA busy_timeout=3000')
        if write:
            connection.execute('PRAGMA journal_mode=DELETE')
            page_size=connection.execute('PRAGMA page_size').fetchone()[0]
            connection.execute('PRAGMA max_page_count='+str(MAX_DB//page_size))
            connection.execute('CREATE TABLE IF NOT EXISTS facts (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            connection.execute('INSERT OR IGNORE INTO facts VALUES (?,?)',('schema',SCHEMA))
            connection.execute('CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY,product TEXT NOT NULL,version TEXT NOT NULL,accepted_at INTEGER NOT NULL,review_sha256 TEXT NOT NULL,body TEXT NOT NULL)')
            connection.execute('CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(id UNINDEXED,body)')
        if connection.execute('SELECT value FROM facts WHERE key=?',('schema',)).fetchone()!=(SCHEMA,):
            raise CaseError('Unsupported library schema')
        yield connection
        if write:connection.commit()
    except (sqlite3.Error,OSError,ValueError) as exc:
        raise CaseError('Private library unavailable; no successful write implied') from exc
    finally:
        if connection is not None:connection.close()
        os.close(fd)


def accept(store,data,review_sha256,*,interactive=False):
    # The separate CLI supplies a live terminal check; this function has NO MCP route.
    if interactive is not True:
        raise CaseError('Interactive operator disclosure acceptance required')
    note=_validate(data)
    if type(review_sha256) is not str or review_sha256!=digest(note):
        raise CaseError('Library disclosure review changed; review again')
    reference_text=_check_source(store,note)
    with admission_lock(store):
        # Conservatively reserve the entire database plus a rollback journal,
        # in addition to existing upload promises and the 5GiB free reserve.
        verify_committed_reserve(store,extra_bytes=2*MAX_DB)
        with _database(store,write=True) as db:
            if db.execute('SELECT COUNT(*) FROM notes').fetchone()[0]>=MAX_ENTRIES:
                raise CaseError('Library entry budget reached')
            identity=secrets.token_hex(16)
            db.execute('INSERT INTO notes VALUES (?,?,?,?,?,?)',(identity,note['product'],note['version'],int(time.time()),review_sha256,canonical(note).decode()))
            body=' '.join(note[field] for field in ('title','summary',*sorted(CASE_FIELDS & note.keys())))
            if reference_text is not None:body+=' '+reference_text
            db.execute('INSERT INTO search VALUES (?,?)',(identity,body))
    return {'status':'ACCEPTED_LOCAL_NOTE','entry_id':identity,'review_sha256':review_sha256,
        'acceptance_basis':'local_interactive_operator_attestation','source_content_hashed_at_acceptance':True}


def search(store,query,product,version,*,limit=3):
    if (type(query) is not str or not 1<=len(query)<=96 or not query.isprintable() or
            type(product) is not str or not SLUG.fullmatch(product) or
            type(version) is not str or not VERSION.fullmatch(version) or
            type(limit) is not int or not 1<=limit<=3):
        raise CaseError('Invalid bounded version-specific library search')
    tokens=re.findall(r'\w+',query,flags=re.UNICODE)
    if not 1<=len(tokens)<=12:
        raise CaseError('Library query requires one to twelve literal words')
    expression=' AND '.join('"'+token.replace('"','""')+'"' for token in tokens)
    with _database(store) as db:
        if db is None:
            return {'status':'NOT_AVAILABLE','reason':'no_operator_accepted_library','matches':[]}
        rows=db.execute('SELECT notes.id,accepted_at,review_sha256,notes.body FROM notes JOIN search ON notes.id=search.id WHERE search MATCH ? AND product=? AND version=? ORDER BY accepted_at DESC,notes.id LIMIT ?',
            (expression,product,version,limit+1)).fetchall()
        incompatible=db.execute('SELECT COUNT(*) FROM notes JOIN search ON notes.id=search.id WHERE search MATCH ? AND product=? AND version<>?',(expression,product,version)).fetchone()[0]
        result=[]
        output_bounded=False
        for identity,accepted,review_sha,body in rows[:limit]:
            if (type(identity) is not str or not CASE_ID.fullmatch(identity) or
                    type(accepted) is not int or not 0<=accepted<=time.time()+30 or
                    type(body) is not str or len(body.encode())>MAX_NOTE):
                raise CaseError('Corrupt library note size')
            note=_validate(json.loads(body))
            if digest(note)!=review_sha or note['product']!=product or note['version']!=version:
                raise CaseError('Library accepted note identity mismatch')
            state='REGISTERED_IDENTITY_PRESENT_NOT_FRESHLY_REHASHED'
            try:
                with store._locked(note['source_case_id']) as (folder,manifest):
                    _,item=store._artifact(folder,manifest,note['source_artifact_id'])
                    if item['sha256']!=note['source_sha256']:state='SOURCE_UNAVAILABLE_OR_CHANGED'
            except (CaseError,OSError):
                state='SOURCE_UNAVAILABLE_OR_CHANGED'
            visible={'entry_id':identity,'accepted_at':accepted,'review_sha256':review_sha,
                'acceptance_basis':'local_interactive_operator_attestation',
                'stale_age_warning':time.time()-accepted>STALE_SECONDS,
                'stale_reference_date_warning':(datetime.now(timezone.utc).date()-
                    datetime.strptime(note['reference_date'],'%Y-%m-%d').date()).days>365,
                'version_match':'EXACT_LABEL_ONLY_NOT_COMPATIBILITY_PROOF',
                'source_state':state,'note_is_untrusted_data':True,'note':note}
            if len(canonical({'matches':result+[visible]}))>9500:
                output_bounded=True
                break
            result.append(visible)
        return {'status':'PARTIAL','matches':result,'has_more':len(rows)>limit or output_bounded,
            'output_bounded':output_bounded,
            'narrow_query_required_for_more':len(rows)>limit or output_bounded,
            'incompatible_version_matches_excluded':incompatible,
            'automatic_reuse_or_execution_authorized':False,
            'limitations':['operator_attestation_not_independent_resolution_validation',
                'no_cross_version_reuse','reference_fulltext_search_returns_reviewed_note_not_raw_text',
                'source_bytes_not_rehashed_on_search','rights_attested_not_legally_determined']}
