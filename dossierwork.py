"""Local reviewed, attributed reasoning; never automatically established cause."""
import hashlib
import json
import os
import re
import secrets

from casework import CaseError, CASE_ID, _clean_line, _private_directory, _regular_open
from capacitywork import admission_lock, verify_committed_reserve
from correlationwork import _checked_correlation, REVISION

MAX_BYTES=4500
MAX_SOURCE=64*1024*1024
MAX_TOTAL_SOURCE=128*1024*1024
MAX_DOSSIERS=64
STATES={'PROPOSED','TESTED','DISCONFIRMED','OPERATOR_ACCEPTED'}


def canonical(data):
    return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def digest(data):return hashlib.sha256(canonical(data)).hexdigest()


def _text(value,limit=180,empty=False):
    if type(value) is not str or len(value)>limit or (not value and not empty) or (value and not value.isprintable()):
        raise CaseError('Invalid bounded dossier text')
    return _clean_line(value)


def _refs(value,db):
    if type(value) is not list or len(value)>2:raise CaseError('Dossier reference budget exceeded')
    result=[]
    for item in value:
        short={'event_id','source_sha256'}
        full=short|{'artifact_id','locator_type','locator_number'}
        if type(item) is not dict or set(item) not in (short,full) or type(item['event_id']) is not int:
            raise CaseError('Exact dossier event identity required')
        row=db.execute('SELECT e.artifact_id,e.kind,e.locator_type,e.locator_number,s.sha256,s.kind AS source_kind FROM events e JOIN sources s ON s.artifact_id=e.artifact_id WHERE e.id=?',(item['event_id'],)).fetchone()
        if row is None or item['source_sha256']!=row['sha256']:raise CaseError('Dossier source reference unavailable or stale')
        kinds={'text':'line','pcap':'packet','pcapng':'packet','evtx':'record'}
        if (type(row['artifact_id']) is not str or not CASE_ID.fullmatch(row['artifact_id']) or
                row['kind']!=row['source_kind'] or row['kind'] not in kinds or
                row['locator_type']!=kinds[row['kind']] or type(row['locator_number']) is not int or row['locator_number']<1):
            raise CaseError('Invalid dossier portable evidence locator')
        resolved={**item,'artifact_id':row['artifact_id'],'locator_type':row['locator_type'],'locator_number':row['locator_number']}
        if set(item)==full and item!=resolved:raise CaseError('Dossier portable locator mismatch')
        if any(r['event_id']==item['event_id'] for r in result):raise CaseError('Duplicate dossier reference')
        result.append(resolved)
    return result


def _validate(folder,manifest,data,*,rehash=False):
    if type(data) is not dict or set(data)!={'schema','case_id','index_revision','environment','symptoms','impact','reproduction','observed_outputs','hypotheses','conclusion','open_questions'}:
        raise CaseError('Exact dossier fields required')
    if (type(data['schema']) is not int or data['schema']!=1 or data['case_id']!=folder.name or
            type(data['index_revision']) is not str or not REVISION.fullmatch(data['index_revision'])):
        raise CaseError('Invalid dossier case or revision')
    if type(data['environment']) is not dict or set(data['environment'])!={'product','version'}:
        raise CaseError('Explicit dossier product and version required')
    clean={**data,'environment':{k:_text(v,64) for k,v in data['environment'].items()}}
    for k in ('symptoms','impact','observed_outputs'):clean[k]=_text(data[k],240)
    for k in ('reproduction','open_questions'):
        if type(data[k]) is not list or len(data[k])>3:raise CaseError('Dossier statement budget exceeded')
        clean[k]=[_text(v) for v in data[k]]
    if type(data['hypotheses']) is not list or len(data['hypotheses'])>2:raise CaseError('Dossier hypothesis budget exceeded')
    db,facts=_checked_correlation(folder,manifest)
    allrefs=[]
    try:
        if facts['index_revision']!=data['index_revision']:raise CaseError('Dossier correlation revision is stale')
        hypotheses=[]
        for hypothesis in data['hypotheses']:
            if type(hypothesis) is not dict or set(hypothesis)!={'claim','status','test','observed_result','supports','contradicts'} or hypothesis['status'] not in STATES:
                raise CaseError('Invalid dossier hypothesis')
            h={k:_text(hypothesis[k],empty=k in ('test','observed_result')) for k in ('claim','test','observed_result')}
            h.update(status=hypothesis['status'],supports=_refs(hypothesis['supports'],db),contradicts=_refs(hypothesis['contradicts'],db))
            if any(v in h['contradicts'] for v in h['supports']):raise CaseError('Same observation cannot support and contradict one hypothesis')
            if h['status']=='PROPOSED':
                if h['observed_result']:raise CaseError('Proposed hypothesis cannot claim a performed test result')
            elif not h['test'] or not h['observed_result'] or not (h['supports'] or h['contradicts']):
                raise CaseError('Tested dossier reasoning needs a test, result and evidence')
            if h['status']=='DISCONFIRMED' and not h['contradicts']:raise CaseError('Disconfirmed hypothesis needs contradicting evidence')
            if h['status']=='OPERATOR_ACCEPTED' and not h['supports']:raise CaseError('Accepted hypothesis needs supporting evidence')
            allrefs+=h['supports']+h['contradicts'];hypotheses.append(h)
        clean['hypotheses']=hypotheses
        c=data['conclusion']
        if c is not None:
            if type(c) is not dict or set(c)!={'statement','fix','applies_to_version','validation','references'}:
                raise CaseError('Invalid attributed dossier conclusion')
            c={**{k:_text(c[k]) for k in ('statement','fix','applies_to_version','validation')},'references':_refs(c['references'],db)}
            if not c['references'] or not any(h['status']=='OPERATOR_ACCEPTED' for h in hypotheses):
                raise CaseError('Conclusion needs operator-accepted reasoning and evidence')
            if c['applies_to_version']!=clean['environment']['version']:raise CaseError('Conclusion applicability version mismatch')
            allrefs+=c['references']
        clean['conclusion']=c
        if rehash:
            total=0
            for aid in sorted({db.execute('SELECT artifact_id FROM events WHERE id=?',(r['event_id'],)).fetchone()[0] for r in allrefs}):
                # Correlation already binds registered source metadata; rehash referenced bytes at acceptance.
                source=db.execute('SELECT sha256 FROM sources WHERE artifact_id=?',(aid,)).fetchone()[0]
                path=folder/'originals'/aid
                fd,info=_regular_open(path)
                with os.fdopen(fd,'rb') as stream:
                    total+=info.st_size
                    if info.st_nlink!=1 or info.st_size>MAX_SOURCE or total>MAX_TOTAL_SOURCE:raise CaseError('Dossier source rehash budget exceeded')
                    actual=hashlib.sha256();size=0
                    for block in iter(lambda:stream.read(1024*1024),b''):
                        size+=len(block)
                        if size>info.st_size:raise CaseError('Dossier source grew')
                        actual.update(block)
                    after=os.fstat(stream.fileno())
                    if (actual.hexdigest()!=source or size!=info.st_size or
                        (info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
                        raise CaseError('Dossier original bytes changed')
    finally:db.close()
    if len(canonical(clean))>MAX_BYTES:raise CaseError('Dossier output budget exceeded')
    return clean


def prepare(store,data):
    if type(data) is not dict or type(data.get('case_id')) is not str or not CASE_ID.fullmatch(data['case_id']):raise CaseError('Invalid dossier case')
    with store._locked(data['case_id']) as (folder,manifest):
        clean=_validate(folder,manifest,data,rehash=True)
        _check_report_fit(folder,manifest,clean)
    return {'dossier':clean,'review_sha256':digest(clean),
        'disclosure':'Reviewed prose and evidence references become MCP-visible. Masking is incomplete. Review every field.',
        'authority':'OPERATOR_SUPPLIED_INTERPRETATION_NOT_INDEPENDENTLY_PROVEN'}


def accept(store,data,review_sha256,*,interactive=False):
    if interactive is not True:raise CaseError('Interactive dossier disclosure review required')
    preview=prepare(store,data)
    if type(review_sha256) is not str or review_sha256!=preview['review_sha256']:raise CaseError('Dossier review changed')
    with admission_lock(store):
        verify_committed_reserve(store,extra_bytes=2*MAX_BYTES)
        with store._locked(data['case_id']) as (folder,manifest):
            clean=_validate(folder,manifest,data,rehash=True)
            if digest(clean)!=review_sha256:raise CaseError('Dossier review changed')
            _check_report_fit(folder,manifest,clean)
            directory=folder/'rca-dossiers';_private_directory(directory,strict=True)
            path=directory/(clean['index_revision']+'.json')
            payload=canonical(clean)
            if path.exists() or path.is_symlink():
                existing=load_locked(folder,manifest,clean['index_revision'])
                if existing['review_sha256']!=review_sha256:raise CaseError('Dossier revision already accepted; rebuild correlation for a new review')
            else:
                if len(list(directory.iterdir()))>=MAX_DOSSIERS:raise CaseError('Dossier count budget reached')
                temp=directory/('.tmp-'+secrets.token_hex(16))
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                try:
                    with os.fdopen(fd,'wb') as stream:stream.write(payload);stream.flush();os.fsync(stream.fileno())
                    os.replace(temp,path)
                    dfd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
                    try:os.fsync(dfd)
                    finally:os.close(dfd)
                finally:temp.unlink(missing_ok=True)
    return {'status':'LOCAL_REVIEWED_DOSSIER','review_sha256':review_sha256,'external_disclosure_approved':False}


def _projection(clean):
    return {'content':clean,'review_sha256':digest(clean),
        'authority':'OPERATOR_SUPPLIED_INTERPRETATION_NOT_INDEPENDENTLY_PROVEN',
        'external_disclosure_approved':False,'originals_rehashed_at_acceptance_only':True}


def _check_report_fit(folder,manifest,clean):
    from reportwork import _build_locked,attach_dossier
    report=_build_locked(folder,manifest,clean['index_revision'])
    attach_dossier(report,_projection(clean))
    if len(canonical(report))>10500:raise CaseError('Dossier exceeds combined report output budget')


def load_locked(folder,manifest,revision):
    directory=folder/'rca-dossiers'
    if not directory.exists() and not directory.is_symlink():return None
    _private_directory(directory,strict=True)
    path=directory/(revision+'.json')
    if not path.exists() and not path.is_symlink():return None
    fd,info=_regular_open(path)
    with os.fdopen(fd,'rb') as stream:
        if info.st_nlink!=1 or info.st_size>MAX_BYTES:raise CaseError('Unsafe dossier file')
        raw=stream.read(MAX_BYTES+1)
    try:data=json.loads(raw);clean=_validate(folder,manifest,data)
    except (ValueError,KeyError,TypeError) as exc:raise CaseError('Invalid stored dossier') from exc
    if canonical(clean)!=raw:raise CaseError('Stored dossier identity changed')
    return _projection(clean)
