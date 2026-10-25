"""Metadata-only, pinned evidence reports and deliberately reviewed local ZIPs."""
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import zipfile

from capacitywork import admission_lock,verify_committed_reserve
from casework import CaseStore,CaseError,CASE_ID,_private_directory,_regular_open
from correlationwork import _checked_correlation,REVISION,MAX_CORRELATED_EVENTS,MAX_CASE_INPUTS
from eventmodel import checked_time_basis
from producerwork import record,checked
from dossierwork import load_locked as load_dossier

VERSION='0.48.0-dev.1'
MAX_EVENTS=6
MAX_PACKAGE=32768
MAX_PACKAGES=64
KINDS={'text':'line','pcap':'packet','pcapng':'packet','evtx':'record'}


def _counts(values):
    if any(type(value) is not int or not 0<=value<=8_000_000 for value in values.values()):
        raise CaseError('Invalid report analysis coverage count')
    return values


def canonical(data):
    return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def attach_dossier(report,dossier):
    report['reviewed_dossier']=dossier
    report['hypotheses']=dossier['content']['hypotheses']
    report['disclosure']['operator_reviewed_prose_included']=True


def _producer(folder,source):
    aid,kind=source['artifact_id'],source['kind']
    if source['coverage']=='MISSING_INDEX':return {'recorded_producer':{'status':'SOURCE_NOT_INDEXED'},'analysis_coverage':{'status':'MISSING_INDEX'}}
    if kind in ('text','evtx'):
        name='timeline.sqlite3' if kind=='text' else 'evtx-'+aid+'.sqlite3'
        path=folder/'indexes'/name
        fd,info=_regular_open(path);os.close(fd)
        if info.st_nlink!=1:raise CaseError('Unsafe report producer index')
        db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            facts=dict(db.execute('SELECT key,value FROM facts'))
            if kind=='text':
                names=('scanned','indexed','skipped','unanchored','decode_errors','preview_truncated')
                row=db.execute('SELECT scanned,indexed,skipped,unanchored,decode_errors,preview_truncated FROM sources WHERE artifact_id=?',(aid,)).fetchone()
                if row is None:raise CaseError('Missing report text coverage source')
                coverage=_counts(dict(zip(names,row)))
        finally:db.close()
        raw=facts.get('producer_identity')
        if raw is not None and len(raw)>8192:raise CaseError('Oversized producer identity')
        result=checked(json.loads(raw) if raw is not None else None)
        if kind=='evtx':
            version=facts.get('provider_version','unknown')
            if version!='unknown' and not re.fullmatch(r'[0-9][A-Za-z0-9.+!-]{0,31}',version):
                raise CaseError('Invalid recorded EVTX provider version')
            result={**result,'optional_provider':'python-evtx','optional_provider_version':version}
            coverage=_counts({key:int(facts[key]) for key in ('records_examined','records_skipped','records_without_utc')})
            partial=coverage['records_skipped'] or coverage['records_without_utc']
        else:partial=any(coverage[key] for key in ('skipped','unanchored','decode_errors','preview_truncated'))
        return {'recorded_producer':result,'analysis_coverage':{'status':'PARTIAL' if partial else 'PASS',**coverage}}
    path=folder/'indexes'/('protocol-'+aid+'.json')
    fd,info=_regular_open(path)
    with os.fdopen(fd,'rb') as stream:
        if info.st_nlink!=1 or info.st_size>1024*1024:raise CaseError('Unsafe report packet index')
        data=json.loads(stream.read(1024*1024+1))
    if data['status'] not in ('PASS','PARTIAL'):raise CaseError('Unknown packet analysis coverage status')
    counters=data['counters']
    coverage=_counts({key:counters.get(key,0) for key in ('packets_examined','snaplen_truncated_packets','packets_without_timestamp','unsupported_link_type')})
    coverage.update(_counts({'diagnostic_observations_retained':len(data['observations']),
                             'diagnostic_observations_omitted':data.get('observations_omitted',0)}))
    return {'recorded_producer':checked(data.get('producer_identity')),
            'analysis_coverage':{'status':data['status'],**coverage}}


def _build_locked(folder,manifest,revision):
    db,facts=_checked_correlation(folder,manifest)
    try:
        if facts['index_revision']!=revision:raise CaseError('Evidence report revision is stale')
        sources=[dict(row) for row in db.execute('SELECT artifact_id,kind,sha256,coverage,count FROM sources ORDER BY artifact_id')]
        if len(sources)>MAX_CASE_INPUTS:raise CaseError('Evidence report source budget exceeded')
        source_map={s['artifact_id']:s for s in sources}
        for source in sources:
            if (type(source['artifact_id']) is not str or not CASE_ID.fullmatch(source['artifact_id']) or
                    source['kind'] not in KINDS or not re.fullmatch('[a-f0-9]{64}',source['sha256']) or
                    source['coverage'] not in ('INDEXED','MISSING_INDEX') or
                    type(source['count']) is not int or not 0<=source['count']<=MAX_CORRELATED_EVENTS):
                raise CaseError('Invalid report source metadata')
        count=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        if not 0<=count<=MAX_CORRELATED_EVENTS:raise CaseError('Evidence report event budget exceeded')
        unknown=db.execute('SELECT COUNT(*) FROM events WHERE utc IS NULL').fetchone()[0]
        observations=[]
        selected_sources={}
        for row in db.execute('SELECT id AS event_id,artifact_id,kind,utc,time_quality,time_basis,locator_type,locator_number FROM events ORDER BY utc IS NULL,utc,kind,artifact_id,locator_number LIMIT ?', (MAX_EVENTS,)):
            observation=dict(row)
            source=source_map.get(row['artifact_id'])
            if (source is None or row['kind']!=source['kind'] or row['locator_type']!=KINDS[row['kind']] or
                    type(row['locator_number']) is not int or row['locator_number']<0 or
                    type(row['event_id']) is not int or row['event_id']<1 or
                    checked_time_basis(row['utc'],row['time_quality'])!=row['time_basis']):
                raise CaseError('Invalid report observation provenance')
            observation['source_sha256']=source['sha256']
            observations.append(observation)
            if source['artifact_id'] not in selected_sources:
                selected_sources[source['artifact_id']]={**source,**_producer(folder,source)}
        kinds=[{'kind':kind,'events':n} for kind,n in db.execute('SELECT kind,COUNT(*) FROM events GROUP BY kind ORDER BY kind')]
        if any(item['kind'] not in KINDS for item in kinds):raise CaseError('Unknown report source kind')
        result={'schema':1,'report_version':VERSION,'status':'PARTIAL',
            'case_id':folder.name,'index_revision':revision,
            'report_producer':record('reportwork','dossierwork'),
            'facts':{'indexed_events':count,'registered_sources':len(sources),
                'indexed_sources':sum(s['coverage']=='INDEXED' for s in sources),
                'events_without_utc':unknown,'missing_indexes':sum(s['coverage']=='MISSING_INDEX' for s in sources),
                'excluded_artifacts':len(manifest['artifacts'])-len(sources),'by_kind':kinds,
                'source_inventory_sha256':hashlib.sha256(canonical(sources)).hexdigest()},
            'observations':observations,'observation_sample_omitted':count-len(observations),
            'observed_source_producers':list(selected_sources.values()),
            'source_producers_omitted':len(sources)-len(selected_sources),
            'hypotheses':[], 'unknowns':['root_cause_not_established','no_hypotheses_automatically_promoted',
                'collection_completeness_unverified','clocks_and_endpoint_identity_unverified',
                'bounded_sample_not_full_timeline','original_bytes_not_rehashed_during_report',
                'producer_module_hashes_not_full_environment_attestation',
                'legacy_indexes_may_have_no_recorded_producer'],
            'disclosure':{'raw_evidence_included':False,'excerpts_included':False,
                'source_ids_hashes_and_event_times_included':True,
                'external_disclosure_approved':False,'local_operator_review_required_before_package':True}}
        dossier=load_dossier(folder,manifest,revision)
        if dossier is not None:
            attach_dossier(result,dossier)
        # Recheck all source/index identities before exposing the frozen view.
        checked_db,new_facts=_checked_correlation(folder,manifest)
        checked_db.close()
        if new_facts['index_revision']!=revision:raise CaseError('Report revision changed')
        if len(canonical(result))>10500:raise CaseError('Evidence report output budget exceeded')
        return result
    except (sqlite3.Error,ValueError,KeyError,TypeError) as exc:
        raise CaseError('Evidence report unavailable; rebuild source indexes') from exc
    finally:db.close()


def build(store,case_id,index_revision):
    if type(index_revision) is not str or not REVISION.fullmatch(index_revision):
        raise CaseError('Pinned correlation revision required')
    with store._locked(case_id) as (folder,manifest):
        result=_build_locked(folder,manifest,index_revision)
    return {**result,'review_sha256':hashlib.sha256(canonical(result)).hexdigest()}


def markdown(report):
    # Only fixed literals and validated opaque identities/numbers are rendered.
    lines=['# Private evidence report — external disclosure not approved','',
        'Case: `'+report['case_id']+'`', 'Index revision: `'+report['index_revision']+'`',
        'Review SHA256: `'+report['review_sha256']+'`','',
        'Facts: '+str(report['facts']['indexed_events'])+' indexed events; '+
        str(report['facts']['indexed_sources'])+' analysis-indexed sources of '+
        str(report['facts']['registered_sources'])+' tracked sources; '+
        str(report['facts']['events_without_utc'])+' events without UTC.','',
        'Missing source indexes: '+str(report['facts']['missing_indexes'])+
        '. Excluded artifacts: '+str(report['facts']['excluded_artifacts'])+'.','',
        '| Event | Source artifact | Locator | Declared UTC | Source SHA256 |',
        '| --- | --- | --- | --- | --- |']
    for row in report['observations']:
        lines.append('| '+str(row['event_id'])+' | `'+row['artifact_id']+'` | '+
            row['locator_type']+' '+str(row['locator_number'])+' | '+
            (row['utc'] or 'UNKNOWN')+' | `'+row['source_sha256']+'` |')
    lines+=['','Omitted from sample: '+str(report['observation_sample_omitted'])+'.','',
        '| Sampled source | Kind | Analysis coverage | Producer identity |',
        '| --- | --- | --- | --- |']
    for source in report['observed_source_producers']:
        producer='RECORDED_SOURCE_FILES' if 'modules' in source['recorded_producer'] else 'UNRECORDED'
        lines.append('| `'+source['artifact_id']+'` | '+source['kind']+' | '+
            source['analysis_coverage']['status']+' | '+producer+' |')
    lines+=['','Sources outside producer sample: '+str(report['source_producers_omitted'])+'.','',
        'Hypotheses: none automatically established. Operator reasoning, if present, is attributed below.','',
        'Unknowns: collection completeness, clock alignment, endpoint identity and root cause.',
        'Source bytes were not rehashed while rendering. Producer module hashes are not full environment attestation.',
        'Inspect report.json for recorded producer identities and source coverage.',
        'No remediation or external disclosure is authorized by this report.','']
    if 'reviewed_dossier' in report:
        lines+=['','## Operator reviewed dossier (untrusted attributed interpretation)','',
                'This is supplied reasoning, not independently established cause. No remediation authority.', '']
        # Indented JSON keeps customer prose out of active Markdown/HTML/link syntax.
        lines+=['    '+line for line in json.dumps(report['reviewed_dossier'],sort_keys=True,ensure_ascii=True,indent=2).splitlines()]
    return '\n'.join(lines).encode('utf-8')


def package(store,case_id,index_revision,review_sha256,*,interactive=False):
    if interactive is not True:raise CaseError('Interactive operator disclosure review required')
    if type(index_revision) is not str or not REVISION.fullmatch(index_revision):raise CaseError('Invalid report revision')
    with admission_lock(store):
        verify_committed_reserve(store,extra_bytes=2*MAX_PACKAGE)
        with store._locked(case_id) as (folder,manifest):
            report=_build_locked(folder,manifest,index_revision)
            sha=hashlib.sha256(canonical(report)).hexdigest()
            if type(review_sha256) is not str or review_sha256!=sha:raise CaseError('Evidence report review changed')
            report={**report,'review_sha256':sha}
            members={'report.json':canonical(report)+b'\n','report.md':markdown(report)}
            members['manifest.json']=canonical({'schema':1,'review_sha256':sha,
                'members':{name:hashlib.sha256(value).hexdigest() for name,value in members.items()}})+b'\n'
            buffer=BytesIO()
            with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED) as archive:
                for name,data in members.items():
                    item=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                    item.compress_type=zipfile.ZIP_DEFLATED;item.external_attr=0o600<<16
                    archive.writestr(item,data)
            payload=buffer.getvalue()
            if len(payload)>MAX_PACKAGE:raise CaseError('Evidence report package budget exceeded')
            output=store.base/'evidence-report-packages'
            _private_directory(output,strict=True)
            target=output/('report-'+sha+'.zip')
            if target.is_symlink():raise CaseError('Unsafe evidence package symlink')
            if target.exists():
                fd,info=_regular_open(target)
                with os.fdopen(fd,'rb') as stream:
                    if info.st_nlink!=1 or info.st_size!=len(payload) or stream.read(MAX_PACKAGE+1)!=payload:
                        raise CaseError('Existing evidence package identity mismatch')
            else:
                if len(list(output.iterdir()))>=MAX_PACKAGES:raise CaseError('Evidence report package count budget reached')
                temp=output/('.tmp-report-'+secrets.token_hex(16))
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                try:
                    with os.fdopen(fd,'wb') as stream:
                        stream.write(payload);stream.flush();os.fsync(stream.fileno())
                    os.replace(temp,target)
                    directory=os.open(output,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
                    try:os.fsync(directory)
                    finally:os.close(directory)
                finally:temp.unlink(missing_ok=True)
    return {'status':'LOCAL_REVIEWED_REPORT_PACKAGE','review_sha256':sha,
        'package_sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload),
        'filename':target.name,'external_disclosure_approved':False,
        'production_power_loss_durability_verified':False}
