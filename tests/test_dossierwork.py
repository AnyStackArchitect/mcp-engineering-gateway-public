"""Reviewed reasoning stays attributed and bound to actual indexed evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import casework
import correlationwork
import dossierwork
import reportwork
import timelinework


class DossierTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.store=casework.CaseStore(Path(temp.name));self.cid=self.store.open_case()['case_id']
        source=self.store.inbox/'fixture.log';source.write_text('2026-10-18T01:00:00Z failure\n2026-10-18T01:01:00Z recovered\n');source.chmod(0o600)
        self.aid=self.store.register(self.cid,'fixture.log')['artifact_id']
        timelinework.build_timeline(self.store,self.cid);self.rebuild()
        report=reportwork.build(self.store,self.cid,self.rev);self.refs=[{'event_id':r['event_id'],'source_sha256':r['source_sha256']} for r in report['observations']]
        self.data={'schema':1,'case_id':self.cid,'index_revision':self.rev,
            'environment':{'product':'fixture-service','version':'1.2.3'},'symptoms':'Operator reports an outage',
            'impact':'Operator reports one failed request','reproduction':['Send a synthetic request'],
            'observed_outputs':'Synthetic log contains failure and recovered observations',
            'hypotheses':[{'claim':'Fixture condition may explain the symptom','status':'PROPOSED','test':'Compare the two synthetic observations',
                'observed_result':'','supports':[self.refs[0]],'contradicts':[]}],
            'conclusion':None,'open_questions':['Was the original collection complete?']}

    def rebuild(self):
        correlationwork.build_correlation(self.store,self.cid)
        self.rev=correlationwork.correlation_summary(self.store,self.cid)['index_revision']

    def accept(self,data=None):
        data=self.data if data is None else data
        p=dossierwork.prepare(self.store,data)
        return dossierwork.accept(self.store,data,p['review_sha256'],interactive=True)

    def test_reviewed_proposed_reasoning_report_and_package_are_attributed(self):
        before=reportwork.build(self.store,self.cid,self.rev)
        with self.assertRaises(casework.CaseError):dossierwork.accept(self.store,self.data,'0'*64)
        with self.assertRaises(casework.CaseError):dossierwork.accept(self.store,self.data,'0'*64,interactive=True)
        accepted=self.accept();self.assertEqual(accepted,self.accept())
        report=reportwork.build(self.store,self.cid,self.rev)
        self.assertNotEqual(before['review_sha256'],report['review_sha256'])
        self.assertEqual(report['status'],'PARTIAL')
        self.assertEqual(report['reviewed_dossier']['review_sha256'],accepted['review_sha256'])
        self.assertIn('NOT_INDEPENDENTLY_PROVEN',report['reviewed_dossier']['authority'])
        self.assertEqual(report['hypotheses'][0]['status'],'PROPOSED')
        self.assertIn('root_cause_not_established',report['unknowns'])
        self.assertNotIn('symptoms',report['facts'])
        with self.assertRaises(casework.CaseError):reportwork.package(self.store,self.cid,self.rev,before['review_sha256'],interactive=True)
        packaged=reportwork.package(self.store,self.cid,self.rev,report['review_sha256'],interactive=True)
        with zipfile.ZipFile(self.store.base/'evidence-report-packages'/packaged['filename']) as archive:
            self.assertEqual(json.loads(archive.read('report.json'))['reviewed_dossier'],report['reviewed_dossier'])
            self.assertIn(b'Operator reviewed dossier',archive.read('report.md'))

    def test_accepted_conclusion_is_version_bound_and_not_a_measured_fact(self):
        h=self.data['hypotheses'][0];h.update(status='OPERATOR_ACCEPTED',observed_result='Two fixture records differ')
        self.data['conclusion']={'statement':'Operator accepts this synthetic explanation','fix':'Proposed fixture-only adjustment',
            'applies_to_version':'1.2.3','validation':'Operator compared fixture records','references':[self.refs[1]]}
        self.accept();report=reportwork.build(self.store,self.cid,self.rev)
        self.assertEqual(report['reviewed_dossier']['content']['conclusion']['applies_to_version'],'1.2.3')
        self.assertNotIn('conclusion',report['facts']);self.assertFalse(report['reviewed_dossier']['external_disclosure_approved'])
        changed=copy.deepcopy(self.data);changed['impact']='A replacement'
        with self.assertRaisesRegex(casework.CaseError,'already accepted'):self.accept(changed)

    def test_invalid_status_and_evidence_cannot_be_promoted(self):
        mutations=[lambda d:d['hypotheses'][0].update(status='ESTABLISHED_FACT'),
            lambda d:d['hypotheses'][0].update(status='TESTED'),
            lambda d:d['hypotheses'][0].update(status='PROPOSED',observed_result='Claimed result'),
            lambda d:d['hypotheses'][0].update(status='DISCONFIRMED',observed_result='Refuted'),
            lambda d:d['hypotheses'][0].update(supports=[{'event_id':True,'source_sha256':'0'*64}]),
            lambda d:d['hypotheses'][0].update(supports=[{'event_id':999999,'source_sha256':'0'*64}]),
            lambda d:d['hypotheses'][0].update(supports=[{'event_id':self.refs[0]['event_id'],'source_sha256':'0'*64}]),
            lambda d:d['hypotheses'][0].update(contradicts=[self.refs[0]]),
            lambda d:d.update(schema=True),lambda d:d.update(impact='x'*241),
            lambda d:d.update(extra='unsafe'),lambda d:d.update(open_questions=['a']*4)]
        for mutate in mutations:
            data=copy.deepcopy(self.data);mutate(data)
            with self.subTest(data=data),self.assertRaises(casework.CaseError):dossierwork.prepare(self.store,data)

    def test_stale_revision_and_changed_original_refused(self):
        self.rebuild()
        with self.assertRaisesRegex(casework.CaseError,'stale'):dossierwork.prepare(self.store,self.data)
        self.data['index_revision']=self.rev
        source=self.store.cases/self.cid/'originals'/self.aid
        info=source.stat();source.chmod(0o600);source.write_text('x'*info.st_size);source.chmod(0o400)
        os.utime(source,ns=(info.st_atime_ns,info.st_mtime_ns))
        with self.assertRaises(casework.CaseError):dossierwork.prepare(self.store,self.data)

    def test_rebuild_does_not_reuse_old_review(self):
        self.accept();self.rebuild()
        result=reportwork.build(self.store,self.cid,self.rev)
        self.assertNotIn('reviewed_dossier',result);self.assertEqual(result['hypotheses'],[])

    def test_dossier_prose_masked_and_markdown_inert(self):
        self.data['symptoms']='password=secret <script>bad()</script> [link](https://example.com)'
        self.accept();report=reportwork.build(self.store,self.cid,self.rev)
        self.assertNotIn('password=secret',json.dumps(report))
        rendered=reportwork.markdown(report).decode()
        self.assertTrue(all(line.startswith('    ') for line in rendered.splitlines() if '<script>' in line))

    def test_unsafe_or_tampered_stored_content_refused(self):
        self.accept();path=self.store.cases/self.cid/'rca-dossiers'/(self.rev+'.json')
        raw=path.read_bytes();path.write_bytes(raw+b' ')
        with self.assertRaises(casework.CaseError):reportwork.build(self.store,self.cid,self.rev)
        path.write_bytes(raw);path.chmod(0o644)
        with self.assertRaises(casework.CaseError):reportwork.build(self.store,self.cid,self.rev)

    def test_capacity_refusal_and_file_count_preserve_sources(self):
        p=dossierwork.prepare(self.store,self.data)
        with patch('dossierwork.verify_committed_reserve',side_effect=casework.CaseError('reserve')):
            with self.assertRaises(casework.CaseError):dossierwork.accept(self.store,self.data,p['review_sha256'],interactive=True)
        self.assertFalse((self.store.cases/self.cid/'rca-dossiers').exists())
        with patch('dossierwork.MAX_DOSSIERS',0),self.assertRaises(casework.CaseError):self.accept()
        self.assertTrue((self.store.cases/self.cid/'originals'/self.aid).is_file())

    def test_reference_beyond_sample_carries_portable_locator_and_rejects_spoof(self):
        extra=self.store.inbox/'extra.log'
        extra.write_text(''.join(f'2026-10-18T01:02:{n:02d}Z fixture {n}\n' for n in range(10)));extra.chmod(0o600)
        aid=self.store.register(self.cid,extra.name)['artifact_id']
        timelinework.build_timeline(self.store,self.cid);self.rebuild();self.data['index_revision']=self.rev
        folder=self.store.cases/self.cid
        with self.store._locked(self.cid) as (folder,manifest):
            db,facts=correlationwork._checked_correlation(folder,manifest)
            row=db.execute('SELECT e.id,e.locator_number,s.sha256 FROM events e JOIN sources s ON s.artifact_id=e.artifact_id WHERE e.artifact_id=? AND e.locator_number=8',(aid,)).fetchone();db.close()
        self.data['hypotheses'][0]['supports']=[{'event_id':row['id'],'source_sha256':row['sha256']}]
        preview=dossierwork.prepare(self.store,self.data)
        resolved=preview['dossier']['hypotheses'][0]['supports'][0]
        self.assertEqual(resolved['artifact_id'],aid);self.assertEqual(resolved['locator_type'],'line');self.assertEqual(resolved['locator_number'],8)
        changed=copy.deepcopy(preview['dossier']);changed['hypotheses'][0]['supports'][0]['locator_number']=9
        with self.assertRaises(casework.CaseError):dossierwork.prepare(self.store,changed)
        self.accept();report=reportwork.build(self.store,self.cid,self.rev)
        self.assertFalse(any(r['event_id']==row['id'] for r in report['observations']))
        self.assertEqual(report['reviewed_dossier']['content']['hypotheses'][0]['supports'][0],resolved)

    def test_combined_report_budget_refuses_before_publication(self):
        for n in range(6):
            path=self.store.inbox/('extra'+str(n)+'.log')
            path.write_text(f'2026-10-18T00:00:0{n}Z fixture\n');path.chmod(0o600)
            self.store.register(self.cid,path.name)
        timelinework.build_timeline(self.store,self.cid);self.rebuild();self.data['index_revision']=self.rev
        report=reportwork.build(self.store,self.cid,self.rev)
        for key in ('symptoms','impact','observed_outputs'):self.data[key]='x'*240
        for key in ('reproduction','open_questions'):self.data[key]=['x'*180]*3
        hypothesis=self.data['hypotheses'][0];hypothesis['claim']='x'*180;hypothesis['test']='x'*180
        hypothesis['supports']=[{'event_id':row['event_id'],'source_sha256':row['source_sha256']} for row in report['observations'][:2]]
        self.data['hypotheses']=[hypothesis,copy.deepcopy(hypothesis)]
        self.assertLess(len(dossierwork.canonical(self.data)),dossierwork.MAX_BYTES)
        with self.assertRaisesRegex(casework.CaseError,'combined report output budget'):self.accept()
        self.assertFalse((self.store.cases/self.cid/'rca-dossiers').exists())


if __name__=='__main__':unittest.main()
