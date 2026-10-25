"""Declared identity gates never establish vendor-version compatibility."""
import json,os,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from casework import CaseStore,CaseError
import recipework,timelinework,recipeversionwork


class RecipeVersionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.store=CaseStore(Path(temp.name));self.cid=self.store.open_case()['case_id'];self.serial=0

    def register(self,raw):
        self.serial+=1;path=self.store.inbox/('source'+str(self.serial)+'.json')
        path.write_bytes(raw);path.chmod(0o600)
        return self.store.register(self.cid,path.name)['artifact_id']

    def declaration(self,family='vmware',**changes):
        data={'schema':1,'family':family,'product':'fixture-product','version':'1.2.3',
            'recipe_sha256':recipework.recipe_digest(family)};data.update(changes)
        return self.register(json.dumps(data).encode())

    def report(self,aid,family='vmware',**changes):
        args={'product':'fixture-product','platform_version':'1.2.3','version_artifact_id':aid};args.update(changes)
        return recipework.report(self.store,self.cid,family,**args)

    def prepare(self):
        self.register(b'2026-10-15T16:00:00Z vpxa disconnected\n')
        timelinework.build_timeline(self.store,self.cid)
        for family in recipework.FAMILIES:recipework.evaluate(self.store,self.cid,family)

    def test_all_nine_matching_declarations_remain_compatibility_unverified(self):
        aids={f:self.declaration(f) for f in recipework.FAMILIES};self.prepare()
        for family,aid in aids.items():
            result=self.report(aid,family);app=result['version_applicability']
            self.assertEqual(result['status'],'PARTIAL');self.assertEqual(app['status'],'DECLARATION_MATCH_COMPATIBILITY_UNVERIFIED')
            self.assertFalse(app['vendor_compatibility_verified']);self.assertFalse(result['root_cause_established'])
            self.assertEqual(app['artifact_id'],aid);self.assertTrue(all(app['identity_matches'].values()))

    def test_missing_identity_is_unknown(self):
        self.prepare();result=recipework.report(self.store,self.cid,'vmware')
        self.assertEqual(result['version_applicability']['status'],'UNKNOWN')
        self.assertFalse(result['version_applicability']['vendor_compatibility_verified'])

    def test_each_mismatch_suppresses_markers_without_revealing_private_declaration_values(self):
        for change in ({'family':'veeam'},{'product':'private-product'},{'version':'private-version'},
                       {'recipe_sha256':'0'*64}):
            aid=self.declaration(**change);result=self.report(aid)
            self.assertEqual(result['status'],'NOT_APPLICABLE_TO_REQUESTED_DECLARATION')
            self.assertNotIn('findings',result);self.assertNotIn('markers_found',result)
            self.assertNotIn('private-',json.dumps(result))

    def test_partial_controls_invalid_identity_and_unregistered_artifact_refused(self):
        for args in ({'product':'fixture-product'},{'product':'bad value','platform_version':'1','version_artifact_id':'a'*32},
                     {'product':'fixture-product','platform_version':'1','version_artifact_id':'a'*32}):
            with self.assertRaises(CaseError):recipework.report(self.store,self.cid,'vmware',**args)

    def test_malformed_duplicate_nested_and_oversize_sources_refused(self):
        for raw in (b'not JSON',b'{"schema":1,"schema":1}',b'[]',b'\xff',b' '*4097,
                    json.dumps({'schema':True,'family':'vmware','product':{},'version':'1','recipe_sha256':'0'*64}).encode()):
            aid=self.register(raw)
            with self.subTest(raw=raw[:20]),self.assertRaises(CaseError):self.report(aid)

    def test_changed_same_size_original_refused(self):
        aid=self.declaration();path=self.store.cases/self.cid/'originals'/aid
        path.chmod(0o600);path.write_bytes(path.read_bytes().replace(b'1.2.3',b'9.9.9'));path.chmod(0o400)
        with self.assertRaises(CaseError):self.report(aid)

    def test_old_recipe_digest_and_stale_timeline_are_refused_or_inapplicable(self):
        aid=self.declaration(recipe_sha256='f'*64)
        self.assertEqual(self.report(aid)['status'],'NOT_APPLICABLE_TO_REQUESTED_DECLARATION')
        aid=self.declaration();self.prepare();timelinework.build_timeline(self.store,self.cid)
        with self.assertRaisesRegex(CaseError,'stale'):self.report(aid)


if __name__=='__main__':unittest.main()
