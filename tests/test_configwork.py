"""Configuration diff must expose field changes, not secret values."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import casework, configwork


class ConfigTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.home=Path(tmp.name)
        self.store=casework.CaseStore(self.home)
        self.cid=self.store.open_case()['case_id']

    def reg(self,name,data):
        p=self.store.inbox/name
        p.write_bytes(data if isinstance(data,bytes) else data.encode())
        p.chmod(0o600)
        return self.store.register(self.cid,name)['artifact_id']

    def test_json_diff_ignores_key_order_and_leaks_no_values(self):
        a=self.reg('a.json',json.dumps({'version':'7.0','password':'superprivate','enabled':True,'id':'USER-A'}))
        b=self.reg('b.json',json.dumps({'id':'USER-B','enabled':False,'password':'otherprivate','version':'7.0'}))
        r=configwork.compare(self.store,self.cid,a,b)
        self.assertEqual(r['changed_fields'],3)
        self.assertIn({'field':'enabled','change':'CHANGED'},r['changes'])
        combined=json.dumps(r)
        for secret in ('superprivate','otherprivate','USER-A','USER-B','password'):
            self.assertNotIn(secret,combined)
        self.assertFalse(r['values_exposed'])

    def test_semantically_equal_nested_json(self):
        a=self.reg('a.json','{"network":{"mtu":1500,"enabled":true},"version":"9"}')
        b=self.reg('b.json','{"version":"9","network":{"enabled":true,"mtu":1500}}')
        self.assertEqual(configwork.compare(self.store,self.cid,a,b)['changed_fields'],0)

    def test_ambiguous_dot_key_not_collapsed_into_nested(self):
        a=self.reg('a.json','{"a.b":1,"a":{"b":2}}')
        b=self.reg('b.json','{"a.b":2,"a":{"b":2}}')
        r=configwork.compare(self.store,self.cid,a,b)
        self.assertEqual(r['changed_fields'],1)

    def test_empty_nested_object_vs_missing_is_a_change(self):
        a=self.reg('a.json','{"network":{}}')
        b=self.reg('b.json','{}')
        self.assertEqual(configwork.compare(self.store,self.cid,a,b)['changed_fields'],1)

    def test_properties_ignore_comments_and_whitespace(self):
        a=self.reg('a.cfg','# comment\nport = 8443\ntimeout= 30\n')
        b=self.reg('b.cfg','; comment\n timeout = 40 \nport=8443\n')
        r=configwork.compare(self.store,self.cid,a,b,fmt='properties')
        self.assertEqual(r['changed_fields'],1)
        self.assertEqual(r['changes'],[{'field':'timeout','change':'CHANGED'}])

    def test_added_removed_and_truncated(self):
        a=self.reg('a.json',json.dumps({f'v{i}':i for i in range(55)}))
        b=self.reg('b.json',json.dumps({f'z{i}':i for i in range(55)}))
        r=configwork.compare(self.store,self.cid,a,b)
        self.assertEqual(r['changed_fields'],110)
        self.assertTrue(r['results_truncated'])
        self.assertEqual(r['status'],'PARTIAL')
        self.assertEqual(len(r['changes']),40)

    def test_invalid_and_unknown_format(self):
        a=self.reg('a.cfg','hello=no')
        b=self.reg('b.cfg','hello=yes')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,b,fmt='yaml')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,a)
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,'../ssh/id_rsa')

    def test_duplicate_keys_rejected(self):
        a=self.reg('a.json','{"port":9000,"port":8000}')
        b=self.reg('b.json','{"port":8000}')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,b)

    def test_invalid_utf8_rejected(self):
        a=self.reg('a.cfg',b'key=\xff')
        b=self.reg('b.cfg','key=ok')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,b,fmt='properties')

    def test_modified_source_rejected(self):
        a=self.reg('a.cfg','version=1')
        b=self.reg('b.cfg','version=2')
        (self.store.cases/self.cid/'originals'/a).write_text('version=3')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,b,fmt='properties')

    def test_symlink_source_refused(self):
        a=self.reg('a.cfg','version=1')
        b=self.reg('b.cfg','version=2')
        path=self.store.cases/self.cid/'originals'/a
        path.unlink();path.symlink_to(self.home/'elsewhere')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,b,fmt='properties')

    def test_configuration_limit(self):
        a=self.reg('a.cfg',('enabled=true\n'*100000))
        b=self.reg('b.cfg','enabled=false')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,b,fmt='properties')

    def test_nonfinite_json_rejected(self):
        a=self.reg('a.json','{"version":NaN}')
        b=self.reg('b.json','{"version":1}')
        with self.assertRaises(casework.CaseError):
            configwork.compare(self.store,self.cid,a,b)

    def test_unique_identity_array_tracks_field_and_order_separately(self):
        left=self.reg('array-before.json',json.dumps({'vms':[
            {'id':'internal-vm-a','enabled':True,'mtu':1500},
            {'id':'internal-vm-b','enabled':True,'mtu':1500}]}))
        right=self.reg('array-after.json',json.dumps({'vms':[
            {'mtu':1500,'enabled':True,'id':'internal-vm-b'},
            {'mtu':1500,'enabled':False,'id':'internal-vm-a'}]}))
        out=configwork.compare(self.store,self.cid,left,right)
        self.assertEqual(out['status'],'PASS')
        self.assertEqual(out['changed_fields'],2)
        self.assertEqual({c['field'] for c in out['changes']},{'enabled','array_layout'})
        changed=next(c for c in out['changes'] if c['field']=='enabled')
        self.assertEqual(len(changed['field_ref']),24)
        self.assertFalse(out['change_time_known'])
        self.assertFalse(out['same_system_verified'])
        self.assertFalse(out['causality_established'])
        result=json.dumps(out)
        self.assertNotIn('internal-vm-a',result)
        self.assertNotIn('internal-vm-b',result)
        self.assertIn('unique_identity_array',out['array_modes_encountered'])

    def test_duplicate_stable_array_id_refused(self):
        left=self.reg('array-duplicate.json',json.dumps({'vms':[
            {'id':'collision','enabled':True},{'id':'collision','enabled':False}]}))
        right=self.reg('array-unique.json',json.dumps({'vms':[
            {'id':'different','enabled':True}]}))
        with self.assertRaisesRegex(casework.CaseError,'duplicate identities'):
            configwork.compare(self.store,self.cid,left,right)

    def test_sensitive_identity_and_secret_field_never_exported(self):
        before=self.reg('secret-array-a.json',json.dumps({'vms':[{
            'name':'customer.internal.example','password':'secret-value-1',
            'tls_enabled':True}]}))
        after=self.reg('secret-array-b.json',json.dumps({'vms':[{
            'tls_enabled':True,'password':'secret-value-2',
            'name':'customer.internal.example'}]}))
        out=configwork.compare(self.store,self.cid,before,after)
        self.assertEqual(out['changed_fields'],1)
        change=out['changes'][0]
        self.assertTrue(change['field'].startswith('field-'))
        self.assertEqual(change['change'],'CHANGED')
        self.assertEqual(len(change['field_ref']),24)
        rendered=json.dumps(out)
        for secret in ['customer.internal.example','secret-value-1',
                       'secret-value-2','password']:
            self.assertNotIn(secret,rendered)

    def test_arrays_without_identity_are_atomic_and_order_sensitive(self):
        before=self.reg('opaque-a.json',json.dumps({'port':[443,8443,9440]}))
        after=self.reg('opaque-b.json',json.dumps({'port':[9440,8443,443]}))
        out=configwork.compare(self.store,self.cid,before,after)
        self.assertEqual(out['changed_fields'],1)
        self.assertEqual(out['changes'][0]['field'],'port')
        self.assertIn('unidentified_arrays_opaque_ordered_comparison',
                      out['limitations'])
        self.assertIn('unidentified_array_compared_as_ordered_atomic_value',
                      out['array_modes_encountered'])

    def test_nested_identity_array_ignores_object_key_order(self):
        before=self.reg('nested-before.json','{"vms":[{"id":"a","config":{"mtu":1500,"enabled":true}}]}')
        after=self.reg('nested-after.json','{"vms":[{"config":{"enabled":true,"mtu":1500},"id":"a"}]}')
        out=configwork.compare(self.store,self.cid,before,after)
        self.assertEqual(out['changed_fields'],0)
        self.assertEqual(out['status'],'PASS')

    def test_identity_based_added_and_removed_members(self):
        before=self.reg('members-before.json',json.dumps({'vms':[
            {'id':'a','enabled':True},{'id':'b','enabled':False}]}))
        after=self.reg('members-after.json',json.dumps({'vms':[
            {'id':'a','enabled':True},{'id':'c','enabled':False}]}))
        out=configwork.compare(self.store,self.cid,before,after)
        self.assertGreaterEqual(out['change_totals']['ADDED'],1)
        self.assertGreaterEqual(out['change_totals']['REMOVED'],1)
        self.assertNotIn('"b"',json.dumps(out))
        self.assertNotIn('"c"',json.dumps(out))

    def test_source_provenance_hashes_bound_to_exact_snapshots(self):
        a=b'{"enabled":true,"mode":"primary"}'
        b=b'{"enabled":false,"mode":"primary"}'
        before=self.reg('finger-before.json',a)
        after=self.reg('finger-after.json',b)
        result=configwork.compare(self.store,self.cid,before,after)
        import hashlib
        self.assertEqual(result['before_sha256'],hashlib.sha256(a).hexdigest())
        self.assertEqual(result['after_sha256'],hashlib.sha256(b).hexdigest())
        self.assertEqual(result['changed_fields'],1)
        self.assertFalse(result['values_exposed'])

    def test_boolean_identity_is_not_a_stable_element_selector(self):
        a=self.reg('bool-ident-before.json','{"vms":[{"id":true,"enabled":true}]}')
        b=self.reg('bool-ident-after.json','{"vms":[{"id":true,"enabled":false}]}')
        out=configwork.compare(self.store,self.cid,a,b)
        self.assertEqual(out['changed_fields'],1)
        self.assertIn('unidentified_arrays_opaque_ordered_comparison',out['limitations'])


    def test_user_supplied_array_marker_cannot_impersonate_layout(self):
        before=self.reg('marker-before.json',json.dumps({'vms':[
            {'id':'machine-a','__layout__':'private-old','enabled':True},
            {'id':'machine-b','__layout__':'unchanged','enabled':True}]}))
        after=self.reg('marker-after.json',json.dumps({'vms':[
            {'id':'machine-b','__layout__':'unchanged','enabled':True},
            {'id':'machine-a','__layout__':'private-new','enabled':True}]}))
        out=configwork.compare(self.store,self.cid,before,after)
        self.assertEqual(out['changed_fields'],2)
        self.assertEqual(sum(x['field']=='array_layout' for x in out['changes']),1)
        self.assertEqual(sum(x['field'].startswith('field-') for x in out['changes']),1)
        self.assertEqual(len([x for x in out['changes'] if 'field_ref' in x]),1)
        dump=json.dumps(out)
        for forbidden in ('machine-a','machine-b','private-old','private-new','__layout__'):
            self.assertNotIn(forbidden,dump)

    def test_user_supplied_member_prefix_cannot_impersonate_element(self):
        before=self.reg('member-before.json',json.dumps({'vms':[
            {'id':'node-1','member:@fake':'private-old','enabled':True}]}))
        after=self.reg('member-after.json',json.dumps({'vms':[
            {'id':'node-1','member:@fake':'private-new','enabled':True}]}))
        out=configwork.compare(self.store,self.cid,before,after)
        self.assertEqual(out['changed_fields'],1)
        self.assertEqual(out['changes'][0]['change'],'CHANGED')
        self.assertTrue(out['changes'][0]['field'].startswith('field-'))
        self.assertIn('field_ref',out['changes'][0])
        self.assertNotIn('member:@fake',json.dumps(out))

    def test_nonidentity_array_reports_mode_used_not_claimed(self):
        before=self.reg('no-id-before.json','{"enabled":true}')
        after=self.reg('no-id-after.json','{"enabled":false}')
        out=configwork.compare(self.store,self.cid,before,after)
        self.assertEqual(out['identity_array_mode'],'NOT_USED')
        self.assertEqual(out['array_modes_encountered'],[])

if __name__=='__main__': unittest.main()
