"""Stage B CAND-07: private semantic configuration drift known answers."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import casework
import configdelta
import gateway


class DriftTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.home=Path(t.name)
        self.store=casework.CaseStore(self.home)
        self.cid=self.store.open_case()["case_id"]

    def add(self,name,value):
        p=self.store.inbox/name
        p.write_bytes(value.encode() if type(value) is str else value)
        p.chmod(0o600)
        return self.store.register(self.cid,name)["artifact_id"]

    def pair(self,before,after,fmt="json"):
        return self.add("before.txt",before),self.add("after.txt",after)

    def query(self,first,second,**kwargs):
        return configdelta.report(self.store,self.cid,first,second,**kwargs)

    def test_normalized_order_and_nested_types(self):
        a,b=self.pair('{"network":{"enabled":true,"mtu":1500},"version":"9"}',
                      '{"version":"9","network":{"mtu":1500,"enabled":true}}')
        out=self.query(a,b)
        self.assertEqual(out["changed_fields"],0)
        self.assertEqual(out["results"],[])
        self.assertTrue(out["source_originals_sha256_verified"])
        self.assertFalse(out["change_time_verified"])
        self.assertFalse(out["causality_established"])

    def test_array_reorder_preserves_duplicates(self):
        a,b=self.pair('{"password":["alpha","beta","alpha"]}',
                      '{"password":["alpha","alpha","beta"]}')
        out=self.query(a,b)
        self.assertEqual(out["change_totals"],{"ARRAY_ORDER_CHANGED":1})
        visible=json.dumps(out)
        for private in ("alpha","beta","password"):
            self.assertNotIn(private,visible)
        self.assertTrue(out["results"][0]["field"].startswith("field-"))

    def test_array_length_and_contents_are_distinct(self):
        a,b=self.pair('{"items":[1,2]}','{"items":[2,3]}')
        self.assertEqual(self.query(a,b)["change_totals"],{"ARRAY_CONTENT_CHANGED":1})
        c=self.add("len1.json",'{"items":[1,2]}')
        d=self.add("len2.json",'{"items":[1,2,3]}')
        out=self.query(c,d)
        self.assertEqual(out["change_totals"],{"ARRAY_LENGTH_CHANGED":1})

    def test_type_change_and_value_change_are_separate(self):
        a,b=self.pair('{"mode":"auto","timeout":30,"enabled":true}',
                      '{"mode":false,"timeout":60,"enabled":true}')
        out=self.query(a,b)
        self.assertEqual(out["change_totals"],{"TYPE_CHANGED":1,"VALUE_CHANGED":1})
        self.assertTrue(any(r["field"]=="mode" and r["type_after"]=="BOOLEAN" for r in out["results"]))

    def test_properties_ignore_comments_and_do_not_disclose_values(self):
        a,b=self.pair("# before\nport=8443\npassword=supersecret\n",
                      "; after\nport=9443\npassword=othersecret\n")
        out=self.query(a,b,fmt="properties")
        self.assertEqual(out["changed_fields"],2)
        self.assertIn("port",{x["field"] for x in out["results"]})
        for secret in ("supersecret","othersecret","password","8443","9443"):
            self.assertNotIn(secret,json.dumps(out))

    def test_page_is_stable_and_metadata_only(self):
        a,b=self.pair(json.dumps({f"secret{i}":i for i in range(60)}),
                      json.dumps({f"secret{i}":i+1 for i in range(60)}))
        p1=self.query(a,b,limit=20)
        p2=self.query(a,b,offset=p1["next_offset"],limit=20)
        p3=self.query(a,b,offset=p2["next_offset"],limit=20)
        rows=p1["results"]+p2["results"]+p3["results"]
        self.assertEqual(len(rows),60)
        self.assertEqual({r["ordinal"] for r in rows},set(range(1,61)))
        self.assertEqual([r["field"] for r in rows],["field-%04d"%i for i in range(1,61)])
        self.assertFalse(p3["has_more"])
        self.assertIsNone(p3["next_offset"])
        self.assertEqual(p1["status"],"PASS")

    def test_invalid_inputs_fail_closed(self):
        a,b=self.pair('{"port":443}','{"port":8443}')
        for kwargs in ({"offset":True},{"offset":-1},{"offset":10001},
                       {"limit":True},{"limit":0},{"limit":21},
                       {"fmt":"yaml"},{"fmt":None}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(casework.CaseError):
                    self.query(a,b,**kwargs)
        for before,after in ((a,a),("x",b),("../etc/passwd",b),(a,True)):
            with self.assertRaises(casework.CaseError):
                self.query(before,after)

    def test_duplicate_or_nonfinite_json_and_bad_utf8_rejected(self):
        t=self.add("dup1.json",'{"port":1,"port":2}')
        u=self.add("clean2.json",'{"port":3}')
        with self.assertRaises(casework.CaseError):
            self.query(t,u)
        v=self.add("nan3.json",'{"port":NaN}')
        with self.assertRaises(casework.CaseError):
            self.query(v,u)
        w=self.add("bad4.json",b'{"port":"\xff"}')
        with self.assertRaises(casework.CaseError):
            self.query(w,u)

    def test_registered_source_edit_and_symlink_denied(self):
        a,b=self.pair('{"enabled":true}','{"enabled":false}')
        orig=self.store.cases/self.cid/"originals"/a
        orig.write_text('{"enabled":null}')
        with self.assertRaises(casework.CaseError):
            self.query(a,b)
        # A symlink replacement is never followed, even if the target exists.
        orig.unlink()
        orig.symlink_to(self.store.cases/self.cid/"originals"/b)
        with self.assertRaises(casework.CaseError):
            self.query(a,b)

    def test_array_cap_and_nesting_cap(self):
        a,b=self.pair('{"a":['+','.join("1" for _ in range(4097))+']}','{"a":[]}')
        with self.assertRaisesRegex(casework.CaseError,"array"):
            self.query(a,b)
        deep='{"a":'*14+'1'+'}'*14
        c=self.add("deep3.json",deep)
        d=self.add("plain4.json","{}")
        with self.assertRaisesRegex(casework.CaseError,"nesting"):
            self.query(c,d)

    def test_gateway_api_is_read_only_and_strict(self):
        a,b=self.pair('{"enabled":true}','{"enabled":false}')
        gw=gateway.Gateway(gateway.Config({},(),self.home))
        schema={x["name"]:x for x in gw.tools()}
        self.assertIn("config_drift_report",schema)
        self.assertTrue(schema["config_drift_report"]["annotations"]["readOnlyHint"])
        self.assertFalse(schema["config_drift_report"]["annotations"]["destructiveHint"])
        data={"case_id":self.cid,"before_artifact_id":a,
              "after_artifact_id":b,"format":"json"}
        out=gw.call("config_drift_report",data)
        self.assertEqual(out["change_totals"],{"VALUE_CHANGED":1})
        with self.assertRaises(gateway.GatewayError):
            gw.call("config_drift_report",data|{"command":"rm -rf /"})
        with self.assertRaises(gateway.GatewayError):
            gw.call("config_drift_report",data|{"limit":True})

    def test_array_order_is_observed_not_verified_platform_semantics(self):
        a,b=self.pair('{"routes":[{"mode":"a"},{"mode":"b"}]}',
                      '{"routes":[{"mode":"b"},{"mode":"a"}]}')
        result=self.query(a,b)
        self.assertEqual(result["change_totals"],{"ARRAY_ORDER_CHANGED":1})
        self.assertIsNone(result["array_order_semantically_significant"])
        self.assertFalse(result["array_order_semantic_significance_verified"])
        self.assertFalse(result["causality_established"])

    def test_uncontrolled_key_cannot_impersonate_tagged_safe_name(self):
        a,b=self.pair('{"field:enabled":true,"field:port":443}',
                      '{"field:enabled":false,"field:port":8443}')
        result=self.query(a,b)
        self.assertEqual([row['field'] for row in result['results']],
                         ['field-0001','field-0002'])
        self.assertFalse({'enabled', 'port'} &
                         {row['field'] for row in result['results']})



if __name__=="__main__":
    unittest.main()
