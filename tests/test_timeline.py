"""Known-answer/adversarial timeline checks, no external data or network."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import casework
import gateway
import jobwork
import timelinework as t


class TimelineTests(unittest.TestCase):
    def setUp(self):
        ctx = tempfile.TemporaryDirectory(prefix='rocky-timeline-')
        self.addCleanup(ctx.cleanup)
        self.home = Path(ctx.name)
        self.store = casework.CaseStore(self.home)
        self.cid = self.store.open_case()['case_id']

    def put(self, name, value):
        p = self.store.inbox / name
        p.write_bytes(value if isinstance(value, bytes) else value.encode())
        p.chmod(0o600)
        return self.store.register(self.cid, name)['artifact_id']

    def sample(self):
        a = self.put('a.log', '2026-10-15T14:00:00Z INFO start\n'
                     '2026-10-15T14:02:00Z ERROR token=topsecret\n')
        b = self.put('b.log', '2026-10-15T10:01:00-04:00 WARN intermediate\n'
                     'Oct 15 10:04:00 host kernel: missing year\n')
        return a, b

    def test_cross_source_order_and_source_line_identity(self):
        a, b = self.sample()
        result = t.build_timeline(self.store, self.cid)
        self.assertEqual(result['status'], 'PARTIAL')
        rows = t.query_timeline(self.store, self.cid)['events']
        self.assertEqual([(r['artifact_id'], r['line_no']) for r in rows],
                         [(a, 1), (b, 1), (a, 2)])
        self.assertEqual([r['timestamp_utc'] for r in rows], sorted(r['timestamp_utc'] for r in rows))
        self.assertNotIn('topsecret', json.dumps(rows))
        self.assertEqual(rows[2]['level_hint'], 'ERROR')
        self.assertTrue(all(r['time_quality'] == 'OFFSET' for r in rows))
        self.assertNotIn(str(self.home), json.dumps(result) + json.dumps(rows))

    def test_unknown_syslog_time_not_positioned_on_utc_line(self):
        self.sample()
        t.build_timeline(self.store, self.cid)
        anchored = t.query_timeline(self.store, self.cid)
        self.assertEqual(len(anchored['events']), 3)
        mixed = t.query_timeline(self.store, self.cid, include_unanchored=True)
        self.assertEqual(len(mixed['events']), 4)
        self.assertIsNone(mixed['events'][-1]['timestamp_utc'])
        self.assertEqual(mixed['events'][-1]['time_quality'], 'NO_YEAR_OR_TIMEZONE')
        self.assertEqual(mixed['status'], 'PARTIAL')

    def test_timezone_offsets_normalized_without_guessing(self):
        r = t.normalize_line('2026-10-15T10:05:00.123-04:00 INFO zone')
        self.assertEqual(r['utc'], '2026-10-15T14:05:00.123000+00:00')
        self.assertEqual(r['time_quality'], 'OFFSET')
        r = t.normalize_line('2026-10-15 10:05:00 WARNING naive')
        self.assertIsNone(r['utc'])
        self.assertEqual(r['time_quality'], 'NO_TIMEZONE')
        r = t.normalize_line('not a timestamp')
        self.assertIsNone(r['stamp'])
        self.assertEqual(r['time_quality'], 'NO_TIMESTAMP')

    def test_jsonl_timestamp_and_nested_redaction(self):
        line = json.dumps({'@timestamp':'2026-10-15T10:01:00-04:00', 'level':'ERROR',
                           'auth': {'api_key':'longsecret'}, 'token':'badsecret',
                           'message':'Bearer abcdefghi -- problem'})
        result = t.normalize_line(line)
        self.assertEqual(result['utc'], '2026-10-15T14:01:00.000000+00:00')
        self.assertEqual(result['format'], 'jsonl')
        self.assertEqual(result['level_hint'], 'ERROR')
        for secret in ('longsecret', 'badsecret', 'abcdefghi'):
            self.assertNotIn(secret, result['excerpt'])
        self.assertIn('[REDACTED]', result['excerpt'])

    def test_malformed_json_token_still_redacted(self):
        result = t.normalize_line('{"password":"supersecret",')
        self.assertNotIn('supersecret', result['excerpt'])
        self.assertEqual(result['format'], 'plain')
        self.assertNotIn('supersecret', casework._clean_line('{"password":"supersecret"}'))

    def test_invalid_json_timestamp_must_not_echo_arbitrary_secret(self):
        result = t.normalize_line('{"timestamp":"token=secretsayshi","level":"warn"}')
        self.assertIsNone(result['utc'])
        self.assertEqual(result['stamp'], '[INVALID_TIMESTAMP]')
        self.assertNotIn('secretsayshi', result['stamp'])

    def test_explicit_epoch_only_no_ambiguous_numeric_guess(self):
        ms = t.normalize_line('{"timestamp_unix_ms":1792087260000,"level":"info"}')
        self.assertEqual(ms['time_quality'], 'EXPLICIT_EPOCH')
        self.assertIsNotNone(ms['utc'])
        self.assertIsNone(t.normalize_line('{"timestamp":1792087260}')['utc'])
        self.assertEqual(t.normalize_line('{"timestamp":1792087260}')['time_quality'], 'AMBIGUOUS_NUMERIC')
        self.assertIsNone(t.normalize_line('{"timestamp_unix_s":99999999999}')['utc'])

    def test_rfc5424_syslog_with_offset_is_anchored(self):
        line = '<34>1 2026-10-15T10:22:13-04:00 rocky nginx - ID47 - warn test'
        event=t.normalize_line(line)
        self.assertEqual(event['format'],'syslog5424')
        self.assertEqual(event['utc'],'2026-10-15T14:22:13.000000+00:00')
        self.assertEqual(event['level_hint'],'WARN')

    def test_bad_json_recursive_and_invalid_dates_do_not_crash(self):
        for txt in ('{"@timestamp":"2026-15-99T99:00:00Z"}',
                    '{"@timestamp":"2026-10-15T13:01:00+9999"}',
                    '{"timestamp":null}',
                    '{"level":"critical","deep":[[[[[1]]]]]}'):
            self.assertIsInstance(t.normalize_line(txt), dict)

    def test_range_correct_with_offset_and_exact_filter(self):
        self.sample()
        t.build_timeline(self.store, self.cid)
        result = t.query_timeline(self.store, self.cid,
                                  start_utc='2026-10-15T10:00:30-04:00',
                                  end_utc='2026-10-15T14:02:00Z')
        self.assertEqual([x['level_hint'] for x in result['events']], ['WARN', 'ERROR'])
        self.assertTrue(result['time_filter_excludes_unanchored'])
        self.assertEqual(len(t.query_timeline(self.store,self.cid,
                                              start_utc='2026-10-15T14:10:00Z')['events']), 0)

    def test_invalid_utc_range_or_reversed_range_denied(self):
        a=self.put('a.log', '2026-10-15T14:00:00Z hi\n')
        t.build_timeline(self.store,self.cid)
        for opts in ({'start_utc':'2026-10-15T14:00:00'},
                     {'end_utc':'not a date'},
                     {'start_utc':'2026-10-16T00:00:00Z', 'end_utc':'2026-10-15T00:00:00Z'}):
            with self.subTest(options=opts),self.assertRaises(casework.CaseError):
                t.query_timeline(self.store,self.cid,**opts)

    def test_literal_sql_wildcards_and_injection_not_interpreted(self):
        self.put('a.log', '2026-10-15T14:00:00Z 20% _F00\n'
                 '2026-10-15T14:01:00Z safe\n')
        t.build_timeline(self.store,self.cid)
        self.assertEqual(len(t.query_timeline(self.store,self.cid,text='20% _F00')['events']),1)
        self.assertEqual(len(t.query_timeline(self.store,self.cid,text="' OR 1=1--")['events']),0)

    def test_pagination_and_bounded_source_id(self):
        a,b=self.sample()
        t.build_timeline(self.store,self.cid)
        first=t.query_timeline(self.store,self.cid,limit=1)
        self.assertTrue(first['has_more'])
        self.assertEqual(first['next_offset'],1)
        second=t.query_timeline(self.store,self.cid,limit=1,offset=1)
        self.assertNotEqual(first['events'],second['events'])
        filtered=t.query_timeline(self.store,self.cid,artifact_id=b,include_unanchored=True)
        self.assertEqual(len(filtered['events']),2)
        self.assertTrue(all(row['artifact_id']==b for row in filtered['events']))
        with self.assertRaises(casework.CaseError):
            t.query_timeline(self.store,self.cid,artifact_id='a'*32)

    def test_invalid_controls_rejected_even_from_mcp_untyped(self):
        self.put('a.log','2026-10-15T14:00:00Z hi\n')
        t.build_timeline(self.store,self.cid)
        invalid=({'offset':True},{'offset':-1},{'offset':10001},{'limit':0},
                 {'limit':21},{'limit':'10'},{'include_unanchored':'yes'},
                 {'text':''},{'text':'x'*97},{'text':'new\nline'})
        for value in invalid:
            with self.subTest(input=value),self.assertRaises(casework.CaseError):
                t.query_timeline(self.store,self.cid,**value)

    def test_stale_when_same_length_source_mutated(self):
        aid=self.put('a.log', '2026-10-15T14:00:00Z OK\n')
        t.build_timeline(self.store,self.cid)
        source=self.store.cases/self.cid/'originals'/aid
        old=source.stat()
        source.write_bytes(b'2026-10-15T14:00:00Z XX\n')
        os.utime(source, ns=(old.st_atime_ns,old.st_mtime_ns+1_000_000_000))
        with self.assertRaisesRegex(casework.CaseError,'stale'):
            t.query_timeline(self.store,self.cid)

    def test_stale_after_new_text_artifact(self):
        self.put('a.log','2026-10-15T14:00:00Z One\n')
        t.build_timeline(self.store,self.cid)
        self.put('b.log','2026-10-15T14:00:01Z Two\n')
        with self.assertRaisesRegex(casework.CaseError,'stale'):
            t.timeline_sources(self.store,self.cid)
        again=t.build_timeline(self.store,self.cid)
        self.assertEqual(again['sources_indexed'],2)

    def test_added_pcap_does_not_stale_log_timeline(self):
        self.put('a.log','2026-10-15T14:00:00Z One\n')
        t.build_timeline(self.store,self.cid)
        self.put('capture.pcap', b'\xd4\xc3\xb2\xa1\x00'*6)
        self.assertEqual(t.timeline_summary(self.store,self.cid)['sources_indexed'],1)

    def test_corrupt_database_and_symlink_index_refused(self):
        self.put('a.log','2026-10-15T14:00:00Z hi\n')
        t.build_timeline(self.store,self.cid)
        dbfile=self.store.cases/self.cid/'indexes'/'timeline.sqlite3'
        dbfile.write_text('garbage')
        with self.assertRaisesRegex(casework.CaseError,'invalid|unavailable'):
            t.query_timeline(self.store,self.cid)
        dbfile.unlink()
        outside=self.home/'outside.sqlite3';outside.write_text('not SQLite')
        dbfile.symlink_to(outside)
        with self.assertRaisesRegex(casework.CaseError,'symlink'):
            t.query_timeline(self.store,self.cid)
        with self.assertRaisesRegex(casework.CaseError,'Unsafe'):
            t.build_timeline(self.store,self.cid)

    def test_cancellation_preserves_existing_index_and_removes_temporary(self):
        self.put('a.log','2026-10-15T14:00:00Z alive\n')
        t.build_timeline(self.store,self.cid)
        dbfile=self.store.cases/self.cid/'indexes'/'timeline.sqlite3'
        previous=dbfile.read_bytes()
        with self.assertRaises(RuntimeError):
            t.build_timeline(self.store,self.cid,should_cancel=lambda: (_ for _ in ()).throw(RuntimeError('stop')))
        self.assertEqual(dbfile.read_bytes(),previous)
        self.assertFalse(any(p.name.startswith('.tmp-timeline') for p in dbfile.parent.iterdir()))

    def test_oversized_line_is_skipped_but_hash_is_verified(self):
        self.put('a.log','2026-10-15T14:00:00Z this line is too long\n'
                 '2026-10-15T14:00:01Z short\n')
        with patch.object(t,'MAX_LINE',32):
            report=t.build_timeline(self.store,self.cid)
        self.assertEqual(report['lines_skipped'],1)
        self.assertEqual(report['events_indexed'],1)
        self.assertEqual(t.query_timeline(self.store,self.cid)['status'],'PARTIAL')

    def test_event_cap_fails_closed_without_index(self):
        self.put('a.log','2026-10-15T14:00:00Z One\n2026-10-15T14:00:01Z Two\n')
        with patch.object(t,'MAX_TIMELINE_EVENTS',1):
            with self.assertRaisesRegex(casework.CaseError,'count'):
                t.build_timeline(self.store,self.cid)
        self.assertFalse((self.store.cases/self.cid/'indexes'/'timeline.sqlite3').exists())

    def test_source_cap_fails_closed(self):
        self.put('a.log','2026-10-15T14:00:00Z One\n')
        self.put('b.log','2026-10-15T14:00:01Z Two\n')
        with patch.object(t,'MAX_TIMELINE_SOURCES',1):
            with self.assertRaisesRegex(casework.CaseError,'sources'):
                t.build_timeline(self.store,self.cid)

    def test_build_rejects_source_byte_change_same_length_no_output(self):
        aid=self.put('a.log','2026-10-15T14:00:00Z X\n')
        target=self.store.cases/self.cid/'originals'/aid
        target.write_bytes(b'2026-10-15T14:00:00Z Z\n')
        with self.assertRaisesRegex(casework.CaseError,'changed'):
            t.build_timeline(self.store,self.cid)
        self.assertFalse((self.store.cases/self.cid/'indexes'/'timeline.sqlite3').exists())

    def test_invalid_utf8_yields_partial_not_clean_timeline(self):
        self.put('garbled.log', b'2026-10-15T12:00:00Z ERROR invalid=\xff\xfe\n')
        report=t.build_timeline(self.store,self.cid)
        self.assertEqual(report['utf8_decode_errors'],1)
        self.assertEqual(report['status'],'PARTIAL')
        self.assertEqual(t.query_timeline(self.store,self.cid)['utf8_decode_errors'],1)
        self.assertEqual(t.timeline_summary(self.store,self.cid)['utf8_decode_errors'],1)

    def test_truncated_redacted_preview_cannot_report_full_search_coverage(self):
        self.put('long.log','2026-10-15T12:00:00Z '+('a'*400)+' TAIL_TRIGGER\n')
        r=t.build_timeline(self.store,self.cid)
        self.assertEqual(r['previews_truncated'],1)
        self.assertEqual(r['status'],'PARTIAL')
        q=t.query_timeline(self.store,self.cid,text='TAIL_TRIGGER')
        self.assertTrue(q['search_redacted_previews_only'])
        self.assertEqual(len(q['events']),0)
        self.assertEqual(q['status'],'PARTIAL')

    def test_timeline_version_mismatch_requires_rebuild(self):
        self.put('a.log','2026-10-15T14:00:00Z One\n')
        t.build_timeline(self.store,self.cid)
        idx=self.store.cases/self.cid/'indexes'/'timeline.sqlite3'
        with sqlite3.connect(idx) as db:
            db.execute("UPDATE facts SET value='1' WHERE key='schema_version'")
            db.commit()
        with self.assertRaisesRegex(casework.CaseError,'schema'):
            t.query_timeline(self.store,self.cid)

    def test_empty_case_timeline_is_explicit_nonapplicable(self):
        result=t.build_timeline(self.store,self.cid)
        self.assertEqual(result['events_indexed'],0)
        self.assertEqual(result['sources_indexed'],0)
        self.assertEqual(t.query_timeline(self.store,self.cid)['events'],[])
        self.assertEqual(result['status'],'NOT_APPLICABLE')
        self.assertEqual(t.timeline_summary(self.store,self.cid)['status'],'NOT_APPLICABLE')

    def test_summary_aggregates_not_a_false_root_cause(self):
        self.sample()
        t.build_timeline(self.store,self.cid)
        r=t.timeline_summary(self.store,self.cid)
        self.assertEqual(r['sources_indexed'],2)
        self.assertEqual(sum(x['count'] for x in r['level_hints']),4)
        self.assertEqual(sum(x['count'] for x in r['formats']),4)
        self.assertEqual(r['events_unanchored'],1)
        self.assertIn('not a causal diagnosis',r['note'])

    def test_job_submit_build_is_only_named_template_and_persists(self):
        self.put('a.log','2026-10-15T14:00:00Z ERROR job\n')
        j=jobwork.JobStore(self.home)
        with self.assertRaises(jobwork.JobError):
            j.submit('build_timeline',self.cid,artifact_id='a'*32)
        with self.assertRaises(jobwork.JobError):
            j.submit('bash',self.cid)
        queued=j.submit('build_timeline',self.cid)
        self.assertEqual(j.work_once()['state'],'SUCCEEDED')
        result=jobwork.JobStore(self.home).result(queued['job_id'])
        self.assertEqual(result['result']['events_indexed'],1)
        self.assertEqual(result['outcome'],'PASS')

    def test_mcp_tool_schemas_and_handler_permission(self):
        self.put('a.log','2026-10-15T14:00:00Z ERROR password=secret\n')
        conf=gateway.Config.load(self.home)
        g=gateway.Gateway(conf)
        names={x['name']:x for x in g.tools()}
        self.assertIn('timeline_summary',names)
        self.assertTrue(names['timeline_query']['annotations']['readOnlyHint'])
        self.assertFalse(names['job_submit']['annotations']['readOnlyHint'])
        with self.assertRaises(gateway.GatewayError):
            g.call('timeline_query', {'case_id': self.cid})
        job=g.call('job_submit', {'kind':'build_timeline', 'case_id':self.cid})
        self.assertEqual(jobwork.JobStore(self.home).work_once()['state'],'SUCCEEDED')
        res=g.call('timeline_query', {'case_id':self.cid,'text':'ERROR'})
        self.assertEqual(len(res['events']),1)
        self.assertNotIn('secret',json.dumps(res))
        self.assertEqual(g.call('timeline_summary',{'case_id':self.cid})['events_indexed'],1)
        self.assertEqual(len(g.call('timeline_sources',{'case_id':self.cid})['sources']),1)

    def test_no_timeline_without_job(self):
        with self.assertRaisesRegex(casework.CaseError,'not built'):
            t.query_timeline(self.store,self.cid)


if __name__=='__main__':
    unittest.main()
