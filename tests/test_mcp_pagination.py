"""Actual stdio MCP pages must never advertise an unreachable next cursor."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from casework import CaseStore
import correlationwork
import timelinework


class MCPPaginationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.home = Path(cls.temporary.name)
        cls.store = CaseStore(cls.home)
        cls.cases = {}
        for count in (10020, 10025):
            cid = cls.store.open_case()['case_id']
            path = cls.store.inbox/('records-'+str(count)+'.txt')
            path.write_bytes(b'2026-10-24T12:00:00Z synthetic event\n'*count)
            path.chmod(0o600)
            cls.store.register(cid, path.name)
            timelinework.build_timeline(cls.store, cid)
            correlationwork.build_correlation(cls.store, cid)
            cls.cases[count] = cid

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def call(self, tool, count, offset, limit=20, error=False):
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            '_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                      'io.modelcontextprotocol/clientCapabilities': {}},
            'name': tool, 'arguments': {'case_id': self.cases[count], 'offset': offset, 'limit': limit}}}
        root = Path(__file__).resolve().parents[1]
        env = {'HOME': str(self.home), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
               'PYTHONDONTWRITEBYTECODE': '1'}
        p = subprocess.run([sys.executable, '-B', str(root/'gateway.py')],
            input=json.dumps(request)+'\n', capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(p.stderr)
        self.assertLess(len(p.stdout), 65536)
        reply = json.loads(p.stdout)
        failed = 'error' in reply or reply.get('result', {}).get('isError', False)
        self.assertEqual(bool(failed), error, reply)
        if error:
            return reply
        return json.loads(reply['result']['content'][0]['text'])

    def test_normal_continuation_remains_usable(self):
        for tool in ('timeline_query', 'correlation_query'):
            result = self.call(tool, 10025, 0)
            self.assertTrue(result['has_more'])
            self.assertEqual(result['next_offset'], 20)
            self.assertFalse(result['pagination_bound_reached'])
            self.assertFalse(result['more_matching_events_outside_pagination_bound'])

    def test_inaccessible_next_page_is_partial_and_explicit(self):
        for tool in ('timeline_query', 'correlation_query'):
            for offset in (9990, 10000):
                result = self.call(tool, 10025, offset)
                self.assertIsNone(result['next_offset'], result)
                self.assertFalse(result['has_more'])
                self.assertEqual(result['status'], 'PARTIAL')
                self.assertTrue(result['pagination_bound_reached'])
                self.assertTrue(result['more_matching_events_outside_pagination_bound'])
                self.assertEqual(result['maximum_page_offset'], 10000)
                self.assertEqual(len(result['events']), 20)

    def test_full_final_page_does_not_invent_omitted_data(self):
        for tool in ('timeline_query', 'correlation_query'):
            result = self.call(tool, 10020, 10000)
            self.assertIsNone(result['next_offset'])
            self.assertFalse(result['has_more'])
            self.assertFalse(result['pagination_bound_reached'])
            self.assertFalse(result['more_matching_events_outside_pagination_bound'])
            self.assertEqual(result['status'], 'PASS')

    def test_offset_and_result_limit_guards_are_preserved(self):
        for tool in ('timeline_query', 'correlation_query'):
            self.call(tool, 10025, 10001, error=True)
            self.call(tool, 10025, 0, limit=21, error=True)


if __name__ == '__main__':
    unittest.main()
