"""Independent decoder verification must reject identity/time divergence."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from qualify_evtx_corpus import compare_reference


class NativeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.rows = [(7, 4624, '1970-01-01T00:00:00.000000+00:00',
                      'Security', 'Microsoft-Windows-Security-Auditing'),
                     (9, 4625, '1969-12-31T23:59:59.999000+00:00',
                      'Security', 'Microsoft-Windows-Security-Auditing')]
        identity = ('7|4624|Security|Microsoft-Windows-Security-Auditing\n'
                    '9|4625|Security|Microsoft-Windows-Security-Auditing\n')
        self.reference = {'identity_sha256': hashlib.sha256(identity.encode()).hexdigest(),
            'utc_zlib_base64': base64.b64encode(zlib.compress(b'[0,-1]')).decode()}

    def test_exact_and_single_millisecond_differences_include_pre_epoch(self):
        self.assertEqual(compare_reference(list(reversed(self.rows)), self.reference), 0)
        reference = self.reference | {'utc_zlib_base64':
            base64.b64encode(zlib.compress(b'[1,0]')).decode()}
        self.assertEqual(compare_reference(self.rows, reference), 2)

    def test_identity_drift_and_duplicate_record_ids_are_never_tolerated(self):
        altered = [self.rows[0], (9, 4624, *self.rows[1][2:])]
        with self.assertRaises(RuntimeError):
            compare_reference(altered, self.reference)
        with self.assertRaises(RuntimeError):
            compare_reference([self.rows[0], self.rows[0]], self.reference)

    def test_outside_tolerance_missing_or_corrupt_reference_refused(self):
        for times in (b'[2,-1]', b'[0,-3]', b'[0]', b'[0,true]'):
            reference = self.reference | {'utc_zlib_base64':
                base64.b64encode(zlib.compress(times)).decode()}
            with self.subTest(times=times), self.assertRaises(RuntimeError):
                compare_reference(self.rows, reference)
        reference = self.reference | {'utc_zlib_base64':
            base64.b64encode(zlib.compress(b'[0,-1]') + b'unexpected').decode()}
        with self.assertRaises(RuntimeError):
            compare_reference(self.rows, reference)
