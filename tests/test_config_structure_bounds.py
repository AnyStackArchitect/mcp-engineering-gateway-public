"""Opaque JSON arrays must never bypass whole-source resource validation."""
import json
import unittest

from casework import CaseError
import configdelta
import configwork


class WholeConfigBoundsTests(unittest.TestCase):
    def check_rejected(self, value, message):
        for parser in (configwork._flatten_json, configdelta._flatten):
            with self.subTest(parser=parser.__module__, reason=message):
                with self.assertRaisesRegex(CaseError, message):
                    parser(value)

    def test_depth_inside_atomic_array_is_bounded(self):
        value = 0
        for _ in range(20):
            value = [value]
        self.check_rejected({'a': value}, 'nesting')

    def test_array_size_inside_atomic_array_is_bounded(self):
        self.check_rejected({'a': [list(range(4097))]}, 'array')

    def test_nested_keys_inside_atomic_array_are_bounded(self):
        self.check_rejected({'a': [{'k' * 161: 1}]}, 'key')

    def test_nested_field_count_inside_atomic_array_is_bounded(self):
        self.check_rejected({'a': [{str(i): i for i in range(4097)}]}, 'field')

    def test_total_nodes_are_bounded_across_small_arrays(self):
        self.check_rejected({'a': [[0] * 4096 for _ in range(8)]}, 'node')

    def test_exponent_overflow_inside_atomic_array_is_refused(self):
        value = json.loads('{"a":[{"value":1e999}]}')
        self.check_rejected(value, 'nonfinite')

    def test_individual_array_boundary_is_accepted(self):
        value = {'a': list(range(4096))}
        for parser in (configwork._flatten_json, configdelta._flatten):
            with self.subTest(parser=parser.__module__):
                self.assertTrue(parser(value))

    def test_exact_depth_boundary_is_accepted(self):
        value = 0
        for _ in range(11):
            value = [value]
        for parser in (configwork._flatten_json, configdelta._flatten):
            self.assertTrue(parser({'a': value}))

    def test_parse_path_uses_recursive_validation(self):
        with self.assertRaisesRegex(CaseError, 'array'):
            configdelta._decode(json.dumps({'a': [[0] * 4097]}).encode(), 'json')


if __name__ == '__main__':
    unittest.main()
