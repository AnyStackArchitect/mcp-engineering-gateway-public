"""Bounded decoding and fail-closed native module selection fixtures."""
import bz2
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'ops/deployment'))
import policy_preflight as subject


class PolicyPreflightTests(unittest.TestCase):
    def test_plain_and_compressed_sources_have_identical_decoded_bytes(self):
        value = b'(type synthetic_t)\n'
        self.assertEqual(subject.decode(value), value)
        self.assertEqual(subject.decode(bz2.compress(value)), value)

    def test_truncated_concatenated_binary_and_bomb_sources_refused(self):
        with patch.object(subject, 'LIMIT', 64):
            for value in (bz2.compress(b'x'*65), bz2.compress(b'good')[:-3],
                          bz2.compress(b'one')+bz2.compress(b'two'), b'x\x00y', b'x'*65):
                with self.subTest(size=len(value)), self.assertRaises(ValueError):
                    subject.decode(value)

    def test_highest_priority_selected_without_loading_low_priority_override(self):
        root = Path('/synthetic/modules')
        tree = {root: ['100','400','disabled'], root/'100':['base','same'],
                root/'400':['same'], root/'disabled':[]}
        def listing(path): return iter(path/name for name in tree[path])
        info = types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755, st_uid=0)
        with patch.object(Path,'iterdir',listing), patch.object(Path,'lstat',return_value=info):
            selected = subject.select_modules(root)
            self.assertEqual(selected['same'],root/'400/same')
            self.assertEqual(selected['base'],root/'100/base')
            tree[root/'disabled']=['base']
            with self.assertRaises(ValueError): subject.select_modules(root)

    def test_existing_candidate_or_unknown_priority_or_links_refused(self):
        root = Path('/synthetic/modules')
        tree = {root:['100','disabled'],root/'100':['base','engbox_worker'],root/'disabled':[]}
        def listing(path): return iter(path/name for name in tree[path])
        info = types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        with patch.object(Path,'iterdir',listing), patch.object(Path,'lstat',return_value=info):
            with self.assertRaises(ValueError): subject.select_modules(root)
            self.assertIn('engbox_worker',subject.select_modules(root,allow_candidate=True))
            tree[root]=['unknown','disabled']
            with self.assertRaises(ValueError): subject.select_modules(root)
            tree[root]=['100','disabled']
            with patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0)):
                with self.assertRaises(ValueError): subject.select_modules(root)


if __name__ == '__main__': unittest.main()
