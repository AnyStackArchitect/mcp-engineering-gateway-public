import hashlib
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/deployment'))
import deploy


class SourceEntryTests(unittest.TestCase):
    def test_manifest_mismatch_refused_before_source_walk_or_import(self):
        root=Path('/synthetic')
        info=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)
        with patch.object(Path,'lstat',return_value=info),patch.object(deploy,'safe_file',return_value=b'other'), \
             patch.object(deploy.os,'walk') as walk:
            with self.assertRaisesRegex(ValueError,'approved_source_manifest_mismatch'):
                deploy.verify_source(root,'a'*64)
            walk.assert_not_called()

    def test_source_closure_rejects_tamper_extra_missing_and_unsafe_directories(self):
        root=Path('/synthetic');content=b'synthetic source\n';manifest=(hashlib.sha256(content).hexdigest()+'  tool.py\n').encode()
        expected=hashlib.sha256(manifest).hexdigest();info=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)
        def data(path,maximum):return manifest if path.name=='SHA256SUMS.txt' else content
        with patch.object(Path,'lstat',return_value=info),patch.object(deploy,'safe_file',side_effect=data), \
             patch.object(deploy.os,'walk',return_value=[(root,[],['SHA256SUMS.txt','tool.py'])]):
            self.assertEqual(deploy.verify_source(root,expected)['files'],1)
            with patch.object(deploy.os,'walk',return_value=[(root,[],['extra.py'])]):
                with self.assertRaisesRegex(ValueError,'unmanifested'):deploy.verify_source(root,expected)
            with patch.object(deploy.os,'walk',return_value=[(root,[],['SHA256SUMS.txt'])]):
                with self.assertRaisesRegex(ValueError,'source_closure_mismatch'):deploy.verify_source(root,expected)
            with patch.object(deploy,'safe_file',side_effect=lambda p,m:manifest if p.name=='SHA256SUMS.txt' else b'drift'):
                with self.assertRaisesRegex(ValueError,'source_content_mismatch'):deploy.verify_source(root,expected)
            with patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0)):
                with self.assertRaisesRegex(ValueError,'root_owned'):deploy.verify_source(root,expected)


if __name__=='__main__':unittest.main()
