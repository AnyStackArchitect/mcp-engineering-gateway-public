"""Bounded actual local fixture streams; native Podman policy is separate CI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from casework import CaseStore,CaseError
import outputcopy
import outputwork


class OutputCopyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.cases=CaseStore(self.root)
        self.source=self.root/'source';self.source.mkdir(mode=0o700)
        self.target=self.root/'target';self.target.mkdir(mode=0o700)
        self.plan={'id':'a'*32,'disk_mib':8,'output_names':['result.json']}

    def command(self,program=None):
        text=outputcopy.PROGRAM if program is None else program
        text=text.replace("'/output/'",repr(str(self.source)+'/')).replace("'/output'",repr(str(self.source)))
        return [sys.executable,'-I','-B','-c',text,json.dumps(self.plan['output_names']),str(8*1024**2)]

    def copy(self,program=None):
        with patch.object(outputcopy,'stream_command',return_value=self.command(program)):
            outputcopy.copy_outputs(self.cases,self.plan,self.target)

    def test_only_declared_regular_content_is_streamed(self):
        value=b'controlled fixture\x00'*1000
        (self.source/'result.json').write_bytes(value)
        self.copy()
        self.assertEqual((self.target/'result.json').read_bytes(),value)
        self.assertEqual((self.target/'result.json').stat().st_mode&0o777,0o600)

    def test_unexpected_directory_symlink_and_hardlink_refused_before_allocation(self):
        path=self.source/'result.json'
        for kind in ('extra','directory','symlink','hardlink'):
            with self.subTest(kind=kind):
                if kind=='extra':(self.source/'unexpected').write_bytes(b'private')
                elif kind=='directory':path.mkdir()
                elif kind=='symlink':path.symlink_to(self.root/'outside')
                else:
                    (self.root/'outside').write_bytes(b'private');os.link(self.root/'outside',path)
                with self.assertRaises(outputcopy.CopyError):self.copy()
                self.assertFalse(any(self.target.iterdir()))
                for entry in self.source.iterdir():
                    if entry.is_dir() and not entry.is_symlink():entry.rmdir()
                    else:entry.unlink()

    def test_reserved_capacity_refuses_before_any_subprocess(self):
        with patch.object(outputcopy,'verify_committed_reserve',side_effect=CaseError('reserved')), \
            patch.object(outputcopy.subprocess,'Popen') as launch:
            with self.assertRaises(CaseError):self.copy()
            launch.assert_not_called()

    def test_private_registration_stage_rejects_before_opening_a_file(self):
        source=self.source/'result.json';source.write_bytes(b'fixture')
        target=self.cases.inbox/'not-created'
        with patch.object(outputwork,'admission_lock',side_effect=CaseError('unavailable')), \
                patch.object(outputwork.os,'open') as opening:
            with self.assertRaises(CaseError):
                outputwork._stage_output(self.cases,source,target,7,'a'*64)
            opening.assert_not_called()

    def test_untrusted_stream_header_cannot_escape_names_or_byte_limit(self):
        for inventory in ([{'name':'../escape','bytes':1}],[{'name':'result.json','bytes':8*1024**2+1}],
                [{'name':'result.json','bytes':True}],[{'name':'result.json','bytes':1}]*2):
            program='import sys,json; h='+repr(json.dumps(inventory).encode())+'; sys.stdout.buffer.write(len(h).to_bytes(4,"big")+h+b"x")'
            with self.subTest(inventory=inventory),self.assertRaises(outputcopy.CopyError):self.copy(program)
            self.assertFalse(any(self.target.iterdir()))
