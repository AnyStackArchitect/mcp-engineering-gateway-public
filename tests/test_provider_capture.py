"""Actual controlled subprocess fixtures for the fixed runner capture boundary."""
import os
from pathlib import Path
import resource
import sys
import tempfile
import unittest

from provider_runner import bounded_command


class ProviderCaptureTests(unittest.TestCase):
    def test_exact_stdout_stderr_exit_and_finite_file_limit(self):
        code,out,err=bounded_command([sys.executable,'-I','-c',
            'import resource,sys;print(resource.getrlimit(resource.RLIMIT_FSIZE)[1]);sys.stderr.write("fixture");sys.exit(7)'],dict(os.environ))
        self.assertEqual((code,out,err),(7,b'65536\n',b'fixture'))

    def test_stream_overflow_kills_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile=Path(folder)/'fixture.pid'
            for stream in ('stdout','stderr'):
                program='import os,sys,time;open('+repr(str(pidfile))+',"w").write(str(os.getpid()));sys.'+stream+'.write("x"*100000);sys.'+stream+'.flush();time.sleep(100)'
                with self.subTest(stream=stream),self.assertRaisesRegex(RuntimeError,'capture_limit'):
                    bounded_command([sys.executable,'-I','-c',program],dict(os.environ),unlimited_file_size=True)
                pid=int(pidfile.read_text())
                with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_xfs_startup_file_limit_request_uses_bounded_pipe_exception(self):
        program='import resource;resource.setrlimit(resource.RLIMIT_FSIZE,(resource.RLIM_INFINITY,resource.RLIM_INFINITY));print("fixture")'
        code,_,_=bounded_command([sys.executable,'-I','-c',program],dict(os.environ))
        self.assertNotEqual(code,0)
        if resource.getrlimit(resource.RLIMIT_FSIZE)[1]!=resource.RLIM_INFINITY:
            self.skipTest('Clean test runtime has a finite inherited hard file limit')
        code,out,err=bounded_command([sys.executable,'-I','-c',program],dict(os.environ),unlimited_file_size=True)
        self.assertEqual((code,out,err),(0,b'fixture\n',b''))
