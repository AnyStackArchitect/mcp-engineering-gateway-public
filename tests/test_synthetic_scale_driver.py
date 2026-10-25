"""The opt-in driver must start from a genuinely new synthetic HOME."""
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest


class SyntheticScaleDriverTests(unittest.TestCase):
    def test_repeated_signal_groups_use_independent_tcp_connections(self):
        from scripts.qualify_synthetic_scale import make_capture
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'generated.pcap'
            make_capture(path, 'pcap', 2000)
            packets = []
            with path.open('rb') as stream:
                stream.read(24)
                while header := stream.read(16):
                    size = struct.unpack('<IIII', header)[2]
                    packets.append(stream.read(size))
            self.assertEqual(len(packets), 2000)
            for cycle in (0, 1):
                base = cycle*1000
                ports = [struct.unpack('!HH', packets[base+n][34:38]) for n in (2, 3, 4)]
                self.assertEqual(ports, [(445, 50000+cycle), (51000+cycle, 443), (443, 51000+cycle)])

    def test_fresh_home_profile_and_existing_output_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'qualification'
            root = Path(__file__).resolve().parents[1]
            code = ('import sys; from pathlib import Path; '
                    'from scripts.qualify_synthetic_scale import PROFILES,run; '
                    "PROFILES['log-small']=100; "
                    "raise SystemExit(run('log-small',Path(sys.argv[1])))")
            command = [sys.executable, '-B', '-c', code, str(output)]
            first = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr+first.stdout)
            result = json.loads((output/'RESULT.json').read_text())
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['input_bytes'], 19_200)
            self.assertTrue(all(result['checks'].values()))
            before = (output/'RESULT.json').read_bytes()
            second = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual((output/'RESULT.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
