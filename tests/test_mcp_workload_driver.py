"""Transport smoke qualification uses a fresh HOME and preserves its transcript."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class MCPWorkloadDriverTests(unittest.TestCase):
    def test_smoke_workflow_and_existing_output_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'workload'
            root = Path(__file__).resolve().parents[1]
            argv = [sys.executable, '-B', str(root/'scripts/qualify_mcp_workload.py'),
                    '--profile', 'smoke', '--output', str(output)]
            p = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
            result = json.loads((output/'RESULT.json').read_text())
            self.assertEqual(result['status'], 'PASS')
            self.assertTrue(all(c['passed'] for c in result['checks']))
            self.assertEqual(result['skipped_full_scenarios'],
                             ['running_cancel','SIGKILL_recovery','million_line_capacity'])
            self.assertTrue(list((output/'requests').glob('*.json')))
            before = (output/'RESULT.json').read_bytes()
            refused = subprocess.run(argv, cwd=root, capture_output=True, timeout=20)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual((output/'RESULT.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
