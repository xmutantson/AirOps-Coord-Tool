"""Run actual form JavaScript with inert DOM and transport; no live browser or network."""
from pathlib import Path
import shutil
import subprocess
import unittest


class ArrivalBrowserTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node is required for the inert DOM regression suite')
    def test_actual_form_recovery_and_exact_retry(self):
        result=subprocess.run([shutil.which('node'),'--test',str(Path(__file__).with_name('arrival_form_retry.cjs'))],
            capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
