"""Unified CLI dispatch and offline end-to-end catalog normalization."""
import hashlib
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from siem.etl.catalog import build_catalog
from siem.etl.cli import COMMANDS, main


class CLITests(unittest.TestCase):
    def test_dry_run_accepts_no_output(self):
        with redirect_stdout(io.StringIO()) as output:
            main(['crawl', '--dry-run', '--only', 'p13'])
        self.assertIn('p13', output.getvalue())
        self.assertNotIn('p03', output.getvalue())

    def test_command_help_reaches_each_handler(self):
        for command in COMMANDS:
            with self.subTest(command=command), redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as result:
                    main([command, '--help'])
                self.assertEqual(result.exception.code, 0)
                self.assertIn('usage:', output.getvalue())

    def test_module_and_compatibility_entrypoints(self):
        for module in ('siem.etl', 'siem.etl.cli', 'siem.etl.all_cli', 'siem.etl.focused_cli'):
            with self.subTest(module=module):
                result = subprocess.run([sys.executable, '-m', module, '--help'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage:', result.stdout)

    def test_normalize_real_komrad_snapshot_and_report(self):
        snapshot = Path(__file__).parent / 'fixtures/komrad_prerequisites_4_6.html'
        raw = {'run_at': '2026-10-28T10:00:00Z', 'facts': [], 'vendors': [{
            'id': 'p13', 'name': 'KOMRAD', 'source_results': [{
                'source_id': 'hardware_requirements', 'status': 'ok',
                'url': 'https://docs.etecs.ru/komrad/docs/next/install/prerequisites/',
                'snapshot_path': str(snapshot.resolve()),
                'content_sha256': hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            }],
        }]}
        with TemporaryDirectory() as temp:
            source = Path(temp) / 'vendors.json'
            output = Path(temp) / 'normalized'
            source.write_text(json.dumps(raw), encoding='utf-8')
            with redirect_stdout(io.StringIO()):
                main(['normalize', '--etl', str(source), '--output-dir', str(output)])
            expected = build_catalog(raw, source)
            profiles = json.loads((output / 'sizing_profiles.json').read_text(encoding='utf-8'))
            self.assertEqual(profiles['items'], expected['sizing_profiles'])
            self.assertEqual(len(profiles['items']), 4)
            self.assertEqual(len(list(output.glob('*.json'))), 9)
            self.assertIsNone(profiles['items'][0]['nodes'][0]['storage_devices'][0]['quantity'])
            with redirect_stdout(io.StringIO()) as report:
                main(['report', '--focused-dir', str(output)])
            self.assertIn('KOMRAD', report.getvalue())


if __name__ == '__main__':
    unittest.main()
