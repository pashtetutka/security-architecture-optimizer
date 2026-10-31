"""Unified CLI dispatch and offline end-to-end catalog normalization."""
import hashlib
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from siem.etl.catalog import build_catalog
from siem.etl.cli import COMMANDS, main
from siem.etl.reports.overview import write_overview, write_latest_report


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
            self.assertEqual(len(list(output.glob('*.json'))), 10)
            self.assertIsNone(profiles['items'][0]['nodes'][0]['storage_devices'][0]['quantity'])
            with redirect_stdout(io.StringIO()) as report:
                main(['report', '--focused-dir', str(output)])
            self.assertIn('KOMRAD', report.getvalue())

    def test_check_creates_html_from_real_snapshot(self):
        snapshot = Path(__file__).parent / 'fixtures/komrad_prerequisites_4_6.html'
        with TemporaryDirectory() as temp:
            source = Path(temp) / 'vendors.json'
            output = Path(temp) / 'check'
            raw = {'run_at':'now','facts':[],'vendors':[{'id':'p13','name':'KOMRAD',
                'source_results':[{'source_id':'hardware_requirements','status':'ok',
                    'url':'https://docs.etecs.ru/komrad/docs/next/install/prerequisites/',
                    'snapshot_path':str(snapshot.resolve()),
                    'content_sha256':hashlib.sha256(snapshot.read_bytes()).hexdigest()}]}]}
            source.write_text(json.dumps(raw),encoding='utf-8')
            with redirect_stdout(io.StringIO()) as terminal:
                code = main(['check','--etl',str(source),'--output-dir',str(output),'--no-tests'])
            self.assertEqual(code,0)
            page=(output/'report.html').read_text(encoding='utf-8')
            self.assertIn('KOMRAD',page)
            self.assertIn('Base-SMART',page)
            self.assertIn('10.0 TB всего',page)
            self.assertIn('100000 EPS',page)
            self.assertIn('Результат этой проверки:',terminal.getvalue())
            self.assertEqual(len(list(output.glob('*.json'))),10)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['check','--etl',str(source),'--output-dir',str(output),'--no-tests'])

    def test_html_escapes_untrusted_evidence(self):
        catalog={'source_run_at':'now','_raw_run':{'vendors':[{'id':'p01','name':'Demo',
            'source_results':[]}]},'coverage':[{'siem_id':'p01','siem_name':'Demo',
            'integrations':1,'sizing_profiles':0,'requirements':0,'no_normalized_data':False}],
            'integrations':[{'siem_id':'p01','siem_name':'Demo',
                'source_name':'<script>alert(1)</script>',
                'evidence':[{'excerpt':'<img src=x onerror=alert(1)>',
                             'url':'javascript:alert(1)'}]}],
            'sizing_profiles':[],'system_requirements':[],
            'unread_system_documents':[],'unparsed_system_documents':[],
            'unread_source_catalog_documents':[]}
        with TemporaryDirectory() as temp:
            page=write_overview(catalog,Path(temp)).read_text(encoding='utf-8')
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;',page)
        self.assertNotIn('<script>alert(1)</script>',page)
        self.assertNotIn('href="javascript:',page)

    def test_check_runs_tests_and_records_failure(self):
        with TemporaryDirectory() as temp:
            source=Path(temp)/'raw.json'
            out=Path(temp)/'check'
            source.write_text(json.dumps({'run_at':'now','facts':[],'vendors':[]}),encoding='utf-8')
            completed=subprocess.CompletedProcess(args=[],returncode=1,stdout='',
                                                  stderr='Ran 1 test\n\nFAILED (failures=1)\n')
            with patch('siem.etl.commands.normalization.subprocess.run',return_value=completed), \
                 redirect_stdout(io.StringIO()):
                code=main(['check','--etl',str(source),'--output-dir',str(out)])
            self.assertEqual(code,1)
            self.assertIn('FAILED', (out/'tests.txt').read_text(encoding='utf-8'))
            self.assertIn('не прошли', (out/'report.html').read_text(encoding='utf-8'))

    def test_stable_report_uses_run_folder_for_json_links(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            run=root/'history'/'check_example'
            run.mkdir(parents=True)
            report=run/'report.html'
            report.write_text('<html><head><title>Обзор</title></head><body><a href="sources.json">JSON</a></body></html>',encoding='utf-8')
            stable=root/'etl_audit'/'report.html'
            write_latest_report(report,stable)
            page=stable.read_text(encoding='utf-8')
            self.assertIn('<base href="../history/check_example/">',page)
            self.assertIn('href="sources.json"',page)
            self.assertEqual(report.read_text(encoding='utf-8'),
                             '<html><head><title>Обзор</title></head><body><a href="sources.json">JSON</a></body></html>')


if __name__ == '__main__':
    unittest.main()
