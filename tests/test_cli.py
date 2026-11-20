"""Unified CLI dispatch and offline end-to-end catalog normalization."""
import hashlib
import io
import json
import os
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
    def test_additional_etl_preserves_snapshot_base_and_rejects_duplicate_ids(self):
        from siem.etl.commands.normalization import load_inputs
        with TemporaryDirectory() as temp:
            root = Path(temp)
            base = root/'base.json'
            extra_dir = root/'extra'
            extra_dir.mkdir()
            snapshot = extra_dir/'source.html'
            snapshot.write_text('<html>original</html>', encoding='utf-8')
            extra = extra_dir/'run.json'
            base.write_text(json.dumps({'vendors': [{'id': 'p10', 'source_results': []}],
                                        'facts': []}), encoding='utf-8')
            extra.write_text(json.dumps({'vendors': [{'id': 'p10', 'source_results': [{
                'source_id': 'release_sources', 'snapshot_path': 'source.html', 'status': 'ok'}]}],
                'facts': []}), encoding='utf-8')
            result = load_inputs([base, extra])
            self.assertEqual(result['vendors'][0]['source_results'][0]['snapshot_path'], str(snapshot.resolve()))
            self.assertEqual(result['totals']['sources'], 1)
            self.assertEqual(json.loads(base.read_text(encoding='utf-8'))['vendors'][0]['source_results'], [])
            with self.assertRaisesRegex(ValueError, 'Duplicate source_id'):
                load_inputs([base, extra, extra])

    def test_restricted_documents_are_excluded_from_public_collection(self):
        with redirect_stdout(io.StringIO()) as output:
            main(['crawl', '--dry-run', '--only', 'p10', '--source-ids', 'release_sources',
                  '--exclude-restricted-documents'])
        self.assertNotIn('.pdf', output.getvalue())
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
                                        capture_output=True, encoding='utf-8')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage:', result.stdout)

    def test_russian_cli_output_is_utf8_under_cp1252(self):
        env = dict(os.environ, PYTHONUTF8='0', PYTHONIOENCODING='cp1252')
        for module, args, expected in (
            ('siem.etl', ['crawl', '--help'], 'Показать URL'),
            ('siem.etl.cli', ['normalize', '--help'], 'Добавить документы'),
            ('siem.etl.all_cli', ['--help'], 'условная оценка'),
            ('siem.etl.focused_cli', ['--help'], 'Нормализация'),
            ('siem.etl.commands.collection', ['crawl', '--dry-run', '--only', 'p02'], 'СёрчИнформ SIEM'),
            ('siem.etl.commands.normalization', ['--help'], 'Нормализация'),
        ):
            with self.subTest(module=module):
                result = subprocess.run([sys.executable, '-m', module, *args], env=env,
                                        capture_output=True, encoding='utf-8')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
        with TemporaryDirectory() as temp:
            result = subprocess.run([sys.executable, '-m', 'siem.etl', 'check',
                                     '--etl', str(Path(temp)/'missing.json')],
                                    env=env, capture_output=True, encoding='utf-8')
        self.assertEqual(result.returncode, 2)
        self.assertIn('Не найден входной JSON', result.stderr)

    def test_normalize_real_komrad_snapshot_and_report(self):
        snapshot = Path(__file__).resolve().parents[1] / 'data/etl/repro/raw/p13/hardware_requirements_49bf901b512592.html'
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
            self.assertEqual(len(list(output.glob('*.json'))), 13)
            self.assertTrue((output / 'source_classes.json').is_file())
            self.assertIsNone(profiles['items'][0]['nodes'][0]['storage_devices'][0]['quantity'])
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['normalize', '--etl', str(source), '--output-dir', str(output)])
            with redirect_stdout(io.StringIO()) as report:
                main(['report', '--focused-dir', str(output)])
            self.assertIn('KOMRAD', report.getvalue())

    def test_check_creates_html_from_real_snapshot(self):
        snapshot = Path(__file__).resolve().parents[1] / 'data/etl/repro/raw/p13/hardware_requirements_49bf901b512592.html'
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
            self.assertIn('Качество извлечения', page)
            self.assertIn('Условия использования данных в расчётах', page)
            self.assertNotIn('Замечания к структуре:', page)
            self.assertNotIn('source_integrations_not_reviewed', page)
            self.assertEqual(len(list(output.glob('*.json'))),13)
            self.assertTrue((output / 'source_classes.json').is_file())
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
