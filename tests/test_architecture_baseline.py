"""Dev-tool tests use disposable repositories; no project baseline is created."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from importlib.util import module_from_spec, spec_from_file_location
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


SPEC = spec_from_file_location('architecture_baseline_tool',
                               Path(__file__).resolve().parents[1] / 'tools/baseline.py')
baseline = module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


@contextmanager
def working_directory(path):
    before = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(before)


class ArchitectureBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.root = self.home / 'original'
        self.root.mkdir()
        self.output = self.root / 'results/baseline'
        self.snapshot = self.root / 'data/etl/repro/raw/p05/document.pdf'
        self.snapshot.parent.mkdir(parents=True)
        self.snapshot.write_bytes(b'original immutable document bytes')
        self.digest = hashlib.sha256(self.snapshot.read_bytes()).hexdigest()
        self.raw = {
            'schema_version': '1.0', 'run_at': '2026-10-31T10:16:58+00:00', 'facts': [],
            'vendors': [
                {'id': 'p05', 'name': 'SC', 'source_results': [{
                    'source_id': 'product_document', 'url': 'https://example.test/restricted.pdf',
                    'status': 'ok', 'snapshot_status': 'saved',
                    'snapshot_path': self.snapshot.relative_to(self.root).as_posix(),
                    'content_sha256': self.digest, 'acquisition_method': 'manual_import',
                    'retrieved_at': '2026-10-27T05:21:56+00:00',
                    'http_content_type': 'application/pdf',
                }]},
                {'id': 'p08', 'name': 'Unavailable', 'source_results': [{
                    'source_id': 'catalog', 'url': 'https://example.test/blocked',
                    'status': 'access_disallowed', 'acquisition_method': 'automatic_https'}]},
            ],
        }
        self.registry = {'schema_version': 'registry/1', 'vendors': [
            {'id': 'p05', 'sources': [{'id': 'product_document'}]},
            {'id': 'p08', 'sources': [{'id': 'catalog'}]},
        ]}
        self.permission_observations = {
            'schema_version': 'baseline-permission-observations/1.0',
            'observations': [{'document_sha256': self.digest, 'restriction': 'restricted',
                              'owner_permission': 'unknown', 'basis': 'Written permission required.',
                              'source_url': 'https://example.test/restricted.pdf',
                              'locator': {'page': 2}, 'observed_at': '2026-11-16'}],
        }
        self._write_inputs()
        (self.root / 'AGENTS.md').write_text('Mandatory baseline instruction\n', encoding='utf8')
        (self.root / 'README.md').write_text('Repository\n', encoding='utf8')
        (self.root / '.gitignore').write_text('results/\nAGENTS.md\nignored.txt\n', encoding='utf8')
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Baseline Test',
                        '-c', 'user.email=baseline@example.test', 'commit', '-qm', 'fixture'],
                       check=True, capture_output=True)

    def _write_inputs(self):
        for relative, value in [(baseline.MANIFEST, self.raw), (baseline.REGISTRY, self.registry),
                                (baseline.PERMISSION_OBSERVATIONS, self.permission_observations),
                                (baseline.QUESTIONNAIRE, {'schema_version': 'scenario/1'})]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding='utf8')

    def _fake_exports(self, root, output, raw):
        # The seam isolates portable-baseline behavior from the pre-existing
        # vendor parsers. The real 23×13 corpus is checked at integration time.
        baseline._write(output / 'exports/full/sources.json', {'items': [{'name': 'published'}]})
        return {'full': {'counts': {'integrations': 1}, 'catalog_schema': 'catalog/1'},
                'automatic': {'counts': {'integrations': 0}, 'catalog_schema': 'catalog/1'}}

    def _capture(self):
        with patch.object(baseline, '_capture_exports', side_effect=self._fake_exports):
            return baseline.capture(self.root, self.output)

    def test_capture_and_verify_after_root_relocation_from_unrelated_cwd(self):
        (self.root / 'untracked.py').write_text('ANSWER = 42\n', encoding='utf8')
        (self.root / 'ignored.txt').write_text('ignored', encoding='utf8')
        before = self.snapshot.read_bytes()
        captured = self._capture()
        document = captured['documents'][0]
        self.assertEqual(captured['status'], 'captured')
        self.assertEqual(document['snapshot_path'], 'data/etl/repro/raw/p05/document.pdf')
        self.assertEqual(document['acquisition_method'], 'manual_import')
        self.assertEqual(document['retrieved_at'], '2026-10-27T05:21:56+00:00')
        self.assertIsNone(document['acquired_at'])
        self.assertEqual(document['permissions']['restriction'], 'restricted')
        self.assertEqual(document['permissions']['owner_permission'], 'unknown')
        self.assertEqual(document['permissions']['review_status'], 'owner_permission_unverified')
        self.assertIn('permission_observations', captured['inputs'])
        self.assertEqual(captured['documents'][1]['availability'], 'known_unavailable')
        tree_paths = {item['path'] for item in captured['source_tree']['files']}
        self.assertIn('AGENTS.md', tree_paths)
        self.assertIn('untracked.py', tree_paths)
        self.assertNotIn('ignored.txt', tree_paths)
        self.assertEqual(self.snapshot.read_bytes(), before)
        self.assertTrue(all(path.suffix == '.json' for path in self.output.rglob('*') if path.is_file()))
        moved = self.home / 'relocated'
        shutil.copytree(self.root, moved)
        with working_directory(self.home), patch.object(baseline.socket, 'create_connection',
                                                        side_effect=AssertionError('Network attempted')):
            result = baseline.verify(moved, moved / 'results/baseline')
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(result['known_unavailable'], 1)
        with redirect_stdout(StringIO()):
            self.assertEqual(baseline.main(['verify', '--root', str(moved),
                                            '--baseline', 'results/baseline']), 0)

    def test_verify_detects_corrupt_and_missing_snapshot_and_changed_tree(self):
        self._capture()
        self.snapshot.write_bytes(b'changed')
        result = baseline.verify(self.root, self.output)
        self.assertIn('snapshot_hash_mismatch', {error['reason'] for error in result['errors']})
        self.snapshot.unlink()
        result = baseline.verify(self.root, self.output)
        self.assertIn('declared_snapshot_missing', {error['reason'] for error in result['errors']})
        (self.root / 'AGENTS.md').write_text('Changed instruction\n', encoding='utf8')
        self.assertTrue(any('AGENTS.md' in error.get('paths', [])
                            for error in baseline.verify(self.root, self.output)['errors']))

    def test_capture_records_invalid_declared_hash_and_verify_is_nonzero(self):
        self.raw['vendors'][0]['source_results'][0]['content_sha256'] = '0' * 64
        self._write_inputs()
        with patch.object(baseline, '_capture_exports') as exports, redirect_stdout(StringIO()):
            self.assertEqual(baseline.main(['capture', '--root', str(self.root),
                                            '--output-dir', 'results/baseline']), 1)
            exports.assert_not_called()
            self.assertEqual(baseline.main(['verify', '--root', str(self.root),
                                            '--baseline', 'results/baseline']), 1)
        captured = json.loads((self.output / 'baseline_manifest.json').read_text(encoding='utf8'))
        self.assertEqual(captured['integrity_errors'][0]['reason'], 'snapshot_hash_mismatch')

    def test_missing_hash_and_missing_declared_snapshot_are_errors(self):
        self.raw['vendors'][0]['source_results'][0].pop('content_sha256')
        self._write_inputs()
        captured = self._capture()
        self.assertEqual(captured['integrity_errors'][0]['reason'], 'document_hash_missing')
        self.snapshot.unlink()
        documents, errors = baseline._documents(self.root, self.raw, self.registry)
        self.assertEqual(errors[0]['reason'], 'declared_snapshot_missing')
        self.assertEqual(documents[0]['availability'], 'integrity_error')

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir(parents=True)
        existing = self.output / 'keep.txt'
        existing.write_bytes(b'must survive')
        with redirect_stderr(StringIO()):
            self.assertEqual(baseline.main(['capture', '--root', str(self.root),
                                            '--output-dir', str(self.output)]), 1)
        self.assertEqual(existing.read_bytes(), b'must survive')
        self.assertEqual(list(self.output.iterdir()), [existing])

    def test_verify_detects_export_edit_and_manifest_edit(self):
        self._capture()
        (self.output / 'exports/full/sources.json').write_text('{}', encoding='utf8')
        (self.root / baseline.MANIFEST).write_text('{}', encoding='utf8')
        reasons = {error['reason'] for error in baseline.verify(self.root, self.output)['errors']}
        self.assertIn('input_missing_or_changed', reasons)
        self.assertIn('export_missing_or_changed', reasons)

    def test_permission_observation_matches_bytes_after_document_is_renamed(self):
        self.raw['vendors'][0]['id'] = 'another_vendor'
        self.raw['vendors'][0]['source_results'][0]['source_id'] = 'another_document'
        self.registry['vendors'][0]['id'] = 'another_vendor'
        self.registry['vendors'][0]['sources'][0]['id'] = 'another_document'
        self._write_inputs()
        captured = self._capture()
        self.assertEqual(captured['documents'][0]['permissions']['restriction'], 'restricted')
        self.assertEqual(captured['documents'][0]['permissions']['owner_permission'], 'unknown')
        (self.root / baseline.PERMISSION_OBSERVATIONS).write_text('{}', encoding='utf8')
        errors = baseline.verify(self.root, self.output)['errors']
        self.assertTrue(any(error.get('path') == baseline.PERMISSION_OBSERVATIONS and
                            error['reason'] == 'input_missing_or_changed' for error in errors))

    def test_registry_restriction_applies_without_optional_sidecar(self):
        (self.root / baseline.PERMISSION_OBSERVATIONS).unlink()
        self.registry['vendors'][0]['sources'][0]['redistribution'] = 'permission_required_do_not_publish_snapshot'
        (self.root / baseline.REGISTRY).write_text(json.dumps(self.registry), encoding='utf8')
        captured = self._capture()
        permissions = captured['documents'][0]['permissions']
        self.assertEqual(permissions['restriction'], 'restricted')
        self.assertEqual(permissions['owner_permission'], 'unknown')
        self.assertNotIn('permission_observations', captured['inputs'])


if __name__ == '__main__':
    unittest.main()
