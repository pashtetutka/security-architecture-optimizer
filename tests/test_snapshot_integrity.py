"""Downloaded evidence survives parser errors; source facts require its snapshot."""
import copy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from siem.etl.catalog import build_catalog
from siem.etl.pipeline import collect


DATA = (Path(__file__).parent / 'fixtures/catalogs/kuma_sources.html').read_bytes()
URL = 'https://example.test/catalog'
REGISTRY = {'vendors': [{'id': 'p12', 'name': 'KUMA', 'sources': [
    {'id': 'source_catalog', 'url': URL, 'mode': 'kuma'}]}]}


class Replay:
    def fetch(self, url):
        return DATA, 'utf-8', 'text/html'


class SnapshotIntegrityTests(unittest.TestCase):
    def test_bundled_reproduction_data_is_complete_and_hash_verified(self):
        manifest = Path(__file__).parent.parent/'data/etl/repro/vendors.json'
        raw = json.loads(manifest.read_text(encoding='utf-8'))
        result = build_catalog(raw, manifest)
        self.assertEqual((len(result['integrations']), len(result['sizing_profiles']),
                          len(result['system_requirements'])), (1630, 16, 26))
        self.assertEqual(result['unread_source_catalog_documents'], [])
        self.assertEqual(result['unread_system_documents'], [])

    def test_parser_failure_retains_original_hash_url_and_timestamp(self):
        with TemporaryDirectory() as temp:
            with patch('siem.etl.pipeline.extract_content', side_effect=ValueError('broken parser')):
                raw = collect(REGISTRY, Replay(), observed_at='2026-10-31T00:00:00Z', snapshot_dir=temp)
            doc = raw['vendors'][0]['source_results'][0]
            self.assertEqual((doc['status'], doc['failure_stage'], doc['snapshot_status']),
                             ('error', 'extraction', 'saved'))
            self.assertEqual(Path(doc['snapshot_path']).read_bytes(), DATA)
            self.assertEqual(doc['content_sha256'], hashlib.sha256(DATA).hexdigest())
            self.assertEqual(doc['resolved_url'], URL)
            self.assertEqual(doc['retrieved_at'], raw['run_at'])
            self.assertEqual(raw['facts'], [])

    def test_valid_collected_facts_and_rejected_provenance_variants(self):
        with TemporaryDirectory() as temp:
            raw = collect(REGISTRY, Replay(), snapshot_dir=temp)
            path = Path(temp)/'input.json'
            catalog = build_catalog(raw, path)
            self.assertEqual(len(catalog['integrations']), 2)
            self.assertEqual(catalog['unread_source_catalog_documents'], [])
            cases = [
                ('local_snapshot_unavailable', 'snapshot_path', str(Path(temp)/'missing.html')),
                ('document_hash_missing', 'content_sha256', None),
                ('snapshot_hash_mismatch', 'content_sha256', '0'*64),
                ('source_document_not_extracted', 'status', 'error'),
                ('fact_hash_missing', 'source_sha256', None),
                ('fact_hash_mismatch', 'source_sha256', '0'*64),
                ('fact_document_url_mismatch', 'source_url', 'https://another.test/catalog'),
            ]
            for reason, field, value in cases:
                with self.subTest(reason=reason):
                    changed = copy.deepcopy(raw)
                    if field in ('source_sha256', 'source_url'):
                        for fact in changed['facts']: fact[field] = value
                    else:
                        changed['vendors'][0]['source_results'][0][field] = value
                    rejected = build_catalog(changed, path)
                    self.assertEqual(rejected['integrations'], [])
                    self.assertEqual(len(rejected['unread_source_catalog_documents']), 1)
                    issue = rejected['unread_source_catalog_documents'][0]
                    self.assertEqual((issue['reason'], issue['affected_facts']), (reason, 2))
            # The failure cases alter manifests only, never the saved original.
            self.assertEqual(Path(raw['vendors'][0]['source_results'][0]['snapshot_path']).read_bytes(), DATA)

    def test_missing_or_ambiguous_manifest_is_not_accepted(self):
        with TemporaryDirectory() as temp:
            raw = collect(REGISTRY, Replay(), snapshot_dir=temp)
            for multiplier, reason in [(0, 'source_document_missing'), (2, 'ambiguous_source_document')]:
                with self.subTest(reason=reason):
                    changed = copy.deepcopy(raw)
                    changed['vendors'][0]['source_results'] *= multiplier
                    result = build_catalog(changed, Path(temp)/'input.json')
                    self.assertEqual(result['integrations'], [])
                    self.assertEqual(result['unread_source_catalog_documents'][0]['reason'], reason)

    def test_collection_without_snapshots_is_explicit_and_not_normalized(self):
        raw = collect(REGISTRY, Replay())
        self.assertEqual(raw['vendors'][0]['source_results'][0]['snapshot_status'], 'not_requested')
        result = build_catalog(raw, Path('input.json'))
        self.assertEqual(result['integrations'], [])
        self.assertEqual(result['unread_source_catalog_documents'][0]['reason'], 'local_snapshot_unavailable')
