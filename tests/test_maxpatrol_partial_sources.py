"""MaxPatrol 8.6 partial-support table from the user's saved portal HTML."""
import hashlib
import json
import unittest
from pathlib import Path

from siem.etl.catalog import build_catalog
from siem.etl.vendors.maxpatrol import parse_maxpatrol_supported_api
from siem.etl.pipeline import collect


class MaxPatrolPartialSourcesTests(unittest.TestCase):
    def test_supported_api_real_snapshot_and_collection(self):
        from tempfile import TemporaryDirectory
        path = Path(__file__).parent / 'fixtures' / 'maxpatrol_supported_sources.json'
        data = path.read_bytes()
        digest = 'a7df480fe76184cedb6ca032522086d4f293fbae0e8ceb3a852450ea131743d5'
        self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        class Replay:
            acquisition_method = 'snapshot_replay'
            def fetch(self, url): return data, 'utf-8', 'application/json'
        with TemporaryDirectory() as temp:
            raw = collect({'vendors': [{'id': 'p06', 'name': 'MaxPatrol SIEM', 'sources': [{
                'id': 'supported_sources_api', 'url': 'https://example.test/document',
                'mode': 'maxpatrol_api', 'product_version_hint': '8.6'}]}]},
                fetch=Replay(), snapshot_dir=temp)
            doc = raw['vendors'][0]['source_results'][0]
            self.assertTrue(doc['snapshot_path'].endswith('.json'))
            self.assertEqual(doc['content_sha256'], digest)
            catalog = build_catalog(raw, Path(temp)/'raw.json')
        rows = catalog['integrations']
        self.assertEqual(len(rows), 228)
        self.assertTrue(all(r['support_scope'] == 'supported' for r in rows))
        self.assertTrue(all(r['siem_version'] is None and not r['functional_integration_verified'] for r in rows))
        self.assertTrue(all(r['evidence'][0]['document_sha256'] == digest for r in rows))
        self.assertEqual(next(r for r in rows if r['source_name'] == 'Amazon Web Services')['source_version'], None)
        samba = next(r for r in rows if r['source_name'] == 'Samba DC')
        self.assertEqual((samba['source_vendor'], samba['source_version'], samba['collection_profile']),
                         ('Базальт СПО', '10.4', 'SysLog'))
        self.assertIsNone(samba['normalizer_id'])
        self.assertEqual(catalog['unread_source_catalog_documents'], [])

    def test_supported_api_rejects_other_product_and_ambiguous_markup(self):
        doc = json.loads((Path(__file__).parent/'fixtures'/'maxpatrol_supported_sources.json').read_text(encoding='utf-8'))
        meta = {'siem_id': 'p06', 'siem_name': 'MaxPatrol SIEM'}
        with self.assertRaisesRegex(ValueError, 'scope'):
            parse_maxpatrol_supported_api(json.dumps(dict(doc, project='mp10')).encode(), meta)
        with self.assertRaisesRegex(ValueError, 'rowspan'):
            parse_maxpatrol_supported_api(json.dumps(dict(doc, content=doc['content'].replace('<td', '<td rowspan="2"', 1))).encode(), meta)
        with self.assertRaisesRegex(ValueError, 'nested_table'):
            parse_maxpatrol_supported_api(json.dumps(dict(doc, content=doc['content']+'<table></table>')).encode(), meta)

    def test_supported_api_wrong_document_is_reported(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temp:
            path = Path(temp)/'wrong.json'
            path.write_text('{"project":"mp10"}', encoding='utf-8')
            raw = {'facts': [], 'vendors': [{'id': 'p06', 'name': 'MaxPatrol', 'source_results': [{
                'source_id': 'supported_sources_api', 'status': 'empty_review_required',
                'snapshot_path': str(path), 'url': 'https://example.test/api',
                'content_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]}]}
            catalog = build_catalog(raw, path)
        self.assertEqual(catalog['integrations'], [])
        self.assertEqual(catalog['unread_source_catalog_documents'][0]['reason'], 'json_source_extraction_failed')

    def test_real_table_keeps_partial_scope_and_published_versions(self):
        path = Path(__file__).parent / 'fixtures' / 'maxpatrol_partial_sources.html'
        digest = '3ce98d29d804e94a7b99a4a2b58abf18676d81ce9e57370bcafaa413dd343228'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        source = {'source_id': 'partial_sources', 'status': 'ok',
                  'url': 'https://help.ptsecurity.com/ru-RU/projects/siem/8.6/help/1194299019',
                  'snapshot_path': str(path), 'content_sha256': digest,
                  'product_version_hint': '8.6', 'acquisition_method': 'manual_import',
                  'retrieved_at': '2026-10-28T15:47:22+03:00'}
        raw = {'run_at': '2026-10-28T16:00:00+03:00', 'facts': [],
               'vendors': [{'id': 'p06', 'name': 'MaxPatrol SIEM', 'source_results': [source]}]}
        catalog = build_catalog(raw, path.parent / 'input.json')
        rows = catalog['integrations']
        self.assertEqual(len(rows), 179)
        self.assertTrue(all(row['support_scope'] == 'partial' for row in rows))
        self.assertTrue(all(row['integration_evidence'] == 'published_partial_support_table' for row in rows))
        self.assertTrue(all(row['siem_version'] is None and not row['functional_integration_verified']
                            for row in rows))
        redcheck = next(r for r in rows if r['source_name'] == 'RedCheck')
        self.assertEqual((redcheck['source_vendor'], redcheck['source_version']),
                         ('АЛТЭКС-СОФТ', '2.6.2.2833'))
        self.assertEqual(redcheck['evidence'][0]['document_sha256'], digest)
        self.assertEqual(redcheck['evidence'][0]['retrieved_at'], source['retrieved_at'])
        self.assertEqual(sum(r['source_version'] is None for r in rows), 13)
        self.assertFalse(any('\u00ad' in r['source_name'] for r in rows))
        self.assertEqual(catalog['unread_source_catalog_documents'], [])

    def test_hash_mismatch_yields_diagnostic_not_rows(self):
        path = Path(__file__).parent / 'fixtures' / 'maxpatrol_partial_sources.html'
        raw = {'facts': [], 'vendors': [{'id': 'p06', 'name': 'MaxPatrol SIEM',
                'source_results': [{'source_id': 'partial_sources', 'status': 'ok',
                                    'url': 'https://example.test/partial',
                                    'snapshot_path': str(path), 'content_sha256': '0' * 64}]}]}
        catalog = build_catalog(raw, path.parent / 'input.json')
        self.assertEqual(catalog['integrations'], [])
        self.assertEqual(catalog['unread_source_catalog_documents'][0]['reason'], 'snapshot_hash_mismatch')


if __name__ == '__main__':
    unittest.main()
