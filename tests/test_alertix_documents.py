"""Regression checks against byte-for-byte Alertix documentation snapshots."""
import hashlib
import unittest
from pathlib import Path

from siem.etl.catalog import build_catalog


FIXTURES = Path(__file__).parent / 'fixtures'
FAQ_HASH = 'f35a857513e8aef8cc66cf8c76e35e7290488d7296553d8c6d5088c556e5bee8'
ARCH_HASH = '3f3347f0bacf96b4ffe45eb1213bb2c243a87df76f04476d671322cbcc67da5f'


class AlertixDocumentTests(unittest.TestCase):
    def _raw(self):
        documents = []
        for source_id, filename, digest in (
            ('configuration', 'alertix_faq.html', FAQ_HASH),
            ('platform_architecture', 'alertix_architecture.html', ARCH_HASH),
        ):
            path = FIXTURES / filename
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            documents.append({'source_id': source_id, 'status': 'ok',
                              'url': 'https://help.ngrsoftlab.ru/' + filename,
                              'snapshot_path': str(path), 'content_sha256': digest})
        return {'run_at': '2026-10-28T00:00:00Z', 'facts': [],
                'vendors': [{'id': 'p04', 'name': 'Alertix', 'source_results': documents}]}

    def test_faq_and_architecture_extract_only_published_claims(self):
        catalog = build_catalog(self._raw(), FIXTURES / 'input.json')
        sources = catalog['integrations']
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]['source_name'], 'Windows event logs')
        self.assertEqual(sources[0]['collection_method'], 'WEC')
        self.assertEqual(sources[0]['integration_evidence'], 'published_collection_path')
        self.assertFalse(sources[0]['functional_integration_verified'])
        rules = catalog['system_requirements']
        self.assertEqual(len(rules), 4)
        os_names = {r['component'] for r in rules if r['category'] == 'operating_system'}
        self.assertEqual(os_names, {'Ubuntu', 'Astra Linux SE', 'РЕД ОС'})
        capacity = next(r for r in rules if r['category'] == 'capacity_condition')
        self.assertEqual((capacity['operator'], capacity['value'], capacity['unit']),
                         ('<=', 10000, 'EPS'))
        self.assertEqual(capacity['averaging_interval'], 'one_week')
        self.assertFalse(capacity['sizing_complete'])
        self.assertEqual(catalog['sizing_profiles'], [])
        self.assertEqual(catalog['unparsed_system_documents'], [])

    def test_hash_mismatch_reports_unread_faq(self):
        raw = self._raw()
        raw['vendors'][0]['source_results'][0]['content_sha256'] = '0' * 64
        catalog = build_catalog(raw, FIXTURES / 'input.json')
        self.assertEqual(catalog['integrations'], [])
        self.assertEqual(len(catalog['system_requirements']), 1)
        self.assertEqual(catalog['unread_system_documents'][0]['reason'], 'snapshot_hash_mismatch')


if __name__ == '__main__':
    unittest.main()
