"""Regression checks against unchanged official HTML/PDF snapshots."""
import hashlib
import unittest
from pathlib import Path

from siem.etl.catalog import build_catalog
from siem.etl.vendors.published_claims import parse_security_capsule_product


FIXTURES = Path(__file__).parent / 'fixtures'


class AdditionalSourceDocumentsTests(unittest.TestCase):
    def raw(self, vendor, source_id, filename, digest):
        path = FIXTURES / filename
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        return {'run_at': '2026-10-30T14:13:51+00:00', 'facts': [], 'vendors': [{
            'id': vendor, 'name': vendor, 'source_results': [{
                'source_id': source_id, 'status': 'ok', 'snapshot_path': str(path),
                'content_sha256': digest, 'url': 'https://example.test/document',
                'retrieved_at': '2026-10-30T14:13:51+00:00',
            }]}]}

    def solar(self):
        return self.raw('p11', 'source_whitepaper', 'solar_whitepaper.pdf',
                        '9e4d4648aff7aa5107540f6fc41b3cb80a537e086e6fbecfff7045fb0b1a1a2c')

    def test_solar_real_pdf_named_sources_page_and_unknown_versions(self):
        catalog = build_catalog(self.solar(), FIXTURES / 'input.json')
        rows = catalog['integrations']
        self.assertEqual(len(rows), 11)
        self.assertEqual({r['source_name'] for r in rows}, {
            'Linux event logs', 'Windows event logs', 'PostgreSQL', 'Oracle', 'MySQL',
            'Microsoft SQL Server', 'Microsoft Windows Defender Firewall',
            'Microsoft DHCP Server', 'Microsoft Windows DNS Server',
            'Microsoft IIS Server', 'Microsoft Network Policy Server'})
        self.assertTrue(all(r['source_version'] is None and r['siem_version'] is None for r in rows))
        self.assertTrue(all(r['evidence'][0]['page'] == 7 for r in rows))
        self.assertTrue(all(r['review_status'] == 'extracted_unverified' for r in rows))
        self.assertEqual(catalog['sizing_profiles'], [])
        self.assertEqual(catalog['system_requirements'], [])
        self.assertEqual(catalog['unread_source_catalog_documents'], [])
        self.assertEqual(next(r for r in rows if r['source_name'] == 'MySQL')['collection_method'], 'database')

    def test_solar_video_and_whitepaper_are_not_double_counted(self):
        raw = self.solar()
        path = FIXTURES / 'solar_architecture.html'
        raw['vendors'][0]['source_results'].insert(0, {
            'source_id': 'architecture', 'status': 'ok', 'url': 'https://example.test/videos',
            'snapshot_path': str(path), 'content_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        rows = build_catalog(raw, FIXTURES / 'input.json')['integrations']
        self.assertEqual(len(rows), 11)
        windows = next(r for r in rows if r['source_name'] == 'Windows event logs')
        self.assertEqual(len(windows['evidence']), 2)
        self.assertEqual(windows['collection_method'], 'system_log')

    def test_pdf_hash_mismatch_is_a_source_diagnostic(self):
        raw = self.solar()
        raw['vendors'][0]['source_results'][0]['content_sha256'] = '0' * 64
        catalog = build_catalog(raw, FIXTURES / 'input.json')
        self.assertEqual(catalog['integrations'], [])
        self.assertEqual(catalog['unread_source_catalog_documents'][0]['reason'], 'snapshot_hash_mismatch')

    def test_wrong_pdf_is_explicitly_unparsed(self):
        raw = self.solar()
        from unittest.mock import patch
        with patch('siem.etl.vendors.solar.PdfReader', side_effect=ValueError('bad PDF')):
            catalog = build_catalog(raw, FIXTURES / 'input.json')
        self.assertEqual(catalog['integrations'], [])
        self.assertEqual(catalog['unread_source_catalog_documents'][0]['reason'], 'pdf_source_extraction_failed')

    def test_security_capsule_only_explicit_collection_claims(self):
        raw = self.raw('p05', 'source_product', 'security_capsule_product.html',
                       '92319cf58d8dfa3b23ad8d525f0dec90f3cff92918f744715c5448908622250e')
        rows = build_catalog(raw, FIXTURES / 'input.json')['integrations']
        self.assertEqual({r['source_name'] for r in rows},
                         {'Windows event logs', 'Linux event logs', 'Microsoft Sysmon'})
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r['source_version'] is None for r in rows))
        self.assertEqual(parse_security_capsule_product('<p>Совместимость: Astra Linux, Postgres Pro, NGFW</p>',
                                                       {'siem_id': 'p05', 'siem_name': 'SC'}), [])


if __name__ == '__main__':
    unittest.main()
