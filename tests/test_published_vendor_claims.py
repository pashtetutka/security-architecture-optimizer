"""End-to-end regressions using unmodified vendor HTML and PDF snapshots."""
import hashlib
import unittest
from pathlib import Path

from siem.etl.catalog import build_catalog


FIXTURES = Path(__file__).parent / 'fixtures'
DOCUMENTS = (
    ('p02', 'СёрчИнформ SIEM', 'overview', 'data/etl/repro/raw/p02/overview_5e211449f8fd31.html',
     '5e211449f8fd31c7838977e16fd259eb9bbc30227b97beefb37026ff9ac8e34f'),
    ('p05', 'Security Capsule SIEM', 'product_document', 'data/etl/repro/raw/p05/product_document_b04c140ae5df7c.pdf',
     'b04c140ae5df7cfdc0d40e36035fd36a810f22f4f55d855f9cdfb070b8f1a691'),
    ('p07', 'САВРУС', 'product', 'data/etl/repro/raw/p07/product_d68c1de19bcb0b.html',
     'd68c1de19bcb0bb679df42d5d866a99cc8f2de65311ddbb84d240683ef324f02'),
    ('p09', 'UserGate SIEM', 'architecture', 'data/etl/repro/raw/p09/architecture_7b84f0e3e02f5c.html',
     '7b84f0e3e02f5c1bf7225e5c91e3be2f8f71a0f6293ee6ae906a876de8f24aba'),
    ('p11', 'Solar SIEM', 'architecture', 'data/etl/repro/raw/p11/architecture_ba8be340ddf936.html',
     'ba8be340ddf936ed256ab2e5f93b1ec8eaeac2af298e0857d8b6fbeacef1a5cf'),
)


class PublishedVendorClaimsTests(unittest.TestCase):
    def test_real_snapshots_extract_only_explicit_claims(self):
        vendors = []
        for vid, name, source_id, filename, digest in DOCUMENTS:
            path = FIXTURES.parents[1] / filename
            if vid == 'p05':
                continue
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            vendors.append({'id': vid, 'name': name, 'source_results': [{
                'source_id': source_id, 'status': 'ok', 'snapshot_path': str(path),
                'url': 'https://example.test/' + filename, 'content_sha256': digest,
            }]})
        catalog = build_catalog({'run_at': '2026-10-28T00:00:00Z', 'vendors': vendors, 'facts': []},
                                FIXTURES / 'input.json')
        by_vendor = lambda rows, vid: [r for r in rows if r['siem_id'] == vid]
        sources = catalog['integrations']
        self.assertEqual(len(by_vendor(sources, 'p02')), 22)
        self.assertIn('Windows event logs', [r['source_name'] for r in by_vendor(sources, 'p02')])
        self.assertNotIn('Cisco', [r['source_name'] for r in by_vendor(sources, 'p02')])
        self.assertTrue({'СКУД RusGuard', 'VMware ESXi', 'Континент', 'Active Directory Domain Services',
                         '1С:Предприятие', 'PostgreSQL'} <=
                        {r['source_name'] for r in by_vendor(sources, 'p02')})
        continent = next(r for r in by_vendor(sources, 'p02') if r['source_name'] == 'Континент')
        self.assertEqual(continent['source_version'], '3, 4')
        self.assertIn('Континент 3 / 4', continent['evidence'][0]['excerpt'])
        self.assertEqual(len(by_vendor(sources, 'p09')), 3)
        self.assertEqual(len(by_vendor(sources, 'p11')), 2)
        self.assertEqual(by_vendor(sources, 'p05'), [])
        self.assertEqual(by_vendor(sources, 'p07'), [])
        rules = catalog['system_requirements']
        savrus = by_vendor(rules, 'p07')
        self.assertEqual((len(savrus), savrus[0]['value']), (1, '1.7'))
        self.assertEqual(catalog['sizing_profiles'], [])

    def test_local_security_capsule_pdf_preserves_sizing_evidence(self):
        vid, name, source_id, filename, digest = DOCUMENTS[1]
        path = FIXTURES.parents[1] / 'data/private' / Path(filename).name
        if not path.is_file():
            self.skipTest('Security Capsule PDF is restricted and only available locally')
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        raw = {'vendors': [{'id': vid, 'name': name, 'source_results': [{
            'source_id': source_id, 'status': 'ok', 'snapshot_path': str(path),
            'url': 'https://example.test/security-capsule.pdf', 'content_sha256': digest,
        }]}], 'facts': []}
        sc = build_catalog(raw, FIXTURES / 'input.json')['system_requirements']
        self.assertEqual(len(sc), 1)
        self.assertEqual((sc[0]['value'], sc[0]['unit'], sc[0]['scenario']),
                         (2000, 'EPS', 'small_site_all_in_one'))
        self.assertEqual(sc[0]['evidence']['page'], 14)
        self.assertFalse(sc[0]['sizing_complete'])

    def test_hash_mismatch_does_not_create_claim(self):
        vid, name, source_id, filename, _ = DOCUMENTS[0]
        raw = {'vendors': [{'id': vid, 'name': name, 'source_results': [{
            'source_id': source_id, 'status': 'ok', 'snapshot_path': str(FIXTURES.parents[1] / filename),
            'url': 'https://example.test/overview', 'content_sha256': '0' * 64,
        }]}], 'facts': []}
        catalog = build_catalog(raw, FIXTURES / 'input.json')
        self.assertEqual(catalog['integrations'], [])
        self.assertEqual(catalog['unread_source_catalog_documents'][0]['reason'], 'snapshot_hash_mismatch')


if __name__ == '__main__':
    unittest.main()
