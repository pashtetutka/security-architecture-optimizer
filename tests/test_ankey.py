"""Ankey low-load requirements from the unmodified product page."""
import hashlib
import unittest
from pathlib import Path

from siem.etl.catalog import build_catalog


class AnkeyTests(unittest.TestCase):
    def test_low_load_profile_keeps_disk_total_and_alternative_os(self):
        path = Path(__file__).parent / 'fixtures' / 'ankey_product.html'
        digest = '9685e1e1afbed883c92c79f5704eab8c9446a1ac7e031ccd19c65b983123d5d5'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        raw = {'vendors': [{'id': 'p10', 'name': 'Ankey SIEM NG', 'source_results': [{
            'source_id': 'product_docs', 'status': 'ok', 'url': 'https://example.test/ankey',
            'snapshot_path': str(path), 'content_sha256': digest,
        }]}], 'facts': []}
        catalog = build_catalog(raw, path.parent / 'input.json')
        self.assertEqual(len(catalog['sizing_profiles']), 1)
        profile = catalog['sizing_profiles'][0]
        self.assertEqual(profile['scenario'], 'low_load')
        self.assertIsNone(profile['eps_to'])
        node = profile['nodes'][0]
        self.assertEqual((node['quantity'], node['cpu_sockets'], node['logical_cores_min'],
                          node['cpu_frequency_ghz_min'], node['ram_gb']),
                         (1, 2, 56, 2.2, 128.0))
        self.assertIsNone(node['vcpu'])
        disk = node['storage_devices'][0]
        self.assertEqual((disk['total_capacity'], disk['capacity_unit'], disk['capacity_kind']),
                         (1000, 'GB', 'effective_required'))
        self.assertIsNone(disk['quantity'])
        self.assertIsNone(disk['per_device_capacity'])
        self.assertEqual({(r['component'], r['value']) for r in catalog['system_requirements']},
                         {('Astra Linux', '1.7.3'), ('Debian', '10')})
        self.assertEqual(catalog['partial_system_documents'][0]['reason'],
                         'medium_and_high_load_profiles_not_extracted')


if __name__ == '__main__':
    unittest.main()
