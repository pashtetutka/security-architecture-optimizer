"""Ankey low-load requirements from the unmodified product page."""
import hashlib
import unittest
from pathlib import Path

from siem.etl.catalog import build_catalog


class AnkeyTests(unittest.TestCase):
    def test_low_load_profile_keeps_disk_total_and_alternative_os(self):
        path = Path(__file__).resolve().parents[1] / 'data/etl/repro/raw/p10/product_docs_9685e1e1afbed8.html'
        digest = '9685e1e1afbed883c92c79f5704eab8c9446a1ac7e031ccd19c65b983123d5d5'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        raw = {'vendors': [{'id': 'p10', 'name': 'Ankey SIEM NG', 'source_results': [{
            'source_id': 'product_docs', 'status': 'ok', 'url': 'https://example.test/ankey',
            'snapshot_path': str(path), 'content_sha256': digest,
        }]}], 'facts': []}
        catalog = build_catalog(raw, path.parent / 'input.json')
        self.assertEqual(len(catalog['sizing_profiles']), 3)
        profiles = {p['scenario']: p for p in catalog['sizing_profiles']}
        profile = profiles['low_load']
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
        self.assertEqual({(r['component'], r['value']) for r in catalog['system_requirements']
                          if r['scenario'] == 'low_load'},
                         {('Astra Linux', '1.7.3'), ('Debian', '10')})
        medium = profiles['medium_load']
        self.assertEqual((medium['applicability']['published_server_count'],
                          medium['applicability']['listed_node_count']), (2, 3))
        self.assertEqual(medium['applicability']['diagnostic'],
                         'published_server_count_conflicts_with_listed_roles')
        self.assertEqual({n['role'] for n in medium['nodes']},
                         {'core_and_management', 'siem_server_and_events_storage', 'network_sensor'})
        high = profiles['high_load']
        self.assertEqual(sum(n['quantity'] for n in high['nodes']), 7)
        storage = next(n for n in high['nodes'] if n['role'] == 'events_storage')
        self.assertIn((10, 4.0, 'TB', 'RAID 10'),
                      {(d['quantity'], d['per_device_capacity'], d['capacity_unit'], d['raid'])
                       for d in storage['storage_devices']})
        self.assertIn((12, 4.0, 'TB', 'RAID 10'),
                      {(d['quantity'], d['per_device_capacity'], d['capacity_unit'], d['raid'])
                       for d in storage['storage_devices']})
        self.assertTrue(any(d['purpose'] == 'os_and_software'
                            for n in high['nodes'] for d in n['storage_devices']))
        shelf = next(d for d in storage['storage_devices'] if d['purpose'] == 'expansion_shelf')
        self.assertEqual(shelf['activation_conditions'], [
            {'metric': 'EPS', 'operator': '>=', 'value': 15000, 'unit': 'EPS',
             'required_expansion_shelves': 1},
            {'metric': 'EPS', 'operator': '>=', 'value': 20000, 'unit': 'EPS',
             'required_expansion_shelves': 2},
        ])
        self.assertEqual(catalog['partial_system_documents'][0]['reason'],
                         'published_node_count_conflicts_with_listed_roles')


if __name__ == '__main__':
    unittest.main()
