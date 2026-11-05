import hashlib
import unittest
from pathlib import Path

from siem.etl.vendors.kuma import parse_kuma_requirements
from siem.etl.extractors import extract_content
from siem.etl.reports.quality import sizing_quality_report


class KumaRequirementsTests(unittest.TestCase):
    path = Path(__file__).parent.parent/'data/etl/repro/raw/p12/hardware_requirements_8c9f1c436ef727.html'

    def test_real_eps_matrix_preserves_alternatives_roles_and_conditions(self):
        data = self.path.read_bytes()
        digest = '8c9f1c436ef727d62044fc24949b0ad655151d52b0c1a28850a601ed81df81cf'
        self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        meta = {'siem_id': 'p12', 'siem_name': 'KUMA',
                'url': 'https://support.kaspersky.ru/kuma/4.0/217889',
                'content_sha256': digest, 'acquisition_method': 'automatic_https'}
        profiles, rules = parse_kuma_requirements(data.decode('utf-8'), meta)
        self.assertEqual([p['eps_to'] for p in profiles[:4]], [3000, 10000, 20000, 50000])
        self.assertEqual([sum(n['quantity'] for n in p['nodes']) for p in profiles[:4]], [1, 1, 8, 11])
        self.assertEqual([p['nodes'][0]['ram_gb'] for p in profiles[:2]], [32, 64])
        for p in profiles[:4]:
            self.assertIsNone(p['siem_version'])
            for n in p['nodes']:
                self.assertIsNone(n['vcpu'])
                self.assertEqual([a['unit'] for a in n['cpu_alternatives']], ['logical_threads', 'vCPU'])
                disk = n['storage_devices'][0]
                self.assertIsNone(disk['quantity'])
                self.assertEqual(disk['mount_path'], '/opt')
                self.assertIsNone(disk['per_device_capacity'])
        keeper = next(n for n in profiles[2]['nodes'] if n['role'] == 'keeper')
        self.assertEqual((keeper['quantity'], keeper['ram_gb'], keeper['storage_devices'][0]['total_capacity']),
                         (3, 12, 50))
        self.assertEqual(profiles[2]['applicability']['storage_nodes_without_ha'], 1)
        self.assertEqual(profiles[3]['applicability']['storage_nodes_without_ha'], 2)
        self.assertEqual(profiles[2]['network_links'][0]['when_eps_gte'], 20000)
        self.assertEqual(len(rules), 33)
        self.assertEqual({r['alternative_group'] for r in rules},
                         {'kuma_host_os', 'kuma_agent_os_windows', 'kuma_agent_os_linux'})
        platform = profiles[4]
        self.assertIsNone(platform['eps_to'])
        self.assertEqual(sum(n['quantity'] for n in platform['nodes']), 6)
        self.assertFalse(platform['nodes'][0]['cluster_member'])
        worker = platform['nodes'][2]
        self.assertEqual([(d['mount_path'], d['total_capacity'], d['capacity_unit'])
                          for d in worker['storage_devices']], [('/opt/', 1, 'TB'), ('/var/lib/', 32, 'GB')])
        for agent in profiles[5:]:
            self.assertEqual(agent['nodes'][0]['ram_mb'], 512)
            self.assertIsNone(agent['nodes'][0]['ram_gb'])
            self.assertIsNone(agent['nodes'][0]['quantity'])
        restricted = [r for r in rules if r.get('support_scope') == 'partial']
        self.assertEqual(len(restricted), 2)
        debian = next(r for r in rules if r['value'] == 'Debian 12')
        self.assertEqual(debian['prerequisites'][0]['version'], '2.36')
        self.assertTrue(all(r['evidence']['document_sha256'] == digest for r in rules))
        payload = extract_content(data, 'kuma_requirements')
        self.assertEqual(payload['facts'], [])
        self.assertTrue(payload['targeted_normalization_required'])
        report = sizing_quality_report({'sizing_profiles': profiles})
        self.assertEqual(len([i for i in report['issues'] if i['code'] == 'version_unverified']), 1)
        self.assertFalse(any(i['category'] == 'extraction_error' for i in report['issues']))

    def test_unsupported_table_shape_is_explicit(self):
        html = self.path.read_text(encoding='utf-8')
        meta = {'siem_id': 'p12', 'siem_name': 'KUMA'}
        with self.assertRaisesRegex(ValueError, 'unsupported_rowspan'):
            parse_kuma_requirements(html.replace('<td ', '<td rowspan="2" ', 1), meta)
        self.assertEqual(parse_kuma_requirements(html, {'siem_id': 'p10'}), ([], []))
