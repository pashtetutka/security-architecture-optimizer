"""Deployment context from real R-Vision and KOMRAD HTML snapshots."""
import hashlib
import unittest
from pathlib import Path
from siem.etl.catalog import build_catalog


class DeploymentContextTests(unittest.TestCase):
    def test_recommendations_and_listed_databases_are_distinct(self):
        root = Path(__file__).parent / 'fixtures'
        specs = (
            ('p03', 'R-Vision SIEM', 'deployment', 'rvision_deployment.html',
             '46e160f4d5cc7ade90a57788c59a11823368b328422da5990cfd855cb62dfc11'),
            ('p13', 'KOMRAD Enterprise SIEM', 'architecture', 'komrad_architecture.html',
             '43442158a8ba63927339a27ae1b22d5617acc86823483698a54273efac55e627'),
        )
        vendors = []
        for vid, name, source_id, filename, digest in specs:
            path = root / filename
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            vendors.append({'id': vid, 'name': name, 'source_results': [{
                'source_id': source_id, 'url': 'https://example.test/' + filename,
                'status': 'ok', 'snapshot_path': str(path), 'content_sha256': digest,
            }]})
        catalog = build_catalog({'vendors': vendors, 'facts': []}, root / 'input.json')
        rvision = [r for r in catalog['system_requirements'] if r['siem_id'] == 'p03']
        komrad = [r for r in catalog['system_requirements'] if r['siem_id'] == 'p13']
        self.assertEqual({r['component'] for r in rvision}, {'ClickHouse', 'PostgreSQL'})
        self.assertEqual({r['strength'] for r in rvision}, {'recommended'})
        self.assertEqual({r['component'] for r in komrad}, {'ClickHouse', 'PostgreSQL'})
        self.assertEqual({r['strength'] for r in komrad}, {'listed'})
        self.assertEqual(catalog['unparsed_system_documents'], [])


if __name__ == '__main__':
    unittest.main()
