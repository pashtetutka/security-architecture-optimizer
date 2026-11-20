import unittest

from siem.decision.assessment import load_bundled_catalog
from siem.etl.source_classes import SOURCE_CLASSES


class SourceClassesTests(unittest.TestCase):
    def test_real_catalog_keeps_class_and_identity_separate(self):
        catalog = load_bundled_catalog()
        rows = catalog['integrations']
        self.assertEqual(sum(item['claim_count'] for item in catalog['source_classes']['items']),
                         len(rows))
        self.assertTrue(all(row['source_class_id'] in SOURCE_CLASSES and
                            row['source_class_basis'] for row in rows))
        rusiem = {row['source_name']: row for row in rows if row['siem_id'] == 'p01'}
        self.assertEqual(rusiem['D-link Firewall']['source_class_id'], 'network_security')
        self.assertEqual(rusiem['Eltex Switch']['source_class_id'], 'network_infrastructure')
        self.assertEqual(rusiem['MS Windows MS DHCP Server']['source_class_id'], 'dhcp')
        self.assertEqual(rusiem['MS Windows MS DNS Server']['source_class_id'], 'dns')
        self.assertEqual(rusiem['Cyberprotect']['source_class_id'], 'unclassified')
        self.assertEqual(rusiem['Cyberprotect']['source_class_basis'], 'not_determined')


if __name__ == '__main__':
    unittest.main()
