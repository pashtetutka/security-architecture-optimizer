"""Boundaries confirmed by independently reading the saved official catalogs."""
import unittest
from copy import deepcopy
import json
from pathlib import Path

from siem.decision.assessment import assess_organization, load_bundled_catalog
from siem.decision.scenarios import load_scenario


class ManualAuditRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report = assess_organization(
            load_scenario('data/scenarios/s06_engineering.json'),
            load_bundled_catalog())
        cls.vendors = {row['siem_id']: row for row in report['vendors']}

    def test_kuma_related_products_are_not_false_positive_integrations(self):
        rows = self.vendors['p12']['source_matches']
        # D-Link DES switches do not confirm a DFL firewall.
        self.assertFalse(rows[0]['counted_for_coverage'])
        # Staffcop Enterprise and PostgreSQL pgAudit do not establish the
        # unqualified Staffcop edition or Postgres Pro Enterprise installation.
        self.assertFalse(rows[7]['counted_for_coverage'])
        self.assertFalse(rows[17]['counted_for_coverage'])

    def test_all_299_decisions_agree_with_independent_document_review(self):
        reference = json.loads((Path(__file__).parent / 'fixtures' /
                                'manual_questionnaire_review_20261114.json').read_text(encoding='utf-8'))
        self.assertEqual(set(reference['vendors']), set(self.vendors))
        for sid, expected in reference['vendors'].items():
            rows = self.vendors[sid]['source_matches']
            self.assertEqual(len(rows), 23)
            for index, row in enumerate(rows, start=1):
                with self.subTest(siem=sid, source=index):
                    self.assertEqual(row['counted_for_coverage'], index in expected['counted'])
                    if index in expected['candidates']:
                        self.assertIn(row['status'], ('family_candidate', 'component_candidate'))
                    if row['counted_for_coverage']:
                        self.assertTrue(row['evidence'])

    def test_kuma_published_partial_event_scope_survives_coverage_count(self):
        rows = self.vendors['p12']['source_matches']
        for index in (11, 14, 21):  # DNS, ESXi, Windows workstation logs.
            with self.subTest(index=index):
                self.assertTrue(rows[index]['counted_for_coverage'])
                self.assertEqual(rows[index]['status'], 'partial')
                self.assertTrue(rows[index]['support_limitations'])

    def test_product_coverage_keeps_version_and_functional_uncertainty(self):
        rows = self.vendors['p01']['source_matches']
        self.assertTrue(rows[18]['counted_for_coverage'])
        self.assertTrue(rows[18]['version_review_required'])
        self.assertTrue(rows[18]['collection_scope_review_required'])
        rows = self.vendors['p12']['source_matches']
        self.assertTrue(rows[22]['counted_for_coverage'])
        self.assertTrue(rows[22]['collection_scope_review_required'])

    def test_maxpatrol_partial_product_retains_scope_and_import_provenance(self):
        rows = self.vendors['p06']['source_matches']
        for index, name in ((0, 'D-Link DFL-1660'), (6, 'Rusguard Rusguard Soft')):
            with self.subTest(index=index):
                self.assertTrue(rows[index]['counted_for_coverage'])
                self.assertTrue(rows[index]['partial_support'])
                self.assertEqual(rows[index]['evidence'][0]['source_name'], name)
                self.assertEqual(rows[index]['evidence'][0]['acquisition_method'], 'manual_import')

    def test_partial_support_cannot_cover_an_absent_required_component(self):
        scenario = deepcopy(load_scenario('data/scenarios/s06_engineering.json'))
        scenario['event_sources'][15]['products'] = [
            {'name': 'D-Link DFL-1660', 'version': None},
            {'name': 'Unknown required product', 'version': None}]
        report = assess_organization(scenario, load_bundled_catalog())
        row = next(v for v in report['vendors'] if v['siem_id'] == 'p06')['source_matches'][15]
        self.assertEqual(row['status'], 'component_candidate')
        self.assertFalse(row['counted_for_coverage'])


if __name__ == '__main__':
    unittest.main()
