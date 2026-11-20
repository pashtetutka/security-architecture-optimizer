from pathlib import Path
from copy import deepcopy
import unittest

from siem.decision.assessment import assess_organization, load_bundled_catalog
from siem.decision.scenarios import load_scenario


class DecisionAssessmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_bundled_catalog()

    def test_all_organizations_get_a_13_vendor_evidence_report(self):
        for path in sorted(Path('data/scenarios').glob('*.json')):
            with self.subTest(path=path):
                report = assess_organization(load_scenario(path), self.catalog)
                self.assertEqual(len(report['vendors']), 13)
                self.assertEqual(report['assessment_status'], 'preliminary_review')
                self.assertTrue(all(not row['calculation_ready'] for row in report['vendors']))
                self.assertTrue(all(len(row['source_matches']) ==
                                    len(load_scenario(path)['event_sources']) for row in report['vendors']))

    def test_missing_catalog_entry_is_unknown_not_unsupported(self):
        report = assess_organization(load_scenario('data/scenarios/s03_industrial_plant.json'), self.catalog)
        rows = next(row for row in report['vendors'] if row['siem_id'] == 'p12')['source_matches']
        gateway = next(row for row in rows if row['source'] == 'Industrial gateways')
        self.assertEqual(gateway['status'], 'not_found')
        self.assertFalse(gateway['evidence'])
        self.assertIn('Industrial gateways',
                      {item['raw_name'] for item in report['scenario']['unknown_eps_sources']})

    def test_real_published_claim_and_profile_have_document_links(self):
        report = assess_organization(load_scenario('data/scenarios/s02_saas_platform.json'), self.catalog)
        rvision = next(row for row in report['vendors'] if row['siem_id'] == 'p03')
        kubernetes = next(row for row in rvision['source_matches'] if row['source'] == 'Kubernetes')
        self.assertEqual(kubernetes['status'], 'published')
        self.assertTrue(kubernetes['evidence'][0]['url'].startswith('https://'))
        self.assertTrue(rvision['candidate_eps_profiles'])
        self.assertEqual(rvision['capacity_status'], 'modeled_eps_profile_requires_review')

    def test_sizing_remains_provisional_when_all_eps_unknown(self):
        scenario = deepcopy(load_scenario('data/scenarios/s01_branch_retail.json'))
        scenario['synthetic'] = False
        scenario['inventory_provenance'] = {'type': 'user_supplied_image'}
        scenario['organization_size'] = {'class': 'unknown', 'employees': None, 'sites': None}
        for source in scenario['event_sources']:
            source.pop('eps_per_unit_avg', None)
            source.pop('eps_per_unit_peak', None)
            source['eps_status'] = 'unknown'
            source['criticality'] = None
            source['requirement'] = 'unknown'
        report = assess_organization(scenario, self.catalog)
        self.assertIsNotNone(report['integrator_eps_model'])
        self.assertTrue(all(not row['calculation_ready'] for row in report['vendors']))
        self.assertTrue(all(row['capacity_status'] in
                            ('modeled_eps_profile_requires_review', 'no_published_profile_for_modeled_eps')
                            for row in report['vendors']))

    def test_real_questionnaire_uses_components_and_family_status_without_vendor_overrides(self):
        scenario = load_scenario('data/scenarios/s06_engineering.json')
        report = assess_organization(scenario, self.catalog)
        vendors = {row['siem_id']: row for row in report['vendors']}
        rusiem = vendors['p01']
        self.assertEqual(len(scenario['event_sources']), 23)
        self.assertEqual(rusiem['source_counts']['published'], 18)
        self.assertEqual(rusiem['source_counts']['family_candidate'], 3)
        self.assertTrue(rusiem['source_matches'][1]['collection_scope_review_required'])
        self.assertTrue(rusiem['source_matches'][2]['collection_scope_review_required'])
        self.assertEqual(rusiem['source_matches'][3]['status'], 'published')
        self.assertEqual(rusiem['source_matches'][3]['products'][0]['name'], 'Kaspersky Security Center')
        self.assertEqual(rusiem['source_matches'][15]['status'], 'published')
        self.assertEqual(rusiem['source_matches'][15]['products_match'], 'all')
        self.assertEqual(rusiem['source_matches'][19]['status'], 'published')
        self.assertEqual(rusiem['source_matches'][19]['products_match'], 'any')
        self.assertEqual(rusiem['source_matches'][12]['status'], 'family_candidate')
        self.assertFalse(rusiem['source_matches'][12]['counted_for_coverage'])
        self.assertEqual(rusiem['source_matches'][20]['status'], 'published')
        self.assertEqual(rusiem['source_matches'][20]['evidence'][0]['source_name'], 'Qnap NAS')
        self.assertGreaterEqual(vendors['p03']['required_published'], 10)
        self.assertGreaterEqual(vendors['p12']['required_counted'], 16)
        self.assertEqual(vendors['p06']['source_matches'][14]['status'], 'published')
        self.assertEqual(vendors['p03']['required_counted'], 18)
        self.assertEqual(vendors['p03']['source_matches'][1]['evidence'][0]['source_version'], '4')
        self.assertEqual(vendors['p03']['source_matches'][2]['evidence'][0]['source_version'], '4')
        self.assertEqual(vendors['p03']['source_matches'][13]['status'], 'version_candidate')
        self.assertEqual(vendors['p03']['source_matches'][13]['evidence'][0]['source_version'], '4.0')
        self.assertEqual(vendors['p03']['source_matches'][15]['status'], 'component_candidate')
        self.assertEqual([item['name'] for item in vendors['p03']['source_matches'][15]['component_assessments']
                          if item['fully_listed']], ['1С Бухгалтерия'])
        self.assertEqual(vendors['p03']['source_matches'][16]['status'], 'version_candidate')
        self.assertEqual(vendors['p03']['source_matches'][21]['status'], 'published')
        self.assertTrue(vendors['p03']['source_matches'][21]['version_review_required'])
        self.assertTrue(vendors['p03']['source_matches'][22]['collection_scope_review_required'])
        staffcop = vendors['p03']['source_matches'][7]
        self.assertEqual(staffcop['status'], 'version_candidate')
        self.assertTrue(staffcop['counted_for_coverage'])
        self.assertTrue(staffcop['version_review_required'])
        self.assertEqual(staffcop['requested_version'], '5.7.3-3')
        self.assertEqual(staffcop['evidence'][0]['source_version'], '5.5')
        self.assertEqual(vendors['p06']['required_counted'], 16)
        self.assertEqual(vendors['p06']['source_matches'][15]['status'], 'family_candidate')
        self.assertEqual(vendors['p06']['source_matches'][17]['status'], 'family_candidate')
        self.assertEqual(vendors['p06']['source_matches'][21]['status'], 'published')
        self.assertIn('published_version_listed', vendors['p06']['source_matches'][21]['version_scope'])
        self.assertTrue(rusiem['source_matches'][2]['counted_for_coverage'])

    def test_version_qualified_identity_marks_unpublished_version(self):
        scenario = deepcopy(load_scenario('data/scenarios/s06_engineering.json'))
        scenario['event_sources'][1]['raw_name'] = 'Континент-5'
        scenario['event_sources'][1]['version'] = '5'
        report = assess_organization(scenario, self.catalog)
        rvision = next(row for row in report['vendors'] if row['siem_id'] == 'p03')
        self.assertEqual(rvision['source_matches'][1]['status'], 'version_candidate')
        self.assertTrue(rvision['source_matches'][1]['counted_for_coverage'])
        self.assertEqual(rvision['source_matches'][1]['requested_version'], '5')


if __name__ == '__main__':
    unittest.main()
