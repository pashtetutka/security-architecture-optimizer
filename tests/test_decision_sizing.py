from copy import deepcopy
from pathlib import Path
import unittest

from siem.decision.assessment import assess_organization, load_bundled_catalog
from siem.decision.scenarios import load_scenario
from siem.decision.sizing import estimate_integrator_eps


class DecisionSizingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_bundled_catalog()

    def setUp(self):
        self.scenario = deepcopy(load_scenario(Path('data/scenarios/s01_branch_retail.json')))
        self.scenario['synthetic'] = False
        self.scenario['inventory_provenance'] = {'type': 'user_supplied_image'}
        self.scenario['organization_size'] = {'class': 'unknown', 'employees': None, 'sites': None}
        for source in self.scenario['event_sources']:
            source.pop('eps_per_unit_avg', None)
            source.pop('eps_per_unit_peak', None)
            source['eps_status'] = 'unknown'
            source['requirement'] = 'unknown'
            source['criticality'] = None

    def test_continent_product_uses_same_identity_as_every_scenario(self):
        firewall, ids = self.scenario['event_sources'][:2]
        firewall.update(raw_name='Континент 4', manufacturer_model='Континент-4/R550',
                        asset_group_id='continent_r550', log_stream='firewall')
        ids.update(raw_name='СОВ Континент-4/R550', manufacturer_model='СОВ Континент-4/R550',
                   asset_group_id='continent_r550', log_stream='intrusion_detection')
        report = assess_organization(self.scenario, self.catalog)
        komrad = next(v for v in report['vendors'] if v['siem_id'] == 'p13')
        self.assertEqual(komrad['source_matches'][0]['status'], 'published')
        self.assertEqual(komrad['source_matches'][1]['status'], 'not_found')
        self.assertTrue(komrad['source_matches'][0]['evidence'][0]['url'].startswith('https://'))
        self.assertTrue(komrad['source_matches'][0]['counted_for_coverage'])

    def test_shared_device_distinct_streams_and_overlapping_stream(self):
        first, second, third = self.scenario['event_sources'][:3]
        for source in (first, second, third):
            source['asset_group_id'] = 'ad_server_1'
            source['kind'] = 'directory'
            source['quantity'] = 1
        first['log_stream'] = 'directory_security'
        second['log_stream'] = 'dns'
        second['kind'] = 'dns'
        third['log_stream'] = 'directory_security'
        model = estimate_integrator_eps(self.scenario)
        self.assertTrue(model['rows'][0]['counted'])
        self.assertTrue(model['rows'][1]['counted'])
        self.assertFalse(model['rows'][2]['counted'])
        self.assertEqual(model['rows'][2]['duplicate_of_row'], 1)

    def test_file_audit_on_ad_is_a_distinct_stream(self):
        directory, file_audit = self.scenario['event_sources'][:2]
        directory.update(asset_group_id='ad', log_stream='directory_security',
                         kind='directory', quantity=1)
        file_audit.update(asset_group_id='ad', log_stream='file_audit',
                          kind='file_server', quantity=1)
        model = estimate_integrator_eps(self.scenario)
        self.assertTrue(model['rows'][0]['counted'])
        self.assertTrue(model['rows'][1]['counted'])

    def test_unknown_eps_is_modeled_but_marked_as_assumption(self):
        report = assess_organization(self.scenario, self.catalog)
        model = report['integrator_eps_model']
        self.assertGreater(model['totals']['working_eps'], 0)
        self.assertGreater(model['planning_eps_with_25pct_reserve'], model['totals']['stress_eps'])
        self.assertTrue(all(not vendor['calculation_ready'] for vendor in report['vendors']))
        self.assertTrue(all(profile['eps_basis'] == 'integrator_model'
                            for vendor in report['vendors'] for profile in vendor['candidate_eps_profiles']))

    def test_snapshot_keeps_all_exchange_version_claims(self):
        source = self.scenario['event_sources'][0]
        source.update(raw_name='Exchange Server', manufacturer_model='Microsoft Exchange 2010',
                      version='2010')
        report = assess_organization(self.scenario, self.catalog)
        maxpatrol = next(v for v in report['vendors'] if v['siem_id'] == 'p06')
        row = maxpatrol['source_matches'][0]
        self.assertEqual(row['status'], 'published')
        self.assertEqual(row['version_scope'], 'published_version_listed')
        self.assertEqual(row['evidence'][0]['source_version'], '2010')


if __name__ == '__main__':
    unittest.main()
