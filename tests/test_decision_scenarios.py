import json
from copy import deepcopy
from pathlib import Path
import unittest

from siem.decision import load_scenario, summarize_scenario, validate_scenario


SCENARIOS = Path('data/scenarios')


class DecisionScenarioTests(unittest.TestCase):
    def test_all_preloaded_scenarios_use_one_contract(self):
        paths = sorted(SCENARIOS.glob('*.json'))
        self.assertEqual(len(paths), 6)
        reports = [summarize_scenario(load_scenario(path)) for path in paths]
        self.assertEqual({item['scenario_id'] for item in reports}, {
            's01_branch_retail', 's02_saas_platform', 's03_industrial_plant',
            's04_healthcare', 's05_municipal_services', 's06_engineering'})
        self.assertEqual({item['dominant_asset_class'] for item in reports}, {'host', 'server'})
        real = load_scenario(SCENARIOS / 's06_engineering.json')
        self.assertEqual(len(real['event_sources']), 23)
        self.assertFalse(real['synthetic'])
        self.assertTrue(all('catalog_candidates' not in row and 'catalog_components' not in row
                            for row in real['event_sources']))
        self.assertTrue(all(item['ranking_allowed'] is False for item in reports))
        for path in paths:
            scenario = load_scenario(path)
            self.assertGreaterEqual(len(scenario['event_sources']), 15)
            employees = scenario['organization_size']['employees']
            self.assertTrue(employees is None or employees <= 500)
            self.assertTrue(all(source['source_type'] and source['manufacturer_model']
                                for source in scenario['event_sources']))

    def test_unknown_eps_is_preserved_not_treated_as_zero(self):
        report = summarize_scenario(load_scenario(SCENARIOS / 's03_industrial_plant.json'))
        self.assertIn('Industrial gateways',
                      {item['raw_name'] for item in report['unknown_eps_sources']})
        self.assertIsNone(report['asset_classes']['industrial']['known_peak_eps_lower_bound'])
        self.assertGreater(report['known_eps_lower_bound']['peak_eps'], 0)

    def test_peak_below_average_is_rejected(self):
        scenario = load_scenario(SCENARIOS / 's01_branch_retail.json')
        scenario['event_sources'][0]['eps_per_unit_peak'] = 0.1
        with self.assertRaisesRegex(ValueError, 'peak EPS'):
            validate_scenario(scenario)

    def test_real_inventory_keeps_missing_quantity_and_eps_unknown(self):
        scenario = deepcopy(load_scenario(SCENARIOS / 's01_branch_retail.json'))
        scenario['synthetic'] = False
        scenario['inventory_provenance'] = {'type': 'user_supplied_image'}
        scenario['organization_size'] = {'class': 'unknown', 'employees': None, 'sites': None}
        for source in scenario['event_sources']:
            source.pop('eps_per_unit_avg', None)
            source.pop('eps_per_unit_peak', None)
            source['eps_status'] = 'unknown'
            source['criticality'] = None
            source['requirement'] = 'unknown'
        scenario['event_sources'][-1]['quantity'] = None
        report = summarize_scenario(scenario)
        self.assertFalse(report['synthetic'])
        self.assertEqual(len(report['unknown_eps_sources']), len(scenario['event_sources']))
        self.assertIsNone(report['asset_classes']['server']['known_peak_eps_lower_bound'])

    def test_shared_server_roles_count_as_one_asset(self):
        scenario = load_scenario(SCENARIOS / 's01_branch_retail.json')
        first, second = scenario['event_sources'][:2]
        first.update(asset_class='server', asset_group_id='shared_ad', quantity=1)
        second.update(asset_class='server', asset_group_id='shared_ad', quantity=1)
        report = summarize_scenario(scenario)
        clone = deepcopy(scenario)
        clone['event_sources'][1]['asset_group_id'] = 'another_ad'
        separate = summarize_scenario(clone)
        self.assertEqual(separate['asset_classes']['server']['source_instances'] -
                         report['asset_classes']['server']['source_instances'], 1)


if __name__ == '__main__':
    unittest.main()
