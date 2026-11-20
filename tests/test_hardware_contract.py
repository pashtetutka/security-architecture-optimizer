from pathlib import Path
import unittest

from siem.etl.hardware_contract import legacy_profile_to_typed, migrate_hardware
from siem.domain.conditions import evaluate_conditions


ROOT=Path(__file__).resolve().parents[1]


class HardwareContractTests(unittest.TestCase):
    def test_conflicting_shelf_threshold_is_diagnostic(self):
        device = {
            'purpose': 'expansion_shelf', 'capacity_unit': 'TB', 'quantity': 12,
            'per_device_capacity': 4, 'original_value': 'Conflicting shelf counts at 15000 EPS',
            'activation_conditions': [
                {'metric': 'EPS', 'unit': 'EPS', 'operator': '>=', 'value': 15000,
                 'required_expansion_shelves': count}
                for count in (1, 2)
            ],
        }
        profile, issues = legacy_profile_to_typed({'nodes': [{'storage_devices': [device]}]})
        self.assertEqual([], profile['nodes'][0]['storage_groups'])
        self.assertEqual('legacy_conditional_storage_not_projected', issues[0]['code'])
        self.assertEqual(device['original_value'], issues[0]['message'])

    def test_shelf_steps_are_exclusive_at_the_boundary(self):
        triggers = [{'metric': 'EPS', 'unit': 'EPS', 'operator': '>=',
                     'value': eps, 'required_expansion_shelves': count}
                    for eps, count in [(15000, 1), (20000, 2)]]
        profile, issues = legacy_profile_to_typed({'nodes': [{'storage_devices': [{
            'purpose': 'expansion_shelf', 'capacity_unit': 'TB', 'quantity': 12,
            'per_device_capacity': 4, 'activation_conditions': triggers,
        }]}]})
        self.assertFalse(issues)
        groups = profile['nodes'][0]['storage_groups']
        for eps, expected in [(14999, []), (15000, [12]), (19999.5, [12]), (20000, [24])]:
            context = {'workload:main': {'eps': {'value': eps, 'unit': 'EPS', 'basis': 'total'}}}
            self.assertEqual(expected, [group['quantity']['value'] for group in groups
                              if evaluate_conditions(group['conditions'], context).value == 'true'])
        self.assertTrue(all(evaluate_conditions(group['conditions'], {}).value == 'unknown'
                            for group in groups))

    def test_storage_keeps_effective_capacity_and_conditional_text(self):
        profile, issues = legacy_profile_to_typed({'nodes': [{'storage_devices': [
            {'purpose': 'os_and_software', 'capacity_unit': 'GB',
             'total_capacity': 400, 'capacity_kind': 'effective_required', 'raid': 'RAID 10'},
            {'purpose': 'expansion_shelf', 'capacity_unit': 'TB', 'quantity': 12,
             'per_device_capacity': 4, 'original_value': '15000 EPS: one shelf',
             'activation_conditions': [{'value': 15000}]},
        ]}]})
        groups = profile['nodes'][0]['storage_groups']
        self.assertEqual(1, len(groups))
        self.assertEqual('effective', groups[0]['capacity_basis'])
        self.assertEqual(400, groups[0]['total_capacity']['value'])
        self.assertEqual('unknown', groups[0]['quantity']['kind'])
        self.assertEqual('RAID 10', groups[0]['raid'])
        self.assertIn('15000 EPS', issues[0]['message'])

    def test_cpu_quantities_keep_their_documented_units(self):
        profile, _ = legacy_profile_to_typed({'nodes': [
            {'role': 'virtual', 'vcpu': 8},
            {'role': 'physical', 'cpu_sockets': 2, 'physical_cores_per_socket': 14},
            {'role': 'logical', 'logical_cores_min': 56},
        ]})
        self.assertEqual(
            [('vCPU', 8), ('physical_cores', 28), ('logical_threads', 56)],
            [(node['cpu']['unit'], node['cpu']['value']) for node in profile['nodes']],
        )

    def test_conflicting_server_count_preserves_logical_roles(self):
        row = {
            'nodes': [{'role': 'collector', 'quantity': 1}],
            'applicability': {
                'diagnostic': 'published_server_count_conflicts_with_listed_roles',
                'published_server_count': 2,
                'listed_node_count': 3,
            },
        }
        profile, diagnostics = legacy_profile_to_typed(row)
        self.assertEqual('logical_role', profile['nodes'][0]['placement']['kind'])
        self.assertEqual('published_node_count_conflicts_with_listed_roles', diagnostics[-1]['code'])

    @classmethod
    def setUpClass(cls):
        from siem.etl.catalog import load_bundled_catalog

        catalog=load_bundled_catalog(ROOT/'data/etl/repro/vendors.json')
        cls.profiles=catalog['sizing_profiles']
        cls.requirements=catalog['system_requirements']
        cls.result=migrate_hardware(cls.profiles,cls.requirements)

    def test_every_legacy_row_has_projection(self):
        self.assertEqual(25,len(self.profiles)); self.assertEqual(25,len(self.result['profiles']))
        self.assertEqual(66,len(self.requirements)); self.assertEqual(66,len(self.result['requirements']))

    def test_distributed_network_requirement_retains_its_published_scope(self):
        requirement = next(r for r in self.result['requirements']
                           if r['siem_product_ref'] == 'product:siem-p03'
                           and r['property'] == 'min_inter_node_bandwidth')
        scope = {item['key']: item['value'] for item in requirement['extensions']}
        self.assertEqual('distributed', scope['deployment_scenario'])
        self.assertEqual('kubernetes_cluster_inter_node', scope['deployment_applies_to'])
        self.assertEqual('kubernetes_cluster_inter_node', scope['deployment_component'])
        self.assertIsNone(requirement['conditions'])

    def test_unrepresentable_instruction_operator_requires_review(self):
        rule = next(item for item in self.requirements if item['property'] == 'required_cpu_instructions')
        self.assertEqual(['AVX', 'AVX2'], rule['value'])
        diagnostics = [item for item in self.result['diagnostics']
                       if item['code'] == 'legacy_requirement_operator_not_representable']
        diagnostic, = diagnostics
        self.assertIn('contains_all', diagnostic['message'])

    def test_rvision_profile_keeps_eps_units_and_unknown_disk_topology(self):
        profile=self.result['profiles'][0]
        self.assertEqual('EPS',profile['workload']['eps']['unit'])
        self.assertEqual(1000,profile['workload']['eps']['value']['upper'])
        disk=profile['nodes'][0]['storage_groups'][0]
        self.assertEqual('unknown',disk['quantity']['kind'])
        self.assertEqual(500.0,disk['total_capacity']['value'])
        self.assertIsNone(disk['per_device_capacity']['value'])

    def test_cpu_type_and_unknown_release_are_explicit(self):
        node=self.result['profiles'][0]['nodes'][0]
        self.assertEqual('vCPU',node['cpu']['unit'])
        self.assertEqual('unknown',self.result['profiles'][0]['release_scope']['status'])

    def test_no_quantity_one_is_invented_for_unknown_storage(self):
        for profile in self.result['profiles']:
            for node in profile['nodes']:
                for storage in node['storage_groups']:
                    if storage['quantity']['kind']=='unknown':
                        self.assertIsNone(storage['quantity']['value'])

if __name__ == '__main__': unittest.main()
