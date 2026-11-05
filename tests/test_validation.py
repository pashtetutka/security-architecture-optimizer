import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from siem.etl.validation import validate_catalog
from siem.etl.catalog import build_catalog, write_catalog


class ValidationTests(unittest.TestCase):
    def test_cpu_alternatives_units_and_positive_storage_are_enforced(self):
        catalog = {'sizing_profiles': [{'nodes': [{
            'vcpu': 2, 'cpu_alternatives': [{'unit': 'guessed', 'minimum': True}],
            'ram_mb': 512, 'ram_gb': 512,
            'storage_devices': [{'capacity_unit': 'GB', 'quantity': True,
                                 'total_capacity': -1, 'capacity_kind': 'total_required'}]}]}]}
        report = validate_catalog(catalog)
        reasons = {item['reason'] for item in report['errors']}
        self.assertTrue({'invalid_cpu_alternative', 'cpu_alternatives_collapsed_to_single_unit',
                         'ambiguous_ram_units', 'invalid_storage_quantity', 'invalid_total_capacity'} <= reasons)

    def test_writer_revalidates_changed_catalog_and_saves_errors(self):
        catalog = build_catalog({'vendors': [], 'facts': []}, Path('input.json'))
        self.assertTrue(catalog['schema_validation']['valid'])
        catalog['integrations'].append({'source_name': 'Source'})
        with TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                write_catalog(catalog, Path(temp))
            report = json.loads((Path(temp)/'schema_validation.json').read_text(encoding='utf-8'))
            self.assertFalse(report['valid'])
            self.assertFalse((Path(temp)/'sources.json').exists())

    def test_rejects_untyped_identity_and_noncanonical_capacity_unit(self):
        catalog = {'integrations': [{'source_name': 'Source', 'source_entity_id': 'source:wrong'}],
                   'sizing_profiles': [{'nodes': [{'storage_devices': [{
                       'capacity_unit': 'ТБ', 'quantity': 0, 'capacity_kind': 'guessed'}]}]}]}
        report = validate_catalog(catalog)
        self.assertFalse(report['valid'])
        self.assertIn('source_entity_id_mismatch', {item['reason'] for item in report['errors']})
        self.assertIn('invalid_capacity_unit', {item['reason'] for item in report['errors']})
