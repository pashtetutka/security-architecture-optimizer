import unittest

from siem.etl.applicability import evaluate
from siem.etl.identities import type_integrations, unique_source_values


class SourceIdentityTests(unittest.TestCase):
    def test_generic_variants_keep_vendor_family_identity(self):
        rows = [{'siem_id': 'p01', 'source_name': name, 'source_variant': 'Switch'}
                for name in ('Cisco Switch', 'Huawei Switch')]
        type_integrations(rows)
        self.assertNotEqual(rows[0]['source_entity_id'], rows[1]['source_entity_id'])
        self.assertTrue(all(row['source_identity_basis'] == 'source_name' for row in rows))

    def test_curated_catalog_aliases_do_not_require_case_or_punctuation_match(self):
        from siem.etl.coverage import canonical
        pairs = (
            ('FortiGate', 'Fortinet FortiGate'),
            ('Microsoft SCCM', 'Microsoft System Center Configuration Manager (SCCM)'),
            ('Hyper-V', 'Microsoft Hyper-V'),
            ('RedCheck', 'САЗ RedCheck'),
            ('VMware vCenter', 'VMware vCenter Server'),
            ('1С:ЗУП', '1С Зарплата и управление персоналом'),
        )
        for left, right in pairs:
            with self.subTest(left=left):
                self.assertEqual(canonical(left), canonical(right))

    def test_presentation_variants_share_entity_but_keep_claims(self):
        rows = [
            {'siem_id': 'p06', 'source_name': 'UserGate Proxy & Firewall',
             'source_vendor': None, 'source_version': '6', 'collection_method': 'SysLog',
             'normalizer_id': None, 'normalizer_format': None},
            {'siem_id': 'p06', 'source_name': 'UserGate Proxy&Firewall',
             'source_vendor': None, 'source_version': '6.5', 'collection_method': 'SysLog',
             'normalizer_id': None, 'normalizer_format': None},
        ]
        type_integrations(rows)
        self.assertEqual(rows[0]['source_entity_id'], rows[1]['source_entity_id'])
        self.assertNotEqual(rows[0]['source_version_raw'], rows[1]['source_version_raw'])
        values = unique_source_values(rows)
        self.assertEqual(values['summary'], {'support_claims': 2, 'source_entities': 1})

    def test_typed_catalog_is_used_for_matching(self):
        rows = [{'siem_id': 'p06', 'siem_name': 'MaxPatrol',
                 'source_name': '1С Зарплата и управление персоналом', 'source_vendor': None,
                 'source_version': None, 'collection_method': 'SysLog', 'normalizer_id': None,
                 'normalizer_format': None, 'evidence': [{'url': 'https://example.test'}]}]
        type_integrations(rows)
        result = evaluate([{'id': 'p06', 'name': 'MaxPatrol'}], {'items': rows},
                          {'event_sources': [{'name': '1С:ЗУП'}]})[0]
        self.assertEqual((result['documented_source_matches'], result['unknown_integrations']), (1, 0))
        self.assertEqual(result['source_assessments'][0]['match_status'], 'published_integration')

    def test_variant_is_identity_when_display_name_contains_family(self):
        rows = [{'siem_id': 'p01', 'siem_name': 'RuSIEM',
                 'source_name': '1C 8.3 1С Зарплата и управление персоналом',
                 'source_variant': '1С Зарплата и управление персоналом',
                 'source_vendor': '1C', 'source_version': None, 'collection_method': None,
                 'normalizer_id': None, 'normalizer_format': None,
                 'evidence': [{'url': 'https://example.test'}]}]
        type_integrations(rows)
        self.assertEqual(rows[0]['source_entity_id'], 'source:1с зуп')
        result = evaluate([{'id': 'p01', 'name': 'RuSIEM'}], {'items': rows},
                          {'event_sources': [{'name': '1С:ЗУП'}]})[0]
        self.assertEqual(result['source_assessments'][0]['match_status'], 'published_integration')
        self.assertEqual(len(result['source_assessments'][0]['evidence']), 1)

    def test_partial_and_listed_versions_require_correct_confirmation(self):
        rows = [
            {'siem_id': 'p06', 'source_name': 'Only partial', 'source_vendor': None,
             'source_version': None, 'support_scope': 'partial', 'collection_method': None,
             'normalizer_id': None, 'normalizer_format': None, 'evidence': [{'url': 'https://example.test'}]},
            {'siem_id': 'p06', 'source_name': 'Versioned', 'source_vendor': None,
             'source_version': '4.0, 5.4.2', 'support_scope': 'supported', 'collection_method': None,
             'normalizer_id': None, 'normalizer_format': None, 'evidence': [{'url': 'https://example.test'}]},
            {'siem_id': 'p06', 'source_name': 'Ranged', 'source_vendor': None,
             'source_version': '4.0–4.5', 'support_scope': 'supported', 'collection_method': None,
             'normalizer_id': None, 'normalizer_format': None, 'evidence': [{'url': 'https://example.test'}]},
        ]
        type_integrations(rows)
        result = evaluate([{'id': 'p06', 'name': 'MaxPatrol'}], {'items': rows}, {'event_sources': [
            {'name': 'Only partial'}, {'name': 'Versioned', 'version': '4.0'},
            {'name': 'Ranged', 'version': '4.3'},
        ]})[0]
        self.assertEqual([row['match_status'] for row in result['source_assessments']], [
            'published_partial_support_requires_confirmation', 'published_integration',
            'published_integration'])
