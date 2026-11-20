import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from siem.domain.identity import load_default_dictionary
from siem.domain.validation import validate_bundle
from siem.etl.migration import _claim_subject_names, build_migration_bundle


ROOT=Path(__file__).resolve().parents[1]


class MigrationFailureTests(unittest.TestCase):
    def test_search_key_cannot_turn_a_model_into_family_support(self):
        dictionary = load_default_dictionary()
        parents = {'product:catalog-0235': {'product:catalog-0236'}}
        model = 'D-Link DFL-1660'
        family = 'D-Link Firewall'
        row = {'source_name': model, 'source_match_keys': [model, family]}
        self.assertEqual([model], _claim_subject_names(row, dictionary, parents))
        self.assertEqual([model], _claim_subject_names(
            {**row, 'source_version': '4'}, dictionary, parents))
        self.assertEqual([family], _claim_subject_names({'source_name': family}, dictionary, parents))

    def test_empty_extraction_is_a_valid_no_data_bundle(self):
        source=ROOT/'data/etl/repro/vendors.json'
        legacy={key: [] for key in ('integrations','sizing_profiles','system_requirements',
                                   'unread_system_documents','unread_source_catalog_documents')}
        with patch('siem.etl.migration.replay_facts_from_snapshots', return_value=[]), \
             patch('siem.etl.migration.build_catalog', return_value=legacy):
            bundle=build_migration_bundle({'vendors': []}, source, load_default_dictionary())
        self.assertEqual('no_data', bundle['status'])
        self.assertIn('no_data', {item['code'] for item in bundle['diagnostics']})
        self.assertTrue(validate_bundle(bundle).valid)

    def test_specialized_adapter_read_error_rejects_bundle(self):
        source=ROOT/'data/etl/repro/vendors.json'
        legacy={'unread_system_documents': [], 'unread_source_catalog_documents': [
            {'siem_id': 'p06', 'source_id': 'supported_sources_api',
             'reason': 'json_source_extraction_failed'},
        ]}
        with patch('siem.etl.migration.replay_facts_from_snapshots', return_value=[]), \
             patch('siem.etl.migration.build_catalog', return_value=legacy):
            with self.assertRaisesRegex(ValueError, 'p06/supported_sources_api: json_source_extraction_failed'):
                build_migration_bundle({'vendors': []}, source, None)


class MigrationBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=ROOT/'data/etl/repro/vendors.json'
        raw=json.loads(path.read_text('utf-8'))
        dictionary=load_default_dictionary()
        cls.bundle=build_migration_bundle(raw,path,dictionary)

    def test_real_legacy_catalog_produces_valid_v2_bundle(self):
        result=validate_bundle(self.bundle)
        self.assertTrue(result.valid,[x.to_dict() if hasattr(x,'to_dict') else x for x in result.issues][:20])
        self.assertEqual(13,sum('siem' in p['class_ids'] for p in self.bundle['products']))
        self.assertGreater(len(self.bundle['claims']),0)
        self.assertGreater(len(self.bundle['diagnostics']),0)
        self.assertEqual(25,len(self.bundle['profiles']))
        self.assertEqual(66,len(self.bundle['requirements']))
        warning=next(row for row in self.bundle['diagnostics']
                     if row['code']=='published_node_count_conflicts_with_listed_roles')
        evidence=next(row for row in self.bundle['evidence']
                      if row['evidence_id'] in warning['evidence_refs'])
        self.assertEqual('html',evidence['locator']['kind'])
        self.assertEqual('Средненагруженная система',evidence['locator']['section'])

    def test_unknown_names_are_visible_not_false_unsupported(self):
        unresolved=[r for r in self.bundle['resolutions'] if r['status']=='unresolved']
        self.assertTrue(unresolved)
        self.assertTrue(all(d['code']!='unsupported' for d in self.bundle['diagnostics']))

    def test_solar_secondary_listing_is_retained_without_attributing_route_details(self):
        routes = {row['route_id']: row for row in self.bundle['routes']}
        evidence = {row['evidence_id']: row for row in self.bundle['evidence']}
        claims = [row for row in self.bundle['claims']
                  if row['siem_product_ref'] == 'product:siem-p11'
                  and len(row['evidence_refs']) > 1]
        self.assertTrue(claims)
        for claim in claims:
            self.assertGreater(len({evidence[ref]['document_ref']
                                    for ref in claim['evidence_refs']}), 1)
            for route_ref in claim['route_refs']:
                self.assertLess(set(routes[route_ref]['evidence_refs']), set(claim['evidence_refs']))

    def test_replay_ignores_legacy_cache_and_manifest_record_order(self):
        path=ROOT/'data/etl/repro/vendors.json';raw=json.loads(path.read_text('utf-8'))
        dictionary=load_default_dictionary()
        raw['facts']=[{'field':'source_integration','value':'Injected false product',
                       'siem_id':'p01','evidence_status':'vendor_table'}]
        raw['vendors'].reverse()
        for vendor in raw['vendors']:
            vendor['source_results'].reverse()
        previous_cwd=Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                with patch('socket.getaddrinfo', side_effect=AssertionError('offline DNS request')), \
                     patch('socket.socket.connect', side_effect=AssertionError('offline network request')), \
                     patch('socket.socket.connect_ex', side_effect=AssertionError('offline network request')):
                    rebuilt=build_migration_bundle(raw,path,dictionary)
            finally:
                os.chdir(previous_cwd)
        self.assertEqual(self.bundle,rebuilt)

if __name__=='__main__': unittest.main()
