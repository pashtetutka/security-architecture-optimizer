import unittest

from siem.domain.identity import IdentityDictionary, load_default_dictionary, normalize_identity
from siem.domain.versions import compare_versions
from siem.etl.claims import conflicting_claim_diagnostics, normalize_claims, unknown_version


class ClaimNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dictionary=load_default_dictionary()

    def normalize(self, rows):
        return normalize_claims(rows,siem_product_ref='product:siem-test',
                                siem_release_scope=unknown_version(),dictionary=self.dictionary)

    def test_order_does_not_mix_full_and_partial_versions(self):
        full={'field':'source_integration','value':'Континент 4','source_version':'4','evidence_refs':['e:1']}
        partial={'field':'source_integration','value':'Континент 4','source_version':'3.9','support_scope':'partial',
                 'limitation':'only IDS','evidence_refs':['e:2']}
        first=self.normalize([full,partial]); second=self.normalize([partial,full])
        self.assertEqual(first['claims'],second['claims'])
        self.assertEqual(2,len(first['claims']))
        self.assertTrue(all(row['subject_resolution_ref'].startswith('resolution:')
                            for row in first['claims']))
        self.assertEqual({'unspecified','subset'},{row['scope']['extent'] for row in first['claims']})
        for row in first['claims']:
            self.assertEqual(1,len(row['evidence_refs']))

    def test_transport_is_not_normalization(self):
        generic={'field':'source_integration','value':'Microsoft Windows','collection_method':'Syslog'}
        normalized={**generic,'normalizer_id':'product:parser-1'}
        self.assertEqual('collect',self.normalize([generic])['claims'][0]['capability'])
        self.assertEqual('normalize',self.normalize([normalized])['claims'][0]['capability'])

    def test_ksc_route_proves_collection_for_the_named_endpoint_only(self):
        endpoint = {'field': 'source_integration', 'value': 'Kaspersky Endpoint Security for Linux',
                    'collection_intermediary': 'KSC', 'intermediary_transport': 'Syslog',
                    'evidence_refs': ['e:kesl-via-ksc']}
        transport_only = {'field': 'source_integration', 'value': 'Syslog',
                          'collection_method': 'Syslog', 'evidence_refs': ['e:transport']}
        result = normalize_claims(
            [endpoint, transport_only], siem_product_ref='product:siem-test',
            siem_release_scope=unknown_version(), dictionary=load_default_dictionary())
        claim, = result['claims']
        self.assertEqual(('collect', 'supported'), (claim['capability'], claim['assertion']))
        subject = next(r for r in result['resolutions']
                       if r['resolution_id'] == claim['subject_resolution_ref'])
        self.assertEqual('Kaspersky Endpoint Security for Linux', subject['raw_name'])
        route, = result['routes']
        self.assertEqual(claim['route_refs'], [route['route_id']])
        self.assertEqual(['source', 'intermediary', 'siem'], [s['role'] for s in route['steps']])
        self.assertEqual(('product:legacy-017', 'Syslog'),
                         (route['steps'][1]['actor_ref'], route['steps'][1]['transport']))
        self.assertEqual(['e:kesl-via-ksc'], route['evidence_refs'])
        self.assertEqual('Syslog', result['unresolved_queue'][0]['raw_name'])

    def test_separate_guides_prove_separate_routes_for_the_same_product(self):
        listed = {'field': 'source_integration', 'value': 'Microsoft Windows',
                  'source_version': '4', 'evidence_refs': ['e:catalog']}
        result = self.normalize([
            {**listed, 'collection_method': transport, 'collection_evidence_refs': [ref]}
            for transport, ref in [('Syslog', 'e:syslog'), ('PostgreSQL', 'e:database')]
        ])
        self.assertEqual(2, len(result['claims']))
        routes = {row['route_id']: row for row in result['routes']}
        proofs = {'Syslog': 'e:syslog', 'PostgreSQL': 'e:database'}
        for claim in result['claims']:
            route = routes[claim['route_refs'][0]]
            transports = {step['transport'] for step in route['steps']}
            self.assertEqual(1, len(transports))
            ref = proofs[transports.pop()]
            self.assertEqual([ref], route['evidence_refs'])
            self.assertEqual({'e:catalog', ref}, set(claim['evidence_refs']))
        with self.assertRaisesRegex(ValueError, 'requires evidence'):
            self.normalize([{**listed, 'collection_evidence_refs': []}])

    def test_numeric_version_intervals_preserve_bounds_and_raw_text(self):
        base = {'field': 'source_integration', 'value': 'Microsoft Windows'}
        raw = '2008—\u200b2022'
        scope = self.normalize([{**base, 'source_version': raw}])['claims'][0]['scope']['source_version']
        self.assertEqual((raw, 'range', '2008', '2022'),
                         (scope['raw'], scope['kind'], scope['lower'], scope['upper']))
        request = {'kind': 'exact', 'scheme': 'opaque', 'values': ['2022']}
        self.assertEqual('match', compare_versions(request, scope).status)
        request['values'] = ['2023']
        self.assertEqual('mismatch', compare_versions(request, scope).status)
        for raw_value, kind, scheme in [('2016 и выше', 'open', 'dotted_numeric'),
                                         ('17.5—17.14', 'range', 'dotted_numeric'),
                                         ('4—1', 'exact', 'opaque'),
                                         ('2017-04-02', 'exact', 'opaque')]:
            parsed = self.normalize([{**base, 'source_version': raw_value}])['claims'][0]['scope']['source_version']
            self.assertEqual((kind, scheme), (parsed['kind'], parsed['scheme']))

    def test_opposing_assertions_keep_both_evidence_sets_in_same_scope(self):
        positive = {'field': 'source_integration', 'value': 'Microsoft Windows',
                    'source_version': '10', 'evidence_refs': ['e:1']}
        negative = {**positive, 'support_assertion': 'unsupported',
                    'support_capability': 'collect', 'evidence_refs': ['e:2']}
        different_version = {**negative, 'source_version': '11', 'evidence_refs': ['e:3']}
        result = self.normalize([different_version, negative, positive])
        resolutions = {row['resolution_id']: row for row in result['resolutions']}
        diagnostics = conflicting_claim_diagnostics(result['claims'], resolutions)
        self.assertEqual(2, len(diagnostics))
        self.assertTrue(all(row['evidence_refs'] == ['e:1', 'e:2'] for row in diagnostics))
        self.assertEqual(diagnostics, conflicting_claim_diagnostics(
            reversed(result['claims']), resolutions))

    def test_explicit_negative_and_unknown_do_not_invent_capability_routes(self):
        published = {'field': 'source_integration', 'value': 'Microsoft Windows',
                     'collection_method': 'Syslog', 'evidence_refs': ['e:1']}
        negative = {**published, 'support_assertion': 'unsupported',
                    'support_capability': 'respond', 'evidence_refs': ['e:2']}
        unknown = {**negative, 'support_assertion': 'unknown', 'evidence_refs': []}
        result = self.normalize([published, negative, unknown])
        claims = {row['assertion']: row for row in result['claims']}
        self.assertEqual({'supported', 'unsupported', 'unknown'}, set(claims))
        self.assertEqual(1, len(result['routes']))
        self.assertEqual('respond', claims['unsupported']['capability'])
        self.assertEqual(['e:2'], claims['unsupported']['evidence_refs'])
        self.assertEqual([], claims['unsupported']['route_refs'])
        self.assertEqual([], claims['unknown']['route_refs'])
        self.assertEqual(claims['unknown']['claim_id'], result['diagnostics'][0]['target_ref'])
        with self.assertRaisesRegex(ValueError, 'requires evidence'):
            self.normalize([{**negative, 'evidence_refs': []}])

    def test_preserves_documented_limits_from_catalog_and_collection_guide(self):
        row = {'field': 'source_integration', 'value': 'Microsoft Windows',
               'support_scope': 'partial', 'support_limitation': 'only Application events',
               'support_limitations': ['only Application events', 'no custom channels'],
               'collection_limitations': ['Winlogbeat must be configured']}
        scope = self.normalize([row])['claims'][0]['scope']
        self.assertEqual('subset', scope['extent'])
        self.assertEqual(['only Application events', 'no custom channels',
                          'Winlogbeat must be configured'], scope['limitations'])

    def test_event_channels_are_distinct_from_the_route_format(self):
        row = {'field': 'source_integration', 'value': 'Microsoft Windows',
               'collection_method': 'HTTP', 'normalizer_format': 'JSON',
               'event_channels': ['System', 'Application', 'System']}
        result = self.normalize([row])
        self.assertEqual(['Application', 'System'],
                         result['claims'][0]['scope']['event_channels'])
        self.assertEqual('JSON', result['routes'][0]['steps'][0]['format'])
        row.pop('event_channels')
        self.assertEqual([], self.normalize([row])['claims'][0]['scope']['event_channels'])

    def test_unknown_product_stays_in_queue(self):
        result=self.normalize([{'field':'source_integration','value':'Unknown Appliance'}])
        self.assertEqual([],result['claims'])
        self.assertEqual('unresolved',result['unresolved_queue'][0]['status'])

    def test_queue_retains_the_reason_used_to_reject_a_vendor_name(self):
        vendor = next(
            alias['surface'] for alias in self.dictionary.aliases
            if self.dictionary.entities[alias['entity_ref']]['type'] == 'vendor'
            and not alias.get('context')
        )
        row = {'field': 'source_integration', 'value': vendor}
        result = self.normalize([row, row])
        self.assertEqual([], result['claims'])
        self.assertEqual(1, len(result['unresolved_queue']))
        self.assertEqual(['vendor_name_is_not_product'],
                         result['unresolved_queue'][0]['reason_codes'])

    def test_queue_respects_the_vendor_context_used_for_claims(self):
        source_alias = next(
            alias for alias in self.dictionary.aliases
            if self.dictionary.entities[alias['entity_ref']]['type'] == 'product'
        )
        context_alias = {
            **source_alias, 'surface': 'Context Appliance',
            'normalized_key': normalize_identity('Context Appliance'),
            'context': {'vendor_ref': 'vendor:context'},
        }
        dictionary = IdentityDictionary(self.dictionary.version, self.dictionary.entities,
                                        (context_alias,), ())
        row = {'field': 'source_integration', 'value': 'Context Appliance',
               'source_vendor_entity_id': 'vendor:context'}
        result = normalize_claims([row], siem_product_ref='product:siem-test',
                                  siem_release_scope=unknown_version(), dictionary=dictionary)
        self.assertEqual(1, len(result['claims']))
        self.assertEqual([], result['unresolved_queue'])

    def test_more_than_three_distinct_claims_are_not_truncated(self):
        rows=[{'field':'source_integration','value':'Континент 4','source_version':str(v),
               'evidence_refs':[f'e:{v}']} for v in range(1,6)]
        self.assertEqual(5,len(self.normalize(rows)['claims']))

if __name__ == '__main__': unittest.main()
