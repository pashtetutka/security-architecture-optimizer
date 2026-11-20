"""Positive complete catalog and negative boundary probes for RFC T02."""
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from siem.domain.contracts import (Bounds, NumericInterval, Quantity, VersionScope,
                                   bundle_content_digest, canonical_json, claim_id,
                                   evidence_id, review_target_digest, route_id, to_json_value)
from siem.domain.validation import validate_bundle


def unknown_version():
    return to_json_value(VersionScope(None, 'unknown', 'opaque', (), None, None, None, 'unknown'))


def quantity(value, unit='GB', basis='total'):
    return to_json_value(Quantity(value, unit, basis, None))


def condition(operator='eq', value=None, subject='node:main', metric='os'):
    return {'operator': operator, 'operands': {'metric': metric, 'subject_ref': subject,
                                              'value': value or {'type': 'string', 'value': 'Linux'}}}


def seal(bundle):
    """Test producer; never fills evidence, review or unknown values."""
    bundle['manifest']['content_digest'] = bundle_content_digest(bundle)
    return bundle


def replace_ref(value, old, new):
    if isinstance(value, dict):
        return {key: replace_ref(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_ref(item, old, new) for item in value]
    return new if value == old else value


def assign_content_ids(bundle):
    for collection, field, derive in [('evidence', 'evidence_id', evidence_id),
                                       ('routes', 'route_id', route_id),
                                       ('claims', 'claim_id', claim_id)]:
        for row in bundle[collection]:
            bundle = replace_ref(bundle, row[field], derive(row))
    return bundle


def complete_bundle():
    """A self-contained metadata fixture; no live document or download is implied."""
    evidence_refs = ['evidence:row1']
    sha = hashlib.sha256(b'synthetic contract fixture').hexdigest()
    doc_id = 'document:' + sha
    excerpt = 'Synthetic source: only audit events; 4 vCPU and 16 GiB.'
    scope = {'source_version': unknown_version(), 'edition': None, 'hardware_models': [],
             'event_channels': ['audit'], 'extent': 'subset',
             'conditions': {'operator': 'all_of', 'operands': []},
             'limitations': ['Only audit events']}
    claim = {'claim_id': 'claim:pending', 'siem_product_ref': 'siem:example',
             'siem_release_scope': unknown_version(), 'subject_resolution_ref': 'resolution:source',
             'capability': 'normalize', 'assertion': 'supported', 'scope': scope,
             'route_refs': ['route:syslog'], 'evidence_refs': evidence_refs,
             'review_state': 'extracted'}
    claim['claim_id'] = claim_id(claim)
    steps = []
    for actor, role, operation, parser in [('product:source', 'source', 'export', None),
                                          ('siem:example', 'collector', 'collect', None),
                                          ('siem:example', 'normalizer', 'normalize', 'product:parser')]:
        steps.append({'actor_ref': actor, 'role': role, 'operation': operation,
                      'transport': 'Syslog', 'format': 'CEF', 'parser_ref': parser,
                      'source_release_scope': unknown_version(), 'evidence_refs': evidence_refs})
    node = {'node_ref': 'node:main', 'roles': ['collector', 'storage'],
            'quantity': {'kind': 'minimum', 'value': 1, 'raw': 'one node'},
            'placement': {'kind': 'physical_node', 'co_location_refs': [], 'raw': None},
            'cpu': quantity(4, 'vCPU', 'per_node'), 'ram': quantity(16, 'GiB', 'per_node'),
            'network': quantity(1, 'Gbit/s', 'per_node'),
            'storage_groups': [{'purpose': 'events', 'quantity': {'kind': 'unknown', 'value': None, 'raw': None},
                                'per_device_capacity': quantity(None), 'total_capacity': quantity(100),
                                'capacity_basis': 'raw', 'medium': 'SSD', 'raid': None, 'conditions': None,
                                'raw': '100 GB total; number of disks unknown', 'evidence_refs': evidence_refs}],
            'os_constraints': {'operator': 'any_of', 'operands': [condition(), condition(value={'type': 'string', 'value': 'Other Linux'})]},
            'dependency_constraints': {'operator': 'all_of', 'operands': [condition(metric='dependency')]},
            'evidence_refs': evidence_refs}
    bundle = {
        'schema_version': 'siem-catalog/2.0', 'status': 'data',
        'manifest': {'schema_version': 'siem-catalog/2.0', 'dataset_id': 'dataset:fixture',
                     'content_digest': 'sha256:' + '0' * 64, 'input_document_ids': [doc_id],
                     'dictionary_version': 'fixture-1', 'normalizer_version': 'fixture-1',
                     'extractor_versions': {'fixture': '1'},
                     'build_options': {'automatic_only': True, 'public_bundle': False}, 'payloads': []},
        'build': {'build_id': 'build:fixture', 'built_at': '2026-11-16T10:00:00+00:00',
                  'source_revision': 'sha256:' + 'a' * 64, 'input_manifests': [],
                  'dependency_lock_digest': 'sha256:' + 'b' * 64},
        'extension_registry': {'version': '1', 'entries': [
            {'key': 'event_sample', 'type': 'boolean', 'unit': None, 'allowed_values': []}]},
        'vendors': [{'id': 'vendor:siem', 'display_name': 'Example SIEM vendor'},
                    {'id': 'vendor:source', 'display_name': 'Example source vendor'}],
        'products': [{'id': 'siem:example', 'vendor_id': 'vendor:siem', 'display_name': 'Example SIEM',
                      'kind': 'product', 'class_ids': ['siem']},
                     {'id': 'product:source', 'vendor_id': 'vendor:source', 'display_name': 'Example Source',
                      'kind': 'product', 'class_ids': ['network'], 'extensions': [
                          {'key': 'event_sample', 'type': 'boolean', 'value': True, 'unit': None, 'evidence_refs': evidence_refs}]},
                     {'id': 'product:edition', 'vendor_id': 'vendor:source', 'display_name': 'Example Source Edition',
                      'kind': 'product', 'class_ids': ['network']},
                     {'id': 'product:parser', 'vendor_id': 'vendor:siem', 'display_name': 'Example Parser',
                      'kind': 'product', 'class_ids': ['parser']}],
        'aliases': [{'id': 'alias:source', 'surface': 'Example Source', 'normalized_key': 'example source',
                     'entity_ref': 'product:source', 'context': {'vendor_ref': 'vendor:source', 'language': 'en'},
                     'evidence_refs': evidence_refs, 'review_state': 'extracted'}],
        'relations': [{'from_ref': 'product:edition', 'relation': 'edition_of', 'to_ref': 'product:source',
                       'evidence_refs': evidence_refs, 'review_state': 'extracted'}],
        'documents': [{'document_id': doc_id, 'sha256': sha,
                       'source_url': 'https://example.org/source.html', 'resolved_url': 'https://example.org/source.html',
                       'acquired_at': '2026-11-16T09:00:00+00:00', 'acquisition_method': 'automatic_https',
                       'snapshot_path': 'raw/' + sha + '.html', 'media_type': 'text/html',
                       'release_scope': unknown_version(), 'redistribution': 'allowed', 'snapshot_omission': None}],
        'evidence': [{'evidence_id': 'evidence:row1', 'document_ref': doc_id,
                      'locator': {'kind': 'html', 'section': 'sources', 'table': '1', 'row': 1,
                                  'page': None, 'cell': None, 'text_normalization': 'exact_utf8'},
                      'excerpt': excerpt, 'excerpt_sha256': hashlib.sha256(excerpt.encode()).hexdigest(),
                      'extraction_method': 'fixture_table', 'extractor_version': '1'}],
        'resolutions': [{'resolution_id': 'resolution:source', 'raw_name': 'Example Source',
                         'normalized_key': 'example source', 'status': 'resolved', 'product_ref': 'product:source',
                         'candidate_refs': [], 'reason_codes': [], 'dictionary_version': 'fixture-1'}],
        'claims': [claim], 'routes': [{'route_id': 'route:syslog', 'subject_ref': 'product:source',
                                     'steps': steps, 'conditions': None, 'evidence_refs': evidence_refs,
                                     'review_state': 'extracted'}],
        'reviews': [], 'diagnostics': [],
        'profiles': [{'profile_id': 'profile:main', 'siem_product_ref': 'siem:example',
                      'release_scope': unknown_version(),
                      'deployment_scenario': {'id': 'deployment:example', 'description': 'single node', 'architecture': None},
                      'tier': 'minimum', 'workload': {
                          'eps': quantity(NumericInterval(100, 1000, Bounds(None, None)), 'EPS'),
                          'basis': 'technical_sizing', 'search': quantity(None, 'events'),
                          'retention': quantity(None, 'days'), 'event_size': quantity(None, 'bytes')},
                      'conditions': condition('gte', quantity(100, 'EPS'), 'deployment:main', 'eps'),
                      'nodes': [node], 'evidence_refs': evidence_refs, 'review_state': 'extracted'}],
        'requirements': [{'requirement_id': 'requirement:ram', 'siem_product_ref': 'siem:example',
                          'release_scope': unknown_version(), 'subject_ref': 'node:main', 'property': 'ram',
                          'operator': 'gte', 'typed_value': quantity(16, 'GiB', 'per_node'),
                          'strength': 'mandatory', 'conditions': None,
                          'evidence_refs': evidence_refs, 'review_state': 'extracted'}],
    }
    return seal(assign_content_ids(bundle))


class DomainContractTests(unittest.TestCase):
    def assert_codes(self, bundle, *codes):
        result = validate_bundle(seal(bundle))
        self.assertFalse(result.valid)
        actual = {issue.code for issue in result.issues}
        self.assertTrue(set(codes) <= actual, (codes, result.to_dict()))
        return result

    def test_complete_bundle_with_unknown_release_and_unknown_disk_count(self):
        bundle = complete_bundle()
        before = deepcopy(bundle)
        result = validate_bundle(bundle)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(bundle, before)

    def test_offline_schema_references_and_canonical_serialization(self):
        with patch('socket.socket', side_effect=AssertionError('Network forbidden')):
            self.assertTrue(validate_bundle(complete_bundle()).valid)
        self.assertEqual(canonical_json({'b': 1, 'a': [2, 1]}), b'{"a":[2,1],"b":1}')
        self.assertNotEqual(canonical_json([2, 1]), canonical_json([1, 2]))
        with self.assertRaises(ValueError):
            canonical_json(float('nan'))

    def test_f01_missing_evidence_hash_and_foreign_siem(self):
        for mutation, code in [
            (lambda b: b['claims'][0].update(evidence_refs=[]), 'evidence_required'),
            (lambda b: b['documents'][0].pop('sha256'), 'schema_required'),
            (lambda b: b['claims'][0].update(siem_product_ref='siem:absent'), 'unknown_reference'),
            (lambda b: b['evidence'][0].update(excerpt_sha256='c' * 64), 'excerpt_hash_mismatch'),
            (lambda b: b['claims'][0].update(review_state='verified'), 'schema_enum'),
        ]:
            bundle = complete_bundle()
            mutation(bundle)
            with self.subTest(code=code):
                self.assert_codes(bundle, code)

    def test_f07_missing_component_shape_and_duplicate_identity_references(self):
        bundle = complete_bundle()
        del bundle['claims'][0]['scope']['source_version']
        result = self.assert_codes(bundle, 'schema_required')
        self.assertTrue(any(i.location == '/claims/0/scope/source_version' for i in result.issues))
        bundle = complete_bundle()
        bundle['products'].append(deepcopy(bundle['products'][1]))
        self.assert_codes(bundle, 'duplicate_id')
        bundle = complete_bundle()
        bundle['resolutions'][0]['candidate_refs'] = ['product:source', 'product:source']
        self.assert_codes(bundle, 'schema_uniqueItems')

    def test_numeric_resources_and_eps_bounds(self):
        for value in (-1, 0, True, float('nan'), float('inf')):
            bundle = complete_bundle()
            bundle['profiles'][0]['nodes'][0]['cpu']['value'] = value
            if isinstance(value, float) and not __import__('math').isfinite(value):
                # Digest serialization itself rejects non-JSON numbers.
                result = validate_bundle(bundle)
                self.assertFalse(result.valid)
                self.assertIn('non_finite_number', {i.code for i in result.issues})
            else:
                self.assertFalse(validate_bundle(bundle).valid)
        bundle = complete_bundle()
        bundle['profiles'][0]['workload']['eps']['value']['lower'] = 5000
        self.assert_codes(bundle, 'inverted_numeric_bounds')
        bundle = complete_bundle()
        bundle['profiles'][0]['nodes'][0]['quantity']['value'] = True
        self.assert_codes(bundle, 'schema_type')

    def test_units_and_unknown_quantities(self):
        for field, unit in [('cpu', 'GB'), ('ram', 'Gb'), ('network', 'GB')]:
            bundle = complete_bundle()
            bundle['profiles'][0]['nodes'][0][field]['unit'] = unit
            self.assert_codes(bundle, 'invalid_resource_unit')
        bundle = complete_bundle()
        bundle['profiles'][0]['nodes'][0]['cpu']['value'] = None
        self.assertTrue(validate_bundle(seal(bundle)).valid)

    def test_unknown_opaque_version_and_unknown_claim_need_diagnostic(self):
        bundle = complete_bundle()
        scope = bundle['claims'][0]['scope']['source_version']
        scope['raw'] = 'Custom release branch / next'
        bundle['claims'][0]['claim_id'] = claim_id(bundle['claims'][0])
        self.assertTrue(validate_bundle(seal(bundle)).valid)
        bundle['claims'][0].update(assertion='unknown', evidence_refs=[], route_refs=[])
        bundle['claims'][0]['scope']['conditions'] = None
        bundle['claims'][0]['claim_id'] = claim_id(bundle['claims'][0])
        self.assert_codes(bundle, 'unknown_requires_diagnostic')
        bundle['diagnostics'] = [{'code': 'source_version_unknown', 'severity': 'warning',
                                  'target_ref': bundle['claims'][0]['claim_id'], 'stage': 'extraction',
                                  'message': 'Source release is not established', 'evidence_refs': []}]
        self.assertTrue(validate_bundle(seal(bundle)).valid)

    def test_conditions_all_any_and_unknown_comparator(self):
        bundle = complete_bundle()
        bundle['profiles'][0]['nodes'][0]['os_constraints']['operator'] = 'exec'
        self.assert_codes(bundle, 'schema_anyOf')
        bundle = complete_bundle()
        bundle['profiles'][0]['nodes'][0]['os_constraints']['operands'] = []
        self.assert_codes(bundle, 'schema_anyOf')
        bundle = complete_bundle()
        bundle['profiles'][0]['nodes'][0]['os_constraints']['operator'] = 'all_of'
        self.assert_codes(bundle, 'invalid_requirement_group')
        bundle = complete_bundle()
        bundle['routes'][0]['conditions'] = {'operator': 'all_of', 'operands': []}
        self.assertTrue(validate_bundle(seal(assign_content_ids(bundle))).valid)

    def test_routes_cannot_borrow_another_product_or_capability(self):
        bundle = complete_bundle()
        bundle['routes'][0]['subject_ref'] = 'product:edition'
        self.assert_codes(bundle, 'route_subject_conflict')
        bundle = complete_bundle()
        bundle['claims'][0]['capability'] = 'respond'
        self.assert_codes(bundle, 'route_capability_not_proven')
        bundle = complete_bundle()
        bundle['claims'][0]['capability'] = 'export'
        bundle['claims'][0]['claim_id'] = claim_id(bundle['claims'][0])
        self.assertTrue(validate_bundle(seal(bundle)).valid)
        bundle['routes'][0]['steps'][0]['operation'] = 'collect'
        self.assert_codes(bundle, 'route_capability_not_proven')

    def test_route_must_reference_the_evidence_for_each_step(self):
        bundle = complete_bundle()
        original = bundle['evidence'][0]
        excerpt = 'Independent evidence for the collector step.'
        separate = {**original, 'excerpt': excerpt,
                    'excerpt_sha256': hashlib.sha256(excerpt.encode('utf-8')).hexdigest()}
        separate['evidence_id'] = evidence_id(separate)
        bundle['evidence'].append(separate)
        route = bundle['routes'][0]
        route['steps'][1]['evidence_refs'] = [separate['evidence_id']]
        self.assert_codes(assign_content_ids(bundle), 'route_step_evidence_missing_from_route')
        route['evidence_refs'] = [*route['evidence_refs'], separate['evidence_id']]
        self.assertTrue(validate_bundle(seal(assign_content_ids(bundle))).valid)

    def test_validation_errors_are_not_multiplied_for_missing_fields(self):
        result = validate_bundle({})
        identities = [(issue.code, issue.location) for issue in result.issues]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertLess(len(identities), 25)

    def test_quantity_and_condition_invariants_also_apply_to_requirement_claims(self):
        for typed, expected in [(quantity(0, 'GiB'), 'non_positive_resource'),
                                (quantity(16, 'Gb'), 'invalid_resource_unit'),
                                ({'type': 'boolean', 'value': True}, 'invalid_comparator_value')]:
            bundle = complete_bundle()
            bundle['requirements'][0]['typed_value'] = typed
            self.assert_codes(bundle, expected)
        bundle = complete_bundle()
        version = {'raw': '1-3', 'kind': 'range', 'scheme': 'dotted_numeric', 'values': [],
                   'lower': '1', 'upper': '3', 'bounds': {'lower_inclusive': None, 'upper_inclusive': None}, 'status': 'parsed'}
        bundle['profiles'][0]['conditions'] = condition('range', version, 'deployment:main', 'release')
        self.assertTrue(validate_bundle(seal(bundle)).valid)

    def test_capability_ownership_and_publication_invariants(self):
        bundle = complete_bundle()
        bundle['routes'][0]['steps'][2]['parser_ref'] = 'product:edition'
        self.assert_codes(bundle, 'not_a_parser_product')
        bundle = complete_bundle()
        bundle['manifest']['build_options']['public_bundle'] = True
        bundle['documents'][0]['redistribution'] = 'restricted'
        self.assert_codes(bundle, 'public_snapshot_not_allowed')
        bundle = complete_bundle()
        bundle['documents'][0]['acquisition_method'] = 'manual_import'
        self.assert_codes(bundle, 'acquisition_filter_mismatch')
        bundle = complete_bundle()
        bundle['products'].append(dict(bundle['products'][0], id='siem:other'))
        other = deepcopy(bundle['profiles'][0])
        other.update(profile_id='profile:other', siem_product_ref='siem:other')
        other['nodes'][0]['node_ref'] = 'node:other'
        for field in ('os_constraints', 'dependency_constraints'):
            for operand in other['nodes'][0][field]['operands']:
                operand['operands']['subject_ref'] = 'node:other'
        bundle['profiles'].append(other)
        bundle['profiles'][0]['conditions']['operands']['subject_ref'] = 'node:other'
        self.assert_codes(bundle, 'node_owner_conflict')

    def test_evidence_and_route_mutations_cannot_hide_from_claim_review(self):
        bundle = complete_bundle()
        bundle['evidence'][0]['locator']['row'] = 2
        self.assert_codes(bundle, 'evidence_content_id_mismatch')
        bundle = complete_bundle()
        bundle['routes'][0]['steps'][0]['format'] = 'JSON'
        self.assert_codes(bundle, 'route_content_id_mismatch')
        bundle = complete_bundle()
        claim = bundle['claims'][0]
        bundle['reviews'] = [{'decision_id': 'decision:old', 'target_ref': claim['claim_id'],
                              'target_digest': review_target_digest(claim), 'reviewer': 'Fixture reviewer',
                              'reviewed_at': '2026-11-16T11:00:00Z', 'decision': 'approved',
                              'reason': 'Old content', 'evidence_refs': [bundle['evidence'][0]['evidence_id']],
                              'experiment_protocol': None}]
        old_claim_id = claim['claim_id']
        bundle['routes'][0]['steps'][0]['format'] = 'JSON'
        # Rebuild content IDs but retain the append-only historical review.
        historical = deepcopy(bundle['reviews'])
        bundle = assign_content_ids(bundle)
        bundle['reviews'] = historical
        self.assertNotEqual(old_claim_id, bundle['claims'][0]['claim_id'])
        result = validate_bundle(seal(bundle))
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn('stale_review', {i.code for i in result.issues})
        bundle['claims'][0]['review_state'] = 'reviewed'
        self.assert_codes(bundle, 'review_decision_required')

    def test_review_never_comes_from_extraction_or_test_pass(self):
        bundle = complete_bundle()
        claim = bundle['claims'][0]
        claim['review_state'] = 'reviewed'
        self.assert_codes(bundle, 'review_decision_required')
        bundle['reviews'] = [{'decision_id': 'decision:first', 'target_ref': claim['claim_id'],
                              'target_digest': review_target_digest(claim), 'reviewer': 'Synthetic reviewer',
                              'reviewed_at': '2026-11-16T11:00:00+00:00', 'decision': 'approved',
                              'reason': 'Synthetic contract review', 'evidence_refs': [bundle['evidence'][0]['evidence_id']],
                              'experiment_protocol': None}]
        self.assertTrue(validate_bundle(seal(bundle)).valid)
        claim['review_state'] = 'experiment_verified'
        self.assert_codes(bundle, 'experiment_protocol_required')
        claim['review_state'] = 'extracted'
        claim['scope']['limitations'].append('Changed after review')
        claim['claim_id'] = claim_id(claim)
        bundle['reviews'][0]['target_ref'] = claim['claim_id']
        result = validate_bundle(seal(bundle))
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn('stale_review', {i.code for i in result.issues})

    def test_paths_timestamps_and_explicit_snapshot_omission(self):
        for path in ('../private.pdf', '/etc/file', 'C:/file', 'raw\\file', 'raw/../file'):
            bundle = complete_bundle()
            bundle['documents'][0]['snapshot_path'] = path
            self.assert_codes(bundle, 'unsafe_relative_path')
        bundle = complete_bundle()
        bundle['documents'][0]['acquired_at'] = '2026-11-16T10:00:00'
        self.assert_codes(bundle, 'schema_format')
        bundle = complete_bundle()
        doc = bundle['documents'][0]
        doc.update(snapshot_path=None, redistribution='restricted', snapshot_omission={
            'reason': 'Private input', 'external_requirement': 'Reviewer provides original privately'})
        bundle['diagnostics'].append({'code': 'snapshot_omitted', 'severity': 'warning',
                                      'target_ref': doc['document_id'], 'stage': 'publication',
                                      'message': 'Public bundle cannot replay this input', 'evidence_refs': []})
        self.assertTrue(validate_bundle(seal(bundle)).valid)

    def test_empty_dataset_is_not_implicitly_ready(self):
        bundle = complete_bundle()
        for field in ('claims', 'profiles', 'requirements'):
            bundle[field] = []
        self.assert_codes(bundle, 'empty_dataset_requires_no_data')
        bundle['status'] = 'no_data'
        bundle['diagnostics'] = [{'code': 'no_data', 'severity': 'warning', 'target_ref': 'dataset:fixture',
                                  'stage': 'extraction', 'message': 'No facts extracted', 'evidence_refs': []}]
        self.assertTrue(validate_bundle(seal(bundle)).valid)

    def test_registered_extensions_are_typed_and_unknown_fields_fail(self):
        bundle = complete_bundle()
        bundle['products'][0]['random_vendor_flag'] = True
        self.assert_codes(bundle, 'schema_additionalProperties')
        bundle = complete_bundle()
        bundle['products'][1]['extensions'][0]['value'] = 'true'
        self.assert_codes(bundle, 'schema_type')
        bundle = complete_bundle()
        bundle['extension_registry']['entries'] = []
        result = validate_bundle(seal(bundle))
        self.assertTrue(result.valid, result.to_dict())
        self.assertIn('unregistered_extension', {i.code for i in result.issues})


if __name__ == '__main__':
    unittest.main()
