"""Offline JSON Schema validation and cross-record catalog invariants.

This module does not read snapshots, resolve identities, evaluate conditions,
compare releases, select routes or grant review. Those are separate stages.
"""
from __future__ import annotations

from functools import lru_cache
from datetime import datetime
import hashlib
from importlib.resources import files
import json
import math
from pathlib import PurePosixPath
import re
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from .contracts import (CatalogBundle, Severity, ValidationIssue, ValidationResult,
                        bundle_content_digest, claim_id, content_digest,
                        evidence_id, relation_ref, review_target_digest, route_id,
                        to_json_value)


def _no_remote_resource(uri: str):
    raise NoSuchResource(ref=uri)


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schemas = [json.loads(path.read_text(encoding='utf-8'))
               for path in files('siem.domain').joinpath('schemas').iterdir()
               if path.name.endswith('.json')]
    registry = Registry(retrieve=_no_remote_resource)
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    catalog = next(schema for schema in schemas if schema['$id'].endswith(':catalog'))
    formats = FormatChecker()

    @formats.checks('date-time', raises=ValueError)
    def timestamp(value):
        if not isinstance(value, str):
            return True
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.tzinfo is not None and 'T' in value

    @formats.checks('uri', raises=ValueError)
    def uri(value):
        if not isinstance(value, str):
            return True
        parsed = urlsplit(value)
        return (parsed.scheme == 'https' and bool(parsed.hostname) and
                parsed.username is None and parsed.password is None and
                not any(char.isspace() for char in value))

    return Draft202012Validator(catalog, registry=registry, format_checker=formats)


def _pointer(parts) -> str:
    return ''.join('/' + str(part).replace('~', '~0').replace('/', '~1') for part in parts)


def _portable_path(value: str) -> bool:
    return (bool(value) and not any(char in value for char in ('\\', ':', '\x00'))
            and not PurePosixPath(value).is_absolute()
            and all(part not in ('', '.', '..') for part in value.split('/')))


def _walk(value: Any, path=()):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, (*path, index))


def validate_bundle(bundle: CatalogBundle | dict) -> ValidationResult:
    """Validate structure once, then evidence, reference and domain invariants.

    Invalid shape returns schema issues without traversing assumed fields.
    There are no network lookups or mutations of the caller's data. Snapshot
    bytes and payload file hashes are checked by the future bundle loader.
    """
    data = to_json_value(bundle)
    issues: list[ValidationIssue] = []

    def emit(code, path, message, target=None, severity=Severity.ERROR):
        issues.append(ValidationIssue(code, _pointer(path), severity, target, message))

    for path, value in _walk(data):
        if isinstance(value, float) and not math.isfinite(value):
            emit('non_finite_number', path, 'JSON numbers must be finite')
    errors = sorted(_validator().iter_errors(data), key=lambda item: (_pointer(item.absolute_path), item.message))
    for error in errors:
        path = tuple(error.absolute_path)
        missing = ([key for key in error.validator_value if error.message == f'{key!r} is a required property']
                   if error.validator == 'required' and isinstance(error.instance, dict) else [])
        target = None
        current = data
        for depth in range(len(path) + 1):
            if isinstance(current, dict):
                target = next((current[key] for key in ('id', 'claim_id', 'route_id', 'document_id',
                               'evidence_id', 'profile_id', 'requirement_id', 'resolution_id', 'decision_id')
                               if isinstance(current.get(key), str)), target)
            if depth < len(path):
                current = current[path[depth]]
        for location in [(*path, key) for key in missing] or [path]:
            emit('schema_' + str(error.validator), location, error.message, target)
    if issues:
        return ValidationResult(tuple(issues))

    # Namespaces are assigned by a dictionary, never reconstructed from labels.
    collections = {
        'vendors': ('id', 'vendor'), 'products': ('id', None), 'aliases': ('id', 'alias'),
        'documents': ('document_id', 'document'), 'evidence': ('evidence_id', 'evidence'),
        'resolutions': ('resolution_id', 'resolution'), 'claims': ('claim_id', 'claim'),
        'routes': ('route_id', 'route'), 'reviews': ('decision_id', 'decision'),
        'profiles': ('profile_id', 'profile'), 'requirements': ('requirement_id', 'requirement'),
    }
    records: dict[str, tuple[dict, tuple]] = {}
    groups: dict[str, dict[str, dict]] = {}

    def register(ident, record, path):
        if ident in records:
            emit('duplicate_id', path, f'Duplicate identifier {ident}', ident)
        else:
            records[ident] = (record, path)

    for collection, (key, prefix) in collections.items():
        groups[collection] = {}
        for index, row in enumerate(data[collection]):
            ident, path = row[key], (collection, index)
            register(ident, row, path)
            groups[collection][ident] = row
            if prefix and not ident.startswith(prefix + ':'):
                emit('id_namespace', (*path, key), f'Expected {prefix}: identifier', ident)
    for index, relation in enumerate(data['relations']):
        register(relation_ref(relation), relation, ('relations', index))
    for pi, profile in enumerate(data['profiles']):
        for ni, node in enumerate(profile['nodes']):
            register(node['node_ref'], node, ('profiles', pi, 'nodes', ni))
            if not node['node_ref'].startswith('node:'):
                emit('id_namespace', ('profiles', pi, 'nodes', ni, 'node_ref'), 'Expected node: identifier', node['node_ref'])
    dataset_ref = data['manifest']['dataset_id']
    register(dataset_ref, data['manifest'], ('manifest',))
    register(data['build']['build_id'], data['build'], ('build',))
    if not dataset_ref.startswith('dataset:'):
        emit('id_namespace', ('manifest', 'dataset_id'), 'Expected dataset: identifier', dataset_ref)
    if not data['build']['build_id'].startswith('build:'):
        emit('id_namespace', ('build', 'build_id'), 'Expected build: identifier', data['build']['build_id'])
    node_ids = {ref for ref, (row, path) in records.items() if path and path[0] == 'profiles' and 'nodes' in path}
    node_owners = {node['node_ref']: profile['siem_product_ref']
                   for profile in data['profiles'] for node in profile['nodes']}

    def foreign(ref, path, allowed=None, nullable=False):
        if ref is None and nullable:
            return
        valid = ref in records and (allowed is None or ref in allowed)
        if not valid:
            emit('unknown_reference', path, f'Unknown or incompatible reference {ref}', ref)

    def subject(ref, path):
        # Document-local variables have no global entity identity. The future
        # condition evaluator binds them; their values remain unknown here.
        if ref in ('deployment:main', 'workload:main'):
            return
        foreign(ref, path, set(groups['products']) | node_ids | set(groups['profiles']))
        owner = None
        if len(path) > 1 and path[0] in ('profiles', 'requirements'):
            owner = data[path[0]][path[1]]['siem_product_ref']
        target_owner = node_owners.get(ref) or groups['profiles'].get(ref, {}).get('siem_product_ref')
        if owner and target_owner and owner != target_owner:
            emit('node_owner_conflict', path, 'Scoped requirement cannot reference hardware of another SIEM', ref)

    def evidence_refs(row, path, required=False):
        refs = row.get('evidence_refs', [])
        if required and not refs:
            emit('evidence_required', (*path, 'evidence_refs'), 'A published assertion requires evidence')
        for index, ref in enumerate(refs):
            foreign(ref, (*path, 'evidence_refs', index), groups['evidence'])

    def siem(ref, path):
        foreign(ref, path, groups['products'])
        product = groups['products'].get(ref)
        if product and (product['kind'] != 'product' or 'siem' not in product['class_ids']):
            emit('not_a_siem_product', path, 'SIEM reference must identify a concrete product classified as siem', ref)

    for i, row in enumerate(data['products']):
        if not row['id'].startswith(('product:', 'siem:')):
            emit('id_namespace', ('products', i, 'id'), 'Product identifiers use product: or siem: namespaces', row['id'])
        foreign(row['vendor_id'], ('products', i, 'vendor_id'), groups['vendors'])
    for i, row in enumerate(data['aliases']):
        p = ('aliases', i)
        foreign(row['entity_ref'], (*p, 'entity_ref'), set(groups['products']) | set(groups['vendors']))
        vendor = row['context']['vendor_ref']
        foreign(vendor, (*p, 'context', 'vendor_ref'), groups['vendors'], nullable=True)
        product = groups['products'].get(row['entity_ref'])
        if product and vendor and product['vendor_id'] != vendor:
            emit('alias_vendor_conflict', (*p, 'context', 'vendor_ref'), 'Alias context contradicts product manufacturer', row['id'])
        evidence_refs(row, p, required=True)
    for i, row in enumerate(data['relations']):
        p = ('relations', i)
        for key in ('from_ref', 'to_ref'):
            foreign(row[key], (*p, key), groups['products'])
        if row['from_ref'] == row['to_ref']:
            emit('self_relation', p, 'Product relation must connect different entities', row['from_ref'])
        evidence_refs(row, p, required=True)
    for i, row in enumerate(data['resolutions']):
        p = ('resolutions', i)
        foreign(row['product_ref'], (*p, 'product_ref'), groups['products'], nullable=True)
        for j, ref in enumerate(row['candidate_refs']):
            foreign(ref, (*p, 'candidate_refs', j), groups['products'])
        if row['dictionary_version'] != data['manifest']['dictionary_version']:
            emit('dictionary_version_mismatch', (*p, 'dictionary_version'), 'Resolution belongs to a different dictionary', row['resolution_id'])
        if row['status'] == 'resolved':
            if row['product_ref'] is None or row['candidate_refs']:
                emit('invalid_resolved_identity', p, 'Resolved identity requires one product and no candidates', row['resolution_id'])
        elif row['product_ref'] is not None or not row['reason_codes'] or (row['status'] == 'ambiguous' and len(row['candidate_refs']) < 2):
            emit('invalid_unresolved_identity', p, 'Unknown identity requires reasons and no selected product; ambiguous requires two candidates', row['resolution_id'])

    for i, row in enumerate(data['documents']):
        p = ('documents', i)
        if row['document_id'] != 'document:' + row['sha256']:
            emit('document_content_id_mismatch', (*p, 'document_id'), 'Document ID must address its SHA-256 bytes', row['document_id'])
        if data['manifest']['build_options']['automatic_only'] and row['acquisition_method'] != 'automatic_https':
            emit('acquisition_filter_mismatch', (*p, 'acquisition_method'), 'automatic_only bundle cannot include imported input', row['document_id'])
        if data['manifest']['build_options']['public_bundle'] and row['redistribution'] != 'allowed' and row['snapshot_path'] is not None:
            emit('public_snapshot_not_allowed', (*p, 'snapshot_path'), 'Public bundle must omit bytes without redistribution permission', row['document_id'])
        if row['snapshot_path'] is None:
            if row['snapshot_omission'] is None:
                emit('snapshot_omission_required', (*p, 'snapshot_omission'), 'Missing public bytes require a reason and external requirement', row['document_id'])
        else:
            if not _portable_path(row['snapshot_path']):
                emit('unsafe_relative_path', (*p, 'snapshot_path'), 'Snapshot path must be portable and stay beneath bundle root', row['document_id'])
            if row['snapshot_omission'] is not None:
                emit('contradictory_snapshot_state', (*p, 'snapshot_omission'), 'Present snapshot cannot simultaneously be omitted', row['document_id'])
    for i, row in enumerate(data['evidence']):
        p = ('evidence', i)
        if row['evidence_id'] != evidence_id(row):
            emit('evidence_content_id_mismatch', (*p, 'evidence_id'), 'Evidence ID must include its document, locator and excerpt hash', row['evidence_id'])
        foreign(row['document_ref'], (*p, 'document_ref'), groups['documents'])
        excerpt = row['excerpt']
        if row['locator']['text_normalization'] == 'whitespace_collapse_v1':
            excerpt = ' '.join(excerpt.split())
        if hashlib.sha256(excerpt.encode('utf-8')).hexdigest() != row['excerpt_sha256']:
            emit('excerpt_hash_mismatch', (*p, 'excerpt_sha256'), 'Excerpt SHA-256 does not match declared normalization', row['evidence_id'])
        locator = row['locator']
        if locator['kind'] == 'pdf' and locator['page'] is None:
            emit('pdf_page_required', (*p, 'locator', 'page'), 'PDF evidence must locate a page', row['evidence_id'])
        if locator['kind'] == 'html' and locator['section'] is None and (locator['table'] is None or locator['row'] is None):
            emit('html_locator_required', (*p, 'locator'), 'HTML evidence needs a section or a table and row', row['evidence_id'])

    for i, route in enumerate(data['routes']):
        p = ('routes', i)
        if route['route_id'] != route_id(route):
            emit('route_content_id_mismatch', (*p, 'route_id'), 'Route ID must include its actors, ordered hops, conditions and evidence', route['route_id'])
        foreign(route['subject_ref'], (*p, 'subject_ref'), groups['products'])
        evidence_refs(route, p, required=True)
        route_evidence = set(route['evidence_refs'])
        for j, step in enumerate(route['steps']):
            sp = (*p, 'steps', j)
            foreign(step['actor_ref'], (*sp, 'actor_ref'), groups['products'])
            foreign(step['parser_ref'], (*sp, 'parser_ref'), groups['products'], nullable=True)
            parser = groups['products'].get(step['parser_ref'])
            if parser and not set(parser['class_ids']) & {'parser', 'normalizer'}:
                emit('not_a_parser_product', (*sp, 'parser_ref'), 'Parser reference must identify a parser or normalizer entity', route['route_id'])
            evidence_refs(step, sp, required=True)
            if not set(step['evidence_refs']).issubset(route_evidence):
                emit('route_step_evidence_missing_from_route', (*sp, 'evidence_refs'),
                     'The route must reference the evidence for each step', route['route_id'])
            if step['operation'] == 'normalize' and step['parser_ref'] is None:
                emit('normalizer_reference_required', (*sp, 'parser_ref'), 'Normalization step requires the named parser entity', route['route_id'])
        if not any(step['actor_ref'] == route['subject_ref'] for step in route['steps']):
            emit('route_subject_missing', (*p, 'steps'), 'Route must include its source product', route['route_id'])
    for i, claim in enumerate(data['claims']):
        p = ('claims', i)
        siem(claim['siem_product_ref'], (*p, 'siem_product_ref'))
        foreign(claim['subject_resolution_ref'], (*p, 'subject_resolution_ref'), groups['resolutions'])
        evidence_refs(claim, p, required=claim['assertion'] != 'unknown')
        if claim['claim_id'] != claim_id(claim):
            emit('claim_content_id_mismatch', (*p, 'claim_id'), 'Claim ID must include its scope, route and evidence references', claim['claim_id'])
        resolution = groups['resolutions'].get(claim['subject_resolution_ref'])
        if claim['assertion'] != 'unknown' and resolution:
            product = groups['products'].get(resolution['product_ref'])
            if resolution['status'] != 'resolved' or not product:
                emit('claim_subject_unresolved', (*p, 'subject_resolution_ref'),
                     'Published support must name a resolved product or family; family propagation remains a consumer policy',
                     claim['claim_id'])
        if claim['assertion'] == 'supported' and not claim['route_refs']:
            emit('supported_route_required', (*p, 'route_refs'), 'Support requires a documented capability route', claim['claim_id'])
        for j, ref in enumerate(claim['route_refs']):
            foreign(ref, (*p, 'route_refs', j), groups['routes'])
            route = groups['routes'].get(ref)
            if route is None:
                continue
            if resolution and resolution['product_ref'] and route['subject_ref'] != resolution['product_ref']:
                emit('route_subject_conflict', (*p, 'route_refs', j), 'Route proves a different source product', claim['claim_id'])
            actor_steps = [step for step in route['steps'] if (
                step['actor_ref'] != claim['siem_product_ref'] if claim['capability'] == 'export'
                else step['actor_ref'] == claim['siem_product_ref'])]
            if claim['assertion'] == 'supported' and not any(step['operation'] == claim['capability'] for step in actor_steps):
                emit('route_capability_not_proven', (*p, 'route_refs', j), 'Capability must be proved at its source/intermediary for export or at the declared SIEM for other operations', claim['claim_id'])

    # Quantity positivity, dimensional restrictions, and bounds are invariants;
    # no conversions, sizing inference or applicability evaluation happens here.
    memory_units = {'B', 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'}

    def check_resource(quantity, path, property_name):
        if not all(key in quantity for key in ('value', 'unit', 'basis', 'raw')):
            emit('invalid_resource_value', path, 'Resource property requires a typed Quantity')
            return
        number = quantity['value']
        numbers = [number] if not isinstance(number, dict) else [number['lower'], number['upper']]
        if property_name != 'eps' and any(n is not None and n <= 0 for n in numbers):
            emit('non_positive_resource', (*path, 'value'), 'Known resource requirements must be positive')
        allowed = None
        if property_name == 'cpu':
            allowed = {'physical_cores', 'vCPU', 'logical_threads', 'cores_unspecified'}
            if any(n is not None and n != int(n) for n in numbers):
                emit('non_integral_cpu', (*path, 'value'), 'Core/thread requirements must be integral')
        elif property_name in ('ram', 'per_device_capacity', 'total_capacity', 'storage'):
            allowed = memory_units
        elif property_name == 'network':
            allowed = {'Mbit/s', 'Gbit/s'}
        elif property_name == 'eps':
            allowed = {'EPS'}
        if allowed and quantity['unit'] not in allowed:
            emit('invalid_resource_unit', (*path, 'unit'), f'Unit is incompatible with {property_name}')

    def check_comparator(operator, typed, path):
        if operator == 'in' and typed.get('type') != 'set':
            emit('invalid_comparator_value', path, 'in requires a typed set')
        if operator == 'range' and not ((isinstance(typed.get('value'), dict) and typed['value'].get('kind') == 'interval') or
                                        ('scheme' in typed and typed['kind'] in ('range', 'open'))):
            emit('invalid_comparator_value', path, 'range requires a quantity interval or version range/open scope')
        if operator in ('gte', 'lte') and not ('unit' in typed or 'scheme' in typed):
            emit('invalid_comparator_value', path, 'Ordered comparison requires quantity or version scope')

    for path, value in _walk(data):
        if not isinstance(value, dict):
            continue
        if set(('value', 'unit', 'basis', 'raw')) <= value.keys():
            number = value['value']
            if isinstance(number, dict):
                low, high = number['lower'], number['upper']
                if low is None and high is None:
                    emit('empty_numeric_interval', (*path, 'value'), 'Unknown quantity uses null, not an unbounded empty interval')
                if low is not None and high is not None and low > high:
                    emit('inverted_numeric_bounds', (*path, 'value'), 'Lower bound exceeds upper bound')
                if low == high and low is not None and (number['bounds']['lower_inclusive'] is False or number['bounds']['upper_inclusive'] is False):
                    emit('empty_numeric_interval', (*path, 'value'), 'Equal endpoints cannot have an explicitly open bound')
            if path and path[-1] in ('cpu', 'ram', 'network', 'per_device_capacity', 'total_capacity'):
                check_resource(value, path, path[-1])
            if path and path[-1] == 'eps':
                check_resource(value, path, 'eps')
        if set(('operator', 'operands')) <= value.keys():
            op, operands = value['operator'], value['operands']
            if isinstance(operands, dict):
                subject(operands['subject_ref'], (*path, 'operands', 'subject_ref'))
                typed = operands['value']
                check_comparator(op, typed, (*path, 'operands', 'value'))
            elif op == 'all_of' and not operands:
                owners = [data]
                current = data
                for part in path:
                    current = current[part]
                    if isinstance(current, dict):
                        owners.append(current)
                if not any(owner.get('evidence_refs') for owner in owners):
                    emit('unconditional_evidence_required', path, 'Empty all_of requires evidence of unconditional applicability')
        if 'evidence_refs' in value:
            evidence_refs(value, path)
        for key in ('os_constraints', 'dependency_constraints'):
            if key in value and value[key] is not None:
                expected = 'any_of' if key == 'os_constraints' else 'all_of'
                if value[key]['operator'] not in (expected, 'eq', 'in', 'gte', 'lte', 'range'):
                    emit('invalid_requirement_group', (*path, key), f'{key} groups must use {expected}')

    for i, profile in enumerate(data['profiles']):
        p = ('profiles', i)
        siem(profile['siem_product_ref'], (*p, 'siem_product_ref'))
        evidence_refs(profile, p, required=True)
        for j, node in enumerate(profile['nodes']):
            evidence_refs(node, (*p, 'nodes', j), required=True)
            for k, storage in enumerate(node['storage_groups']):
                evidence_refs(storage, (*p, 'nodes', j, 'storage_groups', k), required=True)
            for k, ref in enumerate(node['placement']['co_location_refs']):
                foreign(ref, (*p, 'nodes', j, 'placement', 'co_location_refs', k), node_ids)
                if ref in node_owners and node_owners[ref] != profile['siem_product_ref']:
                    emit('node_owner_conflict', (*p, 'nodes', j, 'placement', 'co_location_refs', k), 'Co-location cannot borrow a node from a different SIEM', ref)
    for i, row in enumerate(data['requirements']):
        p = ('requirements', i)
        siem(row['siem_product_ref'], (*p, 'siem_product_ref'))
        subject(row['subject_ref'], (*p, 'subject_ref'))
        check_comparator(row['operator'], row['typed_value'], (*p, 'typed_value'))
        if row['property'] in ('cpu', 'ram', 'network', 'storage', 'eps'):
            check_resource(row['typed_value'], (*p, 'typed_value'), row['property'])
        if row['subject_ref'] in node_owners and node_owners[row['subject_ref']] != row['siem_product_ref']:
            emit('node_owner_conflict', (*p, 'subject_ref'), 'Requirement references a node of a different SIEM', row['subject_ref'])
        evidence_refs(row, p, required=True)

    diagnostic_targets = {row['target_ref'] for row in data['diagnostics']}
    for i, diagnostic in enumerate(data['diagnostics']):
        foreign(diagnostic['target_ref'], ('diagnostics', i, 'target_ref'))
    for collection in ('claims', 'resolutions', 'documents'):
        key = collections[collection][0]
        for i, row in enumerate(data[collection]):
            unknown = ((collection == 'claims' and row['assertion'] == 'unknown') or
                       (collection == 'resolutions' and row['status'] != 'resolved') or
                       (collection == 'documents' and row['snapshot_path'] is None))
            if unknown and row[key] not in diagnostic_targets:
                emit('unknown_requires_diagnostic', (collection, i), 'Unknown or omitted data needs an explicit diagnostic', row[key])

    registry = data['extension_registry']
    entries = {}
    for i, entry in enumerate(registry['entries']):
        if entry['key'] in entries:
            emit('duplicate_extension_key', ('extension_registry', 'entries', i), 'Extension registry keys must be unique')
        entries[entry['key']] = entry
        if entry['type'] == 'enum' and not entry['allowed_values']:
            emit('extension_enum_values_required', ('extension_registry', 'entries', i, 'allowed_values'), 'Registered enums require an explicit finite set')
        if entry['type'] != 'enum' and entry['allowed_values']:
            emit('extension_enum_values_unexpected', ('extension_registry', 'entries', i, 'allowed_values'), 'Only enum extensions declare allowed_values')
        if entry['type'] != 'quantity' and entry['unit'] is not None:
            emit('extension_unit_unexpected', ('extension_registry', 'entries', i, 'unit'), 'Only quantity extensions declare units')
    for path, row in _walk(data):
        if not isinstance(row, dict) or 'extensions' not in row:
            continue
        seen = set()
        for i, extension in enumerate(row['extensions']):
            ep = (*path, 'extensions', i)
            key = extension['key']
            if key in seen:
                emit('duplicate_extension_key', ep, 'An entity cannot repeat an extension key')
            seen.add(key)
            declaration = entries.get(key)
            if declaration is None:
                emit('unregistered_extension', ep, 'Display only: unregistered extension cannot affect admission', severity=Severity.WARNING)
                continue
            if extension['type'] != declaration['type'] or extension['unit'] != declaration['unit']:
                emit('extension_type_mismatch', ep, 'Extension value contradicts the registry type/unit')
            if declaration['type'] == 'enum' and extension['value'] not in declaration['allowed_values']:
                emit('extension_enum_mismatch', (*ep, 'value'), 'Value is outside the registered enumeration')
            if extension['type'] == 'quantity' and extension['unit'] != extension['value']['unit']:
                emit('extension_unit_mismatch', (*ep, 'unit'), 'Extension and quantity units must agree')

    approved = {}
    for i, review in enumerate(data['reviews']):
        p = ('reviews', i)
        evidence_refs(review, p, required=True)
        target = records.get(review['target_ref'])
        if target is None:
            emit('stale_review', (*p, 'target_ref'), 'Historical target is absent; review is preserved without granting current review state', review['target_ref'], Severity.WARNING)
            continue
        if review['target_digest'] != review_target_digest(target[0]):
            emit('stale_review', (*p, 'target_digest'), 'Target changed; historical review is preserved but cannot grant review state', review['target_ref'], Severity.WARNING)
        elif review['decision'] == 'approved':
            approved.setdefault(review['target_ref'], []).append(review)
    for ident, (row, path) in records.items():
        state = row.get('review_state')
        decisions = approved.get(ident, [])
        if state in ('reviewed', 'experiment_verified') and not decisions:
            emit('review_decision_required', (*path, 'review_state'), 'Review state requires an approved decision for the current content digest', ident)
        if state == 'experiment_verified' and not any(
                review['experiment_protocol'] and review['experiment_protocol']['evidence_refs'] for review in decisions):
            emit('experiment_protocol_required', (*path, 'review_state'), 'Experiment verification requires a separately evidenced protocol with scope', ident)

    manifest = data['manifest']
    if set(manifest['input_document_ids']) != set(groups['documents']):
        emit('manifest_document_set_mismatch', ('manifest', 'input_document_ids'), 'Manifest must enumerate every and only input document')
    payload_paths = set()
    for parent, values in ((('manifest', 'payloads'), manifest['payloads']),
                           (('build', 'input_manifests'), data['build']['input_manifests'])):
        for i, payload in enumerate(values):
            path = payload['path']
            if not _portable_path(path):
                emit('unsafe_relative_path', (*parent, i, 'path'), 'Payload path must be portable and stay beneath bundle root')
            if parent[0] == 'manifest':
                if path.casefold() in payload_paths:
                    emit('duplicate_payload_path', (*parent, i, 'path'), 'Payload names must be unique on case-insensitive systems')
                payload_paths.add(path.casefold())
    if manifest['content_digest'] != bundle_content_digest(data):
        emit('bundle_digest_mismatch', ('manifest', 'content_digest'), 'Semantic content digest does not match bundle')
    has_facts = bool(data['claims'] or data['profiles'] or data['requirements'])
    if not has_facts and (data['status'] != 'no_data' or not any(
            d['code'] == 'no_data' and d['target_ref'] == dataset_ref for d in data['diagnostics'])):
        emit('empty_dataset_requires_no_data', ('status',), 'Empty output requires no_data and a dataset-level diagnostic', dataset_ref)
    if has_facts and data['status'] == 'no_data':
        emit('contradictory_dataset_status', ('status',), 'no_data cannot contain extracted support or requirement facts', dataset_ref)
    return ValidationResult(tuple(sorted(issues, key=lambda issue: (issue.location, issue.code, issue.message))))
