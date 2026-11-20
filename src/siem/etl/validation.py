"""Small, dependency-free validation of the normalized ETL contract."""
from __future__ import annotations
import math

from .identities import identity_name, published_product_keys, source_entity_id
from .source_classes import SOURCE_CLASSES


def validate_catalog(catalog: dict) -> dict:
    """Return explicit errors; never silently coerce normalized values."""
    errors: list[dict] = []

    def error(location: str, reason: str) -> None:
        errors.append({'location': location, 'reason': reason})

    def positive(value):
        return type(value) in (int, float) and math.isfinite(value) and value > 0

    for index, row in enumerate(catalog.get('integrations', [])):
        location = f'integrations[{index}]'
        basis = identity_name(row) if row.get('source_name') else None
        if not row.get('source_name_raw') or not row.get('source_identity_name_raw'):
            error(location, 'missing_raw_source_identity')
        if row.get('source_identity_basis') not in ('source_name', 'source_variant'):
            error(location, 'invalid_source_identity_basis')
        if not basis or row.get('source_entity_id') != source_entity_id(basis):
            error(location, 'source_entity_id_mismatch')
        if row.get('source_match_keys') != published_product_keys(row):
            error(location, 'source_match_keys_mismatch')
        if row.get('source_version_kind') not in ('unknown', 'published_value', 'listed_values', 'range_or_open_ended'):
            error(location, 'invalid_source_version_kind')
        if row.get('support_scope') not in (None, 'supported', 'partial'):
            error(location, 'invalid_support_scope')
        if row.get('source_class_id') not in SOURCE_CLASSES:
            error(location, 'invalid_source_class')
        if not row.get('source_class_basis'):
            error(location, 'missing_source_class_basis')

    for profile_index, profile in enumerate(catalog.get('sizing_profiles', [])):
        for node_index, node in enumerate(profile.get('nodes', [])):
            node_location = f'sizing_profiles[{profile_index}].nodes[{node_index}]'
            alternatives = node.get('cpu_alternatives')
            if alternatives is not None:
                if not isinstance(alternatives, list) or not alternatives:
                    error(node_location, 'invalid_cpu_alternatives')
                else:
                    for alternative in alternatives:
                        if (not isinstance(alternative, dict) or
                            alternative.get('unit') not in ('vCPU', 'logical_threads', 'physical_cores', 'cores_unspecified') or
                            type(alternative.get('minimum')) is not int or alternative['minimum'] <= 0):
                            error(node_location, 'invalid_cpu_alternative')
                if node.get('vcpu') is not None or node.get('cpu_cores') is not None:
                    error(node_location, 'cpu_alternatives_collapsed_to_single_unit')
            if node.get('ram_mb') is not None:
                if not positive(node['ram_mb']):
                    error(node_location, 'invalid_ram_mb')
                if node.get('ram_gb') is not None:
                    error(node_location, 'ambiguous_ram_units')
            for disk_index, disk in enumerate(node.get('storage_devices') or []):
                location = f'sizing_profiles[{profile_index}].nodes[{node_index}].storage_devices[{disk_index}]'
                if disk.get('capacity_unit') not in ('GB', 'TB'):
                    error(location, 'invalid_capacity_unit')
                if disk.get('quantity') is not None and (type(disk['quantity']) is not int or disk['quantity'] < 1):
                    error(location, 'invalid_storage_quantity')
                for field in ('total_capacity', 'per_device_capacity'):
                    if disk.get(field) is not None and not positive(disk[field]):
                        error(location, 'invalid_'+field)
                # ``per_device`` is the established schema spelling used by
                # the table extractor; retain it for backward-compatible JSON.
                if disk.get('capacity_kind') not in ('total_required', 'per_device_required',
                                                     'per_device', 'effective_required'):
                    error(location, 'invalid_capacity_kind')
                for condition in disk.get('activation_conditions', []):
                    if (condition.get('metric') != 'EPS' or condition.get('operator') != '>=' or
                        type(condition.get('value')) is not int or condition['value'] <= 0):
                        error(location, 'invalid_storage_activation_condition')

    return {'schema_version': 'focused-siem-etl-validation/1.0', 'valid': not errors,
            'errors': errors,
            'counts': {'integrations': len(catalog.get('integrations', [])),
                       'sizing_profiles': len(catalog.get('sizing_profiles', [])),
                       'errors': len(errors)}}
