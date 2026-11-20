"""Stable, conservative identities for published event-source names."""
from __future__ import annotations

from collections import defaultdict
import re

from .coverage import ALIAS, canonical


def identity_name(row: dict) -> str:
    """Only curated product aliases may discard a catalog family prefix."""
    variant = row.get('source_variant')
    if variant and canonical(variant) in set(ALIAS.values()):
        return variant
    return row['source_name']


def source_entity_id(name: str) -> str:
    """Return an identity key; retain the vendor spelling separately."""
    return 'source:' + canonical(name)


def published_product_keys(row: dict) -> list[str]:
    """Match explicit catalog products without promoting a vendor or a log type."""
    name = identity_name(row)
    keys = [canonical(name)]
    windows_server = re.fullmatch(r'(?:ms windows )?ms windows \d{4}(?: r2)? server',
                                  re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', ' ', name.casefold())).strip())
    if windows_server or re.fullmatch(r'microsoft windows server \d{4}(?: r2)?', canonical(name)):
        keys.append('microsoft windows server')
    version = row.get('source_version')
    if version and name.casefold().endswith(' ' + version.casefold()):
        base = name[:-(len(version) + 1)].strip()
        if base:
            keys.append(canonical(base))
    suffix = re.fullmatch(r'(.+?)\s+(\d+(?:[.,]\d+)*)', name)
    if suffix and version and re.fullmatch(r'\d+(?:\.\d+)*', version):
        embedded = suffix.group(2).replace(',', '.')
        if embedded == version or embedded.startswith(version + '.'):
            base = suffix.group(1)
            if len(canonical(base).split()) >= 2:
                keys.append(canonical(base))
    # A catalog cell can enumerate concrete products inside parentheses.
    # Only accept a comma-separated list whose entries explicitly start with
    # the published manufacturer, never descriptions of log formats.
    maker = canonical(row.get('source_vendor') or '')
    listed = re.search(r'\(([^()]*(?:,[^()]*)+)\)', name)
    if maker and listed:
        explicit_products = []
        for item in listed.group(1).split(','):
            candidate = canonical(item)
            if candidate.startswith(maker + ' '):
                explicit_products.append(candidate)
        if len(explicit_products) >= 2:
            keys.extend(explicit_products)
        base = canonical(name[:listed.start()].strip())
        if base != maker:
            keys.append(base)
    return list(dict.fromkeys(keys))


def source_vendor_entity_id(name: str | None) -> str | None:
    return None if not name else 'vendor:' + canonical(name)


def version_kind(value: str | None) -> str:
    if not value:
        return 'unknown'
    lowered = value.casefold()
    if any(token in lowered for token in ('—', '–', '-', 'выше', 'ниже', 'до ')):
        return 'range_or_open_ended'
    if ',' in value or ';' in value or ' и ' in lowered:
        return 'listed_values'
    return 'published_value'


def type_integrations(rows: list[dict]) -> list[dict]:
    for row in rows:
        row['source_name_raw'] = row['source_name']
        # A structured catalog variant is the product identity.  The display
        # name can include a broader family, such as "1C 8.3 <variant>".
        name = identity_name(row)
        row['source_identity_basis'] = ('source_variant' if name == row.get('source_variant')
                                        else 'source_name')
        row['source_entity_id'] = source_entity_id(name)
        row['source_identity_name_raw'] = name
        row['source_vendor_entity_id'] = source_vendor_entity_id(row.get('source_vendor'))
        row['source_version_raw'] = row.get('source_version')
        row['source_version_kind'] = version_kind(row.get('source_version'))
        row['source_match_keys'] = published_product_keys(row)
    return rows


def unique_source_values(rows: list[dict]) -> dict:
    """Auditable enumeration of values without collapsing support claims."""
    entities: dict[str, dict] = {}
    fields = ('source_name', 'source_vendor', 'source_version', 'collection_method',
              'normalizer_id', 'normalizer_format', 'support_scope', 'source_version_kind')
    values = {field: defaultdict(int) for field in fields}
    for row in rows:
        entity = entities.setdefault(row['source_entity_id'], {
            'source_entity_id': row['source_entity_id'], 'display_names': set(),
            'source_vendor_entity_ids': set(), 'siem_ids': set(), 'support_claims': 0,
        })
        entity['display_names'].add(row.get('source_identity_name_raw', row['source_name_raw']))
        if row.get('source_vendor_entity_id'):
            entity['source_vendor_entity_ids'].add(row['source_vendor_entity_id'])
        entity['siem_ids'].add(row['siem_id'])
        entity['support_claims'] += 1
        for field in fields:
            if row.get(field) is not None:
                values[field][str(row[field])] += 1
    return {
        'summary': {'support_claims': len(rows), 'source_entities': len(entities)},
        'entities': [{**item, 'display_names': sorted(item['display_names']),
                      'source_vendor_entity_ids': sorted(item['source_vendor_entity_ids']),
                      'siem_ids': sorted(item['siem_ids'])}
                     for _, item in sorted(entities.items())],
        'values': {field: [{'value': value, 'support_claims': count}
                           for value, count in sorted(group.items())]
                   for field, group in values.items()},
    }
