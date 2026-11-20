"""Strict, ranking-free validation and EPS summary for organization inventories."""
from __future__ import annotations

import json
import math
from pathlib import Path

SCHEMA_VERSION = 'siem-decision-scenario/1.0'
REQUIRED_TOP_LEVEL = {'schema_version', 'scenario_id', 'name', 'synthetic',
                      'assumptions', 'event_sources', 'deployment', 'capacity',
                      'selection_constraints', 'organization_size', 'source_defaults'}
REQUIRED_SOURCE_FIELDS = {'raw_name', 'kind', 'asset_class', 'quantity',
                          'criticality', 'requirement', 'eps_status',
                          'eps_basis', 'source_type', 'manufacturer_model', 'version'}
ASSET_CLASSES = {'host', 'server', 'network', 'service', 'industrial'}
REQUIREMENTS = {'required', 'desired', 'unknown'}
EPS_STATUSES = {'estimated', 'measured', 'unknown'}


def _positive_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f'{field}: ожидается положительное число')
    return float(value)


def validate_scenario(scenario: dict) -> None:
    """Fail closed on an ambiguous scenario before any compatibility assessment."""
    missing = REQUIRED_TOP_LEVEL - set(scenario)
    if missing:
        raise ValueError('Отсутствуют обязательные поля: ' + ', '.join(sorted(missing)))
    if scenario['schema_version'] != SCHEMA_VERSION:
        raise ValueError('Неподдерживаемая версия схемы сценария')
    if type(scenario['synthetic']) is not bool:
        raise ValueError('synthetic: ожидается boolean')
    provenance = scenario.get('inventory_provenance')
    if provenance is not None and not isinstance(provenance, dict):
        raise ValueError('inventory_provenance: ожидается объект')
    if not isinstance(scenario['scenario_id'], str) or not scenario['scenario_id']:
        raise ValueError('scenario_id: ожидается непустая строка')
    size = scenario['organization_size']
    if not isinstance(size, dict) or size.get('class') not in ('small', 'medium', 'unknown'):
        raise ValueError('organization_size.class: ожидается small, medium или unknown')
    for field in ('employees', 'sites'):
        value = size.get(field)
        if value is None:
            continue
        if type(value) is not int or value < 1:
            raise ValueError(f'organization_size.{field}: ожидается положительное целое')
    if size['employees'] is not None and size['employees'] > 500:
        raise ValueError('organization_size.employees: сценарий выходит за пределы small/medium')
    if not isinstance(scenario['assumptions'], list) or not scenario['assumptions']:
        raise ValueError('assumptions: требуется хотя бы одно допущение')
    if not isinstance(scenario['event_sources'], list) or not scenario['event_sources']:
        raise ValueError('event_sources: требуется хотя бы один источник')
    if len(scenario['event_sources']) < 15:
        raise ValueError('event_sources: опросный лист должен содержать не менее 15 строк')
    for index, source in enumerate(scenario['event_sources']):
        if not isinstance(source, dict):
            raise ValueError(f'event_sources[{index}]: ожидается объект')
        absent = REQUIRED_SOURCE_FIELDS - set(source)
        if absent:
            raise ValueError(f'event_sources[{index}]: отсутствуют ' + ', '.join(sorted(absent)))
        for field in ('raw_name', 'kind', 'source_type', 'manufacturer_model'):
            if not isinstance(source[field], str) or not source[field].strip():
                raise ValueError(f'event_sources[{index}].{field}: ожидается непустая строка')
        if source['version'] is not None and not isinstance(source['version'], str):
            raise ValueError(f'event_sources[{index}].version: ожидается строка или null')
        if 'scope_review_required' in source and type(source['scope_review_required']) is not bool:
            raise ValueError(f'event_sources[{index}].scope_review_required: ожидается bool')
        products = source.get('products')
        if source.get('products_match', 'all') not in ('all', 'any'):
            raise ValueError(f'event_sources[{index}].products_match: ожидается all или any')
        if source.get('products_match') and products is None:
            raise ValueError(f'event_sources[{index}].products_match: нужен список products')
        if products is not None:
            if (not isinstance(products, list) or len(products) < 2 or any(
                    not isinstance(item, dict) or
                    not isinstance(item.get('name'), str) or not item['name'].strip() or
                    (item.get('version') is not None and not isinstance(item['version'], str))
                    for item in products)):
                raise ValueError(f'event_sources[{index}].products: ожидаются два или более продукта')
            if len({item['name'].casefold().strip() for item in products}) != len(products):
                raise ValueError(f'event_sources[{index}].products: повтор продукта')
        if source['asset_class'] not in ASSET_CLASSES:
            raise ValueError(f'event_sources[{index}].asset_class: неизвестный класс')
        if source['requirement'] not in REQUIREMENTS:
            raise ValueError(f'event_sources[{index}].requirement: неизвестная обязательность')
        if source['eps_status'] not in EPS_STATUSES:
            raise ValueError(f'event_sources[{index}].eps_status: неизвестный статус')
        for field in ('asset_group_id', 'log_stream'):
            if source.get(field) is not None and (not isinstance(source[field], str) or not source[field].strip()):
                raise ValueError(f'event_sources[{index}].{field}: ожидается непустая строка')
        if source.get('inventory_note') is not None and (
                not isinstance(source['inventory_note'], str) or not source['inventory_note'].strip()):
            raise ValueError(f'event_sources[{index}].inventory_note: ожидается непустая строка')
        if source.get('product_family') is not None and (
                not isinstance(source['product_family'], str) or not source['product_family'].strip()):
            raise ValueError(f'event_sources[{index}].product_family: ожидается непустая строка')
        if source.get('counting_policy') not in (None, 'overlap_review'):
            raise ValueError(f'event_sources[{index}].counting_policy: неизвестное правило')
        if source['quantity'] is None:
            if source['eps_status'] != 'unknown':
                raise ValueError(f'event_sources[{index}]: при неизвестном количестве EPS также неизвестен')
        elif type(source['quantity']) is not int or source['quantity'] < 1:
            raise ValueError(f'event_sources[{index}].quantity: ожидается положительное целое')
        criticality = source['criticality']
        if criticality is None:
            pass
        elif isinstance(criticality, bool) or not isinstance(criticality, int) or not 1 <= criticality <= 5:
            raise ValueError(f'event_sources[{index}].criticality: ожидается целое от 1 до 5')
        if not isinstance(source['eps_basis'], str) or not source['eps_basis'].strip():
            raise ValueError(f'event_sources[{index}].eps_basis: требуется основание оценки')
        has_rates = 'eps_per_unit_avg' in source or 'eps_per_unit_peak' in source
        if source['eps_status'] == 'unknown':
            if has_rates:
                raise ValueError(f'event_sources[{index}]: unknown EPS не может иметь численные ставки')
        else:
            if 'eps_per_unit_avg' not in source or 'eps_per_unit_peak' not in source:
                raise ValueError(f'event_sources[{index}]: требуются средняя и пиковая ставки EPS')
            average = _positive_number(source['eps_per_unit_avg'], f'event_sources[{index}].eps_per_unit_avg')
            peak = _positive_number(source['eps_per_unit_peak'], f'event_sources[{index}].eps_per_unit_peak')
            if peak < average:
                raise ValueError(f'event_sources[{index}]: peak EPS не может быть ниже average EPS')
    if not isinstance(scenario['deployment'], dict) or not isinstance(scenario['capacity'], dict):
        raise ValueError('deployment и capacity должны быть объектами')


def load_scenario(path: str | Path) -> dict:
    scenario = json.loads(Path(path).read_text(encoding='utf-8'))
    defaults = scenario.get('source_defaults')
    if not isinstance(defaults, dict):
        raise ValueError('source_defaults: ожидается объект с общими допущениями')
    scenario['event_sources'] = [{**defaults, **source} for source in scenario['event_sources']]
    validate_scenario(scenario)
    return scenario


def summarize_scenario(scenario: dict) -> dict:
    """Return an auditable lower-bound EPS total; unknown sources stay unknown."""
    validate_scenario(scenario)
    totals = {'average_eps': 0.0, 'peak_eps': 0.0}
    classes: dict[str, dict[str, float]] = {}
    grouped_assets: dict[tuple[str, str], float] = {}
    unknown = []
    for source in scenario['event_sources']:
        item = classes.setdefault(source['asset_class'], {'assets': 0.0, 'average_eps': 0.0,
                                                          'peak_eps': 0.0, 'known_rates': 0,
                                                          'unknown_rates': 0})
        if source['quantity'] is not None:
            group = source.get('asset_group_id')
            if group:
                key = (source['asset_class'], group)
                grouped_assets[key] = max(grouped_assets.get(key, 0), float(source['quantity']))
            else:
                item['assets'] += float(source['quantity'])
        if source['eps_status'] == 'unknown':
            item['unknown_rates'] += 1
            unknown.append({'raw_name': source['raw_name'], 'requirement': source['requirement'],
                            'eps_basis': source['eps_basis']})
            continue
        item['known_rates'] += 1
        average = float(source['quantity']) * float(source['eps_per_unit_avg'])
        peak = float(source['quantity']) * float(source['eps_per_unit_peak'])
        totals['average_eps'] += average
        totals['peak_eps'] += peak
        item['average_eps'] += average
        item['peak_eps'] += peak
    for (asset_class, _), quantity in grouped_assets.items():
        classes[asset_class]['assets'] += quantity
    dominant = max(classes, key=lambda key: classes[key]['assets']) if classes else None
    return {
        'schema_version': SCHEMA_VERSION,
        'scenario_id': scenario['scenario_id'],
        'name': scenario['name'],
        'synthetic': scenario['synthetic'],
        'inventory_provenance': scenario.get('inventory_provenance'),
        'organization_size': scenario['organization_size'],
        'known_eps_lower_bound': {key: round(value, 2) for key, value in totals.items()},
        'unknown_eps_sources': unknown,
        'asset_classes': {key: {
            'source_instances': round(value['assets'], 2),
            'known_average_eps_lower_bound': round(value['average_eps'], 2) if value['known_rates'] else None,
            'known_peak_eps_lower_bound': round(value['peak_eps'], 2) if value['known_rates'] else None,
            'unknown_eps_rows': value['unknown_rates'],
        } for key, value in sorted(classes.items())},
        'dominant_asset_class': dominant,
        'ranking_allowed': False,
        'next_step': 'Resolve source identities and compare only against a validated ETL catalog.',
    }
