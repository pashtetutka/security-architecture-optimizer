"""Explicit integrator assumptions for a first-pass event-rate estimate.

These are scenario parameters, not vendor benchmarks or measured rates.
"""
from __future__ import annotations

from math import ceil

from .scenarios import validate_scenario

MODEL_VERSION = 'integrator-eps-assumptions/1.0'
# Low, working, stress EPS per logging instance. Replace with measurements.
RATE_ASSUMPTIONS = {
    'firewall': (5, 20, 70),
    'intrusion_detection': (0.5, 3, 15),
    'endpoint_security': (2, 8, 30),
    'mail': (2, 8, 30),
    'mail_security': (1, 5, 20),
    'physical_security': (0.2, 1, 6),
    'dlp': (2, 8, 35),
    'switch': (0.1, 0.5, 2),
    'dhcp': (0.5, 2, 8),
    'dns': (1, 4, 15),
    'backup': (0.2, 1, 5),
    'virtualization': (0.5, 2, 8),
    'hypervisor': (0.5, 2, 8),
    'business_application': (1, 4, 15),
    'host_security': (0.05, 0.2, 1),
    'database': (1, 4, 15),
    'directory': (2, 7, 25),
    'file_server': (0.5, 2, 10),
    'workstation': (0.1, 0.4, 1.5),
    'document_workflow': (1, 4, 15),
}


def estimate_integrator_eps(scenario: dict) -> dict:
    """Model channels separately and deduplicate identical streams on one asset."""
    validate_scenario(scenario)
    entries = []
    unresolved = []
    grouped = {}
    for index, source in enumerate(scenario['event_sources']):
        if source.get('counting_policy') == 'overlap_review':
            unresolved.append({'row': index + 1, 'source': source['manufacturer_model'],
                               'reason': 'Поток может совпадать с журналом другого сервиса на AD; не добавлен повторно'})
            continue
        quantity = source['quantity']
        if quantity is None:
            unresolved.append({'row': index + 1, 'source': source['manufacturer_model'],
                               'reason': 'Количество экземпляров неизвестно'})
            continue
        if source['eps_status'] == 'unknown':
            rates = RATE_ASSUMPTIONS.get(source['kind'])
            if rates is None:
                unresolved.append({'row': index + 1, 'source': source['manufacturer_model'],
                                   'reason': 'Нет инженерного диапазона для типа источника'})
                continue
            origin = MODEL_VERSION
        else:
            rates = (source['eps_per_unit_avg'], source['eps_per_unit_avg'], source['eps_per_unit_peak'])
            origin = source['eps_status']
        values = [round(quantity * rate, 3) for rate in rates]
        entry = {'row': index + 1, 'source': source['manufacturer_model'],
                 'asset_group_id': source.get('asset_group_id'),
                 'log_stream': source.get('log_stream'),
                 'quantity': quantity, 'rates_per_instance': list(rates),
                 'low_eps': values[0], 'working_eps': values[1], 'stress_eps': values[2],
                 'basis': origin, 'counted': True}
        key = (source.get('asset_group_id') or f'row:{index}',
               source.get('log_stream') or f'row:{index}')
        if key in grouped:
            previous = grouped[key]
            # Identical event channels on one declared asset are not additive.
            for field in ('low_eps', 'working_eps', 'stress_eps'):
                previous[field] = max(previous[field], entry[field])
            entry['counted'] = False
            entry['duplicate_of_row'] = previous['row']
        else:
            grouped[key] = entry
        entries.append(entry)
    totals = {field: round(sum(item[field] for item in grouped.values()), 2)
              for field in ('low_eps', 'working_eps', 'stress_eps')}
    planning = ceil(totals['stress_eps'] * 1.25 / 10) * 10 if grouped else None
    return {'model_version': MODEL_VERSION, 'rates_unit': 'events/second per instance',
            'totals': totals, 'planning_eps_with_25pct_reserve': planning,
            'rows': entries, 'unresolved': unresolved,
            'assumptions': [
                'Диапазоны ставок заданы интегратором для сценарного расчёта; это не замеры и не нормы вендоров.',
                '25% резерва прибавлено к стресс-сценарию; число не является гарантированным верхним пределом.',
                'Роли DHCP, DNS и AD на одном сервере — разные журналы; одинаковый канал одного устройства учитывается один раз.',
                'Одна строка развёртывания EDR/AV не означает одного агента; телеметрия защищаемых узлов требует отдельного замера.',
            ]}
