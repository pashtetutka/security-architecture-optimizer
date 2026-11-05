"""Structural QA; does not verify vendor claims."""
from __future__ import annotations

from collections import Counter

def sizing_quality_report(catalog: dict) -> dict:
    """Structural QA only. Does NOT validate vendor truth or completeness of all documents."""
    issues = []
    profiles = catalog.get('sizing_profiles', [])
    sources = catalog.get('integrations', [])
    requirements = catalog.get('system_requirements', [])

    def add(siem_id, code, severity, detail, idx=None):
        category = ('verification' if code == 'version_unverified' else
                    'extraction_error' if severity == 'error' or code.endswith('_incomplete')
                    or code == 'system_document_not_normalized' else 'data_gap')
        existing = next((row for row in issues if row['siem_id'] == siem_id
                         and row['code'] == code and row['detail'] == detail), None)
        if existing is not None:
            if idx is not None:
                existing.setdefault('profile_indices', [existing['profile_index']]).append(idx)
            return
        row = {'siem_id': siem_id, 'code': code, 'severity': severity,
               'category': category, 'detail': detail}
        if idx is not None:
            row['profile_index'] = idx
        issues.append(row)

    for i, p in enumerate(profiles):
        siem_id = p.get('siem_id')
        if p.get('siem_version') is None:
            add(siem_id, 'version_unverified', 'warning', 'Версия SIEM не подтверждена', i)
        if not p.get('nodes'):
            add(siem_id, 'no_nodes', 'error', 'Отсутствуют роли и ресурсы узлов', i)
        if p.get('eps_from') is None and p.get('eps_to') is None:
            add(siem_id, 'eps_scope_missing', 'warning', 'Не указан диапазон EPS', i)
        if p.get('network_gbps') is None and not p.get('network_links'):
            add(siem_id, 'network_unspecified', 'warning', 'Сеть не указана в профиле', i)
        if p.get('edition') == 'all-in-one' and siem_id == 'p04':
            limits = p.get('limits') or {}
            if limits.get('max_eps') is None or limits.get('retention_max_months') is None or limits.get('high_availability') is None:
                add(siem_id, 'all_in_one_limits_incomplete', 'warning', 'Не все ограничения режима все-в-одном извлечены', i)
            groups = {d.get('vendor_group') for n in p.get('nodes', []) for d in n.get('storage_devices', [])}
            if not {'HDD1', 'HDD2'} <= groups:
                add(siem_id, 'all_in_one_storage_incomplete', 'warning', 'Не найдены HDD1/HDD2', i)
        for node in p.get('nodes', []):
            if node.get('disk_gb') is None and not node.get('storage_devices'):
                add(siem_id, 'node_storage_unspecified', 'warning',
                    'Не указан объём хранения для роли ' + str(node.get('role')), i)
    for vendor in catalog.get('coverage', []):
        sid = vendor.get('siem_id')
        if vendor.get('no_normalized_data'):
            add(sid, 'no_normalized_data', 'info', 'Публичные данные не извлечены или пока нет адаптера')
        if vendor.get('integrations', 0) == 0:
            add(sid, 'integration_catalog_not_extracted', 'info', 'Интеграции не извлечены; отсутствие поддержки не доказано')
        if vendor.get('sizing_profiles', 0) == 0:
            add(sid, 'sizing_profiles_not_extracted', 'info', 'Профили sizing не извлечены; технические требования неизвестны')
    for missing in catalog.get('unparsed_system_documents', []):
        add(missing.get('siem_id'), 'system_document_not_normalized', 'warning',
            'Документ загружен, но не нормализован: ' + str(missing.get('source_id')))
    return {
        'schema_version': 'focused-siem-etl-quality/1.0',
        'source_run_at': catalog.get('source_run_at'),
        'totals': {
            'integrations': len(sources), 'sizing_profiles': len(profiles),
            'system_requirements': len(requirements),
            'issues': len(issues),
            'issues_by_severity': dict(Counter(x['severity'] for x in issues)),
            'issues_by_category': dict(Counter(x['category'] for x in issues)),
        },
        'issues': issues,
        'scope': 'Проверка структуры и очевидных пропусков; не верифицирует факты документации',
    }
