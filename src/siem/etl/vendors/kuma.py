"""Version-scoped KUMA EPS matrix; do not infer sizing for other components."""
from __future__ import annotations

import re
from bs4 import BeautifulSoup

from ..common import clean, document_evidence, document_nullable


def _node(cell, role: str) -> dict:
    text = clean(cell.get_text(' ', strip=True))
    cpu = re.search(r'От (\d+) потоков или vCPU', text)
    ram = re.search(r'От (\d+) ГБ оперативной памяти', text)
    disk = re.search(r'От (\d+) ГБ в каталоге (/\w+)', text)
    if not all((cpu, ram, disk)):
        raise ValueError('ambiguous_cells: missing KUMA CPU/RAM/directory capacity')
    counts = {'Одно': 1, 'Два': 2, 'Три': 3, 'Четыре': 4}
    quantity = next((number for word, number in counts.items()
                     if text.startswith(word + ' устройств')), None)
    if quantity is None and 'Установка на одном сервере' in text:
        quantity = 1
    if quantity is None:
        raise ValueError('ambiguous_cells: missing KUMA node count')
    media = 'HDD' if 'допустим HDD' in text else 'SSD'
    return {'role': role, 'quantity': quantity, 'vcpu': None,
            'cpu_alternatives': [{'unit': 'logical_threads', 'minimum': int(cpu.group(1))},
                                 {'unit': 'vCPU', 'minimum': int(cpu.group(1))}],
            'ram_gb': float(ram.group(1)), 'disk_gb': None, 'disk_type': media,
            'network_gbps': 0.1 if '100 Мбит/с' in text else None,
            'storage_devices': [{'purpose': 'installation_directory', 'mount_path': disk.group(2),
                                 'quantity': None, 'total_capacity': float(disk.group(1)),
                                 'per_device_capacity': None, 'capacity_unit': 'GB',
                                 'capacity_kind': 'total_required', 'media': media, 'raid': None,
                                 'conditional_media_alternative': (
                                     {'media': 'HDD SAS', 'rpm_min': 15000, 'raid': 'RAID 10',
                                      'condition': 'no_aggregation_queries_deeper_than_24_hours'}
                                     if '*' in text else None),
                                 'original_value': disk.group(0)}],
            'evidence_excerpt': text[:350]}


def parse_kuma_requirements(html: str, meta: dict) -> tuple[list[dict], list[dict]]:
    if meta.get('siem_id') != 'p12':
        return [], []
    soup = BeautifulSoup(html, 'html.parser')
    tables = [t for t in soup.find_all('table')
              if all(label in t.get_text(' ', strip=True)
                     for label in ('До 3000 EPS', 'До 10 000 EPS', 'Требования к Ядру KUMA'))]
    if len(tables) != 1:
        raise ValueError('ambiguous_cells: KUMA EPS matrix not found uniquely')
    table = tables[0]
    if table.find('table'):
        raise ValueError('nested_table')
    if table.select('[rowspan]'):
        raise ValueError('unsupported_rowspan')
    rows = [[c for c in tr.find_all(['td', 'th'], recursive=False)]
            for tr in table.find_all('tr')]
    rows = [row for row in rows if any(clean(c.get_text(' ', strip=True)) for c in row)]
    if len(rows) != 9 or any(len(row) != 5 for row in rows[:7]):
        raise ValueError('ambiguous_cells: KUMA matrix dimensions')
    headings = [clean(c.get_text(' ', strip=True)) for c in rows[0][1:]]
    if headings != ['До 3000 EPS', 'До 10 000 EPS', 'До 20 000 EPS', 'До 50 000 EPS']:
        raise ValueError('ambiguous_cells: KUMA EPS headers')
    roles = ['core', 'collector', 'correlator', 'keeper', 'storage']
    labels = ['Требования к Ядру KUMA', 'Требования к коллектору',
              'Требования к коррелятору', 'Требования к Киперу', 'Требования к хранилищу']
    if [clean(row[0].get_text(' ', strip=True)) for row in rows[2:7]] != labels:
        raise ValueError('ambiguous_cells: KUMA role labels')
    common = {'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
              'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
              'review_status': 'extracted_unverified'}
    profiles = []
    for column, eps in enumerate((3000, 10000, 20000, 50000), 1):
        configuration = clean(rows[1][column].get_text(' ', strip=True))
        nodes = ([_node(rows[1][column], 'all_in_one')] if column <= 2 else
                 [_node(row[column], role) for row, role in zip(rows[2:7], roles)])
        for node in nodes:
            node['evidence'] = document_evidence(meta, node.pop('evidence_excerpt'),
                                                 'kuma_eps_matrix_node', headings[column-1])
        profiles.append({**common, 'scenario': 'single_server' if column <= 2 else 'distributed_replicated',
                         'edition': None, 'component': 'KUMA', 'eps_from': None, 'eps_to': eps,
                         'eps_bounds_inclusive': {'lower': None, 'upper': True},
                         'sizing_scope': 'published_recommended_configuration',
                         'network_gbps': 0.1 if column <= 2 else None,
                         'network_links': ([] if column <= 2 else [{
                             'from_role': 'storage', 'to_role': 'storage', 'min_gbps': 10,
                             'strength': 'recommended', 'when_eps_gte': 20000}]),
                         'applicability': {
                             'deployment': 'single_server' if column <= 2 else 'dedicated_servers',
                             'configuration_strength': 'recommended',
                             'cpu_units': 'logical_threads_or_vcpu_alternatives',
                             'workload': 'ingestion_without_search_for_database_sizing',
                             'dashboards': 'vendor_supplied' if column <= 2 else None,
                             'storage_replicas_per_shard': 2 if column > 2 else None,
                             'storage_nodes_without_ha': (1 if eps == 20000 else 2) if column > 2 else None,
                             'event_retention_sizing': 'not_specified_by_500gb_installation_directory',
                             'additional_sections': 'metrics_connector_performance_optional_services_not_normalized'},
                         'nodes': nodes,
                         'evidence': document_evidence(meta, headings[column-1] + ' | ' + configuration,
                                                       'kuma_eps_matrix', 'Рекомендуемые требования к оборудованию')})
    os_row = rows[7]
    if len(os_row) != 2 or clean(os_row[0].get_text(' ', strip=True)) != 'Операционные системы':
        raise ValueError('ambiguous_cells: KUMA OS alternatives')
    requirements = []
    os_entries = os_row[1].find_all('li') or os_row[1].find_all('p')
    if not os_entries:
        raise ValueError('ambiguous_cells: KUMA OS list missing')
    for paragraph in os_entries:
        name = clean(paragraph.get_text(' ', strip=True)).rstrip('.')
        if not name:
            continue
        requirements.append({**common, 'category': 'operating_system', 'component': name,
                             'property': 'supported_host_os', 'operator': '=', 'value': name,
                             'unit': 'published_name', 'strength': 'supported',
                             'scenario': 'eps_matrix', 'applies_to': 'KUMA_hosts',
                             'alternative_group': 'kuma_host_os',
                             'evidence': document_evidence(meta, name, 'kuma_os_alternatives')})
    extra_profiles, extra_rules = _platform_and_agents(soup, meta, common)
    return profiles + extra_profiles, requirements + extra_rules


def _flat_matrix(soup, headers, labels):
    candidates = []
    for table in soup.find_all('table'):
        rows = [[clean(c.get_text(' ', strip=True)) for c in tr.find_all(['td', 'th'], recursive=False)]
                for tr in table.find_all('tr')]
        if rows and rows[0][1:] == headers:
            candidates.append((table, rows))
    if len(candidates) != 1:
        raise ValueError('ambiguous_cells: KUMA platform matrix not unique')
    table, rows = candidates[0]
    if table.find('table'):
        raise ValueError('nested_table')
    if table.select('[rowspan], [colspan]'):
        raise ValueError('unsupported_span: KUMA platform matrix')
    if len(rows) != len(labels)+1 or any(len(row) != len(headers)+1 for row in rows):
        raise ValueError('ambiguous_cells: KUMA platform matrix dimensions')
    if [row[0] for row in rows[1:]] != labels:
        raise ValueError('ambiguous_cells: KUMA platform row labels')
    return table, rows


def _platform_and_agents(soup, meta, common):
    """Keep platform minima and agent-host requirements separate from SIEM EPS."""
    profiles, requirements = [], []
    _, rows = _flat_matrix(soup, ['Балансировщик', 'Контроллер', 'Рабочий узел'],
                          ['Процессор', 'ОЗУ', 'Свободное дисковое пространство', 'Пропускная способность сети'])
    whole_text = clean(soup.get_text(' ', strip=True))
    if not all(value in whole_text for value in ('1 узел балансировщика', '3 узла-контроллера', '2 рабочих узла')):
        raise ValueError('ambiguous_cells: KUMA Kubernetes topology')
    nodes = []
    for column, (role, quantity) in enumerate((('load_balancer', 1), ('controller', 3), ('worker', 2)), 1):
        cpu = rows[1][column]
        expected = '12 потоков или 12 vCPU.' if role == 'worker' else '1 ядро с 2 потоками или 2 vCPU.'
        if cpu != expected:
            raise ValueError('ambiguous_cells: KUMA Kubernetes CPU alternatives')
        ram = re.fullmatch(r'От (\d+) ГБ', rows[2][column])
        if ram is None or rows[4][column] != '10 Гбит/с':
            raise ValueError('ambiguous_cells: KUMA Kubernetes memory/network')
        storage = []
        disk_text = rows[3][column]
        for disk in re.finditer(r'От (\d+) (ГБ|ТБ)(?: в директории (/[^\s]+))?', disk_text):
            storage.append({'purpose': 'directory_capacity' if disk.group(3) else 'system',
                            'mount_path': disk.group(3), 'quantity': None,
                            'total_capacity': int(disk.group(1)), 'per_device_capacity': None,
                            'capacity_unit': {'ГБ': 'GB', 'ТБ': 'TB'}[disk.group(2)],
                            'capacity_kind': 'total_required', 'media': None, 'raid': None,
                            'original_value': disk.group(0)})
        if len(storage) != (2 if role == 'worker' else 1):
            raise ValueError('ambiguous_cells: KUMA Kubernetes directories')
        alternatives = ([{'unit': 'logical_threads', 'minimum': 12}, {'unit': 'vCPU', 'minimum': 12}]
                        if role == 'worker' else [
                            {'unit': 'cores_unspecified', 'minimum': 1, 'logical_threads': 2},
                            {'unit': 'vCPU', 'minimum': 2}])
        nodes.append({'role': role, 'quantity': quantity, 'vcpu': None,
                      'cluster_member': role != 'load_balancer',
                      'cpu_alternatives': alternatives, 'ram_gb': int(ram.group(1)),
                      'disk_gb': None, 'storage_devices': storage, 'network_gbps': 10,
                      'evidence': document_evidence(meta, f'{role}: {cpu} | {ram.group(0)} | {disk_text}',
                                                    'kuma_kubernetes_matrix')})
    profiles.append({**common, 'scenario': 'kubernetes_high_availability', 'edition': None,
                     'component': 'KUMA_platform', 'eps_from': None, 'eps_to': None,
                     'eps_bounds_inclusive': None, 'sizing_scope': 'platform_minimum_without_eps',
                     'network_gbps': 10, 'applicability': {
                         'deployment': 'kubernetes', 'configuration_strength': 'minimum',
                         'eps_sizing': False, 'load_balancer_outside_cluster': True,
                         'event_storage_capacity': 'not_sized'}, 'nodes': nodes,
                     'evidence': document_evidence(meta, '1 узел балансировщика – не входит в кластер. '
                         '3 узла-контроллера. 2 рабочих узла.', 'kuma_kubernetes_matrix',
                         'Требования к устройствам для установки KUMA в Kubernetes')})
    table, rows = _flat_matrix(soup, ['Устройства с ОС Windows', 'Устройства с ОС Linux'],
                              ['Процессор', 'ОЗУ', 'Свободное дисковое пространство', 'Операционные системы'])
    os_cells = table.find_all('tr')[-1].find_all(['td', 'th'], recursive=False)
    for column, platform in enumerate(('windows', 'linux'), 1):
        if (rows[1][column] != 'Одноядерный, 1.4 ГГц или выше.' or
                rows[2][column] != '512 МБ' or rows[3][column] != '1 ГБ'):
            raise ValueError('ambiguous_cells: KUMA base agent resources')
        scenario = 'agent_host_' + platform
        profiles.append({**common, 'scenario': scenario, 'edition': None, 'component': 'KUMA_agent',
                         'eps_from': None, 'eps_to': None, 'eps_bounds_inclusive': None,
                         'sizing_scope': 'agent_host_minimum_without_eps', 'network_gbps': None,
                         'applicability': {'deployment': 'agent_on_source_host', 'eps_sizing': False,
                                           'platform': platform, 'configuration_strength': 'minimum',
                                           'connector_specific_sizing': 'separate_requirements'},
                         'nodes': [{'role': 'agent_host', 'quantity': None,
                                    'cpu_alternatives': [{'unit': 'cores_unspecified', 'minimum': 1}],
                                    'cpu_frequency_ghz_min': 1.4, 'vcpu': None,
                                    'ram_gb': None, 'ram_mb': 512, 'disk_gb': None,
                                    'storage_devices': [{'purpose': 'agent_installation', 'quantity': None,
                                        'total_capacity': 1, 'per_device_capacity': None, 'capacity_unit': 'GB',
                                        'capacity_kind': 'total_required', 'media': None, 'raid': None,
                                        'original_value': '1 ГБ'}]}],
                         'evidence': document_evidence(meta, ' | '.join(row[column] for row in rows[1:4]),
                             'kuma_agent_host_matrix', 'Требования к устройствам для установки агентов')})
        for item in os_cells[column].select('ul > li'):
            text = clean(item.get_text(' ', strip=True)).rstrip('.')
            os_name = text.split(' с установленной библиотекой ', 1)[0]
            if 'поддерживается ограниченно' in os_name:
                os_name = os_name.split('. Microsoft ', 1)[0]
            library = re.search(r'с установленной библиотекой (glibc) (\d+(?:\.\d+)+)\s*(\([^)]*\))?', text)
            prerequisites = ([{'component': library.group(1), 'operator': '=',
                                'version': library.group(2), 'published_package': library.group(3)}]
                             if library else [])
            requirements.append({**common, 'category': 'operating_system', 'component': os_name,
                'property': 'supported_agent_host_os', 'operator': '=', 'value': os_name,
                'unit': 'published_name', 'strength': 'supported', 'scenario': scenario,
                'applies_to': 'KUMA_agent_host', 'alternative_group': 'kuma_agent_os_'+platform,
                'support_scope': 'partial' if 'поддерживается ограниченно' in text else 'supported',
                'prerequisites': prerequisites,
                'evidence': document_evidence(meta, text, 'kuma_agent_os_alternatives')})
    return profiles, requirements
