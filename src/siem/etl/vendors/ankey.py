"""Conservative extraction of Ankey's low-load deployment on the product page."""
from __future__ import annotations

import re
from bs4 import BeautifulSoup
from ..common import clean, document_evidence, document_nullable


def _parse_ankey_low_load(html: str, meta: dict) -> tuple[list[dict], list[dict]]:
    soup = BeautifulSoup(html, 'html.parser')
    pane = soup.select_one('#kharakteristiki')
    if pane is None:
        return [], []
    parts = pane.find_all('p', recursive=False)
    for index, p in enumerate(parts):
        heading = clean(p.get_text(' ', strip=True))
        if heading != 'Низконагруженная система' or index + 2 >= len(parts):
            continue
        description = clean(parts[index + 1].get_text(' ', strip=True))
        statement = clean(parts[index + 2].get_text(' ', strip=True))
        if 'на одной аппратной платформе или в виртуальной машине' not in description:
            continue
        cpu = re.search(r'Процессор:\s*(\d+) процессора.*?не менее\s*([\d,]+) ГГц.*?не менее\s*(\d+) логических ядер', statement)
        ram = re.search(r'Оперативная память:\s*(\d+) ГБ', statement)
        disk = re.search(r'не менее\s*([\d\s]+) ГБ эффективного объема дискового пространства в RAID-массиве', statement)
        if not all((cpu, ram, disk)):
            return [], []
        common = {'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
                  'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
                  'review_status': 'extracted_unverified'}
        excerpt = ' | '.join((cpu.group(0), ram.group(0), disk.group(0)))
        profile = {**common, 'scenario': 'low_load', 'edition': None,
                   'component': 'all-in-one_installation', 'eps_from': None, 'eps_to': None,
                   'eps_bounds_inclusive': None, 'sizing_scope': 'low_load_without_eps_bound',
                   'applicability': {'deployment': 'single_physical_or_virtual_server',
                                     'load_class': 'low_load', 'eps_sizing': False},
                   'nodes': [{'role': 'all-in-one', 'quantity': 1, 'vcpu': None,
                              'cpu_sockets': int(cpu.group(1)),
                              'cpu_frequency_ghz_min': float(cpu.group(2).replace(',', '.')),
                              'logical_cores_min': int(cpu.group(3)),
                              'ram_gb': float(ram.group(1)), 'disk_gb': None, 'disk_type': None,
                              'storage_devices': [{
                                  'purpose': 'os_and_software', 'quantity': None,
                                  'total_capacity': int(re.sub(r'\s+', '', disk.group(1))),
                                  'per_device_capacity': None, 'capacity_unit': 'GB',
                                  'capacity_kind': 'effective_required', 'media': 'HDD SAS or SSD',
                                  'raid': 'RAID array, level unspecified',
                                  'original_value': disk.group(0),
                              }]}],
                   'network_gbps': None,
                   'evidence': document_evidence(meta, excerpt, 'ankey_low_load_product_page',
                                                 'Низконагруженная система')}
        requirements = []
        for os_name, version in (('Astra Linux', '1.7.3'), ('Debian', '10')):
            if f'{os_name} {version}' not in statement:
                continue
            requirements.append({**common, 'category': 'operating_system',
                                 'component': os_name, 'property': 'supported_host_os_version',
                                 'operator': '=', 'value': version, 'unit': 'version',
                                 'strength': 'supported', 'scenario': 'low_load',
                                 'applies_to': 'ankey_all_in_one_host',
                                 'alternative_group': 'low_load_host_os',
                                 'evidence': document_evidence(meta, f'{os_name} {version}',
                                                               'ankey_low_load_os', 'Низконагруженная система')})
        return [profile], requirements
    return [], []


def _role(text: str) -> tuple[str, int, str]:
    first = text.split('Требования к вычислительным ресурсам:', 1)[0].strip(' .')
    if 'Agent' in first and ('трех серверов' in first or 'трёх серверов' in first):
        return 'agent', 3, 'minimum'
    if 'Ankey SIEM NG Server' in first and 'Events Storage' in first:
        return 'siem_server_and_events_storage', 1, 'exact'
    for marker, role in (
        ('Events Storage', 'events_storage'), ('Network Sensor', 'network_sensor'),
        ('Ankey SIEM NG Server', 'siem_server'), ('Core', 'core_and_management'),
    ):
        if marker in first:
            return role, 1, 'exact'
    return first, 1, 'exact'


def _storage_devices(text: str) -> list[dict]:
    devices = []
    for clause in re.split(r'(?=Для\s|Дополнительная\s+дисковая)', text, flags=re.I):
        # The role name may contain words such as "Events Storage".  Storage
        # purpose must be determined from the disk statement itself.
        statement = re.search(r'(?:Для\s+|Дополнительная\s+дисковая).*', clause, re.I)
        storage_text = statement.group(0) if statement else clause
        raid = re.search(r'RAID\s*(\d+)', clause, re.I)
        if not raid:
            continue
        per_device = re.search(r'(\d+)\s+диск\w*.*?не менее\s*([\d,]+)\s*(ТБ|ГБ)\s*кажд', clause, re.I)
        total = None if per_device else re.search(r'не менее\s*([\d,]+)\s*(ТБ|ГБ)', clause, re.I)
        if not per_device and not total:
            continue
        lowered = storage_text.casefold()
        purpose = ('expansion_shelf' if 'дополнительная дисковая' in lowered else
                   'event_storage' if 'хранен' in lowered or 'events storage' in lowered else
                   'pcap_storage' if 'pcap' in lowered else
                   'database' if 'бд' in lowered else 'os_and_software')
        match = per_device or total
        unit_raw = match.group(3 if per_device else 2).casefold()
        conditions = []
        if purpose == 'expansion_shelf':
            for trigger in re.finditer(r'(\d[\d\s]*)\s*eps\s*(?:необходимо\s+подключить\s*)?[-–—]?\s*(одну|две)\s+полк', storage_text, re.I):
                conditions.append({'metric': 'EPS', 'operator': '>=',
                                   'value': int(re.sub(r'\s+', '', trigger.group(1))), 'unit': 'EPS',
                                   'required_expansion_shelves': {'одну': 1, 'две': 2}[trigger.group(2).casefold()]})
        devices.append({
            'purpose': purpose,
            'quantity': int(per_device.group(1)) if per_device else None,
            'total_capacity': None if per_device else float(total.group(1).replace(',', '.')),
            'per_device_capacity': float(per_device.group(2).replace(',', '.')) if per_device else None,
            'capacity_unit': {'тб': 'TB', 'tb': 'TB', 'гб': 'GB', 'gb': 'GB'}[unit_raw],
            'capacity_kind': 'per_device_required' if per_device else 'total_required',
            'media': None, 'raid': f'RAID {raid.group(1)}',
            'activation_conditions': conditions,
            'original_value': clean(storage_text)[:350],
        })
    return devices


def _parse_distributed(pane, heading: str, scenario: str, meta: dict) -> tuple[dict | None, list[dict]]:
    marker = next((p for p in pane.find_all('p', recursive=False)
                   if clean(p.get_text(' ', strip=True)) == heading), None)
    if marker is None:
        return None, []
    description = marker.find_next_sibling('p')
    listing = description.find_next_sibling('ol') if description else None
    if description is None or listing is None:
        return None, []
    description_text = clean(description.get_text(' ', strip=True))
    declared = re.search(r'на\s+(\d+)\s+выделенн', description_text)
    nodes, requirements = [], []
    common = {'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
              'siem_version': None,
              'siem_version_hint': document_nullable(meta.get('product_version_hint')),
              'review_status': 'extracted_unverified'}
    for item in listing.find_all('li', recursive=False):
        text = clean(item.get_text(' ', strip=True))
        cpu = re.search(r'Процессор:\s*(\d+) процессора.*?частот\w*\s*([\d,]+)\s*ГГц;\s*(\d+) ядер', text)
        ram = re.search(r'Оперативная память:\s*(\d+)\s*ГБ', text)
        os_match = re.search(r'Среда установки:\s*операционная система\s*(.*?)\s*Процессор:', text)
        if not cpu or not ram:
            return None, []
        role, quantity, quantity_kind = _role(text)
        nodes.append({'role': role, 'quantity': quantity, 'quantity_kind': quantity_kind,
                      'vcpu': None, 'cpu_sockets': int(cpu.group(1)),
                      'cpu_frequency_ghz_min': float(cpu.group(2).replace(',', '.')),
                      'physical_cores_per_socket': int(cpu.group(3)),
                      'logical_cores_min': None, 'ram_gb': float(ram.group(1)),
                      'disk_gb': None, 'disk_type': None,
                      'storage_devices': _storage_devices(text)})
        if os_match:
            published_os = clean(os_match.group(1))
            requirements.append({**common, 'category': 'operating_system',
                                 'component': published_os, 'property': 'supported_host_os',
                                 'operator': '=', 'value': published_os, 'unit': 'published_name',
                                 'strength': 'supported', 'scenario': scenario,
                                 'applies_to': role, 'alternative_group': None,
                                 'evidence': document_evidence(meta, os_match.group(0),
                                                               'ankey_distributed_os', heading)})
    declared_count = int(declared.group(1)) if declared else None
    listed_count = sum(n['quantity'] for n in nodes)
    applicability = {'deployment': 'dedicated_servers', 'load_class': scenario,
                     'eps_sizing': False, 'published_server_count': declared_count,
                     'listed_node_count': listed_count}
    if declared_count != listed_count:
        applicability['diagnostic'] = 'published_server_count_conflicts_with_listed_roles'
    profile = {**common, 'scenario': scenario, 'edition': None,
               'component': 'distributed_installation', 'eps_from': None, 'eps_to': None,
               'eps_bounds_inclusive': None, 'sizing_scope': f'{scenario}_without_eps_bound',
               'applicability': applicability, 'nodes': nodes, 'network_gbps': None,
               'evidence': document_evidence(meta, description_text,
                                             'ankey_distributed_product_page', heading)}
    return profile, requirements


def parse_ankey_profiles(html: str, meta: dict) -> tuple[list[dict], list[dict]]:
    profiles, requirements = _parse_ankey_low_load(html, meta)
    soup = BeautifulSoup(html, 'html.parser')
    pane = soup.select_one('#kharakteristiki')
    if pane is None:
        return profiles, requirements
    for heading, scenario in (('Средненагруженная система', 'medium_load'),
                              ('Высоконагруженная система', 'high_load')):
        profile, rules = _parse_distributed(pane, heading, scenario, meta)
        if profile is not None:
            profiles.append(profile)
            requirements.extend(rules)
    return profiles, requirements


# Compatibility for external callers of the original adapter name.
parse_ankey_low_load = parse_ankey_profiles
