"""Conservative extraction of Ankey's low-load deployment on the product page."""
from __future__ import annotations

import re
from bs4 import BeautifulSoup
from ..common import clean, document_evidence, document_nullable


def parse_ankey_low_load(html: str, meta: dict) -> tuple[list[dict], list[dict]]:
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
