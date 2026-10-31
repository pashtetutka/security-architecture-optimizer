"""Alertix all-in-one hardware and deployment conditions."""
from __future__ import annotations

import re
from bs4 import BeautifulSoup
from ..common import clean, document_evidence, document_nullable, table_rows
from ..storage import parse_storage_group, parse_network_gbps

def all_in_one_constraints(html: str) -> dict:
    soup = BeautifulSoup(html, 'html.parser')
    # The documented limits apply ONLY to the all-in-one installation.
    text = clean(soup.get_text(' ', strip=True))
    result = {'max_eps': None, 'retention_max_months': None, 'high_availability': None}
    if not re.search(r'все\s*[-–‑]?\s*в\s*[-–‑]?\s*одном', text, re.I):
        return result
    context_pattern = r'исполнени[ея]\s*[«"\']?\s*все\s*[-–‑]?\s*в\s*[-–‑]?\s*одном[»"\']?(.{0,400})'
    contexts = [m.group(1) for m in re.finditer(context_pattern, text, re.I)]
    context = next((s for s in contexts if re.search(r'не\s+более\s+\d+\s*EPS', s, re.I)),
                   (contexts[-1] if contexts else ''))
    eps = re.search(r'не\s+более\s+(\d[\d\s]*)\s*EPS\b', context, re.I)
    duration = re.search(r'не\s+более\s+(\d+)\s*месяц', context, re.I)
    if eps:
        result['max_eps'] = int(re.sub(r'\s+', '', eps.group(1)))
    if duration:
        result['retention_max_months'] = int(duration.group(1))
    if re.search(r'(?:неотказоустойчив|не\s+отказоустойчив)', context, re.I):
        result['high_availability'] = False
    return result


def parse_alertix_all_in_one(html: str, meta: dict) -> list[dict]:
    """Two tiers, distinct disk groups, network and all-in-one restrictions."""
    soup = BeautifulSoup(html, 'html.parser')
    if not re.search(r'все\s*[-–‑]?\s*в\s*[-–‑]?\s*одном', clean(soup.get_text(' ', strip=True)), re.I):
        return []
    constraints = all_in_one_constraints(html)
    for table in soup.select('table'):
        indexed: dict[str, list[str]] = {}
        for cells in table_rows(table):
            if len(cells) >= 3:
                indexed[cells[0].strip().casefold()] = cells[1:]
        cpu = indexed.get('vcpu')
        ram = indexed.get('ram')
        if not cpu or not ram or len(cpu) < 2 or len(ram) < 2:
            continue
        profiles = []
        for pos, scenario in enumerate(('minimum', 'recommended')):
            mc = re.fullmatch(r'\s*(\d+)\s*', cpu[pos])
            mr = re.match(r'\s*(\d+(?:[.,]\d+)?)\s*(?:Gb|Гб|GB)?\s*$', ram[pos], re.I)
            if not mc or not mr:
                continue
            storage = []
            for group in ('hdd1', 'hdd2', 'hdd3'):
                vals = indexed.get(group)
                if vals and len(vals) > pos:
                    dev = parse_storage_group(group, vals[pos])
                    if dev:
                        storage.append(dev)
            network_vals = indexed.get('net', [])
            network = parse_network_gbps(network_vals[pos]) if len(network_vals) > pos else None
            excerpt = ' | '.join(
                f'{label}: {values[pos]}' for label, values in indexed.items()
                if len(values) > pos and label in ('vcpu', 'ram', 'hdd1', 'hdd2', 'hdd3', 'net')
            )
            # A disk total cannot be calculated from raw disk quantities and RAID without
            # assumptions about usable capacity; keep per-device storage only.
            profiles.append({
                'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
                'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
                'scenario': scenario, 'edition': 'all-in-one',
                'component': 'primary_installation',
                'eps_from': None, 'eps_to': constraints['max_eps'],
                'eps_bounds_inclusive': {'lower': None, 'upper': True} if constraints['max_eps'] is not None else None,
                'nodes': [{
                    'role': 'all-in-one', 'quantity': 1, 'vcpu': int(mc.group(1)),
                    'ram_gb': float(mr.group(1).replace(',', '.')),
                    'disk_gb': None, 'disk_type': None,
                    'storage_devices': storage,
                }],
                'network_gbps': network,
                'network_links': ([{'scope': 'server_network', 'min_gbps': network, 'strength': scenario}]
                                  if network is not None else []),
                'limits': constraints.copy(),
                'review_status': 'extracted_unverified',
                'evidence': document_evidence(meta, excerpt, 'alertix_all_in_one_table', 'Таблица: все-в-одном'),
            })
        if profiles:
            return profiles
    return []


def parse_alertix_faq(html: str, meta: dict) -> tuple[list[dict], list[dict]]:
    """Extract only explicit collection and host OS claims from the saved FAQ."""
    soup = BeautifulSoup(html, 'html.parser')
    paragraphs = soup.select('p')
    sources, requirements = [], []
    for p in paragraphs:
        statement = clean(p.get_text(' ', strip=True))
        if ('WEC-коллектор' in statement and 'встроенный WEC-ресивер' in statement
                and 'событий' in statement):
            sources.append({
                'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
                'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
                'source_name': 'Windows event logs', 'source_vendor': None,
                'source_family': None, 'source_variant': None, 'source_version': None,
                'collection_method': 'WEC', 'normalizer_id': None, 'normalizer_format': None,
                'integration_evidence': 'published_collection_path',
                'functional_integration_verified': False, 'review_status': 'extracted_unverified',
                'evidence': [document_evidence(meta, statement, 'alertix_faq_wec', 'FAQ: сбор событий Windows')],
            })
        if statement == 'Серверную часть Alertix можно установить на ОС:':
            listing = p.find_next_sibling('ul')
            if listing is None:
                continue
            for item in listing.find_all('li', recursive=False):
                name = clean(item.get_text(' ', strip=True)).rstrip(';.')
                if name not in ('Ubuntu', 'Astra Linux SE', 'РЕД ОС'):
                    continue
                requirements.append({
                    'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
                    'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
                    'category': 'operating_system', 'component': name,
                    'property': 'supported_host_os', 'operator': '=', 'value': name,
                    'unit': 'operating_system', 'strength': 'supported',
                    'scenario': 'server_installation', 'applies_to': 'alertix_server',
                    'review_status': 'extracted_unverified',
                    'evidence': document_evidence(meta, statement + ' ' + clean(item.get_text(' ', strip=True)),
                                                  'alertix_faq_host_os', 'FAQ: серверная ОС'),
                })
    return sources, requirements


def parse_alertix_architecture(html: str, meta: dict) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    for p in soup.select('p'):
        statement = clean(p.get_text(' ', strip=True))
        match = re.search(r'при соблюдении аппаратных требований.{0,250}?до\s+(\d[\d\s]*)\s+событий в секунду,\s*измеряемую на усредненном недельном интервале', statement, re.I)
        if not match:
            continue
        return [{
            'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
            'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
            'category': 'capacity_condition', 'component': 'platform_deployment',
            'property': 'published_eps_capacity', 'operator': '<=',
            'value': int(re.sub(r'\s+', '', match.group(1))), 'unit': 'EPS',
            'strength': 'conditional', 'scenario': 'hardware_requirements_met',
            'applies_to': 'one_or_more_computing_units', 'averaging_interval': 'one_week',
            'sizing_complete': False, 'reason': 'full_hardware_requirements_in_separate_document',
            'review_status': 'extracted_unverified',
            'evidence': document_evidence(meta, statement, 'alertix_architecture_conditional_capacity',
                                          'Архитектура платформы'),
        }]
    return []


def parse_alertix_connectors(html: str, meta: dict, receiver: str) -> list[dict]:
    """Rows from the four published 3.9.1 receiver connector tables."""
    if receiver not in {'Syslog', 'Beats', 'JDBC', 'SNMP'}:
        return []
    soup = BeautifulSoup(html, 'html.parser')
    for table in soup.select('table'):
        rows = table_rows(table)
        if not rows or rows[0] != ['Источник', 'Производитель', 'Тип']:
            continue
        result = []
        for row in rows[1:]:
            if len(row) != 3 or not row[0] or not row[1]:
                continue
            name, maker, source_type = row
            result.append({
                'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
                'siem_version': None,
                'siem_version_hint': document_nullable(meta.get('product_version_hint')),
                'source_name': name, 'source_vendor': None if maker == 'Различные' else maker,
                'source_family': source_type or None, 'source_variant': None,
                'source_version': None, 'collection_method': receiver,
                'normalizer_id': None, 'normalizer_format': None,
                'integration_evidence': 'published_connector_table',
                'functional_integration_verified': False,
                'review_status': 'extracted_unverified',
                'evidence': [document_evidence(meta, ' | '.join(row),
                                               'alertix_connector_table',
                                               f'Перечень коннекторов {receiver} ресивера')],
            })
        return result
    return []
