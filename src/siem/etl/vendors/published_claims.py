"""Narrow adapters for explicit claims on vendor overview and architecture pages."""
from __future__ import annotations

import re
from bs4 import BeautifulSoup

from ..common import clean, document_evidence, document_nullable


def _source(meta: dict, name: str, excerpt: str, method: str,
            collection_method: str | None = None, integration_evidence: str = 'published_connector',
            source_vendor: str | None = None) -> dict:
    return {
        'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
        'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
        'source_name': name, 'source_vendor': source_vendor, 'source_family': None,
        'source_variant': None, 'source_version': None,
        'collection_method': collection_method, 'normalizer_id': None,
        'normalizer_format': None, 'integration_evidence': integration_evidence,
        'functional_integration_verified': False, 'review_status': 'extracted_unverified',
        'evidence': [document_evidence(meta, excerpt, method)],
    }


def parse_searchinform_overview(html: str, meta: dict) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    rows = []
    named_sources = {
        'WinEventConnector': ('Windows event logs', None),
        'MSSQLConnector': ('Microsoft SQL', 'Microsoft'),
        'ExchangeConnector': ('Microsoft Exchange', 'Microsoft'),
        '1CConnector': ('1C', None),
        'Kaspersky Anti-Virus Connector': ('Kaspersky Anti-Virus', 'Kaspersky'),
        'VMwareConnector': ('Vmware', None),
        'FortigateConnector': ('Fortigate', None),
        'SIDLPConnector': ('СёрчИнформ КИБ', 'СёрчИнформ'),
        'LinuxConnector': ('Linux event logs', None),
        'RedCheckConnector': ('RedCheck', None),
    }
    for li in soup.select('li'):
        statement = clean(li.get_text(' ', strip=True))
        match = re.fullmatch(r'Контроллер\s+(.+?)\s*\(([^()]*(?:Connector))\)(?:\s+и другие)?', statement)
        if not match or match.group(2) not in named_sources:
            continue
        source_name, maker = named_sources[match.group(2)]
        rows.append(_source(meta, source_name, statement,
                            'searchinform_published_connector', match.group(2), source_vendor=maker))
    return rows


def parse_usergate_architecture(html: str, meta: dict) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    for p in soup.select('p'):
        statement = clean(p.get_text(' ', strip=True))
        if all(term in statement for term in ('сенсор UserGate', 'UserGate Client', 'сенсор WMI', 'сенсор SNMP')):
            return [
                _source(meta, 'UserGate firewall', statement, 'usergate_sensor_description',
                        'UserGate sensor', source_vendor='UserGate'),
                _source(meta, 'UserGate Client endpoint', statement, 'usergate_sensor_description',
                        'endpoint sensor', source_vendor='UserGate'),
                _source(meta, 'Windows computer', statement, 'usergate_sensor_description', 'WMI sensor'),
            ]
    return []


def parse_solar_architecture(html: str, meta: dict) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    names = {'Windows': 'Windows event logs', 'Linux': 'Linux event logs'}
    rows = []
    for name, source_name in names.items():
        for p in soup.select('li p'):
            statement = clean(p.get_text(' ', strip=True))
            if statement == f'Как настроить сбор событий с {name} в Solar SIEM':
                rows.append(_source(meta, source_name, statement, 'solar_published_collection_video',
                                    integration_evidence='published_collection_video'))
                break
    return rows


def parse_security_capsule_product(html: str, meta: dict) -> list[dict]:
    """Named collection claims only; exclude infrastructure compatibility lists."""
    soup = BeautifulSoup(html, 'html.parser')
    rows = []
    for p in soup.select('p'):
        text = clean(p.get_text(' ', strip=True))
        if 'SC SIEM принимает логи' in text and 'нативные коннекторы для Windows и Linux' in text:
            for name, vendor in [('Windows event logs', 'Microsoft'), ('Linux event logs', None)]:
                rows.append(_source(meta, name, text, 'security_capsule_native_connector',
                                    'native connector', source_vendor=vendor))
        sentence = 'Внедрение утилиты Sysmon и интеграция её событий в платформу Security Capsule SIEM.'
        if sentence in text:
            rows.append(_source(meta, 'Microsoft Sysmon', sentence,
                                'security_capsule_published_case',
                                integration_evidence='published_collection_case', source_vendor='Microsoft'))
    return rows


def parse_savrus_product(html: str, meta: dict) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    for div in soup.select('div'):
        statement = clean(div.get_text(' ', strip=True))
        match = re.search(r'Поддерживает работу на сертифицированноц ОС (Astra Linux Special Edition 1\.7)', statement)
        if not match or len(statement) > 500:
            continue
        return [{
            'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
            'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
            'category': 'operating_system', 'component': 'Astra Linux Special Edition',
            'property': 'supported_host_os_version', 'operator': '=', 'value': '1.7',
            'unit': 'version', 'strength': 'supported', 'scenario': 'server_installation',
            'applies_to': 'savrus_host', 'review_status': 'extracted_unverified',
            'evidence': document_evidence(meta, match.group(0), 'savrus_product_os'),
        }]
    return []


def parse_security_capsule_pdf(data: bytes, meta: dict) -> list[dict]:
    from io import BytesIO
    from pypdf import PdfReader

    for page_number, page in enumerate(PdfReader(BytesIO(data), strict=False).pages, start=1):
        statement = clean(page.extract_text() or '')
        match = re.search(r'Для малых объектов информатизации\s*\(до\s*(\d[\d\s]*)\s*EPS\)\s*возможно развертывание модулей SC SIEM в формате All\s*-\s*in\s*-\s*one', statement)
        if not match:
            continue
        evidence = document_evidence(meta, match.group(0), 'security_capsule_pdf_all_in_one')
        evidence['page'] = page_number
        return [{
            'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
            'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
            'category': 'capacity_condition', 'component': 'all-in-one_deployment',
            'property': 'documented_deployment_eps_range', 'operator': '<=',
            'value': int(re.sub(r'\s+', '', match.group(1))), 'unit': 'EPS',
            'strength': 'conditional', 'scenario': 'small_site_all_in_one',
            'applies_to': 'single_physical_or_virtual_server',
            'sizing_complete': False, 'reason': 'hardware_parameters_not_specified',
            'review_status': 'extracted_unverified', 'evidence': evidence,
        }]
    return []
