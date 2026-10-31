"""Explicit deployment guidance from R-Vision and KOMRAD architecture pages."""
from __future__ import annotations

from bs4 import BeautifulSoup
from ..common import clean, document_evidence, document_nullable


def parse_rvision_deployment(html: str, meta: dict) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    rules = []
    for table in soup.select('table'):
        statement = clean(table.get_text(' ', strip=True))
        if 'ClickHouse' in statement and 'выделенном кластере' in statement:
            rules.append(_rule(meta, 'ClickHouse', 'recommended_dedicated_cluster', True,
                               'boolean', 'recommended', statement, 'rvision_deployment_clickhouse'))
        elif 'PostgreSQL' in statement and 'выделенном сервере' in statement:
            rules.append(_rule(meta, 'PostgreSQL', 'recommended_dedicated_server_or_cluster', True,
                               'boolean', 'recommended', statement, 'rvision_deployment_postgresql'))
    return rules


def parse_komrad_architecture(html: str, meta: dict) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    article = soup.select_one('article') or soup
    statement = clean(article.get_text(' ', strip=True))
    rules = []
    for component, service in (('PostgreSQL', 'postgresql.service'),
                               ('ClickHouse', 'clickhouse-server.service')):
        excerpt = f'СУБД {component} {service}'
        if excerpt in statement:
            rules.append(_rule(meta, component, 'listed_external_database', True,
                               'boolean', 'listed', excerpt, 'komrad_architecture_external_database'))
    return rules


def _rule(meta: dict, component: str, prop: str, value: object, unit: str,
          strength: str, excerpt: str, method: str) -> dict:
    return {'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
            'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
            'category': 'software_dependency', 'component': component,
            'property': prop, 'operator': '=', 'value': value, 'unit': unit,
            'strength': strength, 'scenario': 'distributed_deployment',
            'applies_to': 'platform_components', 'review_status': 'extracted_unverified',
            'evidence': document_evidence(meta, excerpt, method)}
