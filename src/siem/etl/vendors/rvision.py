"""R-Vision sizing context, CPU features and cluster requirements."""
from __future__ import annotations

import re
from bs4 import BeautifulSoup
from ..common import clean, document_evidence, document_nullable

def eps_bound_details(text: str) -> dict | None:
    t = clean(text).replace('\u200b', '').replace('\u00a0', '')
    if re.search(r'^до\s*\d+', t, re.I):
        return {'lower': None, 'upper': True}
    if re.search(r'^\d[\d\s]*\s*[-–—]\s*\d', t):
        return {'lower': None, 'upper': None}
    return None


def enrich_rvision_profiles(profiles: list[dict], html: str) -> list[dict]:
    soup = BeautifulSoup(html, 'html.parser')
    text = clean(soup.get_text(' ', strip=True))
    minimum_unstable = bool(re.search(r'при\s+установке\s+в\s+минимальной\s+конфигурации\s+возможны\s+задержки', text, re.I))
    roles_logical = bool(re.search(r'разделение\s+требований\s+к\s+worker\s*[-‑]?\s*узлам\s+на\s+роли', text, re.I))
    for p in profiles:
        snippet = p.get('evidence', {}).get('excerpt', '')
        band = snippet.split('|', 1)[0]
        p['eps_bounds_inclusive'] = eps_bound_details(band)
        if p.get('network_gbps') is not None:
            p['network_links'] = [{
                'scope': 'configuration_table_connection', 'min_gbps': p['network_gbps'],
                'strength': 'published_profile',
            }]
        else:
            p['network_links'] = []
        p['limits'] = {'max_eps': None, 'retention_max_months': None, 'high_availability': None}
        # No extrapolation of the nine published sizing bands to other loads.
        p['stability_warning'] = 'minimum_configuration_may_be_unstable' if p['scenario'] == 'minimum' and minimum_unstable else None
        p['worker_roles_logical'] = True if p['scenario'] == 'recommended' and len(p['nodes']) > 1 and roles_logical else None
    return profiles


def parse_rvision_context_requirements(html: str, meta: dict) -> list[dict]:
    """Only explicitly stated requirements scoped to the SIEM's Kubernetes nodes.

    These cannot be merged with the 1Gbps number from the sizing table.
    """
    soup = BeautifulSoup(html, 'html.parser')
    for elem in soup(['script', 'style', 'nav', 'aside', 'footer', 'header']):
        elem.decompose()
    results: list[dict] = []
    seen = set()

    def append(key: str, category: str, prop: str, val: Any, unit: str | None,
               scenario: str, applies_to: str, excerpt: str, operator: str = '>=') -> None:
        if key in seen:
            return
        seen.add(key)
        results.append({
            'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
            'siem_version': None, 'siem_version_hint': document_nullable(meta.get('product_version_hint')),
            'category': category, 'component': applies_to, 'property': prop,
            'operator': operator, 'value': val, 'unit': unit,
            'strength': 'mandatory', 'scenario': scenario, 'applies_to': applies_to,
            'review_status': 'extracted_unverified',
            'evidence': document_evidence(meta, excerpt, 'rvision_explicit_hardware_rule'),
        })

    for elem in soup.find_all(['p', 'li']):
        s = clean(elem.get_text(' ', strip=True))
        if len(s) < 15 or len(s) > 500:
            continue
        if 'распределенн' in s.lower() and 'между узлами' in s.lower() and re.search(r'не\s+менее\s+10\s*Гбит\s*/\s*с', s, re.I):
            append('inter_node_10_gbps', 'network', 'min_inter_node_bandwidth', 10.0, 'Gbps',
                   'distributed', 'kubernetes_cluster_inter_node', s)
        if re.search(r'поддержка\s+инструкций\s+AVX\s+и\s+AVX2', s, re.I):
            append('AVX_AVX2', 'hardware', 'required_cpu_instructions', ['AVX', 'AVX2'], None,
                   'kubernetes', 'kubernetes_cluster_nodes', s, 'contains_all')
        if 'тактовая частота' in s.lower() and '2,5' in s and '3,5' in s and 'Boost' in s:
            append('cpu_base_2_5', 'hardware', 'cpu_base_frequency_min', 2.5, 'GHz',
                   'kubernetes', 'kubernetes_cluster_nodes', s)
            append('cpu_boost_3_5', 'hardware', 'cpu_boost_frequency_min', 3.5, 'GHz',
                   'kubernetes', 'kubernetes_cluster_nodes', s)
    return results
