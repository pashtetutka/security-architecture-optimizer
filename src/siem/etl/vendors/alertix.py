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
