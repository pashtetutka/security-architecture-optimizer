"""MaxPatrol SIEM source tables, retaining the published support scope."""
from __future__ import annotations

import re
import json
from bs4 import BeautifulSoup

from ..common import clean, document_evidence, document_nullable, table_rows
from .published_claims import _source


def maxpatrol_api_document(data: bytes) -> dict:
    doc = json.loads(data)
    if not isinstance(doc, dict) or doc.get('project') != 'siem' or doc.get('type') != 'help':
        raise ValueError('unexpected_maxpatrol_document_scope')
    if doc.get('title') != 'Поддерживаемые источники и профили для сбора событий' or not isinstance(doc.get('content'), str):
        raise ValueError('unexpected_maxpatrol_document_title_or_content')
    return doc


def parse_maxpatrol_supported_api(data: bytes, meta: dict) -> list[dict]:
    doc = maxpatrol_api_document(data)
    soup = BeautifulSoup(doc['content'], 'html.parser')
    tables = soup.select('table')
    if len(tables) != 1:
        raise ValueError('ambiguous_tables_or_nested_table')
    table = tables[0]
    if table.select('[rowspan], [colspan]'):
        raise ValueError('unsupported_rowspan_or_colspan')
    rows = table_rows(table)
    if not rows or [_visible(x).casefold() for x in rows[0]] != ['источник', 'версия', 'профиль']:
        raise ValueError('unexpected_source_table_header')
    output = []
    for cells in rows[1:]:
        if len(cells) != 3 or not all(_visible(cell) for cell in cells):
            raise ValueError('ambiguous_cells')
        label, version, profiles = map(_visible, cells)
        row = _source(meta, label, ' | '.join((label, version, profiles)),
                      'maxpatrol_supported_source_api_table',
                      integration_evidence='published_supported_source_table')
        named_vendor = re.fullmatch(r'«([^»]+)»[,\.]\s*(.+)', label)
        if named_vendor:
            row['source_vendor'] = named_vendor.group(1)
            row['source_name'] = named_vendor.group(2).strip(' «»')
        row.update(source_version=document_nullable(version), collection_profile=profiles,
                   support_scope='supported')
        row['evidence'][0]['section'] = doc['title']
        row['evidence'][0]['document_version_hint'] = doc.get('version')
        output.append(row)
    if not output:
        raise ValueError('empty_supported_source_table')
    return output


def _visible(value: str) -> str:
    # The saved portal HTML contains discretionary hyphens inside Russian words.
    return clean(value.replace('\u00ad', ''))


def parse_maxpatrol_partial_sources(html: str, meta: dict) -> list[dict]:
    """Extract only rows under the exact Source/Version partial-support heading."""
    soup = BeautifulSoup(html, 'html.parser')
    for table in soup.select('table'):
        rows = table_rows(table)
        if not rows or [_visible(cell).casefold() for cell in rows[0]] != ['источник', 'версия']:
            continue
        output = []
        seen = set()
        for row in rows[1:]:
            if len(row) != 2:
                continue
            label, version = (_visible(cell) for cell in row)
            if not label or (label, version) in seen:
                continue
            seen.add((label, version))
            maker = None
            match = re.fullmatch(r'«([^»]+)»(?:,\s*(.*))?', label)
            if match:
                maker = match.group(1)
                product = match.group(2)
                name = product.strip(' «»') if product else maker
            else:
                name = label
            output.append({
                'siem_id': meta['siem_id'], 'siem_name': meta['siem_name'],
                'siem_version': None,
                'siem_version_hint': document_nullable(meta.get('product_version_hint')),
                'source_name': name, 'source_vendor': maker,
                'source_family': None, 'source_variant': None,
                'source_version': document_nullable(version),
                'collection_method': None, 'normalizer_id': None,
                'normalizer_format': None,
                'integration_evidence': 'published_partial_support_table',
                'support_scope': 'partial',
                'functional_integration_verified': False,
                'review_status': 'extracted_unverified',
                'evidence': [document_evidence(meta, f'{label} | {version}',
                                               'maxpatrol_partial_source_table',
                                               'Источники с частичной поддержкой')],
            })
        return output
    return []
