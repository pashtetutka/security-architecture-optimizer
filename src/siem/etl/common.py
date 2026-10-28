"""Shared text cleaning, null handling and document evidence."""
from __future__ import annotations

import re
from typing import Any

SCHEMA = 'focused-siem-etl/1.0'
SYSTEM_DOC_IDS = {'hardware_requirements', 'system_requirements', 'deployment', 'architecture', 'platform_architecture'}
ELIGIBLE_SOURCE_STATUSES = {'vendor_catalog', 'vendor_table'}
NULL_TOKENS = {'', '-', '—', '–', 'не указано', 'неизвестно', 'unknown', 'n/a', 'none'}

def nullable(value: Any) -> str | None:
    if value is None:
        return None
    s = re.sub(r'\s+', ' ', str(value)).strip()
    return None if s.casefold() in NULL_TOKENS else s


def evidence_for_doc(meta: dict, excerpt: str, method: str) -> dict:
    return {
        'url': meta['url'], 'document_title': meta.get('title'),
        'document_sha256': meta.get('content_sha256'),
        'document_version_hint': meta.get('product_version_hint'),
        'retrieved_at': meta.get('retrieved_at'),
        'excerpt': clean(excerpt)[:350],
        'page': None, 'extraction_method': method,
    }


def clean(text: str) -> str:
    return re.sub(r'\s+', ' ', text).strip()


def document_evidence(meta: dict, excerpt: str, method: str, section: str | None = None) -> dict:
    result = {
        'url': meta.get('url'), 'document_title': meta.get('title'),
        'document_sha256': meta.get('content_sha256'),
        'document_version_hint': meta.get('product_version_hint'),
        'retrieved_at': meta.get('retrieved_at'),
        'excerpt': clean(excerpt)[:350], 'page': None,
        'extraction_method': method,
    }
    if section:
        result['section'] = section
    return result


def document_nullable(value: Any) -> str | None:
    if value is None:
        return None
    value = clean(str(value))
    return value if value and value.casefold() not in ('unknown', '-', '—', 'none') else None


def table_rows(table) -> list[list[str]]:
    rows = []
    for tr in table.find_all('tr'):
        cells = [clean(c.get_text(' ', strip=True)) for c in tr.find_all(['td', 'th'], recursive=False)]
        if cells:
            rows.append(cells)
    return rows
