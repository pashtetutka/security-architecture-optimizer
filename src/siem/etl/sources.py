"""Normalize published event-source facts without inferring support."""
from __future__ import annotations
import json
import re

from .common import nullable, ELIGIBLE_SOURCE_STATUSES

def provenance(item: dict) -> dict:
    return {
        'url': item.get('source_url'),
        'document_title': item.get('source_document_title'),
        'document_sha256': item.get('source_sha256'),
        'document_version_hint': item.get('document_version_hint'),
        'retrieved_at': item.get('collected_at'),
        'acquisition_method': item.get('acquisition_method', 'unknown'),
        'excerpt': item.get('evidence_excerpt'),
        'page': item.get('page'),
        'extraction_method': item.get('evidence_status'),
    }


def normalize_sources(raw: dict) -> list[dict]:
    """Only explicit integration rows, never vendor categories or review candidates."""
    out, seen = [], {}
    for f in raw.get('facts', []):
        if f.get('field') != 'source_integration' or f.get('evidence_status') not in ELIGIBLE_SOURCE_STATUSES:
            continue
        name = nullable(f.get('value'))
        if not name:
            continue
        family = nullable(f.get('source_family'))
        variant = nullable(f.get('source_variant'))
        maker = nullable(f.get('source_vendor'))
        # R-Vision rows have source_vendor and product in value. RuSIEM has
        # family + variant. Don't infer a manufacturer from arbitrary phrases.
        entry = {
            'siem_id': f['siem_id'],
            'siem_name': f.get('siem_name'),
            'siem_version': nullable(f.get('product_version_verified')),
            'siem_version_hint': nullable(f.get('product_version_hint')),
            'source_name': name,
            'source_vendor': maker,
            'source_family': family,
            'source_variant': variant,
            'source_version': nullable(f.get('source_version_verified') or f.get('source_version')),
            'normalizer_description': nullable(f.get('normalizer_description')),
            'collection_method': nullable(f.get('collection_method')),
            'normalizer_id': nullable(f.get('normalizer_id')),
            'normalizer_format': nullable(f.get('normalizer_format')),
            'integration_evidence': 'published_catalog_entry',
            'functional_integration_verified': False,
            'review_status': 'extracted_unverified',
            'evidence': [provenance(f)],
        }
        for field in ('support_assertion', 'support_capability'):
            if field in f:
                entry[field] = f[field]
        description = f.get('normalizer_description') or ''
        if f.get('published_connection_entries'):
            entry['published_connection_entries'] = f['published_connection_entries']
        if re.search(r'IPS/IDS|обнаружения вторжений', description, re.I):
            entry['source_event_kinds'] = ['intrusion_detection']
        if name == 'PostgreSQL pgAudit':
            entry['source_family'] = 'PostgreSQL'
        limitations = [sentence.strip() for sentence in re.split(r'(?<=[.!?])\s+', description)
                      if re.search(r'част[ьи]\s+событий|ограниченного\s+количества\s+событий|не поддерживает',
                                   sentence, re.I)]
        if limitations:
            entry['support_scope'] = 'partial'
            entry['support_limitations'] = limitations
        key = json.dumps({field: value for field, value in entry.items() if field != 'evidence'},
                         sort_keys=True, ensure_ascii=False)
        if key in seen:
            if entry['evidence'][0] not in seen[key]['evidence']:
                seen[key]['evidence'].append(entry['evidence'][0])
            continue
        seen[key] = entry
        out.append(entry)
    return sorted(out, key=lambda e: (e['siem_id'], e['source_name'].casefold()))
