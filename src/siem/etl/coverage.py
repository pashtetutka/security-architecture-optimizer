"""Only explicit aliases and provenance-backed matching; no fuzzy-positive inference."""
import re

# Small curated ontology; each alias requires an explicit editorial decision.
ALIAS = {
    '1с зуп': '1с зуп',
    '1с зарплата и управление персоналом': '1с зуп',
    '1с предприятие 8 3': '1с предприятие 8 3',
    '1с 8 3': '1с предприятие 8 3',
    'kaspersky security center': 'kaspersky security center',
    'ksc': 'kaspersky security center',
}


def canonical(text: str) -> str:
    val = text.casefold().replace('ё','е')
    val = re.sub(r'(?<!\w)1c(?!\w)', '1с', val)  # Latin C -> Cyrillic С only in '1C'
    val = re.sub(r'[^\w\s]', ' ', val)
    val = re.sub(r'\s+', ' ', val).strip()
    return ALIAS.get(val, val)


def match_inventory(requirements: list[str], records: list[dict]) -> list[dict]:
    """Match known subproducts vs broad platform families; unknown != unsupported."""
    variants = {}
    families = {}
    for rec in records:
        key = canonical(rec['variant'] or rec['family'])
        (variants if rec['variant'] else families).setdefault(key, []).append(rec)
    report = []
    for required in requirements:
        key = canonical(required)
        if key in variants:
            status, evidence = 'vendor_listed_variant', variants[key]
        elif key in families:
            status, evidence = 'vendor_listed_family', families[key]
        else:
            status, evidence = 'not_found_in_catalog', []
        report.append({
            'requested_source': required,
            'status': status,
            'verified_collection': False, 'verified_normalization': False,
            'evidence': [{'source_url': r['source_url'], 'raw_fragment': r['raw_fragment']}
                         for r in evidence],
            'needs_review': True,
        })
    return report
