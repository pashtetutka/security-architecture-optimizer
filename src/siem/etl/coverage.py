"""Only explicit aliases and provenance-backed matching; no fuzzy-positive inference."""
import re

# Small curated ontology; each alias requires an explicit editorial decision.
ALIAS = {
    # Explicit editorial aliases observed in saved official catalog rows.
    # Do not add broad families, versions, or neighbouring components here.
    '1с зуп': '1с зуп',
    '1с зарплата и управление персоналом': '1с зуп',
    '1с предприятие 8 3': '1с предприятие 8 3',
    '1с 8 3': '1с предприятие 8 3',
    'kaspersky security center': 'kaspersky security center',
    'ksc': 'kaspersky security center',
    'kaspersky kaspesky security center ksc': 'kaspersky security center',
    'fortigate': 'fortinet fortigate',
    'fortianalyzer': 'fortinet fortianalyzer',
    'fortisoar': 'fortinet fortisoar',
    'redcheck': 'саз redcheck',
    'rt solar solar dozor': 'solar dozor',
    'positive technologies nad': 'positive technologies network attack discovery nad',
    'positive technologies network attack discovery': 'positive technologies network attack discovery nad',
    'positive technologies isim': 'positive technologies industrial security incident manager pt isim',
    'pt industrial security incident manager': 'positive technologies industrial security incident manager pt isim',
    'vmware vcenter': 'vmware vcenter server',
    'hyper v': 'microsoft hyper v',
    'microsoft sccm': 'microsoft system center configuration manager sccm',
    'microsoft configuration manager': 'microsoft system center configuration manager sccm',
    'microsoft iis': 'microsoft iis server',
    'microsoft network policy server nps': 'microsoft network policy server',
    'microsoft sql': 'microsoft sql server',
    'microsoft 365': 'microsoft office 365',
    'microsoft skype for business': 'skype for business',
    'exchange server': 'microsoft exchange server',
    'ideco ideco utm': 'ideco utm',
    'dionis nx': 'factor ts dionis nx',
    'ffr yarai': 'ffri ffr yarai',
    'new security safeinspect': 'new security technologies safeinspect',
    'veeam software veeam backup replication': 'veeam backup replication',
    'kaspersky kaspersky web traffic security kwts': 'kaspersky web traffic security kwts',
    'kaspersky kaspersky secure mail gateway ksmg': 'kaspersky secure mail gateway ksmg',
    'kaspersky anti targeted attack kata': 'kaspersky anti targeted attack platform kata',
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
