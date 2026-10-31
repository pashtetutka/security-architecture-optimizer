"""KOMRAD edition hardware, OS choices and conditional capacity extraction.

Works ONLY on a specifically registered vendor hardware_requirements document.
Does not infer hardware sizing from an overview, external links, or another SIEM.
"""
from __future__ import annotations
import re
from bs4 import BeautifulSoup, NavigableString, Comment
from ..common import clean, document_evidence, nullable


def _table_rows(table):
    """Read the flat KOMRAD matrix in source order, including optional end tags.

    html.parser nests cells/rows when their end tags are omitted. Descendant
    text of a cell then includes following cells; recursive=False loses them.
    New tr/td/th starts delimit this matrix regardless of that artificial tree.
    Spanned or nested tables are unsupported, rather than silently misaligned.
    """
    if table.select('table, [colspan], [rowspan]'):
        return []
    rows=[]
    row=None
    cell=None
    for item in table.descendants:
        if isinstance(item, Comment):
            continue
        if isinstance(item, NavigableString):
            if cell is not None:
                cell.append(str(item))
        elif item.name == 'tr':
            row=[]
            rows.append(row)
            cell=None
        elif item.name in ('td','th') and row is not None:
            cell=[]
            row.append(cell)
    return [[clean(' '.join(parts)) for parts in row] for row in rows if row]


def _metadata(meta, document_release):
    return {'siem_id':meta['siem_id'],'siem_name':meta['siem_name'],
            # The heading validates a DOCUMENT release family, not the installation build.
            'siem_version':None,'siem_version_hint':meta.get('product_version_hint'),
            'document_release':document_release,'review_status':'extracted_unverified'}


def _release(soup):
    text=clean(soup.get_text(' ',strip=True))
    # Docusaurus version labels are explicit (not the ambiguous /next/ URL).
    m=re.search(r'\bВерсия\s*:\s*(\d+\.\d+\.\s*[xX]|\d+(?:\.\d+){1,3})\b',text,re.I)
    return re.sub(r'\s+','',m.group(1)).upper() if m else None


def parse_komrad_requirements(html: str, meta: dict) -> tuple[list[dict],list[dict]]:
    """Edition minimum hardware; OS choices; separate conditional 100k EPS note.

    Do NOT label the 100k EPS distributed deployment as sizing of an edition.
    """
    if meta.get('siem_id') != 'p13':
        return [],[]
    soup=BeautifulSoup(html,'html.parser')
    article=soup.select_one('article') or soup.select_one('main') or soup
    document_release=_release(article) or _release(soup)
    common=_metadata(meta,document_release)
    profiles=[]; requirements=[]
    for table in article.select('table'):
        rows=_table_rows(table)
        if len(rows)<3:continue
        header=[x.casefold() for x in rows[0]]
        if not header:continue
        # SKU-specific minimum hardware (KOMRAD product editions).
        if 'характеристика' in header[0] and any('all-in-one' in x for x in header[1:]) and any('enterprise' in x for x in header[1:]):
            row_lookup={r[0].casefold():r[1:] for r in rows[1:] if len(r)>1}
            def cell(contains: str,j: int):
                return next((vs[j] for label,vs in row_lookup.items() if contains in label and j<len(vs)),None)
            for j, edition in enumerate(rows[0][1:]):
                cpu_text=cell('количество ядер процессора',j)
                frequency_text=cell('базовая тактовая частота',j)
                ram_text=cell('оперативная память',j)
                disk_text=cell('ssd/hdd',j)
                cpu=re.fullmatch(r'\s*(\d+)\s*',cpu_text or '')
                frequency=re.search(r'(\d+(?:[.,]\d+)?)\s*(?:ГГц|GHz)',frequency_text or '',re.I)
                ram=re.search(r'(\d+(?:[.,]\d+)?)\s*(?:Гб|GB)\b',ram_text or '',re.I)
                disk=re.search(r'(\d+(?:[.,]\d+)?)\s*(Гб|GB|Тб|TB)\b',disk_text or '',re.I)
                # Don't create a deceptively complete server if mandatory numeric columns can't be parsed.
                if not all((cpu, frequency, ram, disk)):continue
                value=float(disk.group(1).replace(',','.'))
                unit='TB' if disk.group(2).casefold() in ('тб','tb') else 'GB'
                cpu_value=int(cpu.group(1))
                nodes=[{
                    'role':'edition_server','quantity':1,'vcpu':None,
                    'cpu_cores':cpu_value,'cpu_base_frequency_ghz':float(frequency.group(1).replace(',','.')),
                    'ram_gb':float(ram.group(1).replace(',','.')),
                    # Legacy GB field carries the published total, never a device size.
                    'disk_gb':value if unit=='GB' else None,
                    'disk_type':None,
                    'storage_devices':[{'purpose':'unspecified','quantity':None,
                                        'total_capacity':value,'per_device_capacity':None,
                                        'capacity_unit':unit,'capacity_kind':'total_required',
                                        'media':None,'raid':None,'original_value':disk_text}],
                }]
                profile={**common,'scenario':'minimum','edition':edition.strip(),
                    'component':'primary_installation','eps_from':None,'eps_to':None,
                    'eps_bounds_inclusive':None,'nodes':nodes,'network_gbps':None,
                    'sizing_scope':'edition_minimum_not_eps_sizing',
                    'applicability':{'edition':edition.strip(),
                                     'requirement_level':'minimum',
                                     'document_release':document_release,
                                     'eps_sizing':False},
                    'evidence':document_evidence(meta, ' | '.join([edition,cpu_text,frequency_text,ram_text,disk_text]),'komrad_v09_edition_matrix','Минимальные требования'),
                }
                profiles.append(profile)
        # Explicit supported host OS versions, different from system's own dependencies.
        if len(header)>=2 and header[0]=='ос' and 'версия' in header[1]:
            for row in rows[1:]:
                if len(row)<2:continue
                os_name,version=row[0].strip(),row[1].strip()
                if not os_name or not version:continue
                requirements.append({**common,
                    'category':'operating_system','component':os_name,
                    'property':'supported_minimum_version','operator':'>=',
                    'value':version,'unit':'version','strength':'supported',
                    'scenario':'installation_host','applies_to':'komrad_host',
                    'evidence':document_evidence(meta, ' | '.join(row), 'komrad_v09_os_table','Поддерживаемые ОС'),
                })
    # The 100000 EPS statement is an explicitly CONDITIONAL published example.
    # Without complete collector count/CPU, it is not a usable sizing profile.
    text=clean(article.get_text(' ',strip=True))
    match=re.search(r'KOMRAD\s+способен\s+обработать\s+(\d[\d\s]*)\s*EPS\s+при\s+следующих\s+параметрах',text,re.I)
    if match:
        eps=int(re.sub(r'\s+','',match.group(1)))
        # Capture just the claim; don't silently transfer a hardware requirement to all editions.
        requirements.append({**common,'category':'capacity_condition',
            'component':'distributed_deployment','property':'published_eps_example',
            'operator':'=','value':eps,'unit':'EPS','strength':'conditional',
            'scenario':'separated_components','applies_to':'conditional_deployment_only',
            'sizing_complete':False,'reason':'collector_resources_not_specified',
            'evidence':document_evidence(meta,match.group(0),'komrad_v09_conditional_capacity','100000 EPS'),
        })
    return profiles,requirements


def parse_komrad_catalog(html: str, meta: dict) -> list[dict]:
    """Links inside the main documentation ARTICLE to individual source guides."""
    soup=BeautifulSoup(html,'html.parser')
    target=soup.select_one('article .markdown') or soup.select_one('article')
    if not target:return []
    found=[];seen=set()
    from urllib.parse import urljoin
    for link in target.select('a[href]'):
        href=link.get('href','')
        # Don't include navigation, sibling docs or unrelated cross-links.
        if '/collect/sources/' not in href:continue
        # Docusaurus prepends a document icon to each link's visible text.
        name=re.sub(r'^[\s📄\ufe0f]+', '', clean(link.get_text(' ',strip=True)))
        if len(name)<3 or len(name)>100 or name.casefold() in ('источники событий','назад','далее'):continue
        absolute=urljoin(meta['url'],href)
        key=(name.casefold(),absolute)
        if key in seen:continue
        seen.add(key)
        found.append({
            'siem_id':meta['siem_id'],'siem_name':meta['siem_name'],
            'siem_version':None,'siem_version_hint':nullable(meta.get('product_version_hint')),
            'source_name':name,'source_vendor':None,'source_family':None,'source_variant':None,
            'source_version':None,'collection_method':None,'normalizer_id':None,
            'normalizer_format':None,'integration_evidence':'published_integration_guide_index',
            'functional_integration_verified':False,'review_status':'extracted_unverified',
            'evidence':[{'url':absolute,'document_title':meta.get('title'),
                'document_sha256':meta.get('content_sha256'),'document_version_hint':meta.get('product_version_hint'),
                'retrieved_at':meta.get('retrieved_at'),'excerpt':name,
                'page':None,'extraction_method':'komrad_document_link'}],
        })
    return found
