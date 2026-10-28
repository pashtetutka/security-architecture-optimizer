"""Strict parsing of published resource tables and dependency statements."""
from __future__ import annotations

import re
from bs4 import BeautifulSoup
from .common import clean, nullable, evidence_for_doc

def parse_eps_bound(cell: str) -> tuple[int | None, int | None] | None:
    """A table's published load band. None at an open end, upper inclusive is unknown."""
    t = clean(cell).lower().replace('\u200b', '').replace('\u00a0', '').replace(' ', '')
    t = t.replace('–', '-').replace('—', '-').replace('−', '-')
    match = re.search(r'до(\d+)', t)
    if match:
        return (None, int(match.group(1)))
    match = re.fullmatch(r'(\d+)-(\d+)', t)
    if match:
        a,b=map(int,match.groups())
        return (a,b) if a < b else None
    return None


def parse_nodes(cell: str) -> list[dict]:
    """Strictly parse roles with numerical resource tuples, don't guess."""
    text = clean(cell).replace('\u200b', '')
    chunks = re.split(r'(?=\b(?:Один сервер|Master|Worker\s*\([^)]*\)|ClickHouse)\s*:)', text, flags=re.I)
    nodes=[]
    for chunk in chunks:
        match = re.match(r'\s*(Один сервер|Master|Worker\s*\([^)]*\)|ClickHouse)\s*:\s*(.*)',chunk,re.I)
        if not match:
            continue
        role, description = match.groups()
        cpu = re.search(r'(\d+)\s*vCPU\b',description,re.I)
        ram = re.search(r'(\d+(?:[.,]\d+)?)\s*ГБ\s*ОЗУ',description,re.I)
        disk = re.search(r'(\d+(?:[.,]\d+)?)\s*ГБ\s*(?:на\s*)?(SSD|HDD)',description,re.I)
        if not cpu or not ram:
            continue
        count = re.search(r'(?<!\d)(\d+)\s*уз(?:ел|ла|лов)', description,re.I)
        nodes.append({
            'role': role.strip(),
            'quantity': int(count.group(1)) if count else 1,
            'vcpu': int(cpu.group(1)),
            'ram_gb': float(ram.group(1).replace(',','.')),
            'disk_gb': float(disk.group(1).replace(',','.')) if disk else None,
            'disk_type': disk.group(2).upper() if disk else None,
        })
    return nodes


def dom_title(soup: BeautifulSoup) -> str | None:
    return clean(soup.title.get_text(' ',strip=True)) if soup.title else None


def previous_section(table) -> str:
    prev=table.find_previous(re.compile('^h[1-6]$'))
    return clean(prev.get_text(' ',strip=True)) if prev else ''


def parse_hardware_tables(html: str, meta: dict) -> list[dict]:
    """EPS configuration tables: one output row per scenario and band."""
    soup=BeautifulSoup(html,'html.parser')
    profiles=[]
    for tbl in soup.select('table'):
        rows=[]
        for tr in tbl.select('tr'):
            cells=[clean(c.get_text(' ',strip=True)) for c in tr.find_all(['td','th'],recursive=False)]
            if cells: rows.append(cells)
        if len(rows)<2: continue
        heading=' '.join(rows[0]).casefold()
        if 'eps' not in heading or 'конфигурац' not in heading: continue
        section=previous_section(tbl).casefold()
        if 'минималь' in section: tier='minimum'
        elif 'рекомендуем' in section: tier='recommended'
        else: tier='unspecified'
        for cells in rows[1:]:
            if len(cells)<2: continue
            band=parse_eps_bound(cells[0]); nodes=parse_nodes(cells[1])
            if band is None or not nodes: continue
            net = re.search(r'(\d+(?:[.,]\d+)?)\s*Гбит\s*/\s*с',cells[2],re.I) if len(cells)>2 else None
            profiles.append({
                'siem_id':meta['siem_id'], 'siem_name':meta['siem_name'],
                'siem_version':None,
                'siem_version_hint':nullable(meta.get('product_version_hint')),
                'scenario':tier,
                'component':'primary_installation',
                'eps_from':band[0], 'eps_to':band[1],
                'eps_bounds_inclusive':None,
                'nodes':nodes,
                'network_gbps':float(net.group(1).replace(',','.')) if net else None,
                'review_status':'extracted_unverified',
                'evidence':evidence_for_doc(meta,' | '.join(cells),'structured_eps_table'),
            })
    return profiles


def parse_explicit_requirements(html: str, meta: dict) -> list[dict]:
    """Very small whitelist of unmistakable statements from requirements pages.
    In particular, technology mentions are NOT treated as mandatory dependencies.
    """
    soup=BeautifulSoup(html,'html.parser')
    for elem in soup(['script','style','nav','footer','header','aside']): elem.decompose()
    rules=[]; seen=set()
    for elem in soup.find_all(['p','li']):
        s=clean(elem.get_text(' ',strip=True))
        if not 12<=len(s)<=380: continue
        # only a precise declarative requirement, never bare "Kubernetes".
        match=re.search(r'(?:минимальная\s+версия\s+Kubernetes\s*:\s*)(\d+(?:\.\d+){1,2})',s,re.I)
        if match:
            key=('kubernetes','minimum_version',match.group(1))
            if key not in seen:
                seen.add(key)
                rules.append({'category':'platform','component':'Kubernetes','property':'minimum_version',
                    'operator':'>=','value':match.group(1),'unit':'version','strength':'mandatory',
                    'scenario':'unspecified','evidence':evidence_for_doc(meta,s,'explicit_requirement_pattern')})
        match=re.search(r'для\s+работы\s+системы\s+требуется\s+СУБД\s+(ClickHouse)\b',s,re.I)
        if match:
            key=('database','required',match.group(1).lower())
            if key not in seen:
                seen.add(key)
                rules.append({'category':'software_dependency','component':match.group(1),'property':'required',
                    'operator':'=','value':True,'unit':None,'strength':'mandatory',
                    'scenario':'unspecified','evidence':evidence_for_doc(meta,s,'explicit_requirement_pattern')})
        match=re.search(r'рекомендуется\s+(PostgreSQL)\s+версии\s+(\d+(?:\.\d+)*)\s+или\s+выше',s,re.I)
        if match:
            key=('database','recommended_version',match.group(1).lower(),match.group(2))
            if key not in seen:
                seen.add(key)
                rules.append({'category':'software_dependency','component':match.group(1),'property':'recommended_minimum_version',
                    'operator':'>=','value':match.group(2),'unit':'version','strength':'recommended',
                    'scenario':'unspecified','evidence':evidence_for_doc(meta,s,'explicit_requirement_pattern')})
    for rule in rules:
        rule.update(siem_id=meta['siem_id'],siem_name=meta['siem_name'],siem_version=None,
                    siem_version_hint=nullable(meta.get('product_version_hint')),
                    review_status='extracted_unverified')
    return rules
