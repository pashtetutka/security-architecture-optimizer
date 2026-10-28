"""Extract source-table evidence and candidate characteristics. Never infer unsupported.

All extractors emit short, attributable claims rather than full copyrighted documents.
Tables recognized only with strict header matches; other material remains review_candidate.
"""
from __future__ import annotations
import hashlib
import re
from bs4 import BeautifulSoup, UnicodeDammit
from io import BytesIO
from .vendors.rusiem import parse_html as parse_rusiem

LIMIT=240
KEYWORDS={
 'deployment':r'\bkubernetes\b|\bk8s\b|\bконтейнер|\bвиртуальн|\ball.in.one\b|\bкластер',
 'resources':r'\beps\b|\bv?cpu\b|\bram\b|\bозу\b|\bпамят|\bдиск|\bгб\b|\btb\b|\bтб\b',
 'collection':r'\bколлектор|\bконнектор|\bsyslog\b|\bwef\b|\bwmi\b|\bapi\b|\bsnmp\b|\bжурнал',
 'normalization':r'\bнормализатор|\bпарсер|\bнормализац|\bправил.*нормализац',
 'dependencies':r'\bpostgresql\b|\bclickhouse\b|\bopensearch\b|\bkafka\b|\bredis\b|\bбалансировщик',
 'certification':r'\bфстэк\b|\bсертификат\b|\bуровн.*довер',
 'licensing':r'\bлицензи|\bтарифи|\bподписк|\bпоставк',
 'ha':r'\bотказоустойчив|\bрезервир|\breplicat|\bрепликаци',
}

def clean(text): return re.sub(r'\s+',' ',text).strip()

def present_or_none(text):
 text=clean(text)
 return None if text in ('', '-', '—', '–', 'не указано', 'Не указано') else text

def make_claim(field, value, excerpt, status='review_candidate', **more):
 return {'field':field,'value':str(value)[:200], 'evidence_excerpt':clean(excerpt)[:LIMIT], 'evidence_status':status, **more}

def structured_tables(html, mode):
 soup=BeautifulSoup(html,'html.parser')
 facts=[]
 for table in soup.find_all('table'):
  rows=[]
  for tr in table.find_all('tr'):
   vals=[clean(x.get_text(' ',strip=True)) for x in tr.find_all(['th','td'],recursive=False)]
   if vals:rows.append(vals)
  if len(rows)<2:continue
  head=' '.join(rows[0]).casefold()
  if mode=='rvision' and not ('продукт' in head and 'нормализац' in head and 'версия' in head):continue
  if mode=='kuma' and not ('систем' in head and 'нормализатор' in head):continue
  if mode not in ('rvision','kuma'):continue
  for vals in rows[1:]:
   if mode=='rvision':
    if len(vals)<5:continue
    vendor,product,version,connection,normalizer=vals[:5]
    if not product or product.casefold()=='продукт':continue
    facts.append(make_claim('source_integration',product,' | '.join(vals), 'vendor_table',
       source_vendor=vendor, source_version=present_or_none(version), collection_method=present_or_none(connection),
       normalizer_id=present_or_none(normalizer), supported_version_scope='published_doc_version_only'))
   else:
    if len(vals)<2:continue
    source,norm=vals[:2]
    if not source or source.casefold()=='название системы':continue
    facts.append(make_claim('source_integration',source,' | '.join(vals), 'vendor_table',
       normalizer_id=present_or_none(norm), collection_method=None, source_version=None,
       normalizer_format=(vals[2] if len(vals)>2 else None),
       normalizer_description=(vals[3] if len(vals)>3 else None),
       supported_version_scope='published_doc_version_only'))
 return facts

def extract_html(html, mode):
 soup=BeautifulSoup(html,'html.parser')
 for bad in soup(['script','style','nav','footer','header','form']):bad.decompose()
 title=clean(soup.title.get_text(' ',strip=True)) if soup.title else ''
 if mode=='rusiem':
  result=parse_rusiem(html)
  facts=[]
  # Parent headings (Cisco, Dell etc.) are catalog taxonomy, not integrations.
  # Only variants and standalone families are eligible for downstream matching.
  has_variants={r['family'] for r in result['records'] if r['variant']}
  for r in result['records']:
   family=re.sub(r'\*\*|⇒+', '', r['family']).strip();variant=r['variant']
   if variant:
    field='source_integration'
    value=(family+' '+variant).strip()
    specificity='vendor_product'
   elif family in has_variants:
    field='source_family';value=family;specificity='taxonomy_only'
   else:
    field='source_integration';value=family;specificity='standalone_name'
   facts.append(make_claim(field,value,r['raw_fragment'],'vendor_catalog',
                 source_family=family,source_variant=variant,source_specificity=specificity,
                 collection_method=None,normalizer_id=None,source_version=None,
                 supported_version_scope='not_specified'))
  return {'title':title,'facts':facts,'warnings':result['warnings']}
 table_facts=structured_tables(html,mode)
 facts=list(table_facts)
 # Critical: a vendor's *source integration catalog* is not installation guidance.
 # The same KUMA description can mention EPS, QEMU, PostgreSQL etc. without
 # asserting the SIEM's own EPS/sizing, virtualization or PostgreSQL dependency.
 # Preserve the entire table description in the structured fact instead.
 if mode in ('rvision', 'kuma'):
  return {'title':title,'facts':facts,'warnings':[]}
 # Candidate-only sentences/paragraphs: never used as verified deployment dependencies.
 seen=set()
 for node in soup.find_all(['p','li','h2','h3','h4','td']):
  txt=clean(node.get_text(' ',strip=True))
  if len(txt)<25 or len(txt)>600 or txt in seen:continue
  seen.add(txt)
  for category,pattern in KEYWORDS.items():
   if re.search(pattern,txt,re.I):
    facts.append(make_claim(category,txt[:110],txt))
    break
 return {'title':title,'facts':facts[:4000], 'warnings':(['Достигнут лимит фрагментов 4000'] if len(facts)>4000 else [])}

def extract_pdf(data:bytes):
 try:
  from pypdf import PdfReader
 except ImportError as exc:
  raise RuntimeError('Для PDF установите: pip install pypdf') from exc
 reader=PdfReader(BytesIO(data),strict=False)
 facts=[]
 for i,page in enumerate(reader.pages[:150]):
  text=page.extract_text() or ''
  for line in text.splitlines():
   line=clean(line)
   if len(line)<25 or len(line)>450: continue
   for category,pattern in KEYWORDS.items():
    if re.search(pattern,line,re.I):
     facts.append(make_claim(category,line[:110],line,page=i+1))
     break
 return {'title':str(reader.metadata.title) if reader.metadata and reader.metadata.title else '',
         'facts':facts[:3500], 'warnings':(['PDF ограничен 150 страницами'] if len(reader.pages)>150 else [])}

def extract_content(data:bytes,mode:str,charset='utf-8'):
 if mode=='pdf': return extract_pdf(data)
 # Most modern vendor HTML is UTF-8. Avoid Latin-1 mojibake caused by
 # missing HTTP charset; if UTF-8 is invalid, honor a declared charset
 # and finally use UnicodeDammit for encoding detection.
 if data.startswith((b'\xef\xbb\xbf',)):
  html=data.decode('utf-8-sig')
 else:
  try: html=data.decode('utf-8')
  except UnicodeDecodeError:
   try: html=data.decode(charset) if charset else None
   except (UnicodeError,LookupError): html=None
   if html is None: html=UnicodeDammit(data,is_html=True).unicode_markup
   if html is None: raise UnicodeError('Не удалось определить кодировку HTML')
 return extract_html(html,mode)
