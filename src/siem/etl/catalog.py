"""Build and write the event-source and system-requirements catalog."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json

from .common import SCHEMA, SYSTEM_DOC_IDS
from .sources import normalize_sources
from .requirements import parse_hardware_tables, parse_explicit_requirements
from .vendors.alertix import parse_alertix_all_in_one
from .vendors.komrad import parse_komrad_requirements, parse_komrad_catalog
from .vendors.rvision import enrich_rvision_profiles, parse_rvision_context_requirements
from .reports.quality import sizing_quality_report
from .reports.readiness import readiness_report

def locate_snapshot(value: str | None, base: Path) -> Path | None:
    if not value: return None
    p=Path(value)
    if p.is_file(): return p
    # JSON generated on Windows may be read on Linux and vice versa.
    alt=Path(value.replace('\\','/'))
    if alt.is_file(): return alt
    candidate=base/alt
    return candidate if candidate.is_file() else None


def normalize_requirements(raw: dict, input_file: Path) -> tuple[list[dict],list[dict],list[dict]]:
    profiles,requirements,unread=[],[],[]
    for vendor in raw.get('vendors',[]):
        for s in vendor.get('source_results',[]):
            if s.get('source_id') not in SYSTEM_DOC_IDS or s.get('status') != 'ok': continue
            snapshot=locate_snapshot(s.get('snapshot_path'), input_file.parent)
            if snapshot is None:
                unread.append({'siem_id':vendor['id'],'source_id':s.get('source_id'),
                    'url':s.get('url'),'reason':'local_snapshot_unavailable'})
                continue
            if snapshot.suffix.lower()!='.html':
                unread.append({'siem_id':vendor['id'],'source_id':s.get('source_id'),
                    'url':s.get('url'),'reason':'not_html_or_unsupported_format'})
                continue
            data=snapshot.read_bytes()
            import hashlib
            digest=hashlib.sha256(data).hexdigest()
            if s.get('content_sha256') and digest!=s['content_sha256']:
                unread.append({'siem_id':vendor['id'],'source_id':s.get('source_id'),
                    'url':s.get('url'),'reason':'snapshot_hash_mismatch'})
                continue
            try: html=data.decode('utf-8-sig')
            except UnicodeDecodeError: html=data.decode(s.get('http_charset') or 'utf-8',errors='replace')
            meta=dict(s,siem_id=vendor['id'],siem_name=vendor['name'],retrieved_at=raw.get('run_at'))
            meta['url']=s.get('resolved_url') or s.get('url')
            if s.get('source_id')=='hardware_requirements':
                if vendor['id']=='p13':
                    komrad_profiles, komrad_rules = parse_komrad_requirements(html,meta)
                    profiles.extend(komrad_profiles)
                    requirements.extend(komrad_rules)
                elif vendor['id']=='p04':
                    profiles.extend(parse_alertix_all_in_one(html,meta))
                else:
                    extracted = parse_hardware_tables(html, meta)
                    if vendor['id'] == 'p03':
                        enrich_rvision_profiles(extracted, html)
                        requirements.extend(parse_rvision_context_requirements(html, meta))
                    profiles.extend(extracted)
                requirements.extend(parse_explicit_requirements(html,meta))
            # Other docs deliberately produce nothing until targeted adapters
            # exist; their paragraphs must not masquerade as requirements.
    return profiles,requirements,unread


def build_catalog(raw: dict, input_file: Path) -> dict:
    integrations=normalize_sources(raw)
    unread_source_catalog_documents=[]
    # This adapter reads the actual vendor source guide index, not generic
    # keyword candidates. The crawler merely obtains the document.
    for vendor in raw.get('vendors', []):
        if vendor['id']!='p13':continue
        for doc in vendor.get('source_results', []):
            if doc.get('source_id')!='sources_catalog' or doc.get('status') not in ('ok','empty_review_required'):
                continue
            snapshot=locate_snapshot(doc.get('snapshot_path'), input_file.parent)
            if not snapshot or snapshot.suffix.lower()!='.html':
                unread_source_catalog_documents.append({
                    'siem_id':vendor['id'],'source_id':doc.get('source_id'),
                    'url':doc.get('url'),'reason':'local_snapshot_unavailable_or_unsupported_format'})
                continue
            data=snapshot.read_bytes()
            import hashlib
            digest=hashlib.sha256(data).hexdigest()
            if doc.get('content_sha256') and digest!=doc['content_sha256']:
                unread_source_catalog_documents.append({
                    'siem_id':vendor['id'],'source_id':doc.get('source_id'),
                    'url':doc.get('url'),'reason':'snapshot_hash_mismatch'})
                continue
            try: html=data.decode('utf-8-sig')
            except UnicodeDecodeError: html=data.decode(doc.get('http_charset') or 'utf-8',errors='replace')
            meta=dict(doc,siem_id=vendor['id'],siem_name=vendor['name'],retrieved_at=raw.get('run_at'))
            meta['url']=doc.get('resolved_url') or doc.get('url')
            integrations.extend(parse_komrad_catalog(html,meta))
    integrations.sort(key=lambda r:(r['siem_id'],r['source_name'].casefold()))
    profiles,requirements,unread=normalize_requirements(raw,input_file)
    # A successfully downloaded document may still be unprocessed because no
    # targeted adapter exists. Do NOT silently report this as complete coverage.
    parsed_document_urls = {
        (row['siem_id'], row.get('evidence', {}).get('url'))
        for row in profiles + requirements
    }
    unread_document_ids = {(x['siem_id'], x.get('source_id'), x.get('url')) for x in unread}
    unparsed_system_documents = []
    for vendor in raw.get('vendors', []):
        for doc in vendor.get('source_results', []):
            if doc.get('source_id') not in SYSTEM_DOC_IDS or doc.get('status') != 'ok':
                continue
            url = doc.get('resolved_url') or doc.get('url')
            if (vendor['id'], url) in parsed_document_urls:
                continue
            if (vendor['id'], doc.get('source_id'), doc.get('url')) in unread_document_ids:
                continue
            unparsed_system_documents.append({
                'siem_id': vendor['id'], 'siem_name': vendor['name'],
                'source_id': doc.get('source_id'), 'url': url,
                'reason': ('no_targeted_extractor_yet' if doc.get('source_id') != 'hardware_requirements'
                           else 'no_matching_typed_structure'),
            })
    by_vendor=defaultdict(lambda:{'integrations':0,'sizing_profiles':0,'requirements':0})
    for row in integrations: by_vendor[row['siem_id']]['integrations']+=1
    for row in profiles: by_vendor[row['siem_id']]['sizing_profiles']+=1
    for row in requirements: by_vendor[row['siem_id']]['requirements']+=1
    coverage=[]
    for v in raw.get('vendors',[]):
        result=by_vendor[v['id']].copy()
        result['no_normalized_data'] = not any(result.values())
        result.update(siem_id=v['id'],siem_name=v['name'])
        coverage.append(result)
    return {
        'schema_version':SCHEMA,'source_run_at':raw.get('run_at'),
        '_raw_run': raw,
        'integrations':integrations,'sizing_profiles':profiles,
        'system_requirements':requirements,
        'coverage':coverage,'unread_system_documents':unread,
        'unparsed_system_documents':unparsed_system_documents,
        'unread_source_catalog_documents':unread_source_catalog_documents,
        'notes':[
            'Only published catalog rows; an entry is not proof that an integration works.',
            'Requirements only from strict rules on designated system-requirement pages.',
            'Null means unknown or uncollected, never unsupported.',
            'Versions inferred from hints are NOT verified product versions.',
        ],
    }


def write_catalog(catalog: dict, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True,exist_ok=True)
    files={
        'readiness_report.json': readiness_report(catalog,catalog.get('_raw_run')),
        'quality_report.json': sizing_quality_report(catalog),
        'sources.json':catalog['integrations'],
        'sizing_profiles.json':catalog['sizing_profiles'],
        'system_requirements.json':catalog['system_requirements'],
        'coverage.json':catalog['coverage'],
        'unread_system_documents.json':catalog['unread_system_documents'],
        'unparsed_system_documents.json':catalog['unparsed_system_documents'],
        'unread_source_catalog_documents.json':catalog['unread_source_catalog_documents'],
    }
    for name, data in files.items():
        payload = data if name in ('quality_report.json', 'readiness_report.json') else {
            'schema_version': SCHEMA, 'source_run_at': catalog['source_run_at'], 'items': data,
        }
        (out_dir/name).write_text(json.dumps(payload, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')
    return {'integrations':len(catalog['integrations']), 'sizing_profiles':len(catalog['sizing_profiles']),
        'system_requirements':len(catalog['system_requirements']),
        'unread_system_documents':len(catalog['unread_system_documents']),
        'unparsed_system_documents':len(catalog['unparsed_system_documents']),
        'unread_source_catalog_documents':len(catalog['unread_source_catalog_documents']),
        'by_product':catalog['coverage']}
