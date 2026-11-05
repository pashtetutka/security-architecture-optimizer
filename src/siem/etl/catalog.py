"""Build and write the event-source and system-requirements catalog."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json
import hashlib

from .common import SCHEMA, SYSTEM_DOC_IDS, ELIGIBLE_SOURCE_STATUSES
from .sources import normalize_sources
from .requirements import parse_hardware_tables, parse_explicit_requirements
from .vendors.alertix import (parse_alertix_all_in_one, parse_alertix_faq,
                             parse_alertix_architecture, parse_alertix_connectors)
from .vendors.komrad import parse_komrad_requirements, parse_komrad_catalog
from .vendors.published_claims import (parse_searchinform_overview, parse_usergate_architecture,
                                       parse_solar_architecture, parse_savrus_product,
                                       parse_security_capsule_pdf)
from .vendors.ankey import parse_ankey_low_load
from .vendors.kuma import parse_kuma_requirements
from .vendors.ankey_release import parse_ankey_release_pdf
from .vendors.deployment_context import parse_rvision_deployment, parse_komrad_architecture
from .vendors.maxpatrol import parse_maxpatrol_partial_sources, parse_maxpatrol_supported_api
from .vendors.solar import parse_solar_whitepaper
from .vendors.published_claims import parse_security_capsule_product
from .vendors.rvision import enrich_rvision_profiles, parse_rvision_context_requirements
from .reports.quality import sizing_quality_report
from .reports.readiness import readiness_report
from .identities import type_integrations, unique_source_values
from .validation import validate_catalog

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
            digest=hashlib.sha256(data).hexdigest()
            if s.get('content_sha256') and digest!=s['content_sha256']:
                unread.append({'siem_id':vendor['id'],'source_id':s.get('source_id'),
                    'url':s.get('url'),'reason':'snapshot_hash_mismatch'})
                continue
            try: html=data.decode('utf-8-sig')
            except UnicodeDecodeError: html=data.decode(s.get('http_charset') or 'utf-8',errors='replace')
            meta=dict(s,siem_id=vendor['id'],siem_name=vendor['name'],
                      retrieved_at=s.get('retrieved_at') or raw.get('run_at'))
            meta['url']=s.get('resolved_url') or s.get('url')
            if s.get('source_id')=='hardware_requirements':
                if vendor['id']=='p12':
                    try:
                        kuma_profiles, kuma_rules = parse_kuma_requirements(html, meta)
                        profiles.extend(kuma_profiles)
                        requirements.extend(kuma_rules)
                    except ValueError as ex:
                        unread.append({'siem_id': vendor['id'], 'source_id': s.get('source_id'),
                                       'url': meta['url'], 'reason': str(ex)})
                    continue
                elif vendor['id']=='p13':
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
            elif vendor['id']=='p04' and s.get('source_id')=='platform_architecture':
                requirements.extend(parse_alertix_architecture(html,meta))
            elif vendor['id']=='p03' and s.get('source_id')=='deployment':
                requirements.extend(parse_rvision_deployment(html,meta))
            elif vendor['id']=='p13' and s.get('source_id')=='architecture':
                requirements.extend(parse_komrad_architecture(html,meta))
            # Other docs deliberately produce nothing until targeted adapters
            # exist; their paragraphs must not masquerade as requirements.
    return profiles,requirements,unread


def validated_source_facts(raw: dict, input_file: Path) -> tuple[list[dict], list[dict]]:
    """Check the snapshot behind collected source facts before normalizing them."""
    documents = defaultdict(list)
    for vendor in raw.get('vendors', []):
        for doc in vendor.get('source_results', []):
            documents[(vendor['id'], doc.get('source_id'))].append(doc)
    checked, accepted, issues = {}, [], {}
    for fact in raw.get('facts', []):
        if fact.get('field') != 'source_integration' or fact.get('evidence_status') not in ELIGIBLE_SOURCE_STATUSES:
            continue
        key = (fact.get('siem_id'), fact.get('source_id'))
        if key not in checked:
            candidates = documents.get(key, [])
            doc = candidates[0] if len(candidates) == 1 else {}
            reason, digest = None, None
            if not candidates:
                reason = 'source_document_missing'
            elif len(candidates) != 1:
                reason = 'ambiguous_source_document'
            elif doc.get('status') not in ('ok', 'empty_review_required'):
                reason = 'source_document_not_extracted'
            elif not doc.get('content_sha256'):
                reason = 'document_hash_missing'
            else:
                snapshot = locate_snapshot(doc.get('snapshot_path'), input_file.parent)
                if snapshot is None:
                    reason = 'local_snapshot_unavailable'
                else:
                    try:
                        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                        if digest != doc['content_sha256']:
                            reason = 'snapshot_hash_mismatch'
                    except OSError:
                        reason = 'local_snapshot_unreadable'
            checked[key] = (doc, digest, reason)
        doc, digest, reason = checked[key]
        if reason is None:
            if not fact.get('source_sha256'):
                reason = 'fact_hash_missing'
            elif fact['source_sha256'] != digest:
                reason = 'fact_hash_mismatch'
            elif (not fact.get('source_url') or fact['source_url'] != (doc.get('resolved_url') or doc.get('url'))
                  or (fact.get('manifest_url') and fact['manifest_url'] != doc.get('url'))):
                reason = 'fact_document_url_mismatch'
        if reason:
            issue_key = (*key, reason)
            issue = issues.setdefault(issue_key, {
                'siem_id': key[0], 'source_id': key[1],
                'url': doc.get('url') or fact.get('source_url'),
                'reason': reason, 'affected_facts': 0,
            })
            issue['affected_facts'] += 1
        else:
            accepted.append(fact)
    return accepted, list(issues.values())


def build_catalog(raw: dict, input_file: Path, *, automatic_only: bool = False) -> dict:
    if automatic_only:
        documents = {(v['id'], d.get('source_id'))
                     for v in raw.get('vendors', []) for d in v.get('source_results', [])
                     if d.get('acquisition_method') == 'automatic_https'}
        raw = {**raw, 'vendors': [{**v, 'source_results': [
            d for d in v.get('source_results', []) if (v['id'], d.get('source_id')) in documents
        ]} for v in raw.get('vendors', [])], 'facts': [
            f for f in raw.get('facts', []) if (f.get('siem_id'), f.get('source_id')) in documents
        ]}
    source_facts, unread_source_catalog_documents = validated_source_facts(raw, input_file)
    integrations=normalize_sources({'facts': source_facts})
    partial_system_documents=[]
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
            digest=hashlib.sha256(data).hexdigest()
            if doc.get('content_sha256') and digest!=doc['content_sha256']:
                unread_source_catalog_documents.append({
                    'siem_id':vendor['id'],'source_id':doc.get('source_id'),
                    'url':doc.get('url'),'reason':'snapshot_hash_mismatch'})
                continue
            try: html=data.decode('utf-8-sig')
            except UnicodeDecodeError: html=data.decode(doc.get('http_charset') or 'utf-8',errors='replace')
            meta=dict(doc,siem_id=vendor['id'],siem_name=vendor['name'],
                      retrieved_at=doc.get('retrieved_at') or raw.get('run_at'))
            meta['url']=doc.get('resolved_url') or doc.get('url')
            integrations.extend(parse_komrad_catalog(html,meta))
    profiles,requirements,unread=normalize_requirements(raw,input_file)
    if any(p['siem_id'] == 'p12' for p in profiles):
        partial_system_documents.append({
            'siem_id': 'p12', 'source_id': 'hardware_requirements',
            'url': next(p['evidence']['url'] for p in profiles if p['siem_id'] == 'p12'),
            'reason': 'additional_infrastructure_sections_not_normalized',
            'detail': 'EPS matrix, host OS, base agents and Kubernetes extracted; separate metrics scaling, connector-specific agent performance and optional service sections remain outside this adapter.'})
    # Alertix FAQ is outside the generic system-document set. Parse its two
    # explicit claims without treating unrelated FAQ integration names as sources.
    for vendor in raw.get('vendors', []):
        if vendor['id'] != 'p04':
            continue
        for doc in vendor.get('source_results', []):
            if doc.get('source_id') != 'configuration' or doc.get('status') != 'ok':
                continue
            snapshot = locate_snapshot(doc.get('snapshot_path'), input_file.parent)
            if snapshot is None or snapshot.suffix.lower() != '.html':
                unread.append({'siem_id': vendor['id'], 'source_id': 'configuration',
                               'url': doc.get('url'), 'reason': 'local_snapshot_unavailable_or_unsupported_format'})
                continue
            data = snapshot.read_bytes()
            if doc.get('content_sha256') and hashlib.sha256(data).hexdigest() != doc['content_sha256']:
                unread.append({'siem_id': vendor['id'], 'source_id': 'configuration',
                               'url': doc.get('url'), 'reason': 'snapshot_hash_mismatch'})
                continue
            try: html = data.decode('utf-8-sig')
            except UnicodeDecodeError: html = data.decode(doc.get('http_charset') or 'utf-8', errors='replace')
            meta = dict(doc, siem_id=vendor['id'], siem_name=vendor['name'],
                        retrieved_at=doc.get('retrieved_at') or raw.get('run_at'))
            meta['url'] = doc.get('resolved_url') or doc.get('url')
            faq_sources, faq_requirements = parse_alertix_faq(html, meta)
            integrations.extend(faq_sources)
            requirements.extend(faq_requirements)
    published_adapters = {
        ('p04', 'connectors_syslog'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'Syslog')),
        ('p04', 'connectors_beats'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'Beats')),
        ('p04', 'connectors_jdbc'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'JDBC')),
        ('p04', 'connectors_snmp'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'SNMP')),
        ('p06', 'partial_sources'): ('html_source', parse_maxpatrol_partial_sources),
        ('p06', 'supported_sources_api'): ('json_source', parse_maxpatrol_supported_api),
        ('p02', 'overview'): ('html_source', parse_searchinform_overview),
        ('p05', 'product_document'): ('pdf_requirement', parse_security_capsule_pdf),
        ('p05', 'source_product'): ('html_source', parse_security_capsule_product),
        ('p07', 'product'): ('html_requirement', parse_savrus_product),
        ('p09', 'architecture'): ('html_source', parse_usergate_architecture),
        ('p10', 'product_docs'): ('html_profile', parse_ankey_low_load),
        ('p10', 'release_sources'): ('pdf_source', parse_ankey_release_pdf),
        ('p11', 'architecture'): ('html_source', parse_solar_architecture),
        ('p11', 'source_whitepaper'): ('pdf_source', parse_solar_whitepaper),
    }
    for vendor in raw.get('vendors', []):
        for doc in vendor.get('source_results', []):
            selected = published_adapters.get((vendor['id'], doc.get('source_id')))
            if selected is None or doc.get('status') not in ('ok', 'empty_review_required'):
                continue
            kind, adapter = selected
            snapshot = locate_snapshot(doc.get('snapshot_path'), input_file.parent)
            expected_suffix = '.pdf' if kind.startswith('pdf_') else '.json' if kind.startswith('json_') else '.html'
            if snapshot is None or snapshot.suffix.lower() != expected_suffix:
                issue = {'siem_id': vendor['id'], 'source_id': doc.get('source_id'),
                         'url': doc.get('url'), 'reason': 'local_snapshot_unavailable_or_unsupported_format'}
                (unread_source_catalog_documents if kind.endswith('_source') else unread).append(issue)
                continue
            data = snapshot.read_bytes()
            if doc.get('content_sha256') and hashlib.sha256(data).hexdigest() != doc['content_sha256']:
                issue = {'siem_id': vendor['id'], 'source_id': doc.get('source_id'),
                         'url': doc.get('url'), 'reason': 'snapshot_hash_mismatch'}
                (unread_source_catalog_documents if kind.endswith('_source') else unread).append(issue)
                continue
            meta = dict(doc, siem_id=vendor['id'], siem_name=vendor['name'],
                        retrieved_at=doc.get('retrieved_at') or raw.get('run_at'))
            meta['url'] = doc.get('resolved_url') or doc.get('url')
            if kind.startswith(('pdf_', 'json_')):
                try:
                    rows = adapter(data, meta)
                except Exception as ex:
                    if not kind.endswith('_source'):
                        raise
                    unread_source_catalog_documents.append({
                        'siem_id': vendor['id'], 'source_id': doc.get('source_id'),
                        'url': meta['url'], 'reason': kind.split('_')[0] + '_source_extraction_failed',
                        'detail': f'{type(ex).__name__}: {ex}',
                    })
                    continue
            else:
                try: html = data.decode('utf-8-sig')
                except UnicodeDecodeError: html = data.decode(doc.get('http_charset') or 'utf-8', errors='replace')
                rows = adapter(html, meta)
            if kind == 'html_profile':
                extracted_profiles, extracted_requirements = rows
                profiles.extend(extracted_profiles)
                requirements.extend(extracted_requirements)
                ambiguous = [p for p in extracted_profiles
                             if p.get('applicability', {}).get('diagnostic')]
                if ambiguous:
                    partial_system_documents.append({
                        'siem_id': vendor['id'], 'siem_name': vendor['name'],
                        'source_id': doc.get('source_id'), 'url': meta['url'],
                        'reason': 'published_node_count_conflicts_with_listed_roles',
                        'detail': 'All listed roles were extracted; the published medium-load '
                                  'heading says two servers while three role entries are listed.',
                    })
            else:
                (integrations if kind.endswith('_source') else requirements).extend(rows)
    # The white paper documents the same Windows/Linux paths as the older
    # collection videos. Retain both evidences without counting them twice.
    for row in list(integrations):
        if row['siem_id'] != 'p11' or row.get('integration_evidence') != 'published_collection_video':
            continue
        richer = next((r for r in integrations if r['siem_id'] == 'p11'
                       and r['source_name'] == row['source_name']
                       and r.get('integration_evidence') == 'published_collection_list'), None)
        if richer is not None:
            richer['evidence'].extend(row['evidence'])
            integrations.remove(row)
    type_integrations(integrations)
    integrations.sort(key=lambda r:(r['siem_id'],r['source_entity_id'],r['source_name'].casefold()))
    # A successfully downloaded document may still be unprocessed because no
    # targeted adapter exists. Do NOT silently report this as complete coverage.
    parsed_document_urls = {
        (row['siem_id'], row.get('evidence', {}).get('url'))
        for row in profiles + requirements
    }
    parsed_document_urls.update(
        (row['siem_id'], evidence.get('url'))
        for row in integrations for evidence in row.get('evidence', [])
        if isinstance(evidence, dict)
    )
    unread_document_ids = {(x['siem_id'], x.get('source_id'), x.get('url')) for x in unread}
    unparsed_system_documents = []
    for vendor in raw.get('vendors', []):
        for doc in vendor.get('source_results', []):
            # R-Vision's registered "architecture" URL is actually the
            # source-connection guide, not an infrastructure document.
            if vendor['id'] == 'p03' and doc.get('source_id') == 'architecture':
                continue
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
    catalog = {
        'schema_version':SCHEMA,'source_run_at':raw.get('run_at'),
        '_raw_run': raw,
        'integrations':integrations,'sizing_profiles':profiles,
        'unique_source_values':unique_source_values(integrations),
        'system_requirements':requirements,
        'coverage':coverage,'unread_system_documents':unread,
        'unparsed_system_documents':unparsed_system_documents,
        'partial_system_documents':partial_system_documents,
        'unread_source_catalog_documents':unread_source_catalog_documents,
        'notes':[
            'Only published catalog rows; an entry is not proof that an integration works.',
            'Requirements only from strict rules on designated system-requirement pages.',
            'Null means unknown or uncollected, never unsupported.',
            'Versions inferred from hints are NOT verified product versions.',
        ],
    }
    catalog['schema_validation'] = validate_catalog(catalog)
    return catalog


def write_catalog(catalog: dict, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True,exist_ok=True)
    validation = validate_catalog(catalog)
    catalog['schema_validation'] = validation
    if not validation['valid']:
        (out_dir/'schema_validation.json').write_text(
            json.dumps(validation, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        raise ValueError('Normalized catalog does not satisfy the ETL contract')
    files={
        'readiness_report.json': readiness_report(catalog,catalog.get('_raw_run')),
        'quality_report.json': sizing_quality_report(catalog),
        'sources.json':catalog['integrations'],
        'unique_source_values.json':catalog['unique_source_values'],
        'schema_validation.json': validation,
        'sizing_profiles.json':catalog['sizing_profiles'],
        'system_requirements.json':catalog['system_requirements'],
        'coverage.json':catalog['coverage'],
        'unread_system_documents.json':catalog['unread_system_documents'],
        'unparsed_system_documents.json':catalog['unparsed_system_documents'],
        'partial_system_documents.json':catalog['partial_system_documents'],
        'unread_source_catalog_documents.json':catalog['unread_source_catalog_documents'],
    }
    for name, data in files.items():
        payload = data if name in ('quality_report.json', 'readiness_report.json', 'unique_source_values.json', 'schema_validation.json') else {
            'schema_version': SCHEMA, 'source_run_at': catalog['source_run_at'], 'items': data,
        }
        (out_dir/name).write_text(json.dumps(payload, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')
    return {'integrations':len(catalog['integrations']), 'sizing_profiles':len(catalog['sizing_profiles']),
        'system_requirements':len(catalog['system_requirements']),
        'unread_system_documents':len(catalog['unread_system_documents']),
        'unparsed_system_documents':len(catalog['unparsed_system_documents']),
        'partial_system_documents':len(catalog['partial_system_documents']),
        'unread_source_catalog_documents':len(catalog['unread_source_catalog_documents']),
        'by_product':catalog['coverage']}
