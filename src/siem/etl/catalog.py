"""Build and write the event-source and system-requirements catalog."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json
import hashlib
from typing import TYPE_CHECKING

from .common import SCHEMA, SYSTEM_DOC_IDS, ELIGIBLE_SOURCE_STATUSES
from .sources import normalize_sources
from .requirements import parse_hardware_tables, parse_explicit_requirements
from .vendors.alertix import (parse_alertix_all_in_one, parse_alertix_faq,
                             parse_alertix_architecture, parse_alertix_connectors)
from .vendors.komrad import (parse_komrad_requirements, parse_komrad_catalog,
                             parse_komrad_windows_source, parse_komrad_cyberbackup_scope)
from .vendors.published_claims import (parse_searchinform_overview, parse_usergate_architecture,
                                       parse_solar_architecture, parse_savrus_product,
                                       parse_security_capsule_pdf, parse_savrus_news)
from .vendors.ankey import parse_ankey_low_load
from .vendors.kuma import parse_kuma_requirements
from .vendors.ankey_release import parse_ankey_release_pdf
from .vendors.deployment_context import parse_rvision_deployment, parse_komrad_architecture
from .vendors.maxpatrol import parse_maxpatrol_partial_api, parse_maxpatrol_partial_sources, parse_maxpatrol_supported_api
from .vendors.solar import parse_solar_whitepaper
from .vendors.published_claims import parse_security_capsule_product
from .vendors.rvision import enrich_rvision_profiles, parse_rvision_context_requirements
from .reports.quality import sizing_quality_report
from .reports.readiness import readiness_report
from .identities import type_integrations, unique_source_values
from .source_classes import type_source_classes, source_class_index
from .validation import validate_catalog

if TYPE_CHECKING:
    from .adapters import ExtractionResult


PUBLISHED_ADAPTERS = {
    ('p04', 'configuration'): ('html_mixed', parse_alertix_faq),
    ('p13', 'sources_catalog'): ('html_source', parse_komrad_catalog),
    ('p04', 'connectors_syslog'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'Syslog')),
    ('p04', 'connectors_beats'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'Beats')),
    ('p04', 'connectors_jdbc'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'JDBC')),
    ('p04', 'connectors_snmp'): ('html_source', lambda html, meta: parse_alertix_connectors(html, meta, 'SNMP')),
    ('p06', 'partial_sources'): ('html_source', parse_maxpatrol_partial_sources),
    ('p06', 'supported_sources_api'): ('json_source', parse_maxpatrol_supported_api),
    ('p06', 'partial_sources_api'): ('json_source', parse_maxpatrol_partial_api),
    ('p07', 'compatibility_news'): ('html_source', parse_savrus_news),
    ('p13', 'windows_source'): ('html_source', parse_komrad_windows_source),
    ('p13', 'cyberbackup_scope'): ('html_source', parse_komrad_cyberbackup_scope),
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

def locate_snapshot(value: str | None, base: Path) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path if path.is_file() else None
    # JSON generated on Windows may be read on Linux and vice versa.
    normalized = Path(value.replace('\\', '/'))
    for relative in dict.fromkeys((path, normalized)):
        candidate = base / relative
        if candidate.is_file():
            return candidate
    # Older crawl output recorded paths relative to the invocation directory.
    return next((relative for relative in (path, normalized) if relative.is_file()), None)


def parse_hardware_document(html: str, meta: dict) -> tuple[list[dict], list[dict]]:
    vendor_id = meta['siem_id']
    if vendor_id == 'p12':
        return parse_kuma_requirements(html, meta)
    requirements = []
    if vendor_id == 'p13':
        profiles, requirements = parse_komrad_requirements(html, meta)
    elif vendor_id == 'p04':
        profiles = parse_alertix_all_in_one(html, meta)
    else:
        profiles = parse_hardware_tables(html, meta)
        if vendor_id == 'p03':
            enrich_rvision_profiles(profiles, html)
            requirements.extend(parse_rvision_context_requirements(html, meta))
    requirements.extend(parse_explicit_requirements(html, meta))
    return profiles, requirements


SYSTEM_ADAPTERS = {
    ('p04', 'platform_architecture'): ('html_requirement', parse_alertix_architecture),
    ('p03', 'deployment'): ('html_requirement', parse_rvision_deployment),
    ('p13', 'architecture'): ('html_requirement', parse_komrad_architecture),
}


def normalize_requirements(raw: dict, input_file: Path,
                           published_results: dict[tuple[str, str], ExtractionResult] | None = None
                           ) -> tuple[list[dict],list[dict],list[dict]]:
    profiles,requirements,unread=[],[],[]
    for vendor in raw.get('vendors',[]):
        for s in vendor.get('source_results',[]):
            if s.get('source_id') not in SYSTEM_DOC_IDS or s.get('status') != 'ok': continue
            replay = (published_results or {}).get((vendor['id'], s['source_id']))
            if replay is not None:
                profiles.extend(dict(row) for row in replay.profiles)
                requirements.extend(dict(row) for row in replay.requirements)
                continue
            if not s.get('content_sha256'):
                unread.append({'siem_id':vendor['id'],'source_id':s['source_id'],
                               'url':s.get('url'),'reason':'document_hash_missing'})
                continue
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
            if digest!=s['content_sha256']:
                unread.append({'siem_id':vendor['id'],'source_id':s.get('source_id'),
                    'url':s.get('url'),'reason':'snapshot_hash_mismatch'})
                continue
            try: html=data.decode('utf-8-sig')
            except UnicodeDecodeError: html=data.decode(s.get('http_charset') or 'utf-8',errors='replace')
            meta=dict(s,siem_id=vendor['id'],siem_name=vendor['name'],
                      retrieved_at=s.get('retrieved_at') or raw.get('run_at'))
            meta['url']=s.get('resolved_url') or s.get('url')
            if s.get('source_id')=='hardware_requirements':
                try:
                    extracted_profiles, extracted_requirements = parse_hardware_document(html, meta)
                except ValueError as exc:
                    if vendor['id'] != 'p12':
                        raise
                    unread.append({'siem_id': vendor['id'], 'source_id': s['source_id'],
                                   'url': meta['url'], 'reason': str(exc)})
                    continue
                profiles.extend(extracted_profiles)
                requirements.extend(extracted_requirements)
            elif entry := SYSTEM_ADAPTERS.get((vendor['id'], s['source_id'])):
                requirements.extend(entry[1](html, meta))
            # Other docs deliberately produce nothing until targeted adapters
            # exist; their paragraphs must not masquerade as requirements.
    return profiles,requirements,unread


def validated_source_facts(raw: dict, input_file: Path, *,
                           verified_hashes: dict[tuple[str, str], str] | None = None
                           ) -> tuple[list[dict], list[dict]]:
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
            elif verified_hashes is not None and key in verified_hashes:
                digest = verified_hashes[key]
                if digest != doc['content_sha256']:
                    reason = 'snapshot_hash_mismatch'
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


def build_catalog(raw: dict, input_file: Path, *, automatic_only: bool = False,
                  published_results: dict[tuple[str, str], ExtractionResult] | None = None,
                  verified_hashes: dict[tuple[str, str], str] | None = None) -> dict:
    if automatic_only:
        documents = {(v['id'], d.get('source_id'))
                     for v in raw.get('vendors', []) for d in v.get('source_results', [])
                     if d.get('acquisition_method') == 'automatic_https'}
        raw = {**raw, 'vendors': [{**v, 'source_results': [
            d for d in v.get('source_results', []) if (v['id'], d.get('source_id')) in documents
        ]} for v in raw.get('vendors', [])], 'facts': [
            f for f in raw.get('facts', []) if (f.get('siem_id'), f.get('source_id')) in documents
        ]}
    source_facts, unread_source_catalog_documents = validated_source_facts(
        raw, input_file, verified_hashes=verified_hashes)
    integrations=normalize_sources({'facts': source_facts})
    partial_system_documents=[]
    profiles,requirements,unread=normalize_requirements(raw,input_file,published_results)
    if any(p['siem_id'] == 'p12' for p in profiles):
        partial_system_documents.append({
            'siem_id': 'p12', 'source_id': 'hardware_requirements',
            'url': next(p['evidence']['url'] for p in profiles if p['siem_id'] == 'p12'),
            'reason': 'additional_infrastructure_sections_not_normalized',
            'detail': 'EPS matrix, host OS, base agents and Kubernetes extracted; separate metrics scaling, connector-specific agent performance and optional service sections remain outside this adapter.'})
    for vendor in raw.get('vendors', []):
        for doc in vendor.get('source_results', []):
            key = (vendor['id'], doc.get('source_id'))
            selected = PUBLISHED_ADAPTERS.get(key)
            if selected is None:
                continue
            kind, adapter = selected
            eligible_statuses = ('ok',) if kind == 'html_mixed' else ('ok', 'empty_review_required')
            if doc.get('status') not in eligible_statuses:
                continue
            replay = (published_results or {}).get(key)
            if replay is not None:
                if kind == 'html_profile':
                    rows = ([dict(row) for row in replay.profiles],
                            [dict(row) for row in replay.requirements])
                elif kind == 'html_mixed':
                    rows = ([dict(row) for row in replay.integrations or ()],
                            [dict(row) for row in replay.requirements])
                else:
                    entries = replay.integrations if kind.endswith('_source') else replay.requirements
                    rows = [dict(row) for row in entries or ()]
                meta = {'url': doc.get('resolved_url') or doc.get('url')}
            else:
                issues = unread_source_catalog_documents if kind.endswith('_source') else unread
                if not doc.get('content_sha256'):
                    issues.append({'siem_id': vendor['id'], 'source_id': doc['source_id'],
                                   'url': doc.get('url'), 'reason': 'document_hash_missing'})
                    continue
                snapshot = locate_snapshot(doc.get('snapshot_path'), input_file.parent)
                expected_suffix = '.pdf' if kind.startswith('pdf_') else '.json' if kind.startswith('json_') else '.html'
                if snapshot is None or snapshot.suffix.lower() != expected_suffix:
                    issue = {'siem_id': vendor['id'], 'source_id': doc.get('source_id'),
                             'url': doc.get('url'), 'reason': 'local_snapshot_unavailable_or_unsupported_format'}
                    issues.append(issue)
                    continue
                data = snapshot.read_bytes()
                if hashlib.sha256(data).hexdigest() != doc['content_sha256']:
                    issue = {'siem_id': vendor['id'], 'source_id': doc.get('source_id'),
                             'url': doc.get('url'), 'reason': 'snapshot_hash_mismatch'}
                    issues.append(issue)
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
            elif kind == 'html_mixed':
                faq_sources, faq_requirements = rows
                integrations.extend(faq_sources)
                requirements.extend(faq_requirements)
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
    # A guide with explicit collection limits refines its broad index card.
    # The index must not erase those limits by remaining a separate full claim.
    for guide in list(integrations):
        if guide['siem_id'] != 'p13' or not guide.get('collection_limitations'):
            continue
        for card in list(integrations):
            if (card is not guide and card['siem_id'] == guide['siem_id']
                    and card['source_name'] == guide['source_name']
                    and card.get('integration_evidence') == 'published_integration_guide_index'):
                guide['evidence'].extend(card['evidence'])
                integrations.remove(card)
    type_integrations(integrations)
    type_source_classes(integrations)
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
        'source_classes':source_class_index(integrations),
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


def load_bundled_catalog(path: str | Path = 'data/etl/repro/vendors.json') -> dict:
    """Build the historical preview input from the saved ETL manifest."""
    source = Path(path)
    raw = json.loads(source.read_text(encoding='utf-8'))
    catalog = build_catalog(raw, source, automatic_only=False)
    if not catalog['schema_validation']['valid']:
        raise ValueError('Каталог ETL не прошёл проверку схемы')
    if catalog['unread_system_documents'] or catalog['unread_source_catalog_documents']:
        raise ValueError('Не удалось проверить исходные снимки ETL')
    catalog['readiness'] = readiness_report(catalog, catalog['_raw_run'])
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
        'source_classes.json':catalog['source_classes'],
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
        payload = data if name in ('quality_report.json', 'readiness_report.json', 'unique_source_values.json', 'source_classes.json', 'schema_validation.json') else {
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
