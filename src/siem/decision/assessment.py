"""Read-only comparison for every preloaded organization questionnaire."""
from __future__ import annotations

from collections import defaultdict
import re

from siem.etl.catalog import load_bundled_catalog as load_bundled_catalog
from siem.etl.coverage import canonical

from .scenarios import summarize_scenario
from .sizing import estimate_integrator_eps
from .versions import version_status


def assess_organization(scenario: dict, catalog: dict) -> dict:
    """Show evidence and review priority, never assert unsupported or ready."""
    summary = summarize_scenario(scenario)
    if not catalog.get('schema_validation', {}).get('valid'):
        raise ValueError('Каталог ETL не прошёл проверку схемы')
    indexed = defaultdict(list)
    version_qualified = defaultdict(list)
    families = defaultdict(list)
    for row in catalog['integrations']:
        for product_key in row['source_match_keys']:
            indexed[(row['siem_id'], 'source:' + product_key)].append(row)
        catalog_version = row.get('source_version')
        if catalog_version and re.fullmatch(r'\d+(?:\.\d+)*', catalog_version):
            # A catalog may put "4" in the version column while an inventory
            # names the same product "Product-4". Keep the published row intact.
            version_qualified[(row['siem_id'], canonical(row['source_name'] + ' ' + catalog_version))].append(row)
        for family in (row.get('source_family'), row.get('source_vendor'), row.get('source_name')):
            if family:
                families[(row['siem_id'], canonical(family))].append(row)
        edition = re.fullmatch(r'(.+)\s+Enterprise', row['source_name'], re.I)
        if edition:
            families[(row['siem_id'], canonical(edition.group(1)))].append(row)
    profiles = defaultdict(list)
    for row in catalog['sizing_profiles']:
        profiles[row['siem_id']].append(row)
    ready = {row['siem_id']: row for row in catalog['readiness']['items']}
    model = estimate_integrator_eps(scenario)
    streams_by_device_product = defaultdict(set)
    for source in scenario['event_sources']:
        if source.get('asset_group_id'):
            streams_by_device_product[(source['asset_group_id'], canonical(source['raw_name']))].add(
                source.get('log_stream'))
    has_known_eps = len(summary['unknown_eps_sources']) < len(scenario['event_sources'])
    required_peak = (model['planning_eps_with_25pct_reserve'] if model else
                     summary['known_eps_lower_bound']['peak_eps'])
    eps_basis = 'integrator_model' if model else 'inventory_estimate'
    report = []
    for vendor in catalog['coverage']:
        sid = vendor['siem_id']
        matches = []
        counts = {'published': 0, 'partial': 0, 'version_candidate': 0,
                  'component_candidate': 0, 'family_candidate': 0,
                  'not_found': 0}
        for source in scenario['event_sources']:
            products = source.get('products') or [
                {'name': source['raw_name'], 'version': source['version']}]
            exact_claims = [indexed[(sid, 'source:' + canonical(item['name']))]
                            for item in products]
            if not source.get('products') and not exact_claims[0]:
                exact_claims[0] = indexed[(sid, 'source:' + canonical(source['manufacturer_model']))]
            component_claims = []
            effective_versions = []
            for item, exact in zip(products, exact_claims):
                qualified = version_qualified[(sid, canonical(item['name']))]
                embedded = re.fullmatch(r'(.+?)\s+(\d+(?:\.\d+)*)', canonical(item['name']))
                base_claims = (indexed[(sid, 'source:' + embedded.group(1))]
                               if embedded else [])
                candidates = exact or qualified or base_claims
                stream_claims = [row for row in exact + qualified + base_claims
                                 if source.get('log_stream') in row.get('source_event_kinds', [])]
                component_claims.append(stream_claims or candidates)
                effective_versions.append(item['version'] or (embedded.group(2) if base_claims else None))
            full_claims = [[row for row in claims if row.get('support_scope') != 'partial']
                           for claims in component_claims]
            any_mode = source.get('products_match', 'all') == 'any'
            if (any(full_claims) if any_mode else all(full_claims)):
                status, chosen = 'published', [row for claims in full_claims for row in claims]
                basis = 'catalog_version_qualified_identity' if any(
                    not exact and claims for exact, claims in zip(exact_claims, component_claims)
                ) else 'catalog_identity'
            elif (any(component_claims) if any_mode else all(component_claims)):
                status, chosen, basis = 'partial', [row for claims in component_claims for row in claims], 'published_partial_support'
            elif any(component_claims):
                status, chosen, basis = 'component_candidate', [row for claims in component_claims for row in claims], 'some_components_listed'
            elif source.get('product_family') and families[(sid, canonical(source['product_family']))]:
                status = 'family_candidate'
                chosen = families[(sid, canonical(source['product_family']))]
                basis = 'published_family_only'
            else:
                status, chosen, basis = 'not_found', [], None
            # Multiple catalog claims for one inventory line remain one match.
            chosen = list({id(row): row for row in chosen}.values())
            versions = [version_status(requested, claims) if claims else None
                        for requested, claims in zip(effective_versions, component_claims)]
            version = versions[0] if len(versions) == 1 else versions
            matched_versions = [value for value, claims in zip(versions, full_claims) if claims]
            if status == 'published' and (
                    all(value == 'published_other_versions' for value in matched_versions)
                    if any_mode else 'published_other_versions' in matched_versions):
                status = 'version_candidate'
            counted_for_coverage = status in ('published', 'version_candidate', 'partial')
            partial_scope = status == 'partial'
            version_review = status == 'version_candidate' or any(
                value in ('requires_confirmation', 'published_other_versions') and requested is not None
                for value, requested, claims in zip(versions, effective_versions, component_claims)
                if claims)
            stream_review = (source.get('asset_group_id') is not None and
                             len(streams_by_device_product[(source['asset_group_id'],
                                                            canonical(source['raw_name']))]) > 1)
            stream_review = stream_review or source.get('scope_review_required', False)
            if source.get('kind') == 'directory' and chosen and not any(
                    'active directory domain services' in row['source_match_keys'] for row in chosen):
                stream_review = True
            counts[status] += 1
            matches.append({
                'source': source['raw_name'], 'source_type': source['source_type'],
                'manufacturer_model': source['manufacturer_model'],
                'requested_version': source['version'] or (effective_versions[0] if len(products) == 1 else None),
                'products': products,
                'component_assessments': [
                    {'name': item['name'], 'requested_version': requested,
                     'listed': bool(claims), 'fully_listed': bool(full),
                     'published_names': list(dict.fromkeys(row['source_name'] for row in claims))}
                    for item, requested, claims, full in zip(
                        products, effective_versions, component_claims, full_claims)
                ],
                'products_match': source.get('products_match', 'all'),
                'requirement': source['requirement'],
                'status': status, 'match_basis': basis,
                'counted_for_coverage': counted_for_coverage,
                'partial_support': partial_scope,
                'support_limitations': list(dict.fromkeys(
                    limitation for row in chosen for limitation in
                    row.get('support_limitations', []) + row.get('collection_limitations', []))),
                'version_review_required': version_review,
                'collection_scope_review_required': stream_review,
                'version_scope': version,
                'asset_group_id': source.get('asset_group_id'),
                'log_stream': source.get('log_stream'),
                'evidence': [{
                    'source_name': row['source_name'],
                    'source_version': row.get('source_version'),
                    'support_scope': row.get('support_scope'),
                    'acquisition_method': row['evidence'][0].get('acquisition_method') if row.get('evidence') else None,
                    'url': row['evidence'][0]['url'] if row.get('evidence') else None,
                    'excerpt': row['evidence'][0]['excerpt'] if row.get('evidence') else None,
                } for row in (sorted(chosen, key=lambda row: version_status(source['version'], [row])
                                      not in ('published_version_listed', 'version_in_published_name'))[:3])],
            })
        eps_profiles = [row for row in profiles[sid] if required_peak is not None and
                        (has_known_eps or model is not None)
                        if row.get('eps_to') is not None and row['eps_to'] >= required_peak
                        and (row.get('eps_from') is None or row['eps_from'] <= required_peak)
                        and row.get('sizing_scope') != 'edition_minimum_not_eps_sizing']
        profile_evidence = [{
            'scenario': row.get('scenario'), 'eps_from': row.get('eps_from'),
            'eps_to': row.get('eps_to'), 'node_roles': [node.get('role') for node in row.get('nodes', [])],
            'url': (row.get('evidence') or {}).get('url'), 'eps_basis': eps_basis,
        } for row in eps_profiles]
        # A compatible EPS interval alone is not proof of deployability.
        if model:
            capacity_status = ('modeled_eps_profile_requires_review' if profile_evidence else
                               'no_published_profile_for_modeled_eps')
        elif summary['unknown_eps_sources']:
            capacity_status = 'unknown_total_eps'
        elif profile_evidence:
            capacity_status = 'eps_profile_found_needs_architecture_review'
        else:
            capacity_status = 'no_applicable_published_eps_profile'
        required_matches = sum(row['status'] == 'published' and row['requirement'] != 'desired'
                               for row in matches)
        required_counted = sum(row['counted_for_coverage'] and row['requirement'] != 'desired'
                               for row in matches)
        required_total = sum(row['requirement'] != 'desired' for row in matches)
        candidate_matches = sum(row['status'] in ('version_candidate', 'component_candidate', 'family_candidate', 'partial')
                                for row in matches)
        version_review_count = sum(row['version_review_required'] for row in matches)
        questions = [f"Подтвердить интеграцию: {row['source']}"
                     for row in matches if row['requirement'] != 'desired' and row['status'] != 'published']
        if any(row['counted_for_coverage'] and row['collection_scope_review_required'] for row in matches):
            questions.append('Подтвердить отдельный сбор каждого журнала с одного устройства')
        if version_review_count:
            questions.append('Подтвердить версии источников с пометкой проверки')
        if not profile_evidence and (has_known_eps or model):
            questions.append('Запросить применимый sizing-профиль для пикового EPS')
        if summary['unknown_eps_sources']:
            questions.append('Измерить EPS источников с неизвестной нагрузкой')
        questions.append('Подтвердить версии, HA, ОС, сеть и доступные ресурсы у вендора')
        report.append({
            'siem_id': sid, 'siem_name': vendor['siem_name'],
            'catalog_integration_count': vendor['integrations'],
            'source_counts': counts, 'required_published': required_matches,
            'required_counted': required_counted,
            'required_total': required_total, 'candidate_matches': candidate_matches,
            'version_review_count': version_review_count,
            'source_matches': matches,
            'capacity_status': capacity_status, 'candidate_eps_profiles': profile_evidence,
            'calculation_ready': ready[sid]['calculation_ready'],
            'blocking_reasons': ready[sid]['blocking_reasons'],
            'review_questions': questions,
        })
    # This is a review queue based on evidence, not a product quality score.
    report.sort(key=lambda row: (-row['required_counted'], -row['candidate_matches'],
                                 -bool(row['candidate_eps_profiles']), row['siem_name']))
    inventory_audit = []
    for index, source in enumerate(scenario['event_sources']):
        states = defaultdict(list)
        for vendor in report:
            states[vendor['source_matches'][index]['status']].append(vendor['siem_name'])
        inventory_audit.append({
            'row': index + 1, 'source_type': source['source_type'],
            'manufacturer_model': source['manufacturer_model'],
            'quantity': source['quantity'], 'asset_group_id': source.get('asset_group_id'),
            'log_stream': source.get('log_stream'),
            'published_name_in': states['published'],
            'counted_in': states['published'] + states['version_candidate'] + states['partial'],
            'partial_in': states['partial'],
            'version_candidate_in': states['version_candidate'],
            'component_candidate_in': states['component_candidate'],
            'family_candidate_in': states['family_candidate'],
            'not_found_in': states['not_found'],
        })
    return {'scenario': summary, 'integrator_eps_model': model,
            'document_acquisition_methods': sorted({doc.get('acquisition_method', 'unknown')
                for vendor in catalog.get('_raw_run', {}).get('vendors', [])
                for doc in vendor.get('source_results', [])}),
            'catalog_run_at': catalog['source_run_at'],
            'catalog_counts': catalog['schema_validation']['counts'],
            'assessment_status': 'preliminary_review',
            'inventory_audit': inventory_audit, 'vendors': report}
