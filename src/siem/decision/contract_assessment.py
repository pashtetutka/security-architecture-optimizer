"""Ranking-free questionnaire projection over the public v2 contract."""
from __future__ import annotations
from collections import defaultdict
from typing import Any, Mapping

from siem.domain.identity import IdentityDictionary, resolve_name
from siem.domain.versions import compare_versions

POLICY_VERSION='preview-coverage/1.0'
MODEL_POLICY_VERSION='preview-coverage/1.1-candidate'


def _requested_version(value: str | None):
    if value is None:return None
    return {'raw':value,'kind':'exact','scheme':'opaque','values':[value],
            'lower':None,'upper':None,'bounds':None,'status':'parsed'}


def project_legacy_coverage(scenario: Mapping[str,Any],bundle: Mapping[str,Any],
                            dictionary: IdentityDictionary,
                            policy_version: str=POLICY_VERSION) -> dict[str,Any]:
    if policy_version not in (POLICY_VERSION, MODEL_POLICY_VERSION):
        raise ValueError('unsupported coverage policy')
    if bundle['manifest']['dictionary_version'] != dictionary.version:
        raise ValueError('bundle and questionnaire dictionary versions differ')
    products={p['id']:p for p in bundle['products']};resolutions={r['resolution_id']:r for r in bundle['resolutions']}
    evidence={e['evidence_id']:e for e in bundle['evidence']};documents={d['document_id']:d for d in bundle['documents']}

    def describe_evidence(ref: str) -> dict[str, Any]:
        item = evidence[ref]
        document = documents[item['document_ref']]
        return {
            'evidence_ref': ref, 'document_ref': document['document_id'],
            'document_sha256': document['sha256'], 'locator': item['locator'],
            'url': document['resolved_url'], 'excerpt': item['excerpt'],
            'acquisition_method': document['acquisition_method'],
        }

    claims=defaultdict(list)
    nonpositive_claims=defaultdict(list)
    conflicts = {item['target_ref']: item for item in bundle['diagnostics']
                 if item['code'] == 'opposing_support_assertions'}
    for claim in bundle['claims']:
        resolution=resolutions[claim['subject_resolution_ref']]
        if resolution['product_ref']:
            index=claims if claim['assertion']=='supported' else nonpositive_claims
            index[(claim['siem_product_ref'],resolution['product_ref'])].append(claim)
    siems=sorted((p for p in bundle['products'] if 'siem' in p['class_ids']),key=lambda p:p['id'])
    parents=defaultdict(list)
    for relation in dictionary.relations:
        if relation['relation'] == 'member_of':
            parents[relation['from_ref']].append(relation)
    vendors=[]
    for siem in siems:
        matches=[]
        for source in scenario['event_sources']:
            requested=source.get('products') or [{'name':source['raw_name'],'version':source.get('version')}]
            components=[]
            relation_candidates=[]
            related_claim_refs=set()
            model_resolution=resolve_name(source['manufacturer_model'],None,dictionary)
            if not model_resolution.entity_ref and '/' in source['manufacturer_model']:
                model_resolution=resolve_name(source['manufacturer_model'].replace('/', ' '),None,dictionary)
            for item in requested:
                resolution=resolve_name(item['name'],None,dictionary)
                found=claims.get((siem['id'],resolution.entity_ref),[]) if resolution.entity_ref else []
                if (not found and policy_version == MODEL_POLICY_VERSION
                        and len(requested) == 1 and any(
                            relation['to_ref'] == resolution.entity_ref
                            for relation in parents.get(model_resolution.entity_ref, ()))):
                    found=claims.get((siem['id'],model_resolution.entity_ref),[])
                    related_claim_refs.update(claim['claim_id'] for claim in found)
                if not found and policy_version == MODEL_POLICY_VERSION:
                    found=[
                        claim
                        for relation in parents.get(resolution.entity_ref, ())
                        for claim in claims.get((siem['id'], relation['to_ref']), ())
                        if compare_versions(_requested_version(item.get('version')),
                                            claim['scope']['source_version']).status == 'match'
                    ]
                    related_claim_refs.update(claim['claim_id'] for claim in found)
                components.append((item,resolution,found))
                if found:
                    continue
                for relation in parents.get(resolution.entity_ref, ()):
                    for claim in claims.get((siem['id'], relation['to_ref']), ()):
                        relation_candidates.append({
                            'requested_product_ref': resolution.entity_ref,
                            'published_product_ref': relation['to_ref'],
                            'relation': relation['relation'],
                            'claim_ref': claim['claim_id'],
                            'evidence_refs': claim['evidence_refs'],
                            'published_version': claim['scope']['source_version'],
                        })
            any_mode=source.get('products_match','all')=='any'
            present=any(bool(rows) for _,_,rows in components) if any_mode else all(bool(rows) for _,_,rows in components)
            some=any(bool(rows) for _,_,rows in components)
            selected=[claim for _,_,rows in components for claim in rows]
            partial=bool(selected) and all(c['scope']['extent']=='subset' for c in selected)
            if present and related_claim_refs:status='relation_match'
            elif present:status='partial' if partial else 'published'
            elif some:status='component_candidate'
            else:status='not_found'
            claim_applicability=[]
            for item,_,rows in components:
                for claim in rows:
                    fit = compare_versions(_requested_version(item.get('version')),
                                           claim['scope']['source_version'])
                    claim_applicability.append({
                        'claim_ref': claim['claim_id'], 'product': item['name'],
                        'requested_version': item.get('version'),
                        'published_version': claim['scope']['source_version']['raw'],
                        'version_status': fit.status, 'reason_codes': list(fit.reason_codes),
                        'extent': claim['scope']['extent'],
                    })
            version_fits=[item['version_status'] for item in claim_applicability]
            version_review=any(x in ('mismatch','unknown') for x in version_fits) and any(i.get('version') for i,_,_ in components)
            trace=[]
            for claim in selected:
                for ref in claim['evidence_refs']:
                    trace.append({'claim_ref':claim['claim_id'],'route_refs':claim['route_refs'],
                                  'match_basis':'relation' if claim['claim_id'] in related_claim_refs else 'identity',
                                  'capability':claim['capability'],'review_state':claim['review_state'],
                                  **describe_evidence(ref),
                                  'source_name':resolutions[claim['subject_resolution_ref']]['raw_name'],
                                  'source_version':claim['scope']['source_version']['raw'],
                                  'support_scope':claim['scope']['extent']})
            row_diagnostics = [conflicts[ref] for ref in dict.fromkeys(
                claim['claim_id'] for claim in selected) if ref in conflicts]
            matches.append({'source':source['raw_name'],'source_type':source['source_type'],
                'manufacturer_model':source['manufacturer_model'],'requested_version':source.get('version'),
                'products':requested,'products_match':source.get('products_match','all'),
                'requirement':source['requirement'],'status':status,
                'counted_for_coverage':status in ('published','partial','relation_match'),'partial_support':partial,
                'version_review_required':version_review,
                'collection_scope_review_required':bool(related_claim_refs or row_diagnostics) or source.get('scope_review_required',False),
                'diagnostics':row_diagnostics,
                'support_limitations':sorted({x for c in selected for x in c['scope']['limitations']}),
                'version_scope':version_fits or ['unknown'],'evidence':trace,
                'claim_applicability':claim_applicability,
                'relation_candidates':relation_candidates,
                'nonpositive_claims':[
                    {'claim_ref':claim['claim_id'],'assertion':claim['assertion'],
                     'capability':claim['capability'],'scope':claim['scope'],
                     'review_state':claim['review_state'],'route_refs':claim['route_refs'],
                     'evidence_refs':claim['evidence_refs'],
                     'evidence':[describe_evidence(ref) for ref in claim['evidence_refs']]}
                    for _, resolution, _ in components
                    for claim in nonpositive_claims.get((siem['id'],resolution.entity_ref), ())
                ],
                'model_candidates':[
                    {'product_ref':model_resolution.entity_ref,
                     'claim_ref':claim['claim_id'],'evidence_refs':claim['evidence_refs'],
                     'published_version':claim['scope']['source_version']}
                    for claim in claims.get((siem['id'],model_resolution.entity_ref), ())
                    if any(relation['to_ref'] == resolution.entity_ref
                           for relation in parents.get(model_resolution.entity_ref, ())
                           for _, resolution, _ in components)
                ],
                'component_assessments':[{'name':i['name'],'requested_version':i.get('version'),
                                          'product_ref':resolution.entity_ref,
                                          'identity_status':resolution.status.value,
                                          'candidate_refs':list(resolution.candidate_refs),
                                          'identity_reason_codes':list(resolution.reason_codes),
                                          'listed':bool(rows),'fully_listed':any(c['scope']['extent']!='subset' for c in rows),
                                          'published_names':sorted({resolutions[c['subject_resolution_ref']]['raw_name'] for c in rows})}
                                         for i,resolution,rows in components]})
        vendors.append({'siem_id':siem['id'].removeprefix('product:siem-'),'siem_product_ref':siem['id'],
                        'siem_name':siem['display_name'],'source_matches':matches,
                        'required_counted':sum(x['counted_for_coverage'] and x['requirement']!='desired' for x in matches),
                        'required_total':sum(x['requirement']!='desired' for x in matches)})
    used_claim_refs = {item['claim_ref'] for vendor in vendors for row in vendor['source_matches']
                       for item in (*row['evidence'], *row['nonpositive_claims'])}
    used_claims = [claim for claim in bundle['claims'] if claim['claim_id'] in used_claim_refs]
    used_routes = {ref for claim in used_claims for ref in claim['route_refs']}
    return {'schema_version':'questionnaire-projection/1.0','policy_version':policy_version,
            'dataset_digest':bundle['manifest']['content_digest'],'dictionary_version':dictionary.version,
            'scenario_id':scenario['scenario_id'],'vendors':vendors,'claims':used_claims,
            'routes':[route for route in bundle['routes'] if route['route_id'] in used_routes]}
