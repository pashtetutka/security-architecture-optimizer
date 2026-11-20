"""Order-independent construction of support claims from extracted records."""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import re
from typing import Any, Iterable, Mapping

from siem.domain.contracts import Assertion, Capability, claim_id, content_digest, route_id
from siem.domain.identity import (IdentityDictionary, ResolutionContext,
                                  IdentityResolution, resolve_name, unresolved_queue)
from siem.domain.contracts import ResolutionStatus
from siem.domain.versions import parse_published_numeric_interval


def unknown_version(raw: str | None = None) -> dict[str, Any]:
    return {'raw':raw,'kind':'unknown','scheme':'opaque','values':[],
            'lower':None,'upper':None,'bounds':None,'status':'unknown'}


def conflicting_claim_diagnostics(claims: Iterable[Mapping[str, Any]],
                                  resolutions: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Flag opposing assertions with identical recorded scope across documents."""
    groups = defaultdict(list)
    for claim in claims:
        if claim['assertion'] == Assertion.UNKNOWN:
            continue
        scope = {key: value for key, value in claim['scope'].items() if key != 'limitations'}
        subject = resolutions[claim['subject_resolution_ref']]['product_ref']
        key = content_digest([claim['siem_product_ref'], subject, claim['capability'],
                              claim['siem_release_scope'], scope])
        groups[key].append(claim)
    diagnostics = []
    for group in groups.values():
        if {claim['assertion'] for claim in group} != {Assertion.SUPPORTED, Assertion.UNSUPPORTED}:
            continue
        refs = sorted({ref for claim in group for ref in claim['evidence_refs']})
        diagnostics.extend({
            'code': 'opposing_support_assertions', 'severity': 'warning',
            'target_ref': claim['claim_id'], 'stage': 'claims',
            'message': 'Opposing support assertions share the same recorded scope; review both',
            'evidence_refs': refs,
        } for claim in group)
    return sorted(diagnostics, key=lambda item: item['target_ref'])


def _scope(record: Mapping[str, Any]) -> dict[str, Any]:
    raw_version=record.get('source_version')
    version=unknown_version(raw_version)
    if raw_version:
        version={'raw':str(raw_version),'kind':'exact','scheme':'opaque','values':[str(raw_version)],
                 'lower':None,'upper':None,'bounds':None,'status':'parsed'}
        if re.fullmatch(r'\d+(?:\.\d+)*(?:\s*,\s+\d+(?:\.\d+)*)*', str(raw_version)):
            values=list(dict.fromkeys(part.strip() for part in str(raw_version).split(',')))
            version.update(kind='set' if len(values)>1 else 'exact',
                           scheme='dotted_numeric', values=values)
        elif interval := parse_published_numeric_interval(str(raw_version)):
            version = interval
    partial=record.get('support_scope') in ('partial','subset')
    limitations=list(filter(None,(record.get('limitation'),record.get('support_limitation'))))
    for field in ('support_limitations', 'collection_limitations'):
        limitations.extend(filter(None, record.get(field) or ()))
    if record.get('normalizer_id') and not str(record['normalizer_id']).startswith('product:'):
        limitations.append('published normalizer identifier: '+str(record['normalizer_id']))
    return {'source_version':version,'edition':record.get('source_edition'),
            'hardware_models':sorted(set(record.get('hardware_models') or [])),
            'event_channels':sorted(set(filter(None, record.get('event_channels') or ()))),
            'extent':'subset' if partial else 'unspecified',
            'conditions':None,'limitations':list(dict.fromkeys(limitations))}


def _make_route(subject_ref: str, siem_ref: str, record: Mapping[str, Any],
                evidence_refs: list[str], intermediate_ref: str | None = None) -> dict[str, Any]:
    transport=record.get('intermediary_transport') if intermediate_ref else record.get('collection_method')
    parser=record.get('normalizer_id')
    if not transport and not parser:
        # This compatibility marker records a catalog listing with no details
        # on transport or topology. It cannot establish a direct route.
        transport='unspecified_published_route'
    parser_ref=parser if str(parser).startswith('product:') else None
    version = _scope(record)['source_version']
    steps=[{'actor_ref':subject_ref,'role':'source','operation':'export',
            'transport':None if intermediate_ref else transport,
            'format':record.get('normalizer_format'),'parser_ref':None,
            'source_release_scope':version,'evidence_refs':evidence_refs},
           {'actor_ref':siem_ref,'role':'siem','operation':'collect','transport':transport,
            'format':record.get('normalizer_format'),
            'parser_ref':None,
            'source_release_scope':_scope(record)['source_version'],'evidence_refs':evidence_refs}]
    if intermediate_ref:
        steps.insert(1, {'actor_ref': intermediate_ref, 'role': 'intermediary',
                         'operation': 'export', 'transport': transport,
                         'format': record.get('normalizer_format'), 'parser_ref': None,
                         'source_release_scope': version, 'evidence_refs': evidence_refs})
    if parser_ref:
        steps.append({'actor_ref':siem_ref,'role':'siem','operation':'normalize',
                      'transport':None,'format':record.get('normalizer_format'),
                      'parser_ref':parser_ref,'source_release_scope':_scope(record)['source_version'],
                      'evidence_refs':evidence_refs})
    route={'route_id':'','subject_ref':subject_ref,'steps':steps,'conditions':None,
           'evidence_refs':evidence_refs,'review_state':'extracted','extensions':[]}
    route['route_id']=route_id(route)
    return route


def normalize_claims(records: Iterable[Mapping[str, Any]], *, siem_product_ref: str,
                     siem_release_scope: Mapping[str, Any], dictionary: IdentityDictionary,
                     evidence_refs: Mapping[int, list[str]] | None = None) -> dict[str, Any]:
    """Build independent claims; never combines version/scope/route across rows."""
    resolutions=[]; claims=[]; routes=[]; diagnostics=[]
    identities_by_id: dict[str, IdentityResolution] = {}
    for index, record in enumerate(records):
        if record.get('field') != 'source_integration':
            continue
        raw_name=str(record.get('source_identity_name_raw') or record.get('value') or '').strip()
        resolution=resolve_name(raw_name,
            ResolutionContext(vendor_ref=record.get('source_vendor_entity_id')),dictionary)
        if (resolution.entity_ref and
                dictionary.entities[resolution.entity_ref].get('type') == 'vendor'):
            resolution=IdentityResolution(resolution.raw_name,resolution.normalized_key,
                ResolutionStatus.UNRESOLVED,None,(),('vendor_name_is_not_product',),
                resolution.dictionary_version)
        resolution_row={'resolution_id':'','raw_name':resolution.raw_name,
                        'normalized_key':resolution.normalized_key,
                        'status':resolution.status.value,'product_ref':resolution.entity_ref,
                        'candidate_refs':list(resolution.candidate_refs),
                        'reason_codes':list(resolution.reason_codes),
                        'dictionary_version':resolution.dictionary_version,'extensions':[]}
        resolution_row['resolution_id']='resolution:'+content_digest(
            {k:v for k,v in resolution_row.items() if k!='resolution_id'}).removeprefix('sha256:')
        resolutions.append(resolution_row)
        identities_by_id[resolution_row['resolution_id']] = resolution
        if resolution.entity_ref is None:
            diagnostics.append({'code':'source_identity_'+resolution.status.value,
                                'severity':'warning','target_ref':resolution_row['resolution_id'],'stage':'identity',
                                'message':','.join(resolution.reason_codes),'evidence_refs':[]})
            continue
        refs=sorted(set((evidence_refs or {}).get(index,record.get('evidence_refs') or [])))
        assertion = Assertion(record.get('support_assertion', Assertion.SUPPORTED))
        if assertion == Assertion.SUPPORTED:
            capability = (Capability.NORMALIZE if str(record.get('normalizer_id')).startswith('product:')
                          else Capability.COLLECT)
        else:
            capability = Capability(record.get('support_capability'))
            if assertion == Assertion.UNSUPPORTED and not refs:
                raise ValueError('Explicit unsupported assertion requires evidence')
        intermediate_ref = None
        intermediate_name = record.get('collection_intermediary')
        if assertion == Assertion.SUPPORTED and intermediate_name:
            intermediate = resolve_name(intermediate_name, None, dictionary)
            intermediate_ref = intermediate.entity_ref
            if dictionary.entities.get(intermediate_ref, {}).get('type') != 'product':
                diagnostics.append({'code': 'route_intermediary_unresolved', 'severity': 'warning',
                                    'target_ref': resolution_row['resolution_id'], 'stage': 'routes',
                                    'message': intermediate_name, 'evidence_refs': refs})
                continue
        route_refs = sorted(set(record.get('collection_evidence_refs', refs)))
        if assertion == Assertion.SUPPORTED and 'collection_evidence_refs' in record and not route_refs:
            raise ValueError('Explicit collection route requires evidence')
        route = (_make_route(resolution.entity_ref,siem_product_ref,record,route_refs,intermediate_ref)
                 if assertion == Assertion.SUPPORTED else None)
        if route: routes.append(route)
        claim={'claim_id':'','siem_product_ref':siem_product_ref,
               'siem_release_scope':deepcopy(siem_release_scope),
               'subject_resolution_ref':resolution_row['resolution_id'],
               'capability':capability.value,
               'assertion':assertion.value,'scope':_scope(record),
               'route_refs':[route['route_id']] if route else [],
               'evidence_refs':sorted(set(refs) | set(route_refs)) if route else refs,
               'review_state':'extracted','extensions':[]}
        claim['claim_id']=claim_id(claim); claims.append(claim)
        if assertion == Assertion.UNKNOWN:
            diagnostics.append({'code': 'source_support_unknown', 'severity': 'warning',
                                'target_ref': claim['claim_id'], 'stage': 'claims',
                                'message': 'Support remains unknown for the stated capability and scope',
                                'evidence_refs': refs})
    # Exact duplicates only. IDs include every semantic field and evidence refs;
    # unlike the old reducer this operation cannot select full/version/notes from
    # different rows and is invariant to input order.
    unique_claims={row['claim_id']:row for row in claims}
    unique_routes={row['route_id']:row for row in routes}
    unique_resolutions={row['resolution_id']:row for row in resolutions}
    return {'claims':[unique_claims[key] for key in sorted(unique_claims)],
            'routes':[unique_routes[key] for key in sorted(unique_routes)],
            'resolutions':[unique_resolutions[key] for key in sorted(unique_resolutions)],'diagnostics':diagnostics,
            'unresolved_queue':unresolved_queue([
                identities_by_id[key] for key in sorted(identities_by_id)])}
