"""Deterministic migration from the frozen legacy catalog to v2 facts.

This is a temporary producer boundary. Consumers read the resulting bundle and
must not import legacy vendor adapters.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from siem.domain.contracts import bundle_content_digest, claim_id, evidence_id
from siem.domain.identity import IdentityDictionary, ResolutionContext, resolve_name
from siem.domain.validation import validate_bundle
from .catalog import build_catalog
from .claims import conflicting_claim_diagnostics, normalize_claims, unknown_version
from .hardware_contract import (REQUIREMENT_SCOPE_FIELDS, legacy_profile_to_typed,
                                legacy_requirement_to_typed)
from .adapters import ExtractionResult, replay_facts_from_snapshots
from .snapshots import validate_manifest_source_keys


def _uri(value: str) -> str:
    parts=urlsplit(value)
    return urlunsplit((parts.scheme,parts.netloc,quote(parts.path,safe='/%:@'),parts.query,parts.fragment))


def _document(source: dict, restricted_shas: set[str] | None=None,
              include_snapshot_paths: bool=False) -> dict | None:
    sha=source.get('content_sha256')
    if not sha: return None
    restricted=(source.get('redistribution')=='permission_required_do_not_publish_snapshot' or
                sha in (restricted_shas or set()))
    source_path=source.get('snapshot_path');suffix=Path(source_path).suffix if source_path else ''
    included_path=(f'snapshots/{sha}{suffix}' if include_snapshot_paths and source_path and not restricted else None)
    return {'document_id':'document:'+sha,'sha256':sha,'source_url':_uri(source['url']),
            'resolved_url':_uri(source.get('resolved_url',source['url'])),
            'acquired_at':source.get('retrieved_at') or '1970-01-01T00:00:00+00:00',
            'acquisition_method':source.get('acquisition_method') if source.get('acquisition_method') in ('automatic_https','manual_import') else 'manual_import',
            'snapshot_path':included_path,'media_type':(source.get('http_content_type') or 'text/plain').split(';')[0],
            'release_scope':unknown_version(source.get('product_version_hint')),
            'redistribution':'restricted' if restricted else 'unknown',
            'snapshot_omission':None if included_path else {
                'reason':'redistribution restricted or snapshot remains outside this catalog payload',
                'external_requirement':'use an authorized source snapshot and verify SHA-256'},
            'extensions':[]}


def _evidence(row: dict, document_ref: str, *, preserve_locator: bool=False) -> dict:
    source=(row.get('evidence') or [{}])[0]
    excerpt=' '.join(str(source.get('excerpt') or row.get('source_name') or 'published catalog entry').split())
    page=source.get('page')
    section=source.get('section') if preserve_locator else None
    kind='pdf' if preserve_locator and page is not None else 'html' if section else 'document'
    value={'evidence_id':'','document_ref':document_ref,
           'locator':{'kind':kind,'section':section,'table':None,'row':None,
                      'page':page,'cell':None,'text_normalization':'whitespace_collapse_v1'},
           'excerpt':excerpt,'excerpt_sha256':hashlib.sha256(excerpt.encode('utf-8')).hexdigest(),
           'extraction_method':source.get('extraction_method') or 'legacy_catalog_migration',
           'extractor_version':'legacy-migration/1.0','extensions':[]}
    value['evidence_id']=evidence_id(value); return value


def _claim_subject_names(row: dict, dictionary: IdentityDictionary,
                         parent_refs: dict[str, set[str]]) -> list[str]:
    primary = row.get('source_identity_name_raw') or row['source_name']
    keys = list(dict.fromkeys(row.get('source_match_keys') or [primary]))
    if len(keys) < 2:
        return keys
    context = ResolutionContext(vendor_ref=row.get('source_vendor_entity_id'))
    product = resolve_name(keys[0], context, dictionary).entity_ref
    parents = parent_refs.get(product, set())
    if not parents:
        return keys
    # A synthetic family key cannot broaden a documented member.
    return [keys[0], *(key for key in keys[1:]
                       if resolve_name(key, context, dictionary).entity_ref not in parents)]


def build_migration_bundle(raw_manifest: dict, manifest_path: Path,
                           dictionary: IdentityDictionary,
                           include_snapshot_paths: bool=False, *,
                           automatic_only: bool=False) -> dict[str, Any]:
    validate_manifest_source_keys(raw_manifest)
    # The compatibility catalog assigns hardware positions in traversal order.
    # Canonicalize unordered manifest records before replay and migration.
    raw_manifest = {**raw_manifest, 'vendors': [
        {**vendor, 'source_results': sorted(
            (document for document in vendor.get('source_results', ())
             if not automatic_only or document.get('acquisition_method') == 'automatic_https'),
            key=lambda document: document['source_id'],
        )}
        for vendor in sorted(raw_manifest['vendors'], key=lambda vendor: vendor['id'])
    ]}
    registry_path=manifest_path.resolve().parents[2]/'etl/vendors.json'
    published_results: dict[tuple[str, str], ExtractionResult] = {}
    verified_hashes: dict[tuple[str, str], str] = {}
    replayed={**raw_manifest,'facts':replay_facts_from_snapshots(
        raw_manifest,manifest_path,registry_path,published_results=published_results,
        verified_hashes=verified_hashes)}
    root=manifest_path.resolve().parents[3]
    # The compatibility catalog accepts absolute paths. Anchor them to the
    # replay root so its CWD fallback cannot select a different file.
    legacy_inputs=deepcopy(replayed)
    for vendor in legacy_inputs['vendors']:
        for document in vendor.get('source_results', []):
            raw_path=document.get('snapshot_path')
            if not raw_path:
                continue
            relative=Path(raw_path)
            absolute=(root/relative).resolve()
            if relative.is_absolute() or not absolute.is_relative_to(root):
                raise ValueError('snapshot path must be relative to the replay root')
            document['snapshot_path']=str(absolute)
    legacy=build_catalog(legacy_inputs,manifest_path,automatic_only=False,
                         published_results=published_results, verified_hashes=verified_hashes)
    unread=legacy['unread_system_documents'] + legacy['unread_source_catalog_documents']
    if unread:
        details=', '.join(f"{row['siem_id']}/{row['source_id']}: {row['reason']}" for row in unread)
        raise ValueError('Cannot build v2 from unreadable source documents: '+details)
    permission_path=manifest_path.resolve().parent/'permission_observations.json'
    restricted_shas=set()
    if permission_path.exists():
        permission=json.loads(permission_path.read_text('utf-8'))
        restricted_shas={x['document_sha256'] for x in permission.get('observations',[])
                         if x.get('restriction')=='restricted' and x.get('owner_permission')!='approved'}
    vendors=[];products=[]
    for item in raw_manifest['vendors']:
        vendors.append({'id':'vendor:'+item['id'],'display_name':item['name'],'extensions':[]})
        products.append({'id':'product:siem-'+item['id'],'vendor_id':'vendor:'+item['id'],
                         'display_name':item['name'],'kind':'product','class_ids':['siem'],'extensions':[]})
    vendors.append({'id':'vendor:legacy-ontology','display_name':'Legacy ontology migration','extensions':[]})
    included_products={row['id'] for row in products}
    for entity_id,entity in dictionary.entities.items():
        if entity.get('type') not in ('product','family'): continue
        vendor_ref=entity.get('vendor_ref')
        if not vendor_ref or vendor_ref not in dictionary.entities:
            vendor_id='vendor:legacy-ontology'
        else:
            vendor_id=vendor_ref
            if vendor_id not in {v['id'] for v in vendors}:
                vendors.append({'id':vendor_id,'display_name':dictionary.entities[vendor_id]['display_name'],'extensions':[]})
        products.append({'id':entity_id,'vendor_id':vendor_id,'display_name':entity['display_name'],
                         'kind':entity['type'],'class_ids':['event_source'],'extensions':[]})
        included_products.add(entity_id)
    source_by_sha={}
    for vendor in raw_manifest['vendors']:
        for source in vendor.get('source_results',[]):
            if source.get('content_sha256'): source_by_sha[source['content_sha256']]=source
    documents={}; evidence={}; claims=[];routes=[];resolutions=[];diagnostics=[]
    parent_refs: dict[str, set[str]] = {}
    for relation in dictionary.relations:
        if relation['relation'] == 'member_of':
            parent_refs.setdefault(relation['from_ref'], set()).add(relation['to_ref'])
    for index,row in enumerate(legacy['integrations']):
        source=(row.get('evidence') or [{}])[0]; sha=source.get('document_sha256')
        if not sha or sha not in source_by_sha: continue
        document=_document(source_by_sha[sha],restricted_shas,include_snapshot_paths); documents[document['document_id']]=document
        ev=_evidence(row,document['document_id']); evidence[ev['evidence_id']]=ev
        claim_evidence = {ev['evidence_id']}
        for supporting_source in row.get('evidence', [])[1:]:
            supporting_sha = supporting_source.get('document_sha256')
            if supporting_sha not in source_by_sha:
                continue
            supporting_document = _document(source_by_sha[supporting_sha], restricted_shas,
                                            include_snapshot_paths)
            documents[supporting_document['document_id']] = supporting_document
            supporting_evidence = _evidence({**row, 'evidence': [supporting_source]},
                                            supporting_document['document_id'],
                                            preserve_locator=True)
            evidence[supporting_evidence['evidence_id']] = supporting_evidence
            claim_evidence.add(supporting_evidence['evidence_id'])
        explicit_keys = _claim_subject_names(row, dictionary, parent_refs)
        for explicit_key in explicit_keys:
            record=deepcopy(row); record['field']='source_integration';record['value']=explicit_key
            record['source_identity_name_raw']=explicit_key
            result=normalize_claims([record],siem_product_ref='product:siem-'+row['siem_id'],
                                    siem_release_scope=unknown_version(row.get('siem_version_hint')),
                                    dictionary=dictionary,evidence_refs={0:[ev['evidence_id']]})
            resolutions.extend(result['resolutions'])
            for claim in result['claims']:
                resolution=next(x for x in result['resolutions'] if x['resolution_id']==claim['subject_resolution_ref'])
                product=next((x for x in products if x['id']==resolution['product_ref']),None)
                if not product:
                    diagnostics.append({'code':'source_identity_not_concrete','severity':'warning',
                        'target_ref':resolution['resolution_id'],'stage':'identity',
                        'message':'missing entity cannot produce a positive support claim',
                        'evidence_refs':[ev['evidence_id']]})
                    continue
                # A secondary listing may corroborate the product but need not
                # describe the route or its individual steps.
                original_id = claim['claim_id']
                claim['evidence_refs'] = sorted(claim_evidence.union(claim['evidence_refs']))
                claim['claim_id'] = claim_id(claim)
                for diagnostic in result['diagnostics']:
                    if diagnostic['target_ref'] == original_id:
                        diagnostic['target_ref'] = claim['claim_id']
                claims.append(claim); route_ids=set(claim['route_refs'])
                routes.extend(x for x in result['routes'] if x['route_id'] in route_ids)
            diagnostics.extend(result['diagnostics'])
    profiles=[];requirements=[]
    for index,row in enumerate(legacy['sizing_profiles']):
        source=row.get('evidence') or {};sha=source.get('document_sha256')
        if not sha or sha not in source_by_sha: continue
        document=_document(source_by_sha[sha],restricted_shas,include_snapshot_paths);documents[document['document_id']]=document
        evidence_row=_evidence({'source_name':row.get('component'),'evidence':[source]},document['document_id'],
                               preserve_locator=True)
        evidence[evidence_row['evidence_id']]=evidence_row
        typed,issues=legacy_profile_to_typed(row,index);refs=[evidence_row['evidence_id']]
        typed['evidence_refs']=refs
        for node in typed['nodes']:
            node['evidence_refs']=refs
            for storage in node['storage_groups']:storage['evidence_refs']=refs
        profiles.append(typed)
        diagnostics.extend({'code':issue['code'],'severity':'warning','target_ref':issue['target_ref'],
                            'stage':'hardware_migration','message':issue['message'],'evidence_refs':refs}
                           for issue in issues)
    for index,row in enumerate(legacy['system_requirements']):
        source=row.get('evidence') or {};sha=source.get('document_sha256')
        if not sha or sha not in source_by_sha: continue
        document=_document(source_by_sha[sha],restricted_shas,include_snapshot_paths);documents[document['document_id']]=document
        evidence_row=_evidence({'source_name':row.get('component'),'evidence':[source]},document['document_id'],
                               preserve_locator=True)
        evidence[evidence_row['evidence_id']]=evidence_row
        typed,issues=legacy_requirement_to_typed(row,index);typed['evidence_refs']=[evidence_row['evidence_id']]
        for extension in typed['extensions']:
            extension['evidence_refs'] = typed['evidence_refs']
        requirements.append(typed)
        diagnostics.extend({'code':issue['code'],'severity':'warning','target_ref':typed['requirement_id'],
                            'stage':'hardware_migration','message':issue['message'],
                            'evidence_refs':[evidence_row['evidence_id']]}
                           for issue in issues)
    resolutions={x['resolution_id']:x for x in resolutions}
    claims={x['claim_id']:x for x in claims};routes={x['route_id']:x for x in routes}
    guide_routes = {}
    for guide in replayed['facts']:
        if guide['field'] != 'collection_route_guide':
            continue
        siem_ref = 'product:siem-' + guide['siem_id']
        subject = resolve_name(guide['product'], None, dictionary).entity_ref
        candidates = [claim for claim in claims.values()
                      if claim['siem_product_ref'] == siem_ref
                      and claim['assertion'] == 'supported' and claim['capability'] == 'collect'
                      and resolutions[claim['subject_resolution_ref']]['product_ref'] == subject
                      and claim['scope']['source_version']['raw'] == guide['source_version']]
        if len(candidates) != 1:
            raise ValueError(f"Route guide needs one catalog claim for {siem_ref}/{guide['product']}")
        claim = candidates[0]
        document = _document(source_by_sha[guide['source_sha256']], restricted_shas, include_snapshot_paths)
        documents[document['document_id']] = document
        proof = _evidence({'evidence': [{'excerpt': guide['heading'], 'section': guide['heading']}]},
                          document['document_id'], preserve_locator=True)
        proof_ref = proof['evidence_id']
        evidence[proof_ref] = proof
        route_record = {'field': 'source_integration', 'value': guide['product'],
                        'collection_method': guide['transport'], 'source_version': guide['source_version'],
                        'collection_evidence_refs': [proof_ref]}
        if intermediary := guide.get('intermediary'):
            route_record.update(collection_intermediary=intermediary,
                                intermediary_transport=guide['transport'])
        result = normalize_claims([route_record], siem_product_ref=siem_ref,
                                  siem_release_scope=claim['siem_release_scope'], dictionary=dictionary)
        if not result['routes']:
            raise ValueError(f"Cannot resolve the route in {guide['source_id']}: {result['diagnostics']}")
        route, = result['routes']
        routes[route['route_id']] = route
        channels = tuple(guide.get('event_channels', ()))
        separated = guide.get('scope_by_event_channels', False)
        guide_routes.setdefault(claim['claim_id'], []).append((route['route_id'], proof_ref, channels, separated))
    superseded_routes = set()
    for ref, alternatives in guide_routes.items():
        claim = claims.pop(ref)
        superseded_routes.update(claim['route_refs'])
        separation = {separate for _, _, _, separate in alternatives}
        if len(separation) != 1 or (True in separation and any(not channels for _, _, channels, _ in alternatives)):
            raise ValueError(f"Inconsistent route guide stream scopes for {ref}")
        groups = {}
        for route, proof, channels, separate in alternatives:
            groups.setdefault(tuple(sorted(set(channels))) if separate else (), []).append((route, proof, channels))
        for separated_channels, group in groups.items():
            scoped_claim = deepcopy(claim)
            scoped_claim['route_refs'] = sorted({route for route, _, _ in group})
            scoped_claim['evidence_refs'] = sorted(set(claim['evidence_refs']) | {proof for _, proof, _ in group})
            if separated_channels:
                scoped_claim['scope']['event_channels'] = list(separated_channels)
                scoped_claim['scope']['extent'] = 'subset'
            else:
                # Claim-wide channels must be documented for every alternative.
                shared_channels = set.intersection(*(set(channels) for _, _, channels in group))
                scoped_claim['scope']['event_channels'] = sorted(set(claim['scope']['event_channels']) | shared_channels)
            scoped_claim['claim_id'] = claim_id(scoped_claim)
            claims[scoped_claim['claim_id']] = scoped_claim
    used_routes = {ref for claim in claims.values() for ref in claim['route_refs']}
    for ref in superseded_routes - used_routes:
        routes.pop(ref)
    for document in documents.values():
        if document['snapshot_path'] is None:
            diagnostics.append({'code':'document_snapshot_omitted','severity':'warning',
                'target_ref':document['document_id'],'stage':'packaging',
                'message':'snapshot bytes are omitted; release scope and redistribution remain unknown where not documented',
                'evidence_refs':[]})
    diagnostics.extend(conflicting_claim_diagnostics(claims.values(), resolutions))
    dataset_id='dataset:legacy-migration-v2'
    has_facts=bool(claims or profiles or requirements)
    if not has_facts:
        diagnostics.append({'code':'no_data','severity':'warning','target_ref':dataset_id,
                            'stage':'migration','message':'No support or hardware facts were extracted',
                            'evidence_refs':[]})
    diagnostics={(x['code'],x['target_ref'],tuple(x['evidence_refs'])):x for x in diagnostics}
    bundle={'schema_version':'siem-catalog/2.0','status':'data' if has_facts else 'no_data',
      'manifest':{'schema_version':'siem-catalog/2.0','dataset_id':dataset_id,
        'content_digest':'sha256:'+'0'*64,'input_document_ids':sorted(documents),
        'dictionary_version':dictionary.version,'normalizer_version':'claims/1.0',
        'extractor_versions':{'legacy-migration':'1.0'},
        'build_options':{'automatic_only':automatic_only,'public_bundle':False},'payloads':[]},
      'build':{'build_id':'build:migration-preview','built_at':'1970-01-01T00:00:00+00:00',
        'source_revision':'working-tree','input_manifests':[],
        'dependency_lock_digest':'sha256:'+'0'*64},
      'extension_registry':{'version':'1.0','entries':[
          {'key':key,'type':'string','unit':None,'allowed_values':[]}
          for key in REQUIREMENT_SCOPE_FIELDS.values()]},
      'vendors':sorted(vendors,key=lambda x:x['id']),'products':sorted(products,key=lambda x:x['id']),
      'aliases':[],'relations':[],'documents':[documents[x] for x in sorted(documents)],
      'evidence':[evidence[x] for x in sorted(evidence)],
      'resolutions':[resolutions[x] for x in sorted(resolutions)],
      'claims':[claims[x] for x in sorted(claims)],'routes':[routes[x] for x in sorted(routes)],
      'reviews':[],'diagnostics':[diagnostics[x] for x in sorted(diagnostics)],
      'profiles':profiles,'requirements':requirements}
    bundle['manifest']['content_digest']=bundle_content_digest(bundle)
    return bundle
