"""Evidence and data readiness for the focused two-domain ETL.

Not a SIEM score. No vendor is penalized for unpublished documents. ETL never
claims human verification or approval merely because a JSON field is filled.
"""
from __future__ import annotations
from collections import Counter,defaultdict


def _vendor_document_status(raw: dict, sid: str, relevant_ids: set[str]) -> dict:
    vendor=next((v for v in raw.get('vendors', []) if v.get('id')==sid),{})
    documents=[d for d in vendor.get('source_results', []) if d.get('source_id') in relevant_ids]
    counts=dict(Counter(x.get('status','unknown') for x in documents))
    return {'registered':len(documents),'statuses':counts,
            'failed_urls':[d.get('url') for d in documents if d.get('status')=='error'],
            'empty_urls':[d.get('url') for d in documents if d.get('status')=='empty_review_required']}


def readiness_report(catalog: dict, raw: dict | None = None) -> dict:
    raw=raw or {}
    integrations=defaultdict(list); profiles=defaultdict(list); requirements=defaultdict(list)
    for r in catalog.get('integrations',[]):integrations[r['siem_id']].append(r)
    for r in catalog.get('sizing_profiles',[]):profiles[r['siem_id']].append(r)
    for r in catalog.get('system_requirements',[]):requirements[r['siem_id']].append(r)
    unparsed=defaultdict(list)
    for missing in catalog.get('unparsed_system_documents',[])+catalog.get('unread_system_documents',[]):
        unparsed[missing['siem_id']].append(missing)
    source_problems=defaultdict(list)
    for missing in catalog.get('unread_source_catalog_documents',[]):
        source_problems[missing['siem_id']].append(missing)
    result=[]
    for info in catalog.get('coverage',[]):
        sid=info['siem_id']; src=integrations[sid]; prof=profiles[sid]; req=requirements[sid]
        source_docs=_vendor_document_status(raw,sid,{'sources','source_catalog','sources_catalog','parsers'})
        sys_docs=_vendor_document_status(raw,sid,{'hardware_requirements','system_requirements','deployment','architecture','platform_architecture'})
        source_status=('not_extracted' if not src else 'extracted_needs_review')
        system_status=('not_extracted' if not (prof or req) else 'extracted_needs_review')
        reasons=[]
        if not src:reasons.append('source_catalog_not_extracted')
        else:
            if any(r.get('review_status')!='verified' for r in src):reasons.append('source_integrations_not_reviewed')
            if any(not r.get('siem_version') for r in src):reasons.append('source_version_scope_unverified')
        if not (prof or req):reasons.append('system_requirements_not_extracted')
        else:
            if not prof:reasons.append('no_hardware_profiles')
            if any(r.get('review_status')!='verified' for r in prof+req):reasons.append('system_data_not_reviewed')
            if any(not r.get('siem_version') for r in prof+req):reasons.append('system_version_scope_unverified')
            if any(p.get('sizing_scope')=='edition_minimum_not_eps_sizing' for p in prof):
                reasons.append('edition_minimum_not_usable_as_eps_sizing')
            if any(r.get('sizing_complete') is False for r in req):
                reasons.append('incomplete_conditioned_capacity_example')
        if unparsed[sid]:reasons.append('system_documents_not_fully_parsed')
        if source_problems[sid]:reasons.append('source_documents_unreadable')
        # Calculations are explicitly gated by human review and coverage signoff.
        result.append({
            'siem_id':sid,'siem_name':info.get('siem_name'),
            'supported_sources':{'status':source_status,'records':len(src),
                                 'documents':source_docs,'unread_documents':len(source_problems[sid])},
            'system_requirements':{'status':system_status,'sizing_profiles':len(prof),
                                   'typed_rules':len(req),'documents':sys_docs,
                                   'unprocessed_documents':len(unparsed[sid])},
            'calculation_ready':False,'readiness_basis':'automatic_extract_only',
            'blocking_reasons':list(dict.fromkeys(reasons)),
        })
    return {'schema_version':'focused-siem-etl-readiness/1.0',
            'source_run_at':catalog.get('source_run_at'),
            'summary':{'vendors':len(result),
                       'source_catalogs_extracted':sum(r['supported_sources']['records']>0 for r in result),
                       'system_profiles_extracted':sum(r['system_requirements']['sizing_profiles']>0 for r in result),
                       'both_domains_extracted':sum(r['supported_sources']['records']>0 and
                                                    r['system_requirements']['sizing_profiles']>0 for r in result),
                       'calculation_ready':0},
            'items':result,
            'note':'Статус подтверждения присваивается только после проверки первоисточника и версии; автоматический ETL его не выставляет.'}
