"""All-vendor source ETL with per-URL status, provenance and versioned snapshot."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
from .extractors import extract_content
from .fetcher import PublicFetcher

def utcnow(): return datetime.now(timezone.utc).isoformat()

def collect(registry, fetch=None, observed_at=None, snapshot_dir=None):
 timestamp=observed_at or utcnow()
 fetch=fetch or PublicFetcher()
 output={'schema_version':'1.0','run_at':timestamp,'vendors':[],'facts':[],'errors':[]}
 for vendor in registry['vendors']:
  product={'id':vendor['id'],'name':vendor['name'],'source_results':[]}
  output['vendors'].append(product)
  for source in vendor['sources']:
   if not source.get('enabled',True):continue
   url=source['url'];sid=source['id']
   report={'source_id':sid,'url':url,'status':'pending','product_version_hint':source.get('product_version_hint'),
           'acquisition_method':getattr(fetch,'acquisition_method','unknown')}
   product['source_results'].append(report)
   try:
    data,encoding,mime=fetch.fetch(url)
    if not data:raise ValueError('Пустой ответ')
    payload=extract_content(data,source['mode'],encoding)
    digest=hashlib.sha256(data).hexdigest()
    final_url=getattr(fetch,'resolved_urls',{}).get(url,url)
    if snapshot_dir:
     suffix='.pdf' if source['mode']=='pdf' else '.html'
     saved=Path(snapshot_dir)/vendor['id']/(sid+'_'+digest[:14]+suffix)
     saved.parent.mkdir(parents=True,exist_ok=True)
     saved.write_bytes(data)
     report['snapshot_path']=str(saved)
    report['resolved_url']=final_url
    report['http_charset']=encoding
    report['http_content_type']=mime
    report.update(status=('ok' if payload['facts'] else 'empty_review_required'),content_sha256=digest,extracted_facts=len(payload['facts']),title=payload.get('title'),warnings=payload.get('warnings',[]))
    for x in payload['facts']:
     evidence=x.copy()
     evidence.update({'siem_id':vendor['id'],'siem_name':vendor['name'],'source_id':sid,
       'source_url':final_url,'manifest_url':url,'source_type':source.get('source_type'),'collected_at':timestamp,
       'acquisition_method':getattr(fetch,'acquisition_method','unknown'),
       'origin_independently_verified':False,
       'source_sha256':digest,'product_version_hint':source.get('product_version_hint'),
       'product_version_verified':None,'document_version_hint':source.get('product_version_hint'),
       'source_version_verified':None, 'source_document_title':payload.get('title'),
       'evidence_sha256':hashlib.sha256(evidence['evidence_excerpt'].encode('utf-8')).hexdigest()})
     output['facts'].append(evidence)
   except Exception as ex:
    status='error'
    if type(ex).__name__=='RobotsPolicyUnavailable': status='robots_unavailable'
    elif isinstance(ex,PermissionError): status='access_disallowed'
    elif isinstance(ex,FileNotFoundError) and getattr(fetch,'acquisition_method',None)=='manual_import': status='missing_local_document'
    report.update(status=status,error_type=type(ex).__name__,error=str(ex)[:350])
    output['errors'].append({'siem_id':vendor['id'],'source_id':sid,'url':url,
                             'error_type':type(ex).__name__,'message':str(ex)[:350]})
 output['totals']={'vendors':len(output['vendors']),'sources':sum(len(x['source_results']) for x in output['vendors']),
                  'ok_sources':sum(s['status']=='ok' for x in output['vendors'] for s in x['source_results']),
                  'facts':len(output['facts']),'errors':len(output['errors'])}
 return output
