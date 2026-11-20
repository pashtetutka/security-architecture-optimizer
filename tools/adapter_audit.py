"""Offline section-coverage audit for every registered snapshot."""
from __future__ import annotations
import argparse,hashlib,json
from collections import Counter
from pathlib import Path
from siem.etl.adapters import DocumentContext,extract
from siem.etl.snapshots import validate_manifest_source_keys, load_snapshot
from siem.etl.bundle import load_bundle

def audit(registry_path: Path,manifest_path: Path,bundle_path: Path | None=None):
 registry_bytes=registry_path.read_bytes()
 registry=json.loads(registry_bytes)
 manifest_bytes=manifest_path.read_bytes()
 manifest=json.loads(manifest_bytes.decode('utf-8'))
 validate_manifest_source_keys(manifest)
 reviews_path=manifest_path.with_name('connection_reviews.json')
 reviews_bytes=reviews_path.read_bytes() if reviews_path.is_file() else b'{"reviews":[]}'
 reviews={(r['siem_id'],r['catalog_sha256'],r['source'],tuple(r['entries'])):r
          for r in json.loads(reviews_bytes)['reviews']}
 definitions={(v['id'],s['id']):s for v in registry['vendors'] for s in v['sources']}
 root=manifest_path.resolve().parents[3];documents=[]
 facts_by_sha={}
 facts_by_locator={}
 routes_by_catalog_entry={}
 if bundle_path is not None:
  bundle=load_bundle(bundle_path)
  manifest_sha=hashlib.sha256(manifest_bytes).hexdigest()
  manifests=bundle['build']['input_manifests']
  if manifests and not any(row['sha256']==manifest_sha for row in manifests):
   raise ValueError('Audit manifest does not match the bundle input manifest')
  registered_inputs=[row['sha256'] for row in manifests if row['path'].startswith('registry/')]
  if registered_inputs and registered_inputs != [hashlib.sha256(registry_bytes).hexdigest()]:
   raise ValueError('Audit registry does not match the bundle input registry')
  evidence={row['evidence_id']:row for row in bundle['evidence']}
  shas={row['document_id']:row['sha256'] for row in bundle['documents']}
  routes={row['route_id']:row for row in bundle['routes']}
  for claim in bundle['claims']:
   if claim['assertion']!='supported' or len(claim['route_refs'])<2:
    continue
   siem=claim['siem_product_ref']
   alternatives=[]
   for ref in claim['route_refs']:
    route=routes[ref]
    transports={step['transport'] for step in route['steps']
                if step['actor_ref']==siem and step['operation']=='collect'
                and step['transport'] not in (None,'unspecified_published_route')}
    if len(transports)==1:
     alternatives.append({'route_ref':ref,'transport':transports.pop(),
                          'evidence_refs':route['evidence_refs']})
   if len({route['transport'] for route in alternatives})<2:
    continue
   for ref in claim['evidence_refs']:
    proof=evidence[ref]
    key=siem,shas[proof['document_ref']],proof['excerpt']
    routes_by_catalog_entry.setdefault(key,[]).append(
        {'claim_ref':claim['claim_id'],'routes':alternatives})
  for category in ('claims','profiles','requirements'):
   for fact in bundle[category]:
    locations={(shas[row['document_ref']], row['locator']['section'], row['locator']['page'])
               for ref in fact['evidence_refs'] for row in (evidence[ref],)}
    for sha in {location[0] for location in locations}:
     facts_by_sha.setdefault((fact['siem_product_ref'],sha),Counter())[category]+=1
    for sha, section, page in locations:
     by_location=facts_by_locator.setdefault((fact['siem_product_ref'],sha),{})
     by_location.setdefault((section,page),Counter())[category]+=1
 for vendor in manifest['vendors']:
  for row in vendor.get('source_results',[]):
   target={'document_id':f"{vendor['id']}:{row['source_id']}",'siem_id':vendor['id'],
           'source_id':row['source_id'],'status':row.get('status'),'sections':[],'diagnostics':[],
           'has_snapshot':bool(row.get('snapshot_path'))}
   if bundle_path is not None:
    counts=facts_by_sha.get(('product:siem-'+vendor['id'],row.get('content_sha256')), {})
    target['bundle_facts']={category:counts.get(category,0)
                            for category in ('claims','profiles','requirements')}
    locations=facts_by_locator.get(('product:siem-'+vendor['id'],row.get('content_sha256')), {})
    target['bundle_fact_locations']=[
     {'section':section,'page':page,'counts':dict(sorted(counts.items()))}
     for (section,page),counts in sorted(locations.items(),key=lambda item:(item[0][0] or '',item[0][1] or 0))
    ]
   if not row.get('snapshot_path'):
    target['sections']=[{'section':row['source_id'],'status':'not_available','record_count':0,
                         'reason':row.get('status') or 'snapshot_missing'}]
   else:
    content=load_snapshot(row,root);definition=definitions.get((vendor['id'],row['source_id']))
    if definition is None:
     target['sections']=[{'section':row['source_id'],'status':'not_extracted','record_count':0,
                          'reason':'registry_mode_missing'}]
    else:
     context=DocumentContext(target['document_id'],vendor['id'],row['source_id'],row['source_id'],definition['mode'],
       row.get('resolved_url') or row['url'],(row.get('http_content_type') or 'text/plain').split(';')[0],
       row.get('http_charset'),{**row,'siem_name':vendor['name'],'url':row.get('resolved_url') or row['url'],
                                'route_guide':definition.get('route_guide')})
     result=extract(context,content)
     target['sections']=[x.__dict__ for x in result.sections]
     target['diagnostics']=[x.__dict__ for x in result.diagnostics]
     for record in result.records:
      entries=record.get('published_connection_entries', ())
      if len(entries)<2:
       continue
      excerpt=' '.join(record['evidence_excerpt'].split())
      key='product:siem-'+vendor['id'],row.get('content_sha256'),excerpt
      proofs=[item for item in routes_by_catalog_entry.get(key,())
              if len({route['transport'] for route in item['routes']})>=len(entries)]
      connection={'source':record['value'],'entries':entries,'excerpt':excerpt}
      review=reviews.get((vendor['id'],row.get('content_sha256'),record['value'],tuple(entries)))
      if proofs:
       connection.update(relationship='documented_routes',claim_routes=proofs)
       target.setdefault('connection_rows_with_documented_routes',[]).append(connection)
      elif review:
       relationship=review.get('relationship','reviewed_roles')
       connection.update(relationship=relationship,roles=review['roles'],
                         external_evidence=review['evidence'])
       if review.get('shared_transport'):
        connection['shared_transport']=review['shared_transport']
       bucket=('connection_rows_needing_review' if relationship=='partially_reviewed'
               else 'connection_rows_with_reviewed_roles')
       target.setdefault(bucket,[]).append(connection)
      else:
       connection['relationship']='unknown'
       target.setdefault('connection_rows_needing_review',[]).append(connection)
   target['sections_requiring_review']=[
    section for section in target['sections']
    if section['status'] in {'partial','not_extracted','candidates_only','delegated','empty'}
   ]
   documents.append(target)
 section_statuses=Counter(section['status'] for document in documents
                          for section in document['sections'])
 available_documents=sum(document['has_snapshot'] for document in documents)
 summary={'documents':len(documents),
          'with_snapshot':available_documents,
          'section_statuses':dict(sorted(section_statuses.items())),
          'documents_with_sections_requiring_review':sum(
           bool(d['sections_requiring_review']) for d in documents),
          'connection_rows_needing_review':sum(len(d.get('connection_rows_needing_review',()))
                                               for d in documents),
          'connection_rows_with_documented_routes':sum(len(d.get('connection_rows_with_documented_routes',()))
                                                       for d in documents),
          'connection_rows_with_reviewed_roles':sum(len(d.get('connection_rows_with_reviewed_roles',()))
                                                   for d in documents),
          'connection_reviews_sha256':hashlib.sha256(reviews_bytes).hexdigest(),
          'unexplained':sum(not d['sections'] or any(x['status']=='not_extracted' and not x['reason']
                                                   for x in d['sections']) for d in documents)}
 if bundle_path is not None:
  summary['bundle_digest']=bundle['manifest']['content_digest']
  summary['input_manifest_verified']=bool(manifests)
  with_facts=sum(any(document['bundle_facts'].values()) for document in documents)
  summary['bundle_document_coverage']={
   'with_facts':with_facts,
   'with_facts_and_sections_requiring_review':sum(
    bool(d['sections_requiring_review']) and any(d['bundle_facts'].values()) for d in documents),
   'available_without_facts':summary['with_snapshot']-with_facts,
   'unavailable':len(documents)-available_documents,
  }
 return {'schema_version':'adapter-audit/1.0','documents':documents,
         'summary':summary}

def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('--registry',type=Path,default=Path('data/etl/vendors.json'))
 p.add_argument('--manifest',type=Path,default=Path('data/etl/repro/vendors.json'));p.add_argument('--output',type=Path,required=True)
 p.add_argument('--bundle',type=Path);a=p.parse_args(argv)
 if a.output.exists():raise FileExistsError('output exists: '+str(a.output))
 result=audit(a.registry,a.manifest,a.bundle);a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8');print(json.dumps(result['summary']))
if __name__=='__main__':main()
