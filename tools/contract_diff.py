"""Produce the G2 semantic delta between independent legacy review and v2."""
import argparse,json
from pathlib import Path
from siem.decision.contract_assessment import MODEL_POLICY_VERSION, POLICY_VERSION, project_legacy_coverage
from siem.decision.scenarios import load_scenario
from siem.domain.identity import IdentityDictionary, load_default_dictionary
from siem.domain.contracts import content_digest
from siem.etl.bundle import load_bundle
from siem.etl.migration import build_migration_bundle


def validate_matrix_trace(cells, projection, bundle, expected_pairs):
 keys=[(cell['siem_id'],cell['row']) for cell in cells]
 if len(keys)!=len(expected_pairs) or set(keys)!=expected_pairs:
  raise ValueError('G2 matrix does not contain each vendor and source pair exactly once')
 claims={claim['claim_id']:claim for claim in projection['claims']}
 routes={route['route_id'] for route in projection['routes']}
 evidence={item['evidence_id']:item for item in bundle['evidence']}
 documents={doc['document_id']:doc for doc in bundle['documents']}
 for cell in cells:
  key=f"{cell['siem_id']}:{cell['row']}"
  if cell['v2_counted'] and not cell['evidence']:
   raise ValueError(f'G2 counted cell has no evidence: {key}')
  for trace in cell['evidence']:
   claim=claims.get(trace['claim_ref'])
   if (claim is None or claim['siem_product_ref']!='product:siem-'+cell['siem_id']
       or claim['assertion']!='supported' or trace['evidence_ref'] not in claim['evidence_refs']
       or trace['route_refs']!=claim['route_refs'] or not routes.issuperset(trace['route_refs'])):
    raise ValueError(f'G2 claim or route trace is invalid: {key}')
   item=evidence[trace['evidence_ref']]
   document=documents[item['document_ref']]
   if trace['document_ref']!=document['document_id'] or trace['document_sha256']!=document['sha256']:
    raise ValueError(f'G2 document trace is invalid: {key}')


def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
 p.add_argument('--policy',choices=(POLICY_VERSION, MODEL_POLICY_VERSION),default=POLICY_VERSION)
 p.add_argument('--bundle',type=Path,help='Check an existing portable bundle')
 p.add_argument('--dictionary',type=Path,help='Compare a proposed identity dictionary')
 p.add_argument('--check-candidate',action='store_true',
                help='Fail if the reviewed candidate matrix changes')
 a=p.parse_args(argv)
 if a.check_candidate and a.policy != MODEL_POLICY_VERSION:
  p.error('--check-candidate requires the candidate policy')
 if a.output.exists():raise FileExistsError('output exists: '+str(a.output))
 manifest=Path('data/etl/repro/vendors.json')
 dictionary=IdentityDictionary.load(a.dictionary) if a.dictionary else load_default_dictionary()
 bundle=(load_bundle(a.bundle) if a.bundle else
         build_migration_bundle(json.loads(manifest.read_text('utf-8')),manifest,dictionary))
 scenario=load_scenario('data/scenarios/s06_engineering.json')
 current=project_legacy_coverage(scenario,bundle,dictionary,a.policy)
 reference=json.loads(Path('tests/fixtures/manual_questionnaire_review_20261114.json').read_text('utf-8'))
 if reference['scenario_id'] != scenario['scenario_id']:
  raise ValueError('Manual reference belongs to a different questionnaire')
 differences=[]
 relation_matches=[]
 cells=[]
 for vendor in current['vendors']:
  expected=set(reference['vendors'][vendor['siem_id']]['counted'])
  for index,row in enumerate(vendor['source_matches'],1):
   cell={
    'siem_id':vendor['siem_id'],'row':index,'source':row['source'],
    'legacy_counted':index in expected,'v2_counted':row['counted_for_coverage'],
    'v2_status':row['status'],'evidence':row['evidence'],
    'component_assessments':row['component_assessments'],
    'relation_candidates':row['relation_candidates'],'model_candidates':row['model_candidates'],
   }
   if row['nonpositive_claims']:
    cell['nonpositive_claims']=row['nonpositive_claims']
   if row['diagnostics']:
    cell['diagnostics']=row['diagnostics']
   cell['target_digest']=content_digest({
    'scenario_id':scenario['scenario_id'],
    'source_input':scenario['event_sources'][index-1],
    'dictionary_version':current['dictionary_version'],
    'policy_version':current['policy_version'],
    'cell':cell,
   })
   cells.append(cell)
   if row['status']=='relation_match':
    relation_matches.append({
     'siem_id':vendor['siem_id'],'row':index,'source':row['source'],
     'collection_scope_review_required':row['collection_scope_review_required'],
     'version_review_required':row['version_review_required'],'evidence':row['evidence'],
    })
   if (index in expected)!=row['counted_for_coverage']:
    differences.append({'siem_id':vendor['siem_id'],'row':index,'source':row['source'],
      'legacy_counted':index in expected,'v2_counted':row['counted_for_coverage'],
      'v2_status':row['status'],'relation_candidates':row['relation_candidates'],
      'model_candidates':row['model_candidates'],
      'reason':('parent_claim_requires_scope_review' if row['relation_candidates']
                else 'explicit_model_claim_requires_scope_review' if row['model_candidates']
                else 'no_direct_or_parent_claim')})
 result={'schema_version':'g2-contract-diff/1.0','policy_version':current['policy_version'],
         'dictionary_version':current['dictionary_version'],'dataset_digest':current['dataset_digest'],
         'manual_reference':{'scenario_id':reference['scenario_id'],
                             'review_date':reference['review_date'],
                             'basis':reference['basis'],
                             'digest':content_digest(reference)},
         'summary':{'cases':sum(len(vendor['source_matches']) for vendor in current['vendors']),
                    'differences':len(differences),'relation_matches':len(relation_matches)},
         'differences':differences,'relation_matches':relation_matches,'cells':cells,
         'claims':current['claims'],'routes':current['routes']}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n','utf-8')
 print(json.dumps(result['summary']))
 if a.check_candidate:
  expected_pairs={(siem_id,row) for siem_id in reference['vendors']
                  for row in range(1,len(scenario['event_sources'])+1)}
  validate_matrix_trace(cells,current,bundle,expected_pairs)
  approvals=json.loads(Path('tests/fixtures/g2_owner_decisions.json').read_text('utf-8'))
  current_digests={f"{cell['siem_id']}:{cell['row']}":cell['target_digest'] for cell in cells}
  stale=[key for key,digest in approvals['decisions'].items() if current_digests.get(key)!=digest]
  if approvals['policy_version']!=current['policy_version'] or stale:
   raise SystemExit('G2 decisions require review: '+', '.join(stale))
  changed={(row['siem_id'],row['row'],row['legacy_counted'],row['v2_counted'])
           for row in differences}
  related={(row['siem_id'],row['row']) for row in relation_matches}
  expected_related={('p02',2),('p02',3),('p03',2),('p03',3),('p06',1)}
  expected_approvals={f'{sid}:{index}' for sid,index in expected_related | {('p01',19)}}
  if set(approvals['decisions']) != expected_approvals:
   raise SystemExit('G2 approval ledger must contain exactly the six owner decisions')
  if (result['summary']['cases'] != 299
      or changed != {('p01',19,True,False)}
      or related != expected_related):
   raise SystemExit('Candidate matrix changed; inspect the G2 report')
if __name__=='__main__':main()
