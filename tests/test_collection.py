import unittest,json
from pathlib import Path
from siem.etl.extractors import extract_content, structured_tables
from siem.etl.pipeline import collect
from siem.etl.applicability import evaluate
ROOT=Path(__file__).parent.parent
class FakeFetch:
 def fetch(self,url):
  if 'rvision' in url: data=(ROOT/'tests/fixtures/catalogs/rvision_sources.html').read_bytes()
  elif 'kaspersky' in url: data=(ROOT/'tests/fixtures/catalogs/kuma_sources.html').read_bytes()
  else:raise OSError('В тесте загрузка данного URL недоступна')
  return data,'utf-8','text/html'
class CollectionTests(unittest.TestCase):
 def test_route_guide_uses_same_heading_check_during_collection(self):
  registry=json.loads((ROOT/'data/etl/vendors.json').read_text(encoding='utf8'))
  vendor=next(item for item in registry['vendors'] if item['id']=='p03')
  source=next(item for item in vendor['sources'] if item['id']=='continent4_guide_syslog')
  filtered={'vendors':[{**vendor,'sources':[source]}]}
  snapshot=next((ROOT/'data/etl/repro/raw/p03').glob('continent4_guide_syslog_*.html'))
  class Fetcher:
   def __init__(self, data): self.data=data
   def fetch(self, url): return self.data,'utf-8','text/html'
  collected=collect(filtered,Fetcher(snapshot.read_bytes()))
  self.assertEqual('collection_route_guide',collected['facts'][0]['field'])
  self.assertEqual('Syslog',collected['facts'][0]['transport'])
  failed=collect(filtered,Fetcher(b'<article><h1>Unexpected text</h1></article>'))
  self.assertEqual([],failed['facts'])
  report=failed['vendors'][0]['source_results'][0]
  self.assertEqual(('error','extraction'),(report['status'],report['failure_stage']))
  self.assertIn('route_guide_heading_changed',report['error'])
  heading=source['route_guide']['heading']
  heading_only=f'<article><h1>{heading}</h1><p>Placeholder</p></article>'.encode('utf-8')
  failed=collect(filtered,Fetcher(heading_only))
  self.assertEqual([],failed['facts'])
  self.assertIn('route_guide_text_changed',failed['vendors'][0]['source_results'][0]['error'])

 def test_rvision_table(self):
  data=(ROOT/'tests/fixtures/catalogs/rvision_sources.html').read_bytes()
  f=extract_content(data,'rvision')['facts']
  a=[x for x in f if x['field']=='source_integration']
  self.assertEqual(len(a),2);self.assertEqual(a[0]['source_version'],'2');self.assertEqual(a[0]['normalizer_id'],'RV-N-231')
 def test_kuma_table(self):
  data=(ROOT/'tests/fixtures/catalogs/kuma_sources.html').read_bytes()
  f=extract_content(data,'kuma')['facts'];a=[x for x in f if x['field']=='source_integration']
  self.assertEqual(len(a),2);self.assertEqual(a[0]['normalizer_format'],'regexp')
 def test_rvision_collection_cell_preserves_document_boundaries(self):
  path=next((ROOT/'data/etl/repro/raw/p03').glob('source_catalog_*.html'))
  rows=structured_tables(path.read_text(encoding='utf-8'),'rvision')
  entries=[row.get('published_connection_entries') for row in rows]
  self.assertIn(['Syslog','Database'],entries)
  self.assertIn(['Universal CEF'],entries)
  self.assertIn(['WMI','GPO'],entries)
 def test_generic_only_candidates(self):
  f=extract_content(b'<html><p>We require Kubernetes for event collection in this version.</p></html>','generic')['facts']
  self.assertEqual(f[0]['evidence_status'],'review_candidate')
 def test_all_13_vendor_status_even_failures(self):
  manifest=json.loads((ROOT/'data/etl/vendors.json').read_text(encoding='utf-8'))
  self.assertEqual(next(v for v in manifest['vendors'] if v['id']=='p02')['name'], 'СёрчИнформ SIEM')
  maxpatrol=next(v for v in manifest['vendors'] if v['id']=='p06')
  enabled={s['id'] for s in maxpatrol['sources'] if s.get('enabled',True)}
  self.assertNotIn('partial_sources',enabled);self.assertIn('supported_sources_api',enabled)
  self.assertNotIn('sources',enabled);self.assertNotIn('supported_sources',enabled)
  d=collect(manifest,fetch=FakeFetch(),observed_at='2026-10-27T00:00:00Z')
  self.assertEqual(d['totals']['vendors'],13)
  self.assertGreater(d['totals']['errors'],0)
  self.assertTrue(all(x['source_results'] for x in d['vendors']))
  self.assertTrue(all('source_sha256' in x for x in d['facts']))
 def test_source_version_mismatch_needs_confirmation(self):
  v=[{'id':'p03','name':'R-Vision'}]
  facts=[{'siem_id':'p03','field':'source_integration','evidence_status':'vendor_table',
          'value':'Apache HTTP Server','source_version':'2','source_url':'https://rvision.ru'}]
  infra={'event_sources':[{'name':'Apache HTTP Server','version':'3'}],'default_custom_parser_rub':0}
  result=evaluate(v,{'facts':facts},infra)[0]
  self.assertEqual(result['source_assessments'][0]['match_status'],'source_version_requires_confirmation')
 def test_matching_unknown_is_penalty_not_failure(self):
  vendors=[{'id':'p03','name':'R-Vision'}]
  facts=[{'siem_id':'p03','field':'source_integration','evidence_status':'vendor_table',
          'value':'Apache HTTP Server','source_url':'https://docs.rvision.ru','source_version':'2',
          'product_version_hint':'2.9.1','normalizer_id':'RV-N-231'}]
  infra={'budget_rub':800000,'default_custom_parser_rub':100000,
         'event_sources':[{'name':'Apache HTTP Server','criticality':3},{'name':'Custom App','criticality':1}]}
  val=evaluate(vendors,{'facts':facts},infra)[0]
  self.assertEqual(val['unknown_integrations'],1)
  self.assertEqual(val['estimated_extra_cost_rub'],100000)
  self.assertGreater(val['conditional_fit_score_0_100'],0)
  self.assertEqual(val['source_assessments'][1]['match_status'],'not_documented_needs_review')
 def test_cousin_product_not_assumed_supported(self):
  v=[{'id':'p03','name':'R-Vision'}]
  f=[{'siem_id':'p03','field':'source_integration','evidence_status':'vendor_table','value':'1C:Enterprise',
      'source_url':'https://rvision.ru'}]
  infra={'event_sources':[{'name':'1С:ЗУП'}],'default_custom_parser_rub':1}
  self.assertEqual(evaluate(v,{'facts':f},infra)[0]['unknown_integrations'],1)
 def test_reviewed_architecture_rule_adds_cost(self):
  v=[{'id':'p11','name':'Solar'}]
  infra={'event_sources':[{'name':'Linux'}], 'budget_rub':400000,'default_custom_parser_rub':100000,
         'environment':{'kubernetes_available':False,'kubernetes_setup_rub':450000}}
  rules=[{'siem_id':'p11','approval_status':'approved','product_version':'DEMO',
          'requirement':'kubernetes','source_url':'https://example.org/demo'}]
  scored=evaluate(v,{'facts':[]},infra,rules)[0]
  self.assertEqual(scored['infrastructure_changes_estimate_rub'],450000)
  self.assertEqual(scored['estimated_extra_cost_rub'],550000)
  self.assertGreater(scored['budget_overrun_estimate_rub'],0)
 def test_not_reviewed_architecture_does_not_infer_requirement(self):
  v=[{'id':'p11','name':'Solar'}]
  infra={'event_sources':[{'name':'Linux'}],'environment':{'kubernetes_available':False,'kubernetes_setup_rub':800000}}
  rules=[{'siem_id':'p11','approval_status':'pending','product_version':'1','requirement':'kubernetes','source_url':'https://example.org/demo'}]
  scored=evaluate(v,{'facts':[]},infra,rules)[0]
  self.assertIsNone(scored['infrastructure_changes_estimate_rub'])
 def test_no_crazy_confidence_from_generic(self):
  v=[{'id':'p11','name':'Solar'}]
  f=[{'siem_id':'p11','field':'deployment','evidence_status':'review_candidate',
      'value':'Kubernetes','source_url':'https://rt-solar.ru'}]
  infra={'event_sources':[{'name':'Linux'}],'default_custom_parser_rub':0}
  val=evaluate(v,{'facts':f},infra)[0]
  self.assertIsNone(val['infrastructure_changes_estimate_rub'])
  self.assertEqual(val['unknown_integrations'],1)
if __name__=='__main__':unittest.main()
