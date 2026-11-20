from copy import deepcopy
import json
from pathlib import Path
import unittest

from siem.decision.contract_assessment import MODEL_POLICY_VERSION, project_legacy_coverage
from siem.decision.scenarios import load_scenario
from siem.domain.identity import IdentityDictionary, load_default_dictionary
from siem.etl.migration import build_migration_bundle
from tools.contract_diff import validate_matrix_trace

ROOT=Path(__file__).resolve().parents[1]


class MatrixTraceTests(unittest.TestCase):
    def test_rejects_broken_trace_and_duplicate_pair(self):
        digest = 'a' * 64
        trace = {'claim_ref': 'claim:a', 'route_refs': ['route:a'],
                 'evidence_ref': 'evidence:a', 'document_ref': 'document:a',
                 'document_sha256': digest}
        cells = [
            {'siem_id': 'p01', 'row': 1, 'v2_counted': True, 'evidence': [trace]},
            {'siem_id': 'p02', 'row': 1, 'v2_counted': False, 'evidence': []},
        ]
        projection = {
            'claims': [{'claim_id': 'claim:a', 'siem_product_ref': 'product:siem-p01',
                        'assertion': 'supported', 'evidence_refs': ['evidence:a'],
                        'route_refs': ['route:a']}],
            'routes': [{'route_id': 'route:a'}],
        }
        bundle = {
            'evidence': [{'evidence_id': 'evidence:a', 'document_ref': 'document:a'}],
            'documents': [{'document_id': 'document:a', 'sha256': digest}],
        }
        pairs = {('p01', 1), ('p02', 1)}
        validate_matrix_trace(cells, projection, bundle, pairs)

        bad_route = {**trace, 'route_refs': ['route:missing']}
        bad_sha = {**trace, 'document_sha256': '0' * 64}
        for replacement, error in (
            ([], 'counted cell has no evidence'),
            ([bad_route], 'claim or route trace is invalid'),
            ([bad_sha], 'document trace is invalid'),
        ):
            with self.subTest(error=error):
                modified = deepcopy(cells)
                modified[0]['evidence'] = replacement
                with self.assertRaisesRegex(ValueError, error):
                    validate_matrix_trace(modified, projection, bundle, pairs)
        with self.assertRaisesRegex(ValueError, 'exactly once'):
            validate_matrix_trace([cells[0], cells[0]], projection, bundle, pairs)


class ContractAssessmentTests(unittest.TestCase):
 def test_candidate_policy_against_manual_matrix(self):
  path=ROOT/'data/etl/repro/vendors.json'
  dictionary=load_default_dictionary()
  bundle=build_migration_bundle(json.loads(path.read_text('utf-8')),path,dictionary)
  result=project_legacy_coverage(self.scenario,bundle,dictionary,MODEL_POLICY_VERSION)
  os_sources = [
   {**self.scenario['event_sources'][0], 'raw_name': name, 'manufacturer_model': name,
    'version': version, 'products': [{'name': name, 'version': version}]}
   for name, version in [('Linux', None), ('Linux event logs', None),
                         ('macOS', '11'), ('Mac OS over Syslog', None)]
  ]
  os_result = project_legacy_coverage({**self.scenario, 'event_sources': os_sources},
                                      bundle, dictionary, MODEL_POLICY_VERSION)
  coverage = [
   {vendor['siem_id'] for vendor in os_result['vendors']
    if vendor['source_matches'][index]['counted_for_coverage']}
   for index in range(len(os_sources))
  ]
  self.assertEqual([{'p03', 'p12'}, {'p02', 'p05', 'p11'}, {'p03'}, {'p01'}], coverage)
  rvision = next(vendor for vendor in os_result['vendors'] if vendor['siem_id'] == 'p03')
  self.assertEqual(['match'], rvision['source_matches'][2]['version_scope'])
  wmi_subject = next(row['resolution_id'] for row in bundle['resolutions']
                     if row['raw_name'] == 'windows management instrumentation wmi')
  wmi_claim, = [claim for claim in bundle['claims']
                if claim['siem_product_ref'] == 'product:siem-p03'
                and claim['subject_resolution_ref'] == wmi_subject]
  wmi_route, = [route for route in bundle['routes'] if route['route_id'] in wmi_claim['route_refs']]
  self.assertEqual({'WMI'}, {step['transport'] for step in wmi_route['steps']})
  names = {row['resolution_id']: row['raw_name'] for row in bundle['resolutions']}
  stream_claims = {names[claim['subject_resolution_ref']]: claim for claim in bundle['claims']
                   if claim['siem_product_ref'] == 'product:siem-p03'}
  for name, channels in [('apache http server', ['access', 'error']),
                         ('secret net studio', ['audit', 'security'])]:
   self.assertEqual(channels, stream_claims[name]['scope']['event_channels'])
   self.assertEqual(1, len(stream_claims[name]['route_refs']))
  for name, transports in [('linux auditd', {'R-Vision Endpoint', 'Syslog'}),
                           ('oracle database', {'Database', 'Syslog'}),
                           ('ецу dallas lock', {'PostgreSQL', 'Syslog'})]:
   alternatives = [route for route in bundle['routes']
                   if route['route_id'] in stream_claims[name]['route_refs']]
   self.assertEqual(transports, {route['steps'][-1]['transport'] for route in alternatives})
   self.assertEqual(2, len({tuple(route['evidence_refs']) for route in alternatives}))
  firewall, = [claim for claim in bundle['claims']
               if claim['siem_product_ref'] == 'product:siem-p03'
               and names[claim['subject_resolution_ref']] == 'pt application firewall'
               and claim['scope']['source_version']['raw'] == '3']
  firewall_route, = [route for route in bundle['routes']
                     if route['route_id'] in firewall['route_refs']]
  self.assertEqual('Syslog', firewall_route['steps'][-1]['transport'])
  for name, expected in [
      ('virtual apps and desktops', {('audit',): 'Database', ('Application',): 'R-Vision Endpoint'}),
      ('гарда ndr', {('system message', 'user action'): 'Database', ('traffic event',): 'Syslog'}),
  ]:
   claims = [claim for claim in bundle['claims']
             if claim['siem_product_ref'] == 'product:siem-p03'
             and names[claim['subject_resolution_ref']] == name]
   self.assertEqual(2, len(claims))
   routes = {route['route_id']: route for route in bundle['routes']}
   actual = {}
   for claim in claims:
    self.assertEqual('subset', claim['scope']['extent'])
    route_ref, = claim['route_refs']
    actual[tuple(claim['scope']['event_channels'])] = routes[route_ref]['steps'][-1]['transport']
   self.assertEqual(expected, actual)
  route_refs={ref for vendor in result['vendors'] for row in vendor['source_matches']
              for evidence in row['evidence'] for ref in evidence['route_refs']}
  self.assertTrue(route_refs)
  self.assertEqual(route_refs,{route['route_id'] for route in result['routes']})
  claim_refs={item['claim_ref'] for vendor in result['vendors'] for row in vendor['source_matches']
              for item in row['evidence']}
  self.assertEqual([claim for claim in bundle['claims'] if claim['claim_id'] in claim_refs],
                   result['claims'])
  reference=json.loads((ROOT/'tests/fixtures/manual_questionnaire_review_20261114.json').read_text('utf-8'))
  differences=[]
  related=[]
  for vendor in result['vendors']:
   sid=vendor['siem_id']
   expected=set(reference['vendors'][sid]['counted'])
   for index,row in enumerate(vendor['source_matches'],1):
    if row['counted_for_coverage'] != (index in expected):
     differences.append((sid,index))
    if row['status']=='relation_match':
     self.assertTrue(row['evidence'])
     self.assertTrue(row['collection_scope_review_required'])
     related.append((sid,index))
  self.assertEqual([('p01',19)],differences)
  self.assertEqual([('p02',2),('p02',3),('p03',2),('p03',3),('p06',1)],related)
  rvision=next(vendor for vendor in result['vendors'] if vendor['siem_id']=='p03')
  refs={ref for item in rvision['source_matches'][1]['evidence'] for ref in item['route_refs']}
  routes=[route for route in result['routes'] if route['route_id'] in refs]
  self.assertEqual({'Syslog','PostgreSQL'},{route['steps'][-1]['transport'] for route in routes})
  database=next(route for route in routes if route['steps'][-1]['transport']=='PostgreSQL')
  self.assertEqual(['source','intermediary','siem'],[step['role'] for step in database['steps']])
  self.assertEqual('product:catalog-0838',database['steps'][1]['actor_ref'])
  maxpatrol=next(vendor for vendor in result['vendors'] if vendor['siem_id']=='p06')
  exchange=maxpatrol['source_matches'][4]
  self.assertGreaterEqual(len({entry['claim_ref'] for entry in exchange['evidence']}),5)
  changed={**self.scenario, 'event_sources': [
   {**self.scenario['event_sources'][0], 'manufacturer_model': 'D-Link DFL-unknown'},
   {**self.scenario['event_sources'][1], 'version': '4.5'},
  ]}
  changed_result=project_legacy_coverage(changed,bundle,dictionary,MODEL_POLICY_VERSION)
  changed_vendor=next(vendor for vendor in changed_result['vendors'] if vendor['siem_id']=='p06')
  self.assertFalse(changed_vendor['source_matches'][0]['counted_for_coverage'])
  for vendor in changed_result['vendors']:
   if vendor['siem_id'] not in ('p02','p03'):
    continue
   continent=vendor['source_matches'][1]
   self.assertFalse(continent['counted_for_coverage'])
   self.assertTrue(continent['relation_candidates'])
 @classmethod
 def setUpClass(cls):
  path=ROOT/'data/etl/repro/vendors.json';raw=json.loads(path.read_text('utf-8'))
  cls.dictionary=IdentityDictionary.load(ROOT/'src/siem/domain/ontology/identity_dictionary.v4.json')
  cls.bundle=build_migration_bundle(raw,path,cls.dictionary)
  cls.scenario=load_scenario(ROOT/'data/scenarios/s06_engineering.json')
  cls.result=project_legacy_coverage(cls.scenario,cls.bundle,cls.dictionary)
 def test_all_13_by_23_have_trace_and_policy(self):
  self.assertEqual(13,len(self.result['vendors']));self.assertEqual('preview-coverage/1.0',self.result['policy_version'])
  self.assertTrue(all(len(v['source_matches'])==23 for v in self.result['vendors']))
  for vendor in self.result['vendors']:
   for row in vendor['source_matches']:
    if row['counted_for_coverage']:self.assertTrue(row['evidence'])
 def test_no_unknown_is_called_unsupported(self):
  self.assertNotIn('unsupported',{r['status'] for v in self.result['vendors'] for r in v['source_matches']})
 def test_version_fit_and_extent_stay_with_their_claim(self):
  vendor, row = next((vendor, row)
                     for vendor in self.result['vendors'] for row in vendor['source_matches']
                     if row['counted_for_coverage'] and len(row['products']) == 1)
  template = next(claim for claim in self.bundle['claims']
                  if claim['claim_id'] == row['evidence'][0]['claim_ref'])
  claims = []
  for version, extent in [('1', 'unspecified'), ('2', 'subset')]:
   scope = {'raw': version, 'kind': 'exact', 'scheme': 'dotted_numeric',
            'values': [version], 'status': 'parsed'}
   claims.append({**template, 'claim_id': f'claim:version-{version}',
                  'scope': {**template['scope'], 'source_version': scope, 'extent': extent}})
  source = next(src for src in self.scenario['event_sources']
                if src['manufacturer_model'] == row['manufacturer_model'])
  requested = {**source, 'products': [{**row['products'][0], 'version': '2'}]}
  result = project_legacy_coverage({**self.scenario, 'event_sources': [requested]},
                                   {**self.bundle, 'claims': claims}, self.dictionary)
  matched = next(item for item in result['vendors'] if item['siem_id'] == vendor['siem_id'])
  fit = matched['source_matches'][0]['claim_applicability']
  self.assertEqual([('1','mismatch','unspecified'), ('2','match','subset')],
                   [(item['published_version'], item['version_status'], item['extent'])
                    for item in fit])
 def test_opposing_assertions_are_visible_in_the_matching_row(self):
  first = next(row for vendor in self.result['vendors'] for row in vendor['source_matches']
               if row['counted_for_coverage'])
  ref = first['evidence'][0]['claim_ref']
  claim = next(item for item in self.bundle['claims'] if item['claim_id'] == ref)
  negative = {**claim, 'claim_id': 'claim:synthetic-negative', 'assertion': 'unsupported',
              'route_refs': []}
  alert = {'code': 'opposing_support_assertions', 'target_ref': ref,
           'evidence_refs': claim['evidence_refs']}
  bundle = {**self.bundle, 'claims': [*self.bundle['claims'], negative],
            'diagnostics': [*self.bundle['diagnostics'], alert]}
  result = project_legacy_coverage(self.scenario, bundle, self.dictionary)
  affected = [row for vendor in result['vendors'] for row in vendor['source_matches']
              if alert in row['diagnostics']]
  self.assertTrue(affected)
  self.assertTrue(all(row['collection_scope_review_required'] for row in affected))
  self.assertTrue(any(item['claim_ref'] == negative['claim_id']
                      for row in affected for item in row['nonpositive_claims']))

 def test_bundle_and_questionnaire_must_use_same_dictionary_version(self):
  manifest={**self.bundle['manifest'], 'dictionary_version': 'incompatible'}
  with self.assertRaisesRegex(ValueError, 'dictionary versions differ'):
   project_legacy_coverage(self.scenario,{**self.bundle, 'manifest': manifest},self.dictionary)
 def test_nonpositive_assertions_never_count(self):
  for assertion in ('unknown', 'unsupported'):
   with self.subTest(assertion=assertion):
    bundle={**self.bundle, 'claims': [
     {**claim, 'assertion': assertion} for claim in self.bundle['claims']
    ]}
    result=project_legacy_coverage(self.scenario,bundle,self.dictionary)
    self.assertTrue(all(not row['counted_for_coverage']
                        for vendor in result['vendors'] for row in vendor['source_matches']))
    recorded=[claim for vendor in result['vendors'] for row in vendor['source_matches']
              for claim in row['nonpositive_claims']]
    self.assertTrue(recorded)
    self.assertEqual({assertion},{claim['assertion'] for claim in recorded})
    self.assertEqual({ref for claim in recorded for ref in claim['route_refs']},
                     {route['route_id'] for route in result['routes']})
    evidence = [item for claim in recorded for item in claim['evidence']]
    self.assertTrue(evidence)
    self.assertEqual({ref for claim in recorded for ref in claim['evidence_refs']},
                     {item['evidence_ref'] for item in evidence})
    self.assertTrue(all(item['url'] and item['locator'] and item['document_sha256']
                        for item in evidence))
 def test_g2_delta_is_explicit_and_does_not_silently_change(self):
  expected=json.loads((ROOT/'tests/fixtures/manual_questionnaire_review_20261114.json').read_text('utf-8'))
  differences=[]
  for vendor in self.result['vendors']:
   counted=set(expected['vendors'][vendor['siem_id']]['counted'])
   for index,row in enumerate(vendor['source_matches'],start=1):
    if (index in counted)!=row['counted_for_coverage']:
     differences.append((vendor['siem_id'],index,index in counted,row['counted_for_coverage']))
  self.assertEqual([
   ('p01',19,True,False),('p02',2,True,False),
   ('p02',3,True,False),('p02',23,True,False),('p03',2,True,False),
   ('p03',3,True,False),('p03',23,True,False),
   ('p06',1,True,False),('p06',23,True,False),
   ('p12',23,True,False)],differences)

if __name__=='__main__':unittest.main()
