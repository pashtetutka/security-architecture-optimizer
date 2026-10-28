import unittest
from siem.core import normalize,weighted_sum,topsis,estimate_eps,sensitivity,analyze
from pathlib import Path
import json
class TestMethods(unittest.TestCase):
 def setUp(self):
  self.cat=json.loads(Path('data/reference_metrics.json').read_text(encoding='utf8'))
  self.infra=json.loads(Path('data/demo_infra.json').read_text(encoding='utf8'))
 def test_source_count(self):self.assertEqual(len(self.cat['products']),13)
 def test_criteria_count(self):self.assertEqual(len(self.cat['criteria']),15)
 def test_weights_total(self):self.assertAlmostEqual(sum(c['weight'] for c in self.cat['criteria']),1.0,places=5)
 def test_eps(self):self.assertEqual(estimate_eps(self.infra)['required_eps'],905)
 def test_wsm_finite(self):self.assertTrue(all(0<=p['score']<=100 for p in analyze(self.cat,self.infra)['ranking']))
 def test_topsis_range(self):self.assertTrue(all(0<=p['score']<=100 for p in analyze(self.cat,self.infra,'topsis')['ranking']))
 def test_topsis_equal(self):self.assertEqual(topsis(['a','b'],{'a':{'k':1},'b':{'k':1}},{'k':1}),{'a':50.,'b':50.})
 def test_budget_filter(self):self.assertTrue(analyze(self.cat,{**self.infra,'budget_million':1})['excluded'])
 def test_sensitivity_deterministic(self):self.assertEqual(sensitivity(self.cat,self.infra,runs=10),sensitivity(self.cat,self.infra,runs=10))
 def test_negative_eps_rejected(self):
  with self.assertRaises(ValueError):estimate_eps({'sources':[{'type':'x','count':-1,'eps_per_unit':1}]})
if __name__=='__main__':unittest.main()
