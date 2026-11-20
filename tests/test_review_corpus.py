import json
from pathlib import Path
import unittest

from tools.review_corpus import build


ROOT=Path(__file__).resolve().parents[1]


class ReviewCorpusTests(unittest.TestCase):
    def test_all_299_have_independent_expectation_and_trace(self):
        result=build(ROOT/'tests/fixtures/manual_questionnaire_review_20261114.json',
                     ROOT/'data/scenarios/s06_engineering.json',
                     ROOT/'data/etl/repro/vendors.json')
        self.assertEqual(299,result['summary']['cases'])
        self.assertEqual(0,result['summary']['differences'])
        self.assertEqual(299,len({row['case_id'] for row in result['cases']}))
        for row in result['cases']:
            self.assertIn(row['expected_outcome'],('counted','candidate','not_counted'))
            if row['actual_outcome']=='counted': self.assertTrue(row['evidence'])

if __name__=='__main__': unittest.main()
