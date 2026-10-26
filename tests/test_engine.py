import unittest

from sao.engine import rank_products


class RankingTests(unittest.TestCase):
    def setUp(self):
        self.profile = {"min_eps": 1000, "require_on_premise": True,
                        "required_integrations": ["Linux"], "weights": {"quality": 2, "cost": 1}}

    def test_weighted_score(self):
        p = [{"id": "a", "eps": 1200, "on_premise": True,
              "integrations": ["Linux"], "scores": {"quality": 90, "cost": 30}}]
        result = rank_products(self.profile, p)[0]
        self.assertTrue(result["eligible"])
        self.assertEqual(result["score"], 70.0)

    def test_hard_constraints_exclude_high_score(self):
        p = [{"id": "a", "eps": 900, "on_premise": False,
              "integrations": [], "scores": {"quality": 100, "cost": 100}}]
        result = rank_products(self.profile, p)[0]
        self.assertFalse(result["eligible"])
        self.assertIsNone(result["score"])
        self.assertEqual(len(result["rejection_reasons"]), 3)

    def test_missing_value_not_imputed(self):
        p = [{"id": "a", "eps": 1200, "on_premise": True,
              "integrations": ["Linux"], "scores": {"quality": 80}}]
        result = rank_products(self.profile, p)[0]
        self.assertFalse(result["eligible"])
        self.assertIn("Нет оценок", result["rejection_reasons"][0])

    def test_invalid_weights(self):
        with self.assertRaises(ValueError):
            rank_products({**self.profile, "weights": {"quality": 0}}, [])


if __name__ == "__main__":
    unittest.main()
