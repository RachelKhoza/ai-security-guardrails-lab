import unittest
from pathlib import Path

from ai_security_guardrails.evaluation import evaluate_dataset, render_markdown
from ai_security_guardrails.policy import PolicyEngine


ROOT = Path(__file__).parents[1]


class EvaluationTests(unittest.TestCase):
    def test_adversarial_dataset_matches_expected_decisions(self) -> None:
        engine = PolicyEngine.from_file(ROOT / "config" / "policy.toml")
        results = evaluate_dataset(engine, ROOT / "evals" / "adversarial-cases.jsonl")
        self.assertEqual(len(results), 12)
        self.assertTrue(all(result.passed for result in results))
        self.assertIn("12/12", render_markdown(results))


if __name__ == "__main__":
    unittest.main()
