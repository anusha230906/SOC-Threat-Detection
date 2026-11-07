"""Synthetic generator and evaluation."""
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from log_parser import read_authentication_logs
from detection_rules import run_detection_rules
from synthetic_logs import generate, save_synthetic_logs, CSV_NAME
from evaluation import evaluate_detections


class Synthetic(unittest.TestCase):
    def test_same_seed_gives_same_logs(self):
        a, truth_a = generate(42)
        b, truth_b = generate(42)
        self.assertEqual(a, b)
        self.assertEqual(truth_a, truth_b)
        self.assertNotEqual(a, generate(7)[0])

    def test_logs_can_be_saved_and_read_back(self):
        events, truth = generate(1)
        with tempfile.TemporaryDirectory() as folder:
            csv_path, _ = save_synthetic_logs(events, truth, folder)
            self.assertEqual(len(read_authentication_logs(csv_path)), len(events))

    def test_rules_perform_across_seeds(self):
        for seed in (1, 42, 123, 2026):
            with self.subTest(seed=seed):
                events, truth = generate(seed)
                result = evaluate_detections(run_detection_rules(events), truth)
                self.assertEqual(result["missed"], [])
                self.assertEqual(result["false_positive_findings"], [])
                self.assertEqual(result["quiet_scenarios_that_alerted"], [])

    def test_slow_guessing_is_a_known_gap(self):
        events, truth = generate(42)
        gaps = evaluate_detections(run_detection_rules(events), truth)["known_gaps"]
        self.assertTrue(gaps)
        self.assertTrue(all(not g["detected"] for g in gaps))


if __name__ == "__main__":
    unittest.main()
