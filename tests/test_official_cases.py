"""Runs the five official cases from data/soc_detection_test_cases.csv.

Each case_id has a small fixture. The expected class is read from the CSV, so
editing the CSV changes the test.
"""
import csv
import unittest

import helpers
from helpers import make_event, failures
from detection_rules import run_detection_rules

IP = "203.0.113.77"
FIXTURES = {
    "SOC-T01": lambda: failures("a.chen", IP, [0, 8, 15, 24]),
    "SOC-T02": lambda: [make_event(0, "t.garcia", "mfa_denied", method="push"),
                        make_event(33, "t.garcia", "mfa_denied", method="push")],
    "SOC-T03": lambda: [make_event(0, "m.patel", "privilege_granted", target="admin-console", method="MFA",
                                   notes="no change ticket in event; investigate")],
    "SOC-T04": lambda: [make_event(0, "d.ross", "login_failure", target="workstation-22", notes="single typo"),
                        make_event(60, "d.ross", "login_success", target="workstation-22", method="MFA")],
    "SOC-T05": lambda: [make_event(0, "svc-backup", "login_success", "192.0.2.40", "backup-01", "service_token")],
}


class OfficialCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = helpers.PROJECT_DIR / "data" / "soc_detection_test_cases.csv"
        with open(path, newline="", encoding="utf-8") as file:
            cls.cases = list(csv.DictReader(file))

    def test_every_csv_case_has_a_fixture(self):
        self.assertEqual({c["case_id"] for c in self.cases}, set(FIXTURES))

    def test_expected_classes(self):
        for case in self.cases:
            with self.subTest(case=case["case_id"]):
                alerts = run_detection_rules(FIXTURES[case["case_id"]]())
                self.assertIn(case["expected_class"], {a["classification"] for a in alerts},
                              msg=f"{case['case_id']}: {case['input_pattern']}")


if __name__ == "__main__":
    unittest.main()
