"""Basic detection tests (the original seven, updated for the new rules)."""
import unittest

import helpers  # noqa: F401  (adds src/ to the path)
from helpers import make_event, failures, rule_alerts
from detection_rules import run_detection_rules

IP = "203.0.113.10"


class TestSOCDetection(unittest.TestCase):

    def test_brute_force_detection(self):
        alerts = run_detection_rules(failures("test_user", IP, [0, 1, 2, 3]))
        self.assertTrue(any(a["rule"] == "Brute Force Login Detection" for a in alerts))

    def test_mfa_fatigue_detection(self):
        logs = [make_event(0, "test_user", "mfa_denied", method="push"),
                make_event(120, "test_user", "mfa_denied", method="push")]
        alerts = run_detection_rules(logs)
        self.assertTrue(any(a["rule"] == "MFA Fatigue Detection" for a in alerts))

    def test_unapproved_privilege_detection(self):
        logs = [make_event(0, "test_admin", "privilege_granted", target="admin-console",
                           method="MFA", notes="No change ticket reference")]
        alerts = run_detection_rules(logs)
        self.assertTrue(any(a["rule"] == "Unapproved Privilege Detection" for a in alerts))

    def test_normal_login_not_flagged(self):
        logs = [make_event(0, "normal_user", "login_success", method="MFA", notes="Normal login")]
        self.assertEqual(run_detection_rules(logs), [])

    def test_single_failure_not_flagged(self):
        self.assertEqual(run_detection_rules(failures("normal_user", IP, [0])), [])

    # SOC-T04: now classified likely_benign (the old test only checked "no alert")
    def test_single_failure_followed_by_mfa_success(self):
        logs = [make_event(0, "normal_user", "login_failure", notes="typo"),
                make_event(60, "normal_user", "login_success", method="MFA")]
        alerts = run_detection_rules(logs)
        self.assertEqual([a["classification"] for a in alerts], ["likely_benign"])

    # SOC-T05: scheduled service login is likely_benign
    def test_scheduled_backup_login_not_flagged(self):
        logs = [make_event(0, "svc-backup", "login_success", "192.0.2.40", "backup-01", "service_token")]
        alerts = run_detection_rules(logs)
        self.assertEqual([a["classification"] for a in alerts], ["likely_benign"])


class TestSuccessAfterFailures(unittest.TestCase):

    def test_success_within_5_minutes_is_high_review(self):
        logs = failures("u", IP, [0, 8, 15, 24]) + [make_event(58, "u", "login_success", IP, "vpn-gateway", "MFA")]
        found = rule_alerts(run_detection_rules(logs), "R02")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["classification"], "high_review")

    def test_success_after_window_ignored(self):
        logs = failures("u", IP, [0, 8, 15, 24]) + [make_event(24 + 400, "u", "login_success", IP, "vpn-gateway", "MFA")]
        self.assertEqual(rule_alerts(run_detection_rules(logs), "R02"), [])

    def test_success_from_other_ip_ignored(self):
        logs = failures("u", IP, [0, 8, 15, 24]) + [make_event(58, "u", "login_success", "203.0.113.5", "vpn-gateway", "MFA")]
        self.assertEqual(rule_alerts(run_detection_rules(logs), "R02"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
