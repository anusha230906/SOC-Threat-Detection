"""Edge cases: thresholds, windows, grouping, privilege and service rules."""
import unittest

import helpers  # noqa: F401
from helpers import make_event, failures, rule_alerts
from detection_rules import run_detection_rules

IP = "203.0.113.77"


class BruteForce(unittest.TestCase):
    def test_three_failures_do_not_fire(self):
        self.assertEqual(rule_alerts(run_detection_rules(failures("u", IP, [0, 8, 15])), "R01"), [])

    def test_window_boundary_120_seconds(self):
        self.assertEqual(len(rule_alerts(run_detection_rules(failures("u", IP, [0, 40, 80, 120])), "R01")), 1)
        self.assertEqual(rule_alerts(run_detection_rules(failures("u", IP, [0, 40, 80, 121])), "R01"), [])

    def test_slow_failures_do_not_fire(self):
        self.assertEqual(rule_alerts(run_detection_rules(failures("u", IP, [0, 170, 340, 510])), "R01"), [])

    def test_different_sources_not_grouped(self):
        logs = failures("u", "203.0.113.1", [0, 5]) + failures("u", "203.0.113.2", [10, 15])
        self.assertEqual(rule_alerts(run_detection_rules(logs), "R01"), [])

    def test_two_separate_bursts_give_two_alerts(self):
        logs = failures("u", IP, [0, 5, 10, 15]) + failures("u", IP, [1000, 1005, 1010, 1015])
        self.assertEqual(len(rule_alerts(run_detection_rules(logs), "R01")), 2)

    def test_alert_lists_event_ids(self):
        logs = failures("u", IP, [0, 5, 10, 15])
        alert = rule_alerts(run_detection_rules(logs), "R01")[0]
        self.assertEqual(alert["event_ids"], [e["event_id"] for e in logs])


class MfaFatigue(unittest.TestCase):
    @staticmethod
    def denied(offsets):
        return [make_event(o, "u", "mfa_denied", method="push") for o in offsets]

    def test_boundary_300_seconds(self):
        self.assertEqual(len(rule_alerts(run_detection_rules(self.denied([0, 300])), "R03")), 1)
        self.assertEqual(rule_alerts(run_detection_rules(self.denied([0, 301])), "R03"), [])

    def test_single_denial_ignored(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.denied([0])), "R03"), [])

    def test_two_denials_is_review(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.denied([0, 33])), "R03")[0]["classification"], "review")

    def test_five_denials_is_suspicious(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.denied([0, 30, 60, 90, 120])), "R03")[0]["classification"], "suspicious")

    def test_denials_then_success_is_suspicious(self):
        logs = self.denied([0, 30]) + [make_event(90, "u", "login_success", method="MFA")]
        self.assertEqual(rule_alerts(run_detection_rules(logs), "R03")[0]["classification"], "suspicious")


class Privilege(unittest.TestCase):
    @staticmethod
    def grant(offset, notes):
        return make_event(offset, "adm", "privilege_granted", target="admin-console", method="MFA", notes=notes)

    def test_no_ticket_is_high_review(self):
        alerts = run_detection_rules([self.grant(0, "no change ticket in event; investigate")])
        self.assertEqual(rule_alerts(alerts, "R04")[0]["classification"], "high_review")

    def test_empty_notes_still_flagged(self):
        self.assertEqual(len(rule_alerts(run_detection_rules([self.grant(0, "")]), "R04")), 1)

    def test_other_wording_still_flagged(self):
        self.assertEqual(len(rule_alerts(run_detection_rules([self.grant(0, "granted by admin")]), "R04")), 1)

    def test_ticket_is_likely_benign(self):
        alerts = run_detection_rules([self.grant(0, "approved change ticket CHG-1042")])
        self.assertEqual([a["classification"] for a in alerts], ["likely_benign"])

    def test_nearby_ticketed_grant_is_linked(self):
        logs = [self.grant(0, "approved change ticket CHG-1042"), self.grant(150, "")]
        alert = rule_alerts(run_detection_rules(logs), "R04")[0]
        self.assertTrue(alert["related_ids"])
        self.assertIn("cannot tell which", alert["description"])


class BenignTypo(unittest.TestCase):
    @staticmethod
    def pair(gap=60, method="MFA", ok_ip="198.51.100.50", ok_target="workstation-01"):
        return [make_event(0, "u", "login_failure", "198.51.100.50", "workstation-01", "password", "invalid password"),
                make_event(gap, "u", "login_success", ok_ip, ok_target, method)]

    def test_quick_retry_high_confidence(self):
        a = rule_alerts(run_detection_rules(self.pair()), "R05")[0]
        self.assertEqual((a["classification"], a["confidence"]), ("likely_benign", "high"))

    def test_89_minute_gap_lowers_confidence(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.pair(gap=89 * 60)), "R05")[0]["confidence"], "medium")

    def test_gap_over_limit_not_benign(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.pair(gap=121 * 60)), "R05"), [])

    def test_different_ip_or_host_not_benign(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.pair(ok_ip="203.0.113.9")), "R05"), [])
        self.assertEqual(rule_alerts(run_detection_rules(self.pair(ok_target="vpn-gateway")), "R05"), [])

    def test_password_only_success_not_benign(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.pair(method="password")), "R05"), [])

    def test_brute_force_failures_are_never_benign(self):
        logs = failures("u", IP, [0, 8, 15, 24]) + [make_event(58, "u", "login_success", IP, "vpn-gateway", "MFA")]
        self.assertEqual(rule_alerts(run_detection_rules(logs), "R05"), [])


class ServiceAccounts(unittest.TestCase):
    def test_expected_profile(self):
        logs = [make_event(0, "svc-backup", "login_success", "192.0.2.40", "backup-01", "service_token")]
        self.assertEqual(rule_alerts(run_detection_rules(logs), "R06")[0]["classification"], "likely_benign")

    def test_unexpected_ip_is_review(self):
        logs = [make_event(0, "svc-backup", "login_success", "203.0.113.9", "backup-01", "service_token")]
        self.assertEqual(rule_alerts(run_detection_rules(logs), "R06b")[0]["classification"], "review")

    def test_unknown_service_account_is_review(self):
        logs = [make_event(0, "svc-new", "login_success", "192.0.2.40", "backup-01", "service_token")]
        self.assertEqual(len(rule_alerts(run_detection_rules(logs), "R06b")), 1)

    def test_wrong_method_is_review(self):
        logs = [make_event(0, "svc-backup", "login_success", "192.0.2.40", "backup-01", "password")]
        self.assertEqual(len(rule_alerts(run_detection_rules(logs), "R06b")), 1)


class UnknownUsername(unittest.TestCase):
    @staticmethod
    def unknown(count):
        return [make_event(i * 9, "unknown", "login_failure", "203.0.113.91", "vpn-gateway", "password", "unknown username")
                for i in range(count)]

    def test_two_ignored(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.unknown(2)), "R07"), [])

    def test_three_is_review(self):
        self.assertEqual(rule_alerts(run_detection_rules(self.unknown(3)), "R07")[0]["classification"], "review")

    def test_four_is_suspicious_without_duplicate_r01(self):
        alerts = run_detection_rules(self.unknown(4))
        self.assertEqual(rule_alerts(alerts, "R07")[0]["classification"], "suspicious")
        self.assertEqual(rule_alerts(alerts, "R01"), [])


IP = "203.0.113.77"

if __name__ == "__main__":
    unittest.main()
