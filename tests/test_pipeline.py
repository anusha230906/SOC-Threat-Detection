"""End-to-end tests on the starter scenario, EDR correlation and report wording."""
import re
import unittest

import helpers
from helpers import make_event, make_edr_alert, rule_alerts
from log_parser import read_authentication_logs, read_endpoint_alerts, extract_alert_list
from detection_rules import run_detection_rules
from edr_correlation import correlate_endpoint_alerts
from incident_triage import assign_finding_ids, build_cases, build_markdown_report
from incident_timeline import generate_incident_timeline


class StarterScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = read_authentication_logs()
        cls.edr = extract_alert_list(read_endpoint_alerts())
        detections = run_detection_rules(cls.auth)
        cls.findings = assign_finding_ids(detections, correlate_endpoint_alerts(detections, cls.edr, cls.auth))
        cls.cases = build_cases(cls.findings)
        cls.timeline = generate_incident_timeline(cls.auth, cls.edr, cls.findings)
        cls.report = build_markdown_report(cls.cases, cls.findings, cls.timeline, len(cls.auth), len(cls.edr))

    def test_input_sizes(self):
        self.assertEqual((len(self.auth), len(self.edr)), (20, 4))

    def test_case_classifications(self):
        got = {c["entity"]: c["classification"] for c in self.cases}
        self.assertEqual(got, {
            "a.chen": "high_review", "m.patel": "high_review", "t.garcia": "review",
            "unknown@203.0.113.91": "review", "j.lee": "review",
            "svc-backup": "likely_benign", "svc-sync": "likely_benign", "d.ross": "likely_benign"})

    def test_p1_cases_come_first(self):
        priorities = [c["priority"] for c in self.cases]
        self.assertEqual(priorities, sorted(priorities))
        self.assertEqual({c["entity"] for c in self.cases[:2]}, {"a.chen", "m.patel"})

    def test_event_ids_in_alerts(self):
        ids = {f["rule_id"] + f["username"]: set(f["event_ids"]) for f in self.findings}
        self.assertEqual(ids["R01a.chen"], {"AUTH-0003", "AUTH-0004", "AUTH-0005", "AUTH-0006"})
        self.assertEqual(ids["R02a.chen"], {"AUTH-0007"})
        self.assertEqual(ids["R04m.patel"], {"AUTH-0017"})
        self.assertEqual(ids["R04bm.patel"], {"AUTH-0016"})

    def test_edr_1002_timing_problem_is_flagged(self):
        finding = [f for f in self.findings if f["event_ids"] == ["EDR-1002"]][0]
        self.assertIn("BEFORE", finding["description"])

    def test_d_ross_long_gap_lowers_confidence(self):
        self.assertEqual(rule_alerts(self.findings, "R05")[0]["confidence"], "medium")

    def test_timeline_covers_everything_in_time_order(self):
        self.assertEqual(len(self.timeline), 24)
        times = [row["timestamp"] for row in self.timeline]
        self.assertEqual(times, sorted(times))

    def test_report_never_claims_compromise(self):
        self.assertIn("No account is confirmed compromised", self.report)
        for phrase in ("is compromised", "was compromised", "has been compromised", "are compromised"):
            self.assertNotIn(phrase, self.report.lower())

    def test_report_has_every_id_and_required_sections(self):
        for item in [e["event_id"] for e in self.auth] + [a["alert_id"] for a in self.edr]:
            self.assertIn(item, self.report)
        for heading in ("Triage queue", "Timeline", "Evidence to request",
                        "Containment (evidence-preserving)", "Communication"):
            self.assertIn(heading, self.report)

    def test_containment_has_no_destructive_first_steps(self):
        bullets = re.findall(r"^- .*$", self.report.split("**Containment")[1], re.M)
        for bullet in bullets:
            if re.search(r"\b(wipe|reimage the|delete (logs|the host))\b", bullet.lower()):
                self.assertIn("do not", bullet.lower())


class EdrCorrelation(unittest.TestCase):
    def test_supported_alert_inherits_class_and_flags_timing(self):
        auth = [make_event(300, "u", "privilege_granted", target="admin-console", method="MFA", notes="")]
        alert = make_edr_alert(100, "ADMIN-CONSOLE", "u", "Privilege granted without change reference", "high")
        det = run_detection_rules(auth)
        finding = correlate_endpoint_alerts(det, [alert], auth)[0]
        self.assertEqual(finding["classification"], "high_review")
        self.assertIn("BEFORE", finding["description"])

    def test_alert_without_support_is_review_not_escalated(self):
        alert = make_edr_alert(0, "WKSTN-014", "j", "Office child process unusual", "low", "blocked")
        finding = correlate_endpoint_alerts([], [alert], [])[0]
        self.assertEqual((finding["classification"], finding["confidence"]), ("review", "low"))

    def test_alert_outside_time_window_not_linked(self):
        auth = [make_event(0, "u", "mfa_denied", target="workstation-08", method="push"),
                make_event(10, "u", "mfa_denied", target="workstation-08", method="push")]
        alert = make_edr_alert(3 * 3600, "WKSTN-008", "u", "Repeated MFA denial")
        finding = correlate_endpoint_alerts(run_detection_rules(auth), [alert], auth)[0]
        self.assertIn("stands alone", finding["description"])


if __name__ == "__main__":
    unittest.main()
