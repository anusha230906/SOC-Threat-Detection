"""SOC Threat Detection prototype.

Run from the project folder:
  python src/main.py                    analyse the starter scenario (INC-2026-104)
  python src/main.py --generate         create synthetic logs (use --seed N for others)
  python src/main.py --evaluate         score the rules on the synthetic logs
"""
import argparse
import csv
import json
from pathlib import Path

from log_parser import read_authentication_logs, read_endpoint_alerts, extract_alert_list
from detection_rules import run_detection_rules
from edr_correlation import correlate_endpoint_alerts
from incident_triage import (assign_finding_ids, generate_triage_report, display_triage_report,
                             build_markdown_report, save_triage_csv, save_markdown_report)
from incident_timeline import (generate_incident_timeline, save_incident_timeline,
                               display_incident_timeline)
from synthetic_logs import generate, save_synthetic_logs, SYNTHETIC_DIR, CSV_NAME, TRUTH_NAME
from evaluation import evaluate_detections

PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_DIR / "output"

ALERT_FIELDS = ["finding_id", "rule_id", "rule", "severity", "classification", "confidence",
                "username", "source_ip", "event_count", "event_ids", "start", "end", "description"]


def save_alerts(findings):
    OUTPUT_DIR.mkdir(exist_ok=True)
    file_path = OUTPUT_DIR / "security_alerts.csv"

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=ALERT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = dict(finding)
            row["event_ids"] = " ".join(finding["event_ids"])
            writer.writerow(row)

    print("Security alerts saved to:", file_path)


def analyse_starter_data():
    print("\n========== SOC THREAT DETECTION SYSTEM ==========")

    authentication_logs = read_authentication_logs()
    endpoint_alerts = extract_alert_list(read_endpoint_alerts())
    print("\nAuthentication events:", len(authentication_logs))
    print("Endpoint alerts:", len(endpoint_alerts))

    # 1. Detect from authentication logs, 2. correlate endpoint alerts
    auth_findings = run_detection_rules(authentication_logs)
    edr_findings = correlate_endpoint_alerts(auth_findings, endpoint_alerts, authentication_logs)
    findings = assign_finding_ids(auth_findings, edr_findings)

    print("\n========== DETECTED FINDINGS ==========")
    for finding in findings:
        print(f"{finding['finding_id']} | {finding['rule_id']:<8} | {finding['username']:<11} | "
              f"{finding['classification']:<13} | {finding['severity']:<6} | "
              f"{', '.join(finding['event_ids'])}")
    print("\nTotal findings:", len(findings))
    save_alerts(findings)

    # 3. Group into cases and rank
    cases = generate_triage_report(findings)
    display_triage_report(cases)
    save_triage_csv(cases)

    # 4. Timeline and written report
    timeline = generate_incident_timeline(authentication_logs, endpoint_alerts, findings)
    display_incident_timeline(timeline)
    save_incident_timeline(timeline)

    report = build_markdown_report(cases, findings, timeline,
                                   len(authentication_logs), len(endpoint_alerts))
    save_markdown_report(report)
    print("\n========== ANALYSIS COMPLETED ==========")


def make_synthetic_logs(seed):
    events, truth = generate(seed=seed)
    csv_path, truth_path = save_synthetic_logs(events, truth)
    print(f"Wrote {len(events)} events to {csv_path}")
    print(f"Wrote ground truth to {truth_path}")


def evaluate_on_synthetic_logs():
    csv_path = SYNTHETIC_DIR / CSV_NAME
    truth_path = SYNTHETIC_DIR / TRUTH_NAME
    if not csv_path.exists() or not truth_path.exists():
        print("Synthetic logs not found. Run: python src/main.py --generate")
        return

    logs = read_authentication_logs(csv_path)
    with open(truth_path, encoding="utf-8") as file:
        truth = json.load(file)

    result = evaluate_detections(run_detection_rules(logs), truth)
    OUTPUT_DIR.mkdir(exist_ok=True)
    with open(OUTPUT_DIR / "evaluation.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="SOC Threat Detection prototype")
    parser.add_argument("--generate", action="store_true", help="create synthetic logs")
    parser.add_argument("--evaluate", action="store_true", help="score rules on synthetic logs")
    parser.add_argument("--seed", type=int, default=42, help="seed for --generate")
    args = parser.parse_args()

    if args.generate:
        make_synthetic_logs(args.seed)
    elif args.evaluate:
        evaluate_on_synthetic_logs()
    else:
        analyse_starter_data()


if __name__ == "__main__":
    main()
