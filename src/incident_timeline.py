"""Build one timeline from authentication events and endpoint alerts."""
import csv
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_DIR / "output"

CLASS_RANK = {"high_review": 0, "suspicious": 1, "review": 2, "likely_benign": 3}

TIMELINE_FIELDS = ["timestamp", "event_id", "source", "username", "event_type",
                   "source_ip", "system", "details", "assessment", "alert_ids"]


def get_value(record, possible_keys, default="Not available"):
    for key in possible_keys:
        if key in record and record[key] is not None:
            return record[key]
    return default


def assessment_by_id(alerts):
    """For each event/alert ID: the most serious class and the alert numbers."""
    classes, numbers = {}, {}
    for number, alert in enumerate(alerts, start=1):
        for event_id in alert["event_ids"]:
            classes.setdefault(event_id, []).append(alert["classification"])
            numbers.setdefault(event_id, []).append(alert.get("finding_id", f"F-{number:03d}"))
    return classes, numbers


def generate_incident_timeline(auth_logs, endpoint_alerts, alerts=None):
    timeline = []
    classes, numbers = assessment_by_id(alerts or [])

    def assessment_for(event_id):
        found = classes.get(event_id)
        return min(found, key=lambda c: CLASS_RANK[c]) if found else "baseline"

    # Add authentication events
    for event in auth_logs:
        event_id = get_value(event, ["event_id", "id"])
        timeline.append({
            "timestamp": get_value(event, ["timestamp_utc", "timestamp"]),
            "event_id": event_id,
            "source": "Authentication Log",
            "username": get_value(event, ["username", "user"]),
            "event_type": get_value(event, ["event_type", "type"]),
            "source_ip": get_value(event, ["source_ip", "src_ip"]),
            "system": get_value(event, ["target_system", "system"]),
            "details": get_value(event, ["notes", "description"]),
            "assessment": assessment_for(event_id),
            "alert_ids": ", ".join(numbers.get(event_id, [])),
        })

    # Add endpoint alerts
    for alert in endpoint_alerts:
        event_id = get_value(alert, ["alert_id", "event_id", "id"])
        details = (
            f"Process: {get_value(alert, ['process'])}; "
            f"Action: {get_value(alert, ['action'])}; "
            f"Ticket: {get_value(alert, ['ticket'])}; "
            f"Note: {get_value(alert, ['analyst_note'])}"
        )
        timeline.append({
            "timestamp": get_value(alert, ["timestamp_utc", "timestamp"]),
            "event_id": event_id,
            "source": "Endpoint Alert",
            "username": get_value(alert, ["user", "username"]),
            "event_type": get_value(alert, ["rule", "alert_type"]),
            "source_ip": get_value(alert, ["source_ip", "src_ip"]),
            "system": get_value(alert, ["host", "hostname", "device"]),
            "details": details,
            "assessment": assessment_for(event_id),
            "alert_ids": ", ".join(numbers.get(event_id, [])),
        })

    # ISO timestamps sort correctly as text
    timeline.sort(key=lambda item: (item["timestamp"], item["event_id"]))
    return timeline


def save_incident_timeline(timeline, output_dir=None):
    output_dir = Path(output_dir) if output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / "incident_timeline.csv"

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=TIMELINE_FIELDS)
        writer.writeheader()
        writer.writerows(timeline)

    print("Incident timeline saved to:", file_path)


def display_incident_timeline(timeline):
    print("\n========== INCIDENT TIMELINE ==========")

    for event in timeline:
        print(event["timestamp"], "|", event["event_id"], "|", event["username"], "|",
              event["event_type"], "|", event["system"], "|", event["assessment"])

    print("\nTotal timeline events:", len(timeline))
