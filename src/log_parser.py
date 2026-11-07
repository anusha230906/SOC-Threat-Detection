"""Read the input files (authentication CSV and endpoint-alert JSON)."""
import csv
import json
from pathlib import Path

# Find the project folder (one level above src/)
PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"

AUTH_COLUMNS = ["timestamp_utc", "event_id", "username", "event_type",
                "source_ip", "target_system", "auth_method", "notes"]


def read_authentication_logs(file_path=None):
    """Return the authentication events as a list of dictionaries."""
    file_path = Path(file_path) if file_path else DATA_DIR / "authentication_events.csv"

    with open(file_path, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        missing = [c for c in AUTH_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{file_path}: missing columns {missing}")

        return list(reader)


def read_endpoint_alerts(file_path=None):
    """Return the raw JSON content of the endpoint alert file."""
    file_path = Path(file_path) if file_path else DATA_DIR / "endpoint_alerts.json"

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def extract_alert_list(endpoint_data):
    """The JSON can be a list, or a dictionary holding a list under 'alerts'."""
    if isinstance(endpoint_data, list):
        return endpoint_data

    if isinstance(endpoint_data, dict):
        for value in endpoint_data.values():
            if isinstance(value, list):
                return value

    return []


# Quick check: python src/log_parser.py
if __name__ == "__main__":
    logs = read_authentication_logs()
    alerts = extract_alert_list(read_endpoint_alerts())
    print("Authentication events loaded:", len(logs))
    print("Endpoint alerts loaded:", len(alerts))
