"""Shared helpers for the tests."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR / "src"))   # lets tests import the src files

START = datetime(2026, 10, 19, 8, 0, 0, tzinfo=timezone.utc)
_counter = [0]


def make_event(offset_seconds, username, event_type, ip="198.51.100.50",
               target="workstation-01", method="password", notes=""):
    """Build one authentication event dictionary, `offset_seconds` after 08:00:00."""
    _counter[0] += 1
    when = START + timedelta(seconds=offset_seconds)
    return {
        "timestamp_utc": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_id": f"T-{_counter[0]:04d}",
        "username": username, "event_type": event_type, "source_ip": ip,
        "target_system": target, "auth_method": method, "notes": notes,
    }


def failures(username, ip, offsets, target="vpn-gateway"):
    return [make_event(o, username, "login_failure", ip, target, "password", "invalid password")
            for o in offsets]


def rule_alerts(alerts, rule_id):
    return [a for a in alerts if a["rule_id"] == rule_id]


def make_edr_alert(offset_seconds, host, user, rule, severity="medium", action="logged"):
    when = START + timedelta(seconds=offset_seconds)
    return {"alert_id": "EDR-T1", "timestamp_utc": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": host, "user": user, "severity": severity, "rule": rule,
            "process": "x", "action": action, "ticket": "", "analyst_note": ""}
