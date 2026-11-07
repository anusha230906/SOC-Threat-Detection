"""Turn endpoint (EDR) alerts into findings by checking them against the
authentication events.

Match rule: same user + the alert's host maps to the event's target system +
event within CORRELATION_MINUTES of the alert.
The class of an EDR alert comes from the most serious related finding. An alert
with no support is never escalated and never dismissed: it stays "review".
"""
from detection_rules import parse_time, UNKNOWN_USERNAMES

CORRELATION_MINUTES = 30

# EDR host name -> target_system name used in the authentication log
HOST_MAP = {
    "WKSTN-014": "workstation-14",
    "WKSTN-008": "workstation-08",
    "VPN-GW-01": "vpn-gateway",
    "ADMIN-CONSOLE": "admin-console",
}

ACTION_TEXT = {
    "blocked": "The product blocked the activity, which limits impact but not intent.",
    "allowed": "The product allowed the activity; nothing was prevented.",
    "rate_limited": "The product rate-limited the source.",
    "logged": "The product only logged the activity; nothing was prevented.",
}

CLASS_RANK = {"high_review": 0, "suspicious": 1, "review": 2, "likely_benign": 3}


def correlate_endpoint_alerts(detections, endpoint_alerts, auth_logs):
    findings = []

    for alert in endpoint_alerts:
        alert_time = parse_time(alert["timestamp_utc"])
        target = HOST_MAP.get(alert["host"])

        related = [
            e for e in auth_logs
            if e["username"] == alert["user"] and target is not None
            and e["target_system"] == target
            and abs((parse_time(e["timestamp_utc"]) - alert_time).total_seconds())
            <= CORRELATION_MINUTES * 60]
        related_ids = [e["event_id"] for e in related]

        supporting = [d for d in detections
                      if d["username"] == alert["user"]
                      and set(d["event_ids"]) & set(related_ids)
                      and d["classification"] != "likely_benign"]

        timing_note = ""
        context_note = ""
        if supporting:
            top = min(supporting, key=lambda d: CLASS_RANK[d["classification"]])
            classification, confidence = top["classification"], "medium"
            case_key = top["case_key"]
            ids = ", ".join(sorted({d["rule_id"] for d in supporting}))
            support_text = f"Supported by authentication findings ({ids})."

            first = min(parse_time(d["start"]) for d in supporting)
            gap = (first - alert_time).total_seconds()
            if gap > 0:
                timing_note = (f" Timing note: the alert is {int(gap)}s BEFORE the first related "
                               f"authentication event. That suggests clock skew, earlier activity "
                               f"missing from this extract, or a wrong correlation. Check this "
                               f"before relying on the link.")
        else:
            classification, confidence = "review", "low"
            user = alert["user"]
            case_key = user if user not in UNKNOWN_USERNAMES else f"unknown@{alert['host']}"
            support_text = ("No suspicious authentication finding for this user on this host "
                            "in the time window; the alert stands alone.")
            if related:
                nearest = min(related, key=lambda e: abs(
                    (parse_time(e["timestamp_utc"]) - alert_time).total_seconds()))
                context_note = (f" Nearest authentication context: {nearest['event_id']} "
                                f"({nearest['event_type']}, {nearest['auth_method']}) at "
                                f"{nearest['timestamp_utc']}.")

        evidence = ["Full alert record from the originating product (raw event, rule logic)"]
        if alert["rule"].startswith("Office child process"):
            evidence = ["Full EDR telemetry: command line, parent chain, file hash, user session",
                        "Email or download that delivered the document, and its macro content",
                        "Whether the user opened the document knowingly; other child processes"]

        description = (
            f"Endpoint alert {alert['alert_id']} on {alert['host']}: {alert['rule']} "
            f"(process {alert['process']}, severity {alert['severity']}). "
            f"{ACTION_TEXT.get(alert['action'], 'Product action: ' + alert['action'] + '.')} "
            f"{support_text}{context_note}{timing_note} "
            f"Note in alert: \"{alert.get('analyst_note', '')}\"")

        findings.append({
            "rule_id": "EDR-CORR",
            "rule": f"{alert['rule']} ({alert['alert_id']})",
            "severity": alert["severity"].capitalize(),
            "classification": classification,
            "confidence": confidence,
            "username": alert["user"],
            "source_ip": "",
            "event_ids": [alert["alert_id"]],
            "event_count": 1,
            "start": alert["timestamp_utc"],
            "end": alert["timestamp_utc"],
            "description": description,
            "evidence_needed": evidence,
            "related_ids": related_ids,
            "case_key": case_key,
            "edr_kind": "host" if alert["rule"].startswith("Office child process") else "other",
        })

    return findings
