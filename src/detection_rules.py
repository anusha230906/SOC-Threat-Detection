"""Detection rules.

Every rule takes the list of authentication events (dictionaries) and returns
a list of alert dictionaries. All thresholds are constants at the top so they
are easy to explain and to change.

Rule IDs
  R01  Brute force logins                    -> suspicious
  R02  Success right after failures          -> high_review
  R03  MFA fatigue (repeated denials)        -> review (suspicious if worse)
  R04  Privilege granted WITHOUT ticket      -> high_review
  R04b Privilege granted WITH ticket         -> likely_benign
  R05  One typo then MFA success             -> likely_benign
  R06  Service account as expected           -> likely_benign
  R06b Service account NOT as expected       -> review
  R07  Failures for unknown usernames        -> review (suspicious at 4+)

Classes (same words as the official test cases):
  suspicious | review | high_review | likely_benign
"""
import ipaddress
import re
from datetime import datetime

# ------------------------------------------------------------------ settings
BRUTE_FORCE_THRESHOLD = 4          # failures ...
BRUTE_FORCE_WINDOW_SECONDS = 120   # ... within 2 minutes
SUCCESS_FOLLOWUP_SECONDS = 300     # success within 5 min after failures

MFA_THRESHOLD = 2                  # denials ...
MFA_WINDOW_SECONDS = 300           # ... within 5 minutes
MFA_ESCALATE_COUNT = 5             # this many denials = suspicious
MFA_SUCCESS_FOLLOWUP_SECONDS = 1800

TICKET_PATTERN = re.compile(r"CHG-\d+")   # what a change reference looks like
RELATED_TICKET_WINDOW_SECONDS = 900

TYPO_MAX_FAILURES = 2
TYPO_FOLLOWUP_MINUTES = 120
TYPO_HIGH_CONFIDENCE_MINUTES = 10

UNKNOWN_USERNAMES = {"unknown"}
UNKNOWN_THRESHOLD = 3
UNKNOWN_WINDOW_SECONDS = 120

SERVICE_PREFIX = "svc-"
SERVICE_ALLOWLIST = {
    "svc-backup": {"ips": ["192.0.2.40"], "targets": ["backup-01"]},
    "svc-sync": {"ips": ["192.0.2.55"], "targets": ["directory-01"]},
}
SERVICE_AUTH_METHOD = "service_token"

# Documentation address ranges (RFC 5737) used by the fictional scenario
NETWORK_ZONES = {
    "198.51.100.0/24": "internal office range",
    "192.0.2.0/24": "internal service range",
    "203.0.113.0/24": "external / untrusted range",
}


# ------------------------------------------------------------------ helpers
def parse_time(timestamp):
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def event_time(event):
    return parse_time(event["timestamp_utc"])


def seconds_between(first, second):
    return (event_time(second) - event_time(first)).total_seconds()


def zone_label(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "unrecognised address"
    for network, label in NETWORK_ZONES.items():
        if address in ipaddress.ip_network(network):
            return label
    return "unclassified address"


def find_clusters(events, threshold, window_seconds):
    """Groups of at least `threshold` events whose first-to-last time span is
    <= window_seconds. Groups never overlap, so one burst = one cluster."""
    events = sorted(events, key=event_time)
    clusters = []
    i = 0

    while i < len(events):
        j = i
        while (j + 1 < len(events)
               and seconds_between(events[i], events[j + 1]) <= window_seconds):
            j += 1

        if j - i + 1 >= threshold:
            clusters.append(events[i:j + 1])
            i = j + 1
        else:
            i += 1

    return clusters


def make_alert(rule_id, rule, severity, classification, confidence,
               username, events, description, evidence_needed,
               related_ids=None):
    """Build one alert dictionary. `events` are the events that triggered it."""
    source_ip = events[0].get("source_ip", "")
    return {
        "rule_id": rule_id,
        "rule": rule,
        "severity": severity,
        "classification": classification,
        "confidence": confidence,
        "username": username,
        "source_ip": source_ip,
        "event_ids": [e.get("event_id", "?") for e in events],
        "event_count": len(events),
        "start": events[0]["timestamp_utc"],
        "end": events[-1]["timestamp_utc"],
        "description": description,
        "evidence_needed": evidence_needed,
        "related_ids": related_ids or [],
        # Alerts about the same account/source are grouped into one case
        "case_key": username if username not in UNKNOWN_USERNAMES else f"unknown@{source_ip}",
    }


def brute_force_clusters(auth_logs):
    """(username, ip, cluster) for every burst of failures. Unknown usernames
    are handled by R07, so they are left out here."""
    groups = {}
    for event in auth_logs:
        if event["event_type"] == "login_failure" and event["username"] not in UNKNOWN_USERNAMES:
            key = (event["username"], event["source_ip"])
            groups.setdefault(key, []).append(event)

    result = []
    for (username, ip), events in groups.items():
        for cluster in find_clusters(events, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS):
            result.append((username, ip, cluster))
    return result


# ------------------------------------------------------------------- R01
def detect_brute_force(auth_logs):
    alerts = []
    for username, ip, cluster in brute_force_clusters(auth_logs):
        span = int(seconds_between(cluster[0], cluster[-1]))
        alerts.append(make_alert(
            "R01", "Brute Force Login Detection", "Medium", "suspicious", "medium",
            username, cluster,
            f"{len(cluster)} failed logins for {username} from {ip} ({zone_label(ip)}) "
            f"within {span}s. Looks like password guessing, but a user mistyping or a "
            f"stale saved password looks the same. This alone does not show anyone got in.",
            ["Other accounts or systems hit by the same source IP",
             "Geolocation / threat-intel context for the source IP",
             "Whether the user was travelling or working remotely"]))
    return alerts


# ------------------------------------------------------------------- R02
def detect_success_after_failures(auth_logs):
    alerts = []
    for username, ip, cluster in brute_force_clusters(auth_logs):
        for event in auth_logs:
            gap = seconds_between(cluster[-1], event)
            if (event["event_type"] == "login_success" and event["username"] == username
                    and event["source_ip"] == ip and 0 < gap <= SUCCESS_FOLLOWUP_SECONDS):
                alerts.append(make_alert(
                    "R02", "Successful Login After Repeated Failures", "High",
                    "high_review", "medium", username, [event],
                    f"{event['auth_method']} login success for {username} from {ip} "
                    f"({zone_label(ip)}) {int(gap)}s after {len(cluster)} failures from the "
                    f"same address. MFA success lowers the risk but does not remove it. "
                    f"The account is NOT confirmed as compromised; it needs verification.",
                    ["Out-of-band confirmation from the user",
                     "VPN session details: duration, data transferred, resources accessed",
                     "MFA record for this login (device, method, location)",
                     "Any activity by this account after the login"],
                    related_ids=[e.get("event_id", "?") for e in cluster]))
                break
    return alerts


# ------------------------------------------------------------------- R03
def detect_mfa_fatigue(auth_logs):
    alerts = []
    groups = {}
    for event in auth_logs:
        if event["event_type"] == "mfa_denied":
            groups.setdefault(event["username"], []).append(event)

    for username, events in groups.items():
        for cluster in find_clusters(events, MFA_THRESHOLD, MFA_WINDOW_SECONDS):
            later_success = [
                e for e in auth_logs
                if e["username"] == username and e["event_type"] == "login_success"
                and 0 < seconds_between(cluster[-1], e) <= MFA_SUCCESS_FOLLOWUP_SECONDS]

            if later_success:
                classification, severity, confidence = "suspicious", "High", "medium"
                extra = " A successful login followed, the pattern seen when a user finally accepts a prompt."
            elif len(cluster) >= MFA_ESCALATE_COUNT:
                classification, severity, confidence = "suspicious", "Medium", "medium"
                extra = " So many denied prompts is unusual for an honest mistake."
            else:
                classification, severity, confidence = "review", "Medium", "low"
                extra = (" No successful login for this user followed in the data. Denying was the "
                         "right action, so the open question is who triggered the prompts.")

            span = int(seconds_between(cluster[0], cluster[-1]))
            alerts.append(make_alert(
                "R03", "MFA Fatigue Detection", severity, classification, confidence,
                username, cluster,
                f"{len(cluster)} MFA prompts denied by {username} within {span}s. "
                f"Could be MFA fatigue by someone who has the password, or a legitimate mistake."
                + extra,
                ["Ask the user (on a verified channel) if they were signing in then",
                 "Source of the sign-in attempts that created the prompts",
                 "Whether the password was recently reset or leaked",
                 "Any approved prompt shortly after the denials"],
                related_ids=[e.get("event_id", "?") for e in later_success]))
    return alerts


# ------------------------------------------------------------------- R04
def detect_unapproved_privilege(auth_logs):
    """Privilege grant: is there a change reference (CHG-####) in the notes?"""
    alerts = []
    grants = [e for e in auth_logs if e["event_type"] == "privilege_granted"]

    for event in grants:
        match = TICKET_PATTERN.search(event.get("notes", ""))

        if match:
            alerts.append(make_alert(
                "R04b", "Privilege Granted With Change Ticket", "Info", "likely_benign",
                "medium", event["username"], [event],
                f"Privilege grant for {event['username']} cites {match.group(0)}. The reference "
                f"is only text in the log; nobody has checked it against the change system yet.",
                [f"Confirm {match.group(0)} exists, is approved and covers this grant"]))
            continue

        nearby = [g for g in grants if g is not event
                  and TICKET_PATTERN.search(g.get("notes", ""))
                  and g["username"] == event["username"]
                  and abs(seconds_between(event, g)) <= RELATED_TICKET_WINDOW_SECONDS]
        extra = ""
        if nearby:
            other = nearby[0]
            ref = TICKET_PATTERN.search(other["notes"]).group(0)
            extra = (f" A ticketed grant for the same user ({other.get('event_id', '?')}, {ref}) "
                     f"happened {int(abs(seconds_between(event, other)))}s apart. This may be a "
                     f"second step of the same change logged without its reference, or an "
                     f"unapproved extra grant. The log cannot tell which.")

        alerts.append(make_alert(
            "R04", "Unapproved Privilege Detection", "High", "high_review",
            "medium" if nearby else "high", event["username"], [event],
            f"Privilege grant for {event['username']} has no change reference.{extra} "
            f"The log also does not say who made the grant or which role was granted.",
            ["Change records for the time window, including the scope of any nearby ticket",
             "Admin console audit log: who granted what (before and after)",
             "Confirmation from the account owner and their manager",
             "Whether the new privileges were used afterwards"],
            related_ids=[g.get("event_id", "?") for g in nearby]))
    return alerts


# ------------------------------------------------------------------- R05
def detect_benign_typo(auth_logs):
    """One (or two) failed logins, then an MFA success from the same IP and host."""
    alerts = []
    in_burst = {e.get("event_id") for _, _, c in brute_force_clusters(auth_logs) for e in c}
    used_successes = set()

    for failure in auth_logs:
        if (failure["event_type"] != "login_failure" or failure.get("event_id") in in_burst
                or failure["username"] in UNKNOWN_USERNAMES):
            continue

        same_failures = [
            e for e in auth_logs
            if e["event_type"] == "login_failure" and e["username"] == failure["username"]
            and e["source_ip"] == failure["source_ip"]
            and e.get("target_system") == failure.get("target_system")
            and abs(seconds_between(failure, e)) <= TYPO_FOLLOWUP_MINUTES * 60]
        if len(same_failures) > TYPO_MAX_FAILURES:
            continue

        successes = [
            e for e in auth_logs
            if e["event_type"] == "login_success" and e["username"] == failure["username"]
            and e["source_ip"] == failure["source_ip"]
            and e.get("target_system") == failure.get("target_system")
            and e.get("auth_method") == "MFA"
            and 0 < seconds_between(failure, e) <= TYPO_FOLLOWUP_MINUTES * 60]
        if not successes or successes[0].get("event_id") in used_successes:
            continue

        success = successes[0]
        used_successes.add(success.get("event_id"))
        gap_minutes = seconds_between(failure, success) / 60
        confidence = "high" if gap_minutes <= TYPO_HIGH_CONFIDENCE_MINUTES else "medium"
        note = ""
        if confidence == "medium":
            note = (f" The retry came {gap_minutes:.0f} minutes later, so it looks more like "
                    f"the user coming back than an immediate retry; confidence is lowered.")

        alerts.append(make_alert(
            "R05", "Single Failure Then MFA Success", "Info", "likely_benign", confidence,
            failure["username"], [failure, success],
            f"One failed password for {failure['username']} on {failure.get('target_system')} "
            f"was followed by a successful MFA login from the same address and host.{note}",
            ["None needed unless other alerts exist for this user"]))
    return alerts


# ------------------------------------------------------------------- R06
def detect_service_accounts(auth_logs):
    alerts = []
    for event in auth_logs:
        if not event["username"].startswith(SERVICE_PREFIX) or event["event_type"] != "login_success":
            continue

        allowed = SERVICE_ALLOWLIST.get(event["username"])
        expected = (allowed is not None
                    and event["source_ip"] in allowed["ips"]
                    and event.get("target_system") in allowed["targets"]
                    and event.get("auth_method") == SERVICE_AUTH_METHOD)

        if expected:
            alerts.append(make_alert(
                "R06", "Service Account Expected Login", "Info", "likely_benign", "medium",
                event["username"], [event],
                f"{event['username']} used {event['auth_method']} from {event['source_ip']} to "
                f"{event['target_system']}, which matches its allow-list entry. The job "
                f"schedule itself is not checked by this rule.",
                ["Optional: confirm the job schedule"]))
        else:
            alerts.append(make_alert(
                "R06b", "Service Account Unexpected Login", "Medium", "review", "medium",
                event["username"], [event],
                f"{event['username']} logged in from {event['source_ip']} to "
                f"{event.get('target_system')} using {event.get('auth_method')}, which does "
                f"not match its allow-list entry.",
                ["Owner of the service account", "Scheduler / job logs for the same time",
                 "Whether the credential or token was rotated recently"]))
    return alerts


# ------------------------------------------------------------------- R07
def detect_unknown_username_failures(auth_logs):
    alerts = []
    groups = {}
    for event in auth_logs:
        if event["event_type"] == "login_failure" and event["username"] in UNKNOWN_USERNAMES:
            groups.setdefault(event["source_ip"], []).append(event)

    for ip, events in groups.items():
        for cluster in find_clusters(events, UNKNOWN_THRESHOLD, UNKNOWN_WINDOW_SECONDS):
            heavy = len(cluster) >= BRUTE_FORCE_THRESHOLD
            span = int(seconds_between(cluster[0], cluster[-1]))
            if heavy:
                note = "This meets the brute-force threshold. "
            else:
                note = (f"This is below the {BRUTE_FORCE_THRESHOLD}-event brute-force threshold, "
                        f"so it is raised for review, not as suspicious. ")
            alerts.append(make_alert(
                "R07", "Unknown Username Failures", "Medium",
                "suspicious" if heavy else "review", "medium" if heavy else "low",
                "unknown", cluster,
                f"{len(cluster)} failed logins for a username that does not exist, from {ip} "
                f"({zone_label(ip)}) within {span}s. {note}"
                f"Fits username guessing or a misconfigured client.",
                ["All other events from this IP (VPN, web, mail)",
                 "Whether the usernames tried match a real naming scheme",
                 "Whether the gateway rate limit actually held"]))
    return alerts


# ------------------------------------------------------------------ run all
RULE_FUNCTIONS = [
    detect_brute_force,
    detect_success_after_failures,
    detect_mfa_fatigue,
    detect_unapproved_privilege,
    detect_benign_typo,
    detect_service_accounts,
    detect_unknown_username_failures,
]


def run_detection_rules(auth_logs):
    """Run every rule. Returns ALL findings, including likely_benign ones."""
    auth_logs = sorted(auth_logs, key=event_time)
    alerts = []
    for rule_function in RULE_FUNCTIONS:
        alerts.extend(rule_function(auth_logs))
    alerts.sort(key=lambda a: (parse_time(a["start"]), a["rule_id"]))
    return alerts
