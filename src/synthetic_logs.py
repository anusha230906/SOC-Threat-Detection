"""Synthetic authentication log generator with ground-truth labels.

Same CSV columns as the starter file. The same seed always gives the same
logs. Everything is fictional; IPs come from the RFC 5737 documentation ranges.

Scenarios (each one is labelled in the ground-truth file):
  baseline, typo_benign, ticketed_privilege          -> normal activity
  near_miss_3_failures, typo_twice_benign             -> should NOT raise an alert
  brute_force, brute_force_then_success               -> R01 (+R02)
  mfa_fatigue, privilege_without_ticket, unknown_user_spray -> R03, R04, R07
  slow_burn_guessing                                  -> KNOWN GAP (not detected)
"""
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
SYNTHETIC_DIR = PROJECT_DIR / "data" / "synthetic"
CSV_NAME = "synthetic_authentication_events.csv"
TRUTH_NAME = "synthetic_ground_truth.json"

NAMES = ["a.novak", "b.osei", "c.diaz", "d.huang", "e.moreau", "f.ito", "g.silva", "h.berg",
         "i.okafor", "j.reyes", "k.larsen", "l.ahmed", "m.kovacs", "n.dubois", "o.tanaka",
         "p.murphy", "q.rossi", "r.singh", "s.lindgren", "t.mendes"]
ADMINS = ["adm.holt", "adm.vega", "adm.zhou", "adm.nair", "adm.cole", "adm.park"]
VICTIMS = ["v.user%02d" % i for i in range(1, 25)]

FIELDS = ["timestamp_utc", "event_id", "username", "event_type", "source_ip",
          "target_system", "auth_method", "notes"]


def generate(seed=42, hours=8):
    rng = random.Random(seed)
    start = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)
    rows, scenarios = [], []
    victims = VICTIMS[:]
    rng.shuffle(victims)

    def add(when, user, etype, ip, target, method, notes, scenario_id):
        rows.append({"when": when, "username": user, "event_type": etype, "source_ip": ip,
                     "target_system": target, "auth_method": method, "notes": notes,
                     "scenario": scenario_id})

    def scenario(scenario_id, kind, expected_rules, malicious, known_gap=False):
        scenarios.append({"scenario_id": scenario_id, "type": kind, "expected_rules": expected_rules,
                          "malicious": malicious, "known_gap": known_gap})
        return scenario_id

    def random_time(low=20, high=hours * 60 - 20):
        return start + timedelta(seconds=rng.randint(low * 60, high * 60))

    # ---- normal activity
    base = scenario("S-BASE", "baseline", [], False)
    typo = scenario("S-TYPO", "typo_benign", ["R05"], False)
    for index, user in enumerate(NAMES):
        ip, workstation = "198.51.100.%d" % (10 + index), "workstation-%02d" % (index + 1)
        when = random_time(0, 150)
        if rng.random() < 0.25:
            add(when, user, "login_failure", ip, workstation, "password", "invalid password", typo)
            add(when + timedelta(seconds=rng.randint(20, 240)), user, "login_success", ip,
                workstation, "MFA", "normal office login", typo)
        else:
            add(when, user, "login_success", ip, workstation, "MFA", "normal office login", base)
    for hour in range(hours):
        add(start + timedelta(hours=hour, minutes=20, seconds=rng.randint(0, 40)), "svc-backup",
            "login_success", "192.0.2.40", "backup-01", "service_token", "scheduled backup job", base)
        if hour % 2 == 0:
            add(start + timedelta(hours=hour, minutes=18, seconds=rng.randint(0, 40)), "svc-sync",
                "login_success", "192.0.2.55", "directory-01", "service_token", "expected sync job", base)
    for _ in range(3):
        add(random_time(), rng.choice(NAMES), "password_reset", "198.51.100.28", "helpdesk-portal",
            "email_otp", "verified reset", base)
    ticketed = scenario("S-TICKET", "ticketed_privilege", ["R04b"], False)
    for n in range(3):
        add(random_time(), ADMINS[n], "privilege_granted", "198.51.100.%d" % (60 + n), "admin-console",
            "MFA", "approved change ticket CHG-%d" % (2000 + n), ticketed)

    # ---- hard negatives (must NOT alert)
    for n in range(2):
        user, ip = victims.pop(), "198.51.100.%d" % (100 + n)
        sid = scenario("S-NEAR%d" % n, "near_miss_3_failures", [], False)
        when = random_time()
        for k in range(3):
            add(when + timedelta(seconds=k * 20), user, "login_failure", ip, "vpn-gateway",
                "password", "invalid password", sid)
    for n in range(2):
        user, ip = victims.pop(), "198.51.100.%d" % (110 + n)
        sid = scenario("S-TYPO2%d" % n, "typo_twice_benign", ["R05"], False)
        when = random_time()
        add(when, user, "login_failure", ip, "workstation-30", "password", "invalid password", sid)
        add(when + timedelta(seconds=25), user, "login_failure", ip, "workstation-30", "password",
            "invalid password", sid)
        add(when + timedelta(seconds=70), user, "login_success", ip, "workstation-30", "MFA",
            "normal office login", sid)

    # ---- known gap: slow guessing (5 failures ~170 s apart)
    for n in range(2):
        user, ip = victims.pop(), "203.0.113.%d" % (200 + n)
        sid = scenario("S-SLOW%d" % n, "slow_burn_guessing", [], True, known_gap=True)
        when = random_time(20, hours * 60 - 60)
        for k in range(5):
            add(when + timedelta(seconds=k * 170), user, "login_failure", ip, "vpn-gateway",
                "password", "invalid password", sid)

    # ---- attacks that must be detected
    for n in range(4):
        user, ip = victims.pop(), "203.0.113.%d" % (10 + n)
        with_success = n >= 2
        sid = scenario("S-BF%d" % n, "brute_force_then_success" if with_success else "brute_force",
                       ["R01", "R02"] if with_success else ["R01"], True)
        when = random_time()
        for k in range(rng.randint(4, 8)):
            when += timedelta(seconds=rng.randint(4, 14))
            add(when, user, "login_failure", ip, "vpn-gateway", "password", "invalid password", sid)
        if with_success:
            add(when + timedelta(seconds=rng.randint(20, 90)), user, "login_success", ip, "vpn-gateway",
                "MFA", "success after repeated failures; review required", sid)
    for n in range(3):
        user = victims.pop()
        sid = scenario("S-MFA%d" % n, "mfa_fatigue", ["R03"], True)
        when = random_time()
        for k in range(rng.randint(2, 4)):
            when += timedelta(seconds=rng.randint(20, 70))
            add(when, user, "mfa_denied", "198.51.100.%d" % (120 + n), "workstation-%d" % (40 + n),
                "push", "user denied unexpected prompt", sid)
    for n in range(3):
        sid = scenario("S-PRIV%d" % n, "privilege_without_ticket", ["R04"], True)
        add(random_time(), ADMINS[3 + n], "privilege_granted", "198.51.100.%d" % (70 + n),
            "admin-console", "MFA", "no change ticket in event; investigate", sid)
    for n in range(2):
        ip = "203.0.113.%d" % (90 + n)
        sid = scenario("S-SPRAY%d" % n, "unknown_user_spray", ["R07"], True)
        when = random_time()
        for k in range(rng.randint(3, 6)):
            when += timedelta(seconds=rng.randint(4, 14))
            add(when, "unknown", "login_failure", ip, "vpn-gateway", "password", "unknown username", sid)

    # ---- give IDs in time order
    rows.sort(key=lambda r: r["when"])
    events, ids_by_scenario = [], {}
    for number, row in enumerate(rows, start=1):
        event_id = "AUTH-S%04d" % number
        ids_by_scenario.setdefault(row["scenario"], []).append(event_id)
        events.append({
            "timestamp_utc": row["when"].strftime("%Y-%m-%dT%H:%M:%SZ"), "event_id": event_id,
            "username": row["username"], "event_type": row["event_type"],
            "source_ip": row["source_ip"], "target_system": row["target_system"],
            "auth_method": row["auth_method"], "notes": row["notes"]})
    for s in scenarios:
        s["event_ids"] = ids_by_scenario.get(s["scenario_id"], [])
    return events, {"seed": seed, "hours": hours, "scenarios": scenarios}


def save_synthetic_logs(events, truth, output_dir=None):
    output_dir = Path(output_dir) if output_dir else SYNTHETIC_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path, truth_path = output_dir / CSV_NAME, output_dir / TRUTH_NAME

    with open(csv_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(events)
    with open(truth_path, "w", encoding="utf-8") as file:
        json.dump(truth, file, indent=2)

    return csv_path, truth_path
