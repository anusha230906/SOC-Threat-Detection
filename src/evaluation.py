"""Score the detection rules against the synthetic ground truth."""
ALERTING = {"high_review", "suspicious", "review"}


def evaluate_detections(alerts, truth):
    scenarios = truth["scenarios"]
    attack_ids = set()
    for s in scenarios:
        if s["malicious"] and not s["known_gap"]:
            attack_ids.update(s["event_ids"])

    detected, missed, known_gaps = [], [], []
    for s in scenarios:
        ids = set(s["event_ids"])
        if s["known_gap"]:
            hit = [a for a in alerts if ids & set(a["event_ids"]) and a["classification"] in ALERTING]
            known_gaps.append({"scenario": s["scenario_id"], "type": s["type"], "detected": bool(hit)})
            continue
        if not s["expected_rules"]:
            continue
        wanted = set(s["expected_rules"])
        got = {a["rule_id"] for a in alerts if ids & set(a["event_ids"])}
        row = {"scenario": s["scenario_id"], "type": s["type"],
               "expected": sorted(wanted), "got": sorted(got)}
        (detected if wanted <= got else missed).append(row)

    alerting = [a for a in alerts if a["classification"] in ALERTING]
    true_positive = [a for a in alerting if set(a["event_ids"]) & attack_ids]
    false_positive = [a for a in alerting if not set(a["event_ids"]) & attack_ids]

    # Scenarios that should be quiet but raised an alert anyway
    misfired = []
    for s in scenarios:
        if s["malicious"] or s["scenario_id"] in ("S-TYPO", "S-TICKET"):
            continue
        ids = set(s["event_ids"])
        bad = [a for a in alerting if ids & set(a["event_ids"])]
        if bad:
            misfired.append({"scenario": s["scenario_id"], "rules": [a["rule_id"] for a in bad]})

    total = len(detected) + len(missed)
    return {
        "scenarios_expected_to_alert": total,
        "detected": len(detected),
        "missed": missed,
        "recall": round(len(detected) / total, 3) if total else None,
        "alerting_findings": len(alerting),
        "true_positive_findings": len(true_positive),
        "false_positive_findings": [f"{a['rule_id']} {a['username']}" for a in false_positive],
        "precision": round(len(true_positive) / len(alerting), 3) if alerting else None,
        "quiet_scenarios_that_alerted": misfired,
        "known_gaps": known_gaps,
    }
