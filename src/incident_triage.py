"""Group findings into cases, rank them, and write the triage report.

A "case" = all findings about the same account (or the same unknown source IP).
The report says what is likely benign, suspicious, or needs more evidence, how
confident we are, what evidence to ask for, and what to do next without
destroying evidence.
"""
import csv
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_DIR / "output"

CLASS_RANK = {"high_review": 0, "suspicious": 1, "review": 2, "likely_benign": 3}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PRIORITY = {"critical": "P1", "high": "P1", "medium": "P2", "low": "P3", "info": "P4"}

CLASS_LABEL = {
    "high_review": "High-priority review",
    "suspicious": "Suspicious",
    "review": "Needs more evidence",
    "likely_benign": "Likely benign",
    "baseline": "Baseline (no detection)",
}

STATUS_TEXT = {
    "high_review": "Unverified and time-sensitive. Treat as a possible unauthorised action until the owner confirms otherwise. Not confirmed malicious.",
    "suspicious": "Pattern consistent with an attack, not yet tied to any successful access. Not confirmed malicious.",
    "review": "Undetermined. The evidence fits both benign and malicious explanations.",
    "likely_benign": "Matches expected behaviour. Close after the light verification listed.",
}

GENERAL_PRINCIPLES = [
    "**Preserve before you act.** Export and hash the relevant VPN, identity-provider, MFA, admin-console and EDR logs (note when and by whom) before any change that could overwrite state.",
    "**Prefer reversible controls.** Rate limits, temporary source blocks, step-up authentication and session termination (after session details are captured) are better than wiping or deleting anything.",
    "**Do not power off or reimage hosts** with endpoint alerts until volatile data and the EDR timeline are captured.",
    "**Do not reset passwords or disable accounts as the first move.** Capture session and token details first, because a reset can end the sessions you want to inspect.",
    "**Verify out of band.** Contact users on a known channel (phone or chat directory), never by replying to anything in the incident.",
    "**Need-to-know communication.** Factual, non-accusatory wording; no claim of compromise unless the evidence supports it.",
    "**Log every action** (who, what, when, why) in the ticket so the timeline can be rebuilt.",
]

# What to do and who to tell, per rule
PLAYBOOK = {
    "R01": {
        "contain": ["Add a temporary, reversible block or tighter rate limit for the source IP at the VPN gateway.",
                    "Search VPN and identity logs for the same source IP against other accounts before deciding scope."],
        "comms": ["Inform the SOC lead and the VPN/network owner. No user-wide announcement yet."]},
    "R02": {
        "contain": ["Capture the active VPN session (assigned address, bytes, resources) and the MFA record for the success.",
                    "If the user cannot confirm the login: terminate the session, revoke refresh tokens, then reset credentials and re-enrol MFA, in that order.",
                    "Until confirmed, apply step-up authentication or limit the account to low-risk resources (reversible)."],
        "comms": ["Contact the user out of band with a neutral question: did you sign in to the VPN at the time shown?",
                  "Escalate to the Incident Manager if the user denies the login or the session shows unusual access."]},
    "R03": {
        "contain": ["Do not block the user; they did the right thing by denying.",
                    "Pull the sign-in attempts that triggered the prompts and consider number matching on push prompts (a reversible config change)."],
        "comms": ["Tell the user their denials were right, ask whether they started the sign-ins, and ask them to report more unexpected prompts."]},
    "R04": {
        "contain": ["Do not revert the privilege change until the admin console audit record and permission difference are exported.",
                    "After capture, if no approval is found, remove the unapproved privilege (reversible) and review what was done with it."],
        "comms": ["Ask the change manager and the user's manager to confirm the scope of any ticket cited nearby, or whether any approval exists.",
                  "Notify the IAM/platform owner; escalate to the Incident Manager if no approval exists."]},
    "R04b": {"contain": [], "comms": ["Record the check of the cited ticket in the case."]},
    "R05": {"contain": [], "comms": ["No action beyond a closing note."]},
    "R06": {"contain": [], "comms": ["No action."]},
    "R06b": {
        "contain": ["Capture session and token metadata; do not rotate the credential until the owner is consulted and evidence is saved."],
        "comms": ["Contact the service account owner."]},
    "R07": {
        "contain": ["Confirm the gateway rate limit held; add a temporary, reversible block for the source IP if attempts continue.",
                    "Search for the same source IP in other logs (web, mail, other VPN pools)."],
        "comms": ["Share the indicator with the network owner. No user notification needed (no valid account involved)."]},
    "EDR-CORR": {
        "contain": ["Pull the raw alert from the originating product and keep it with the case; no separate containment beyond the related findings."],
        "comms": ["Share the alert context with the owner of the originating product."]},
    "EDR-HOST": {
        "contain": ["Keep the host online and isolated from sensitive resources only if EDR network containment is available and reversible; do not reboot or reimage.",
                    "Collect the EDR process tree and the document/file artefacts for analysis."],
        "comms": ["Tell the user (neutral tone) and ask what they were doing; notify the endpoint team."]},
}


def playbook_key(finding):
    if finding["rule_id"] == "EDR-CORR" and finding.get("edr_kind") == "host":
        return "EDR-HOST"
    return finding["rule_id"]


def assign_finding_ids(auth_findings, edr_findings):
    """F-001, F-002 ... : authentication findings first, then endpoint ones."""
    combined = list(auth_findings) + list(edr_findings)
    for number, finding in enumerate(combined, start=1):
        finding["finding_id"] = f"F-{number:03d}"
    return combined


def build_cases(findings):
    groups = {}
    for finding in findings:
        groups.setdefault(finding["case_key"], []).append(finding)

    cases = []
    for key, items in groups.items():
        items.sort(key=lambda f: (f["start"], f["finding_id"]))
        serious = [f for f in items if f["classification"] != "likely_benign"]
        pool = serious or items
        top = min(pool, key=lambda f: (SEVERITY_RANK[f["severity"].lower()],
                                       CLASS_RANK[f["classification"]]))
        cases.append({
            "key": key,
            "entity": key if key.startswith("unknown@") else items[0]["username"],
            "findings": items,
            "classification": top["classification"],
            "severity": top["severity"].lower(),
            "confidence": top["confidence"],
            "priority": PRIORITY[top["severity"].lower()],
            "start": min(f["start"] for f in items),
            "end": max(f["end"] for f in items),
            "serious_count": len(serious),
        })

    cases.sort(key=lambda c: (SEVERITY_RANK[c["severity"]], CLASS_RANK[c["classification"]],
                              -c["serious_count"], c["start"]))
    for number, case in enumerate(cases, start=1):
        case["case_id"] = f"CASE-{number:02d}"
    return cases


def generate_triage_report(findings):
    """Kept from the first version: returns the cases (one triage row each)."""
    return build_cases(findings)


def _unique(items):
    seen = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def build_markdown_report(cases, findings, timeline, auth_count, edr_count):
    lines = []
    add = lines.append
    needs_action = [c for c in cases if c["classification"] != "likely_benign"]
    benign = [c for c in cases if c["classification"] == "likely_benign"]
    p1 = [c["entity"] for c in cases if c["priority"] == "P1"]

    add("# Incident Triage Report: INC-2026-104 (Suspected Account Misuse)")
    add("")
    add("*Generated by the SOC Threat Detection prototype. All data is synthetic/fictional "
        "(Northstar Community Services scenario). Detection window: 19 Oct 2026, 08:00-10:30 UTC "
        "(one starter event, AUTH-0020, falls outside it; see Caveats).*")
    add("")
    add("## 1. Summary")
    add("")
    add(f"- **Inputs:** {auth_count} authentication events, {edr_count} endpoint alerts.")
    add(f"- **Output:** {len(findings)} findings grouped into {len(cases)} cases "
        f"({len(needs_action)} need analyst action, {len(benign)} are likely benign).")
    conclusion = "- **Conclusion:** No account is confirmed compromised. "
    if p1:
        conclusion += (f"{len(p1)} case(s) ({', '.join(p1)}) are high priority because they need "
                       f"quick verification; ")
    conclusion += "the rest need more evidence or are expected behaviour."
    add(conclusion)
    add("")
    add("## 2. Triage queue")
    add("")
    add("| Priority | Case | Entity | Assessment | Severity | Confidence | Findings |")
    add("|---|---|---|---|---|---|---|")
    for c in cases:
        ids = ", ".join(f["finding_id"] for f in c["findings"])
        add(f"| {c['priority']} | {c['case_id']} | {c['entity']} | {CLASS_LABEL[c['classification']]} "
            f"| {c['severity']} | {c['confidence']} | {ids} |")
    add("")
    add("*Confidence is confidence in the label (how sure the rule logic is that it fits), "
        "not the chance that the user is malicious.*")
    add("")
    add("## 3. Timeline (UTC)")
    add("")
    add("| Time | ID | Entity | Event | Where | Assessment | Findings |")
    add("|---|---|---|---|---|---|---|")
    for row in timeline:
        add(f"| {row['timestamp'][11:19]} | {row['event_id']} | {row['username']} | "
            f"{row['event_type'].replace('|', '/')} | {row['system']} from {row['source_ip']} | "
            f"{CLASS_LABEL[row['assessment']]} | {row['alert_ids'] or '-'} |")
    add("")
    add("## 4. Case analysis")
    for c in needs_action:
        add("")
        add(f"### {c['case_id']}: {c['entity']} ({c['priority']}, {CLASS_LABEL[c['classification']]}, "
            f"confidence {c['confidence']})")
        add("")
        add(f"**Status:** {STATUS_TEXT[c['classification']]}")
        add("")
        add("**What the evidence shows**")
        add("")
        for f in c["findings"]:
            ids = ", ".join(f["event_ids"])
            if f["related_ids"]:
                ids += f" + context {', '.join(f['related_ids'])}"
            add(f"- **{f['finding_id']} [{f['rule_id']}] {f['rule']}**: "
                f"{CLASS_LABEL[f['classification']]} / {f['severity'].lower()} / "
                f"confidence {f['confidence']}. {f['description']} *(IDs: {ids})*")
        add("")
        add("**Evidence to request**")
        add("")
        for item in _unique(i for f in c["findings"] for i in f["evidence_needed"]):
            add(f"- {item}")
        add("")
        add("**Containment (evidence-preserving)**")
        add("")
        for item in _unique(s for f in c["findings"] for s in PLAYBOOK[playbook_key(f)]["contain"]):
            add(f"- {item}")
        add("")
        add("**Communication**")
        add("")
        for item in _unique(s for f in c["findings"] for s in PLAYBOOK[playbook_key(f)]["comms"]):
            add(f"- {item}")
    add("")
    add("## 5. Likely benign: close after light verification")
    add("")
    for c in benign:
        for f in c["findings"]:
            add(f"- **{c['case_id']} {f['finding_id']} [{f['rule_id']}] {f['username']}** "
                f"({', '.join(f['event_ids'])}): {f['description']}")
    add("")
    add("## 6. Response principles applied to every case")
    add("")
    for principle in GENERAL_PRINCIPLES:
        add(f"- {principle}")
    add("")
    add("## 7. Caveats")
    add("")
    add("- Findings are rule-based hypotheses from a tiny synthetic extract, not proof of intent or access.")
    add("- The brief's window ends 10:30 UTC, but AUTH-0020 (11:51 UTC) is in the starter file; it is used only to close the d.ross typo case.")
    add("- The log does not show who made the privilege grants or which role was granted.")
    add("")
    return "\n".join(lines)


def display_triage_report(cases):
    print("\n========== INCIDENT TRIAGE QUEUE ==========")
    for case in cases:
        print(f"\n{case['priority']} {case['case_id']} | {case['entity']}")
        print("  Classification:", CLASS_LABEL[case["classification"]])
        print("  Severity:", case["severity"], "| Confidence:", case["confidence"])
        print("  Findings:", ", ".join(f["finding_id"] + " " + f["rule_id"] for f in case["findings"]))
    print("\n========== TRIAGE COMPLETED ==========")


def save_triage_csv(cases, output_dir=None):
    output_dir = Path(output_dir) if output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / "incident_triage.csv"
    fields = ["priority", "case_id", "entity", "classification", "severity",
              "confidence", "finding_ids", "start", "end"]

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for c in cases:
            writer.writerow({
                "priority": c["priority"], "case_id": c["case_id"], "entity": c["entity"],
                "classification": c["classification"], "severity": c["severity"],
                "confidence": c["confidence"],
                "finding_ids": " ".join(f["finding_id"] for f in c["findings"]),
                "start": c["start"], "end": c["end"]})
    print("Incident triage queue saved to:", file_path)


def save_markdown_report(text, output_dir=None):
    output_dir = Path(output_dir) if output_dir else OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / "triage_report.md"
    file_path.write_text(text, encoding="utf-8")
    print("Triage report saved to:", file_path)
