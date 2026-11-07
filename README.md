# SOC Operations & Threat Detection: Mini-SOC Prototype

RedKross Research Foundation, Task 2.
**Primary outcome:** mini-SOC detection prototype, synthetic logs, detection rules and incident triage workflow.

> All data is synthetic or fictional. IPs come from RFC 5737 documentation ranges; people and the organisation
> (Northstar Community Services) are invented. Nothing here touches real systems.

## What it does

1. **Reads** authentication logs (CSV) and endpoint alerts (JSON) from `data/`.
2. **Detects** with seven explainable rules in `src/detection_rules.py` (thresholds are constants at the top).
3. **Correlates** endpoint alerts with authentication activity (`src/edr_correlation.py`).
4. **Triages**: groups findings into cases, ranks them P1 to P4, and writes `output/triage_report.md` with a timeline,
   benign / suspicious / needs-evidence calls, confidence, evidence to request, and evidence-preserving containment
   and communication steps.
5. **Generates synthetic logs** with ground-truth labels and **scores** the rules.

## Setup and run

Needs Python 3.9 or newer. No packages to install.

```bash
python -m unittest discover -s tests -v     # 58 tests
python src/main.py                          # analyse the starter scenario -> output/
python src/main.py --generate               # synthetic logs -> data/synthetic/   (add --seed 7 for another set)
python src/main.py --evaluate               # score the rules -> output/evaluation.json
```
(On Mac/Linux use `python3`. If `python` is not found on Windows, try `py`.)

Outputs of the main run: `output/triage_report.md` (read this first), `incident_triage.csv`, `security_alerts.csv`,
`incident_timeline.csv`.

## Project layout

| Path | Purpose |
|---|---|
| `src/main.py` | Entry point (analyse / generate / evaluate) |
| `src/log_parser.py` | Reads the CSV and JSON input |
| `src/detection_rules.py` | Rules R01 to R07 |
| `src/edr_correlation.py` | Links endpoint alerts to authentication events |
| `src/incident_triage.py` | Cases, priorities, playbook text, Markdown/CSV report |
| `src/incident_timeline.py` | Combined timeline with assessments |
| `src/synthetic_logs.py`, `src/evaluation.py` | Synthetic log generator and scorer |
| `data/` | Starter files (unchanged) and `data/synthetic/` (generated) |
| `tests/` | 58 tests |
| `output/` | Generated reports, test results, evaluation |
| `docs/` | Rule catalogue, triage workflow, limitations, video script, references |

## Rules at a glance

| ID | Detects | Class | Official case |
|---|---|---|---|
| R01 | 4+ failed logins, same user and IP, within 120 s | suspicious | SOC-T01 |
| R02 | Login success within 5 min after an R01 burst, same user and IP | high_review | brief fact 1 |
| R03 | 2+ MFA denials by one user within 300 s | review (suspicious if 5+ or followed by a success) | SOC-T02 |
| R04 | Privilege grant with no `CHG-####` reference | high_review | SOC-T03 |
| R05 | One failure then MFA success, same IP and host | likely_benign | SOC-T04 |
| R06 | Service account on its allow-listed IP, host and method | likely_benign | SOC-T05 |
| R07 | 3+ failures for a non-existent username from one IP | review (suspicious at 4+) | brief fact; EDR-1003 |

See `docs/detection_rules.md` for logic, false positives and what evidence would settle each one.

## Result on the starter scenario (INC-2026-104)

| Priority | Entity | Call | Why |
|---|---|---|---|
| P1 | a.chen | High-priority review | 4 failures in 24 s, then MFA success from the same external-range IP 34 s later |
| P1 | m.patel | High-priority review | 10:06:12 grant has no ticket; a CHG-1042 grant was 151 s earlier |
| P2 | t.garcia | Needs more evidence | 2 MFA denials in 33 s; EDR-1002 is timestamped 222 s before them |
| P2 | unknown source 203.0.113.91 | Needs more evidence | 3 failures, one short of the brute-force threshold; rate-limited |
| P3 | j.lee | Needs more evidence | Blocked Word-to-PowerShell alert with no supporting anomaly |
| P4 | svc-backup, svc-sync, d.ross | Likely benign | Match allow-list or typo-then-MFA pattern |

**No account is declared compromised**; each case lists the evidence that would settle it.

## Testing evidence

* `output/test_results.txt`: verbose run of all 58 tests.
* Tests cover the five official cases (read from the CSV), boundary values (120 s and 300 s, inclusive), negative cases
  (3 failures, different IPs or users, long gaps), EDR correlation, report wording (never says an account "is
  compromised"), and the synthetic generator across seeds.
* `output/evaluation.json`: synthetic scoring. 16 of 16 attack scenarios detected, no false positives. I wrote both the
  rules and the scenarios, so this is a regression check, not a claim of real-world accuracy. The generator also
  includes slow guessing (5 failures about 170 s apart), which the rules **do not** catch (documented limitation).

## Limitations (short)

Static thresholds can be evaded; no per-user baselines; EDR correlation uses a hand-written host map; change tickets
are only matched by text; synthetic data is small and clean. Details and improvements: `docs/limitations.md`.

## AI assistance

An earlier version was built with ChatGPT and then extended and reviewed with Claude (Anthropic). Everything was run and
tested; see `docs/video_script.md` for the points to be able to explain.

## References

`docs/references.md`
