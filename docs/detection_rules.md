# Detection Rule Catalogue

Thresholds are constants at the top of `src/detection_rules.py`. Windows are first-to-last event span, boundary inclusive.

| ID | Logic | Class / severity | Test | Main false positives | Evidence that would settle it |
|---|---|---|---|---|---|
| R01 | >= 4 `login_failure`, same username + IP, within 120 s (unknown usernames excluded) | suspicious / medium | SOC-T01 | Mistyping, stale saved password | Other accounts hit from the IP; geo/ASN; user confirmation |
| R02 | `login_success` same user + IP within 300 s after an R01 burst | high_review / high | tests `TestSuccessAfterFailures` | Legitimate user who finally typed it right | VPN session details, MFA record, out-of-band check |
| R03 | >= 2 `mfa_denied` by one user within 300 s; suspicious at 5+ or if a success follows within 30 min | review (or suspicious) / medium | SOC-T02 | Mistaken taps, stale push | Who triggered the prompts; any approval afterwards |
| R04 | `privilege_granted` with no `CHG-\d+` in notes; links a ticketed grant for the same user within 15 min | high_review / high | SOC-T03 | Ticket recorded elsewhere, emergency change | Change record scope, admin audit log, owner confirmation |
| R04b | `privilege_granted` with a ticket reference | likely_benign / info | tests `Privilege` | Ticket cited but invalid | Confirm the ticket exists and covers the grant |
| R05 | Failure not in an R01 burst (<= 2 nearby), then `MFA` success within 120 min, same user + IP + host | likely_benign / info (high confidence if <= 10 min, else medium) | SOC-T04 | Attacker holding both password and MFA device | Nothing unless other alerts exist |
| R06 | `svc-*` success from allow-listed IP + host with `service_token` | likely_benign / info | SOC-T05 | Stolen token used from the allowed host | Scheduler logs |
| R06b | `svc-*` success outside its allow-list entry | review / medium | tests `ServiceAccounts` | New job not yet allow-listed | Account owner, rotation history |
| R07 | >= 3 failures for an unknown username from one IP within 120 s (suspicious at 4+) | review / medium | tests `UnknownUsername` | Misconfigured client | Other events from the IP, naming scheme |
| EDR-CORR | Each EDR alert is linked to auth events (same user, host mapped to target system, +/-30 min). Class = most serious related finding; unsupported alerts stay `review` / low confidence | inherits | tests `EdrCorrelation` | Wrong host map, clock skew | Raw EDR telemetry |

## Design choices

* **Explainable thresholds**, not opaque scores: a finding shows exactly why it fired.
* **Benign rules exist on purpose.** Classifying typo-then-MFA and allow-listed service logins as likely benign reduces noise and shows triage, not just alerting.
* **Confidence is about the label**, not the chance the user is malicious. Odd timing or weak support lowers it.
* **Rules never say "compromised".** Wording is "needs verification"; a test enforces it.
* **Privilege check uses absence of `CHG-####`**, not a specific phrase, so empty or differently worded notes are still caught.

## Suggested ATT&CK mappings (for reporting; analyst should validate)
T1110.001 Password Guessing (R01), T1078 Valid Accounts (R02), T1621 MFA Request Generation (R03), T1098 Account
Manipulation (R04), T1110 Brute Force (R07), T1204.002 and T1059.001 for the Office-to-PowerShell alert.
