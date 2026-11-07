# Limitations and Possible Improvements

| Limitation | Evidence in this project | Improvement |
|---|---|---|
| Fixed thresholds can be evaded | Synthetic `S-SLOW*` (5 failures about 170 s apart) is **not detected** (`output/evaluation.json`) | Several windows (2 min / 1 h / 24 h), per-account baselines, many-IP detection |
| Synthetic scores are self-graded | Same author wrote scenarios and rules | Test on public datasets; have a peer write unseen scenarios |
| No baselines | No time-of-day, geography or device history | Per-user baselines, impossible travel, new-device rules |
| Hand-written mappings | `HOST_MAP`, `SERVICE_ALLOWLIST` are constants | Asset inventory (CMDB) integration |
| Tickets matched by text only | R04b trusts `CHG-####` in the notes | Query the change system and check scope |
| Small, clean, single-format data | Real logs are noisy, multi-source, differently timed | Parsers and normalisation (ECS/OCSF), clock-skew handling |
| Log gaps | Privilege log lacks actor and role; EDR-1002 predates its triggering events | Richer logging; explicit skew detection |
| Static playbook text | Keyed by rule ID | SOAR-style playbooks with approvals and ticketing |
| Rules are Python only | Not portable to a SIEM | Export to Sigma (with correlation rules) or SIEM queries |
| Event outside stated window | AUTH-0020 (11:51 UTC) is after the 10:30 window | Make the window explicit and flag out-of-window events |

## Challenges and how they were handled

* **SOC-T04 vs the data:** d.ross retried 89 minutes after the typo, not immediately. The rule allows up to 120 minutes but lowers confidence and says so.
* **EDR-1002 is timestamped before the MFA denials it "correlates with":** flagged as a timing discrepancy, not silently accepted.
* **3 unknown-username failures vs a 4-failure rule:** raised as `review` by R07 instead of stretching R01.
* **Second privilege grant:** could be a follow-on step of CHG-1042 or an unapproved grant; the report says the log cannot tell and lists what to request.
* **First version issues (fixed):** it missed the success after failures and the unknown-username failures, ignored EDR alerts, had no benign class, and no event IDs in alerts.
