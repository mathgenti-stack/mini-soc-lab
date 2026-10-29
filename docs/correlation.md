# Case correlation

Several rules often fire on the same activity. A brute force raises R001 for the account and R003 for the address and for the account. An analyst should triage that activity once, not three times. `soc_lab/correlation.py` groups related alerts into **cases**.

## How alerts are linked

Two alerts are linked when **both** are true:

1. they share at least one account (`usernames`) or one source address (`source_ips`), and
2. their time spans overlap, or the gap between them is at most `window_minutes` (default 120).

Links chain: if A is linked to B and B to C, then A, B and C are in one case, even if A and C share nothing. Every link records the account or address that caused it, so the grouping can always be explained.

```json
"correlation": {
  "window_minutes": 120
}
```

The section in `config/detection_rules.json` is optional. The window can also be changed for the session in the dashboard sidebar (**Case grouping window**).

## What a case contains

| Field | Meaning |
| --- | --- |
| `case_id` | `CASE-0001`, `CASE-0002`, ... in order of first activity |
| `severity` | The **highest** severity among its alerts. It is never raised further: grouping is not evidence |
| `alert_ids`, `rule_ids` | The alerts and the rules that raised them |
| `first_seen`, `last_seen` | From the earliest alert start to the latest alert end |
| `event_count` | Distinct supporting events across all alerts |
| `usernames`, `source_ips`, `mitre_attack` | Combined from the alerts |

Case IDs (`CASE-`) are different from the incident IDs of the per-alert reports (`INC-0010` is the report for `ALR-0010`).

## Result on the sample dataset

The 18 alerts become 9 cases, one per planted scenario:

| Case | Alerts | Scenario |
| --- | --- | --- |
| CASE-0001 | ALR-0001, ALR-0002, ALR-0003 | Brute force against `m.jones` |
| CASE-0002 | ALR-0004 | On-call engineer `d.brown` |
| CASE-0003 | ALR-0005, ALR-0006 | Authorised vulnerability scan |
| CASE-0004 | ALR-0007, ALR-0008 | `e.wilson` forgot a password |
| CASE-0005 | ALR-0009, ALR-0010 | Password spray (Critical) |
| CASE-0006 | ALR-0011, ALR-0012, ALR-0013 | Credential compromise of `r.khan` |
| CASE-0007 | ALR-0014 | Rapid source change for `s.ahmed` |
| CASE-0008 | ALR-0015, ALR-0016 | `svc_backup`, first night |
| CASE-0009 | ALR-0017, ALR-0018 | `svc_backup`, second night |

A test checks that, on the generated dataset, every case contains evidence from a single ground-truth scenario.

## Where to see cases

- **Dashboard:** the **Cases** tab lists the cases with CSV export. Selecting one shows its alerts, why they were grouped, and a combined evidence timeline. The Overview shows the number of cases, and the Investigation tab (free investigation mode) says which case an alert belongs to.
- **CLI:** `python -m soc_lab.cli analyse` prints the cases after the alerts; `--export-cases-csv cases.csv` writes them to a file.

Filters never split a case: cases are built from all alerts, and a case is shown when at least one of its alerts passes the filters.

## Limitations

- **Shared addresses link unrelated activity.** NAT, VPN gateways and proxies put many people behind one address. The time window limits this, but cannot remove it.
- **Long alerts reach further.** R003 alerts span a whole day of activity, so they can link alerts that are hours apart.
- **Only accounts and addresses are compared.** Hostnames, techniques and rule types are not used to link alerts.
- **The window is a fixed number.** Slow attacks spread over more than the window become several cases.
