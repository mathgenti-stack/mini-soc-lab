# Detection rules

All parameters are in `config/detection_rules.json`. Every rule can be switched off with `"enabled": false`, and the main thresholds can be adjusted for the current session in the dashboard sidebar.

Shared environment settings:

| Setting | Default | Used for |
| --- | --- | --- |
| `internal_networks` | `10.0.0.0/8` | Classifying a source as internal or external |
| `business_hours` | 07:00-19:00 UTC, Mon-Fri | R005 out-of-hours check |
| `service_account_prefixes` | `svc_` | Context checks in reports |

Severity levels: **Low**, **Medium**, **High**, **Critical**. Every alert stores a `severity_reason` explaining how its level was reached.

Every alert includes:

- the trigger criteria and the observed values;
- the IDs of the supporting events;
- *observed facts*, written as statements about the logs;
- *hypotheses*, written as "consistent with" or "may indicate", never as conclusions;
- a possible MITRE ATT&CK technique.

---

## R001 - Multiple failed logon attempts

**Question:** Is one account failing to authenticate many times in a short period?

**Trigger:** at least `failure_threshold` (5) failed `LOGON` events for the same username within any `window_minutes` (10) sliding window.

**How it works:** failures for each account are sorted by time and grouped into clusters, where each failure is no more than one window after the previous one. A sliding window then finds the peak count inside each cluster. Every cluster whose peak reaches the threshold becomes one alert, with all of the cluster's failures as evidence.

**Severity:** Medium. Raised to High if any source is external or if the peak reaches `high_severity_threshold` (15).

**MITRE ATT&CK:** T1110.001 Password Guessing.

**Limitations:** slow guessing (fewer than 5 attempts per 10 minutes) is missed. Spraying a few attempts across many accounts is handled by R004.

**False positives:** forgotten or recently changed passwords, and devices that still hold old credentials.

## R002 - Successful logon after repeated failures

**Question:** Did an account finally get in after several failed attempts?

**Trigger:** a successful `LOGON` preceded by at least `min_failures` (3) failures for the same account within `lookback_minutes` (30). The failure count resets after each success, so one typo before each of several logons never adds up.

**Severity:** Medium. High if the successful logon came from an external address. Critical if, in addition, at least `critical_failure_threshold` (10) of the failures came from that same external address.

**MITRE ATT&CK:** T1110 Brute Force followed by T1078 Valid Accounts.

**Limitations:** the rule cannot tell whether the same person made the failures and the success. Failures older than the lookback window are not linked.

**False positives:** users who mistype and then get it right. This is the most common explanation by far.

## R003 - High authentication failure rate

**Question:** Is a source address or account failing far more often than it succeeds?

**Trigger:** for each value of `entity_fields` (`source_ip` and `username`) and each UTC calendar day: at least `min_attempts` (15) logon attempts and a failure rate of at least `failure_rate_threshold` (50%).

**Why a minimum number of attempts:** without it, a single failed attempt is a "100% failure rate". This was tuned from 10 to 15 during development because the authorised scan produced one alert per default account name (admin, guest, root, ...). That was alert fatigue without extra value, since R004 already covers the scan.

**Severity:** Low. Medium if the rate is at least `high_failure_rate` (90%). Raised one level if external addresses are involved.

**MITRE ATT&CK:** T1110 Brute Force.

**Limitations:** activity that spans midnight is split across two days, and low-volume activity is ignored.

**False positives:** service accounts with expired passwords, scanners and misconfigured applications.

## R004 - Repeated failures from a single IP across many accounts

**Question:** Is one address trying many different accounts? This is the shape of password spraying.

**Trigger:** at least `min_distinct_accounts` (5) distinct usernames with failed logons from the same source address within any `window_minutes` (30) sliding window.

**Severity:** Medium. High if the source is external or if `high_distinct_accounts` (10) is reached. **Critical** if *any* account logged on successfully from that address during the activity or within one window after it. This includes accounts that succeeded at the first attempt and therefore never appear among the failures, which is exactly what a successful spray looks like.

**MITRE ATT&CK:** T1110.003 Password Spraying.

**Limitations:** spraying distributed across many addresses is not detected. Shared addresses (NAT, VPN, proxy) cannot be attributed to one device.

**False positives:** authorised vulnerability scans, and many users behind one gateway after a password policy change.

## R005 - Suspicious authentication patterns

These are combinations of weaker signals. Each one produces an alert with its own `pattern` value.

### `lockout_then_success`

**Trigger:** an `ACCOUNT_LOCKOUT` followed by a successful logon for the same account within `lockout_success_window_minutes` (120).

**Severity:** Medium; High if the success came from an external address. The alert records whether an `ACCOUNT_UNLOCK` occurred in between, which is a strong benign indicator when it comes from the service desk.

### `off_hours_new_source`

**Trigger:** a successful logon outside business hours from a source address that has not appeared in any earlier successful logon for that account. Nothing is alerted during the first `baseline_learning_days` (2) of the dataset, because everything is "new" until a baseline exists.

**Severity:** Low for an internal source, Medium for an external one.

### `rapid_source_change`

**Trigger:** two successful logons for the same account from different **external** addresses within `rapid_source_change_minutes` (15).

**Severity:** Medium.

**Note:** this is a simplified version of "impossible travel". The logs have no geolocation, so the rule itself cannot judge distance. The investigation report adds a distance check from the offline enrichment files (see [enrichment.md](enrichment.md)); it is context only and never changes the alert or its severity.

**MITRE ATT&CK:** T1078 Valid Accounts.

---

## Detection coverage on the sample dataset

`tests/test_generator.py` checks that each planted scenario triggers the expected rules, and that the dataset's normal activity on its own triggers none.

| Scenario | Expected rules |
| --- | --- |
| simulated_brute_force | R001, R003 |
| simulated_password_spray | R003, R004 |
| simulated_credential_compromise | R001, R002, R005 |
| ambiguous_rapid_source_change | R005 |
| benign_forgotten_password | R001, R005 |
| benign_authorised_scan | R003, R004 |
| benign_on_call_engineer | R005 |
| benign_service_account_expired | R003 |
