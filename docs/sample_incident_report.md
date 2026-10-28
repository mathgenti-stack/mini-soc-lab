# Incident Investigation Report: INC-0010

**Logon failures against 15 accounts from 203.0.113.88**

| Field | Value |
| --- | --- |
| Incident ID | INC-0010 |
| Alert ID | ALR-0010 |
| Detection rule | R004 - Repeated failures from a single IP across many accounts |
| Severity | Critical |
| Incident status | New |
| First seen | 2026-10-12 11:02:33 UTC |
| Last seen | 2026-10-12 11:17:55 UTC |
| Affected account(s) | a.patel, admin, administrator, b.wood, c.evans, f.hall, g.clarke, guest, j.smith, l.taylor, m.jones, o.hughes, p.green, r.khan, t.walker, test |
| Source IP address(es) | 203.0.113.88 |
| Host(s) | LON-VPN-01 |
| Supporting events | 16 |
| MITRE ATT&CK (possible) | T1110.003 Brute Force: Password Spraying |
| Report generated | 2026-10-28 18:22:01 UTC |

> This report was generated from synthetic lab data. An alert is a lead for investigation, not proof of malicious activity.

## 1. Why this alert was generated

At least 5 distinct accounts failed to log on from one source address within 30 minutes (observed peak: 15).

**Severity rationale:** Raised to High: the source is an external address. Raised to Critical: at least one account logged on successfully from the same address during the activity.

## 2. Observed behaviour (facts from the logs)

- 15 failed logons from 203.0.113.88 (external) targeted 15 distinct accounts between 2026-10-12 11:02:33 UTC and 2026-10-12 11:17:55 UTC.
- The highest number of distinct accounts within any 30-minute window was 15.
- 4 of the attempts were rejected as UNKNOWN_USER (account name not recognised).
- Accounts attempted: a.patel, admin, administrator, b.wood, c.evans, f.hall, g.clarke, guest, j.smith, m.jones, o.hughes, p.green, r.khan, t.walker, test.
- Target host(s): LON-VPN-01.
- Successful logon for 'l.taylor' from the same address at 2026-10-12 11:11:16 UTC (this account had no failed attempts in this burst).

## 3. Context checks

- Source 203.0.113.88 is external; dataset shows no successful logons from this address before the alert.
- Successful logon(s) from the alert's source address(es) were recorded for: l.taylor (between first activity and one hour after the last).
- Account name(s) with no successful logon anywhere in the dataset: admin, administrator, guest, test (they may not exist in the directory).
- Related alerts sharing an account or source address: ALR-0001, ALR-0002, ALR-0003, ALR-0005, ALR-0006, ALR-0009, ALR-0011, ALR-0012, ALR-0013.

## 4. Hypotheses (not confirmed)

- Few attempts per account across many accounts is consistent with password spraying (MITRE ATT&CK T1110.003) or account enumeration, but intent cannot be determined from logs alone.
- Shared egress addresses (VPN, NAT, proxies) and authorised vulnerability scanners produce the same shape of activity.

## 5. Potential benign explanations

- An authorised vulnerability scanner testing default credentials.
- Many users behind one shared NAT, proxy or VPN address after a password policy change.
- A misconfigured application cycling through a list of accounts.

## 6. False-positive considerations

- Internal scanner addresses should be on a documented allow list; confirm the scan window.
- A high proportion of UNKNOWN_USER failures suggests enumeration or default-account testing.
- A successful logon from the same address for one of the targeted accounts changes the priority sharply.

## 7. Event timeline (supporting log events)

| timestamp | event_id | event_type | event_code | result | username | source_ip | hostname | logon_type | failure_reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-10-12 11:02:33 UTC | EVT-000566 | LOGON | 4625 | FAILURE | a.patel | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:03:39 UTC | EVT-000567 | LOGON | 4625 | FAILURE | j.smith | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:04:30 UTC | EVT-000568 | LOGON | 4625 | FAILURE | admin | 203.0.113.88 | LON-VPN-01 | VPN | UNKNOWN_USER |
| 2026-10-12 11:05:12 UTC | EVT-000569 | LOGON | 4625 | FAILURE | m.jones | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:06:17 UTC | EVT-000570 | LOGON | 4625 | FAILURE | r.khan | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:07:47 UTC | EVT-000571 | LOGON | 4625 | FAILURE | administrator | 203.0.113.88 | LON-VPN-01 | VPN | UNKNOWN_USER |
| 2026-10-12 11:08:58 UTC | EVT-000572 | LOGON | 4625 | FAILURE | c.evans | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:09:49 UTC | EVT-000573 | LOGON | 4625 | FAILURE | o.hughes | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:11:16 UTC | EVT-000574 | LOGON | 4624 | SUCCESS | l.taylor | 203.0.113.88 | LON-VPN-01 | VPN | - |
| 2026-10-12 11:12:14 UTC | EVT-000576 | LOGON | 4625 | FAILURE | p.green | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:12:56 UTC | EVT-000577 | LOGON | 4625 | FAILURE | test | 203.0.113.88 | LON-VPN-01 | VPN | UNKNOWN_USER |
| 2026-10-12 11:13:36 UTC | EVT-000578 | LOGON | 4625 | FAILURE | t.walker | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:14:35 UTC | EVT-000580 | LOGON | 4625 | FAILURE | f.hall | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:15:51 UTC | EVT-000581 | LOGON | 4625 | FAILURE | guest | 203.0.113.88 | LON-VPN-01 | VPN | UNKNOWN_USER |
| 2026-10-12 11:17:09 UTC | EVT-000582 | LOGON | 4625 | FAILURE | g.clarke | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |
| 2026-10-12 11:17:55 UTC | EVT-000583 | LOGON | 4625 | FAILURE | b.wood | 203.0.113.88 | LON-VPN-01 | VPN | BAD_PASSWORD |

## 8. Recommended investigation steps

1. Determine whether the source address is internal, a known scanner, or a shared gateway.
2. List which targeted accounts exist and whether any logged on successfully from the address.
3. For any successful account, review its subsequent activity and contact its owner.
4. Search for the same address in other alerts and earlier logs.

## 9. Suggested containment actions

Only to be proposed through the organisation's change and incident processes, and only if the investigation supports them.

- For an external source with a successful logon, escalate immediately and propose resetting the affected account's password and revoking sessions.
- Propose blocking the external address at the perimeter through the change process.

## 10. Evidence-based conclusion

The evidence shows activity matching the detection criteria together with at least one successful logon from an external source address. This is consistent with possible unauthorised access but does not confirm it. Escalation to a senior analyst is recommended if the account owner cannot confirm the activity. This conclusion is based only on the authentication events in this dataset.

## 11. Analyst notes

_No analyst notes recorded._

## 12. Limitations of this investigation

- Distributed spraying from many addresses will not trigger this rule.
- Shared addresses make it impossible to attribute activity to a single device from logs alone.
- Analysis is limited to the authentication events in this dataset; endpoint, email, proxy and EDR telemetry were not available.
- Source IP addresses do not identify a person. Addresses can be shared (NAT, VPN, proxies) or spoofed upstream.
- No threat-intelligence or geolocation enrichment was performed.
- Timestamps are treated as UTC as recorded; clock drift between log sources was not assessed.
