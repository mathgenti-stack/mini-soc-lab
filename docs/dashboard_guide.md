# Dashboard guide

Start the dashboard with `streamlit run streamlit_app.py` and open http://localhost:8501.

## Layout

**Sidebar**

- *Data source*: the bundled sample, a newly generated dataset (choose a seed and number of days, and download the CSV), or an uploaded CSV.
- *Detection thresholds*: enable or disable rules and change their main thresholds. Changes apply immediately and only to your session; the JSON file is not modified.

**Filter bar** (applies to every tab): date range, username, source IP, event type and alert severity. An empty selection means no filter.

**Tabs**

| Tab | Contents |
| --- | --- |
| Overview | KPIs (events, successful/failed logons, failure rate, lockouts, alerts), alerts by severity, a timeline of failed logons per hour with alert markers, and the top failure sources |
| Alerts | The alert queue for the current filters, with CSV export |
| Cases | Related alerts grouped into cases: alerts in each case, why they were grouped, a combined evidence timeline, and CSV export |
| Event Explorer | Every filtered event, with free-text search across all fields and CSV export; an expander shows the offline enrichment of the external addresses in view |
| Investigation | A full report for a selected alert, including offline IP enrichment; status and analyst notes; Markdown and CSV export |
| Data Quality | Rows read, accepted and rejected, duplicates removed, and the rejected rows with reasons |
| Rule Export | The rules as Sigma, Splunk SPL and Sentinel KQL, built from the current thresholds, with downloads and the field mapping |
| About | Scope and safety notes |

## Example uses

### 1. Triage the most severe alert

1. Open **Alerts**. ALR-0010 is the only *Critical* alert.
2. Open **Investigation** and select ALR-0010.
3. Read *Observed facts*: one external address tried 15 accounts in about 15 minutes, and `l.taylor` logged on successfully from the same address.
4. Check *Context checks*: the address was never seen before, and four of the account names never logged on successfully.
5. Set the status to *Escalated*, add a note, and use **Export report (Markdown)**.

### 2. Recognise a false positive

1. Filter **Username** to `e.wilson`.
2. Investigate ALR-0007 (R001). The context checks show a password change on 9 October and an unlock from the IT workstation before the successful logon.
3. The conclusion names these as possible benign indicators that must be verified, for example against a service desk ticket.

### 3. See the effect of tuning

1. On the Overview tab, note the number of alerts (18 by default).
2. In the sidebar, set **R003 minimum attempts per day** to 10. The count rises to 26 because the authorised scan, `e.wilson` and `r.khan` now produce extra per-account alerts.
3. Reset it to 15, then set **R001 failures** to 3. The count rises to 25. Lower thresholds catch more but create more noise.

### 4. Hunt in raw events

In **Event Explorer**, search for `203.0.113` to list every event from the external documentation range, or for `UNKNOWN_USER` to find attempts against account names that are not recognised.

### 5. Check data quality

Open **Data Quality**. It shows 1 exact duplicate removed and 3 rows rejected: an invalid timestamp, a missing username and an unknown event type.

### 6. Triage a case instead of single alerts

1. Open **Cases** and select *CASE-0006*: three alerts (R001, R002, R005) about `r.khan`.
2. *Why these alerts are grouped* shows they all share the account and the address 203.0.113.120.
3. The combined timeline shows the whole story: 8 failures, then a successful VPN logon in the evening.
4. In the sidebar, set **Case grouping window** to 0. *CASE-0004* (`e.wilson`) splits in two, because its alerts are 15 seconds apart and do not overlap.

### 7. Take a rule to a SIEM

1. Open **Rule Export**, choose *R004* and *Microsoft Sentinel KQL*.
2. In the sidebar, set **R004 distinct accounts** to 8. The query now says `let min_distinct_accounts = 8;`.
3. Use **Download all rules (.zip)** to get every rule in every format. See [rule_export.md](rule_export.md).
