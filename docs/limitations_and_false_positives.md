# Limitations and false positives

## An alert is not an incident

Every detection in this lab is a **pattern match on authentication events**. A pattern can be produced by an attacker, a legitimate user, a script or a scanner. The tool records what was observed and offers hypotheses. A human analyst classifies the outcome:

| Outcome | Meaning |
| --- | --- |
| True positive | Malicious or unauthorised activity confirmed |
| Benign true positive | The rule worked as designed, but the activity was legitimate (e.g. an authorised scan) |
| False positive | The rule matched something it should not have (often a sign the rule needs tuning) |

The dashboard's incident status list reflects these outcomes.

## False positives present in the sample data

| Alert(s) | Why it fires | How the report helps |
| --- | --- | --- |
| R001 + R005 for `e.wilson` | Ten wrong passwords after a password change, then lockout and service desk unlock | Context checks list the password change three days earlier and the unlock from the IT workstation. The conclusion flags a possible benign explanation that still needs verifying. |
| R003 + R004 for `10.10.99.5` | Authorised scanner testing default account names | Internal source; account names with no successful logon anywhere; playbook says to check the scan schedule |
| R003 x4 for `svc_backup` / `10.10.5.20` | Backup job retrying with an expired password every 4 minutes | Service-account naming, regular intervals, `EXPIRED_PASSWORD` reason, and a later password change are all reported |
| R005 for `d.brown` | On-call engineer at 02:31 from a hotel | Playbook advises checking the on-call rota. The conclusion stays cautious because the source is external. |
| R005 for `s.ahmed` | Two external addresses within 7 minutes | Explicitly marked as needing user verification; the offline enrichment shows both addresses registered in London (home broadband, then a mobile network) |

## Design choices that reduce false positives

- **Minimum attempts** for failure-rate alerts (R003), so one failed attempt out of one is not reported as a 100% failure rate.
- **Failure counter reset** after each success (R002), so occasional typos never add up.
- **Baseline learning period** (R005), so the first logons in the data are not all flagged as "new".
- **Internal/external classification** lowers severity for internal sources.
- **Tuning recorded:** R003 `min_attempts` was raised from 10 to 15 after the authorised scan produced five near-identical alerts.

## Known detection gaps (false negatives)

- Slow or distributed attacks below the thresholds.
- Credential use with no preceding failures (for example phished or reused passwords). Only R005 might notice it, and only out of hours or from rapidly changing sources.
- Attacks from internal addresses look less severe by design.
- Anything not visible in authentication logs: malware, data exfiltration, lateral movement, MFA fatigue.

## Data and environment limitations

- Synthetic data. Real logs are noisier, have gaps and use different field names.
- Single source type. No correlation with endpoint, email, proxy, firewall or identity-provider logs.
- Limited enrichment. GeoIP, ASN and threat intelligence come from small offline, fictional files; there is no asset inventory or HR data such as leave or travel.
- Business hours are configured in UTC, and UK daylight saving time is not modelled.
- Daily failure-rate buckets split activity at midnight UTC.
- Case status and notes exist only in the dashboard session. Export the report to keep them.
