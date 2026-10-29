# Rule export (detection as code)

The five rules can be exported for real SIEMs:

| Format | Runs in | File |
| --- | --- | --- |
| **Sigma** | Nowhere directly. Sigma is a vendor-neutral standard that tools such as `sigma-cli` convert into a SIEM's language | `sigma/<rule>.yml` |
| **Splunk SPL** | Splunk, on Windows Security events (`sourcetype="XmlWinEventLog:Security"`) | `spl/<rule>.spl` |
| **Microsoft Sentinel KQL** | Microsoft Sentinel / Log Analytics, on the `SecurityEvent` table | `kql/<rule>.kql` |

Every query is generated from the configuration, so a threshold changed in `config/detection_rules.json` or in the dashboard sidebar changes the exported rule. Disabled rules are not exported. R005 has three patterns, so there are seven detections and 21 files.

```bash
python -m soc_lab.cli export-rules                       # all formats, written to rules_export/
python -m soc_lab.cli export-rules --format kql --output-dir my_rules
```

In the dashboard, the **Rule Export** tab shows each rule in each format, with a download button per file and a zip of all files.

> The queries follow each language's documented syntax and are checked by automated tests (structure, required fields, thresholds, balanced brackets and quotes). They have **not** been run on a live Splunk or Sentinel instance. Test them before production use.

## Field mapping

The lab's events imitate the Windows Security log, so the rules use its event IDs and field names.

| Lab field | Sigma / Sentinel | Splunk |
| --- | --- | --- |
| `timestamp` | `TimeGenerated` | `_time` |
| `username` | `TargetUserName` | `TargetUserName` |
| `source_ip` | `IpAddress` | `IpAddress` |
| `event_code` | `EventID` | `EventCode` |
| `hostname` | `Computer` | `host` |

| Event | Event ID |
| --- | --- |
| Successful logon | 4624 |
| Failed logon | 4625 |
| Account locked out | 4740 |
| Account unlocked | 4767 |

The SPL searches start with `index=wineventlog`; change the index to the one used in your environment.

## How each rule is expressed

| Rule | Sigma | SPL / KQL |
| --- | --- | --- |
| R001 Multiple failed logons | `event_count` correlation | Clusters + sliding window, as in the lab |
| R002 Success after failures | `event_count` then `temporal_ordered` correlation | Failure count that restarts after every success, as in the lab |
| R003 High failure rate | **Not expressible** (Sigma cannot divide failures by attempts) | Per entity and UTC day |
| R004 One IP, many accounts | `value_count` correlation | Clusters + sliding window, then successful logons from the same address |
| R005 Lockout then success | `temporal_ordered` correlation | First success after each lockout, with unlock check |
| R005 Out-of-hours new source | **Not expressible** (needs a baseline of known addresses) | First logon from each address, outside business hours |
| R005 Rapid source change | `value_count` correlation on external logons | Consecutive external logons from different addresses |

For the two rules Sigma cannot express, the `.yml` file contains only comments that explain why and point to the SPL and KQL versions.

## Differences from the lab

Each file's header lists the parameters it was built with and the differences that apply to it. The main ones:

- **Severity.** Sigma has one fixed `level` per rule, which is the rule's base severity. The escalation steps (external source, higher peaks, a success during a spray) are in the SPL and KQL versions, which return a `severity` column.
- **Sigma correlations are approximate.** For example, R002 in Sigma does not restart the failure count after a success, and R005 rapid source change in Sigma also fires when the two logons are not consecutive.
- **Time zone.** Business hours and R003's days are in UTC. In Splunk, run the search with the user time zone set to UTC; KQL works in UTC.
- **Baselines.** The out-of-hours rule learns known addresses from the search time range, so search a long enough period.
- **Unparseable addresses.** The lab treats an address it cannot parse (for example `-`) as external. In KQL, `ipv4_is_in_any_range` returns no true/false answer for such addresses, so they may be skipped or treated as internal.

## Validating the Sigma rules

The project has no YAML dependency, so the files are written as text and their structure is checked by the tests. To validate them with the official tooling (not installed by this project):

```bash
pip install sigma-cli
sigma check rules_export/sigma/
```
