# Real-world log formats

Besides its own CSV schema ([log_format.md](log_format.md)), the lab reads three formats that SOC analysts meet every day. `soc_lab/parsers.py` converts each one into the lab schema. The converted events then go through the **same validation and the same rules** as any CSV. Only the Python standard library is used.

| Format | Typical source | Option |
| --- | --- | --- |
| Linux `auth.log` | `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) | `linux_auth` |
| Windows Security events (XML) | Event Viewer → *Save Selected Events…* → XML, or `Get-WinEvent -LogName Security \| ForEach-Object { $_.ToXml() }` | `windows_xml` |
| Microsoft Entra ID sign-ins (JSON) | Entra admin center → Sign-in logs → *Download* → JSON, or the Graph API `auditLogs/signIns` response | `entra_json` |

The format is detected from the file name and its first bytes; it can also be chosen explicitly.

```bash
python -m soc_lab.cli convert --input data/examples/linux_auth.log --year 2026   # writes linux_auth_converted.csv
python -m soc_lab.cli analyse --input data/examples/entra_signins.json            # converts, then analyses
```

In the dashboard, choose **Real-format log examples**, or **Upload a log file** and pick a format. The **Data Quality** tab shows how many records were read, converted and skipped. **Download converted CSV** saves the result in the lab schema.

Binary `.evtx` files are not supported: reading them needs a third-party library, and this project uses only the standard library. Export the events to XML first.

## Linux auth.log

| Line | Lab event |
| --- | --- |
| `sshd: Failed password for USER from IP port N` | `LOGON` / `FAILURE`, `BAD_PASSWORD` |
| `sshd: Failed password for invalid user USER from IP …` | `LOGON` / `FAILURE`, `UNKNOWN_USER` |
| `sshd: Accepted password\|publickey\|keyboard-interactive/pam for USER from IP …` | `LOGON` / `SUCCESS` |
| `pam_faillock(…): Consecutive login failures for user USER account temporarily locked` | `ACCOUNT_LOCKOUT` |
| `pam_unix(passwd:chauthtok): password changed for USER` | `PASSWORD_CHANGE` |
| `pam_unix(sshd:session): session closed for user USER` | `LOGOFF` |

- `hostname` is the syslog host; `logon_type` is `SSH`; `event_code` is the equivalent Windows ID (4624, 4625, ...), so the [rule export](rule_export.md) field mapping still applies.
- sshd writes several lines per attempt (`Invalid user …`, `pam_unix(sshd:auth): authentication failure`, `Connection closed …`). Only the `Failed …` line is counted; the others are skipped as *extra sshd line*, so one attempt is never counted twice.
- **Time:** classic syslog lines (`Oct 20 13:05:00`) have no year and no time zone. The year comes from `--year` (or the dashboard field), and the time is read as UTC. RFC 3339 timestamps (`2026-10-20T13:05:00+02:00`) are converted to UTC exactly.
- Lines without an IP address (lockout, password change, logoff) get `-` as `source_ip`.

## Windows Security XML

| Event ID | Lab event |
| --- | --- |
| 4624 | `LOGON` / `SUCCESS` |
| 4625 | `LOGON` / `FAILURE` |
| 4634, 4647 | `LOGOFF` |
| 4723, 4724 | `PASSWORD_CHANGE` |
| 4740 | `ACCOUNT_LOCKOUT` |
| 4767 | `ACCOUNT_UNLOCK` |

- Fields: `TargetUserName` → `username`, `IpAddress` → `source_ip`, `Computer` → `hostname`, `EventRecordID` → `event_id` (`WIN-<id>`). The original event ID is kept in `event_code`.
- `LogonType` becomes a name (`2` → `INTERACTIVE`, `3` → `NETWORK`, `10` → `REMOTE_INTERACTIVE`, ...).
- The 4625 `SubStatus` (or `Status`) becomes the failure reason: `0xC000006A` → `BAD_PASSWORD`, `0xC0000064` → `UNKNOWN_USER`, `0xC0000234` → `ACCOUNT_LOCKED`, `0xC0000071`/`0xC0000224` → `EXPIRED_PASSWORD`, `0xC0000072` → `ACCOUNT_DISABLED`. Other codes are kept as they are.
- **Skipped:** computer accounts (names ending in `$`), `ANONYMOUS LOGON`, and event IDs the lab does not model (for example 4672, special privileges).
- XML with `<!DOCTYPE>` or `<!ENTITY>` declarations is refused: event exports never contain them, and they are a known way to attack XML parsers.
- UTF-16 files (common from Event Viewer and PowerShell) are read correctly.

## Entra ID sign-ins JSON

- Accepts a list of sign-ins or the Graph API object (`{"value": [...]}`).
- Fields: `createdDateTime` → `timestamp`, `userPrincipalName` → `username` (kept as `user@domain`), `ipAddress` → `source_ip`, `appDisplayName` → `hostname`, `clientAppUsed` → `logon_type`, `id` → `event_id`.
- `status.errorCode` `0` is a success. Failures: `50126` → `BAD_PASSWORD`, `50034` → `UNKNOWN_USER`, `50053` → `ACCOUNT_LOCKED`, `50055` → `EXPIRED_PASSWORD`, `50057` → `ACCOUNT_DISABLED`, `53003` → `BLOCKED_BY_CONDITIONAL_ACCESS`; other codes become `ENTRA_<code>`.
- **Interrupted sign-ins are skipped** (for example `50074` and `50076`: MFA required). The password was right but the sign-in was not finished, so they are neither a success nor a password failure, and guessing would distort the rules. They are counted in the Data Quality tab. In a real investigation, many of them from one address are worth a look.
- Entra *smart lockout* appears as failures with `ACCOUNT_LOCKED`, not as a lockout event.

## Example files

`data/examples/` holds one fictional file per format. Addresses are from the documentation ranges, and domains are `example.com` / `example.local`.

| File | Story | Alerts |
| --- | --- | --- |
| `linux_auth.log` | SSH brute force from 203.0.113.45 against `root` and default account names; `m.jones` mistypes three times from home, then logs on and changes the password | R001, R003, R004, R002 (all High) |
| `windows_security.xml` | `j.smith` forgets a password: six failures, lockout, unlock by the service desk (`h.wright`), success, password change | R001, R002, R005 lockout then success (all Medium) |
| `entra_signins.json` | Password spray from 203.0.113.88 against eight accounts, then a successful sign-in for `l.taylor`; one MFA interruption | R004 **Critical** |

## Limitations

- Each format has many variants (distributions, audit policies, export tools). Lines the parser does not recognise are skipped and counted, never guessed.
- Rules that need history (`off_hours_new_source`) produce nothing on short files, because the first `baseline_learning_days` are a learning period.
- Usernames from different sources are not unified: `j.smith`, `EXAMPLE\j.smith` and `j.smith@example.com` are different accounts to the rules.
