# Log format

Authentication events are stored as CSV (UTF-8, header row required). Linux `auth.log`, Windows Security XML and Entra ID sign-in JSON are converted to this schema first: see [real_log_formats.md](real_log_formats.md).

| Field | Required | Description | Example |
| --- | --- | --- | --- |
| `event_id` | Yes | Unique identifier for the event | `EVT-000535` |
| `timestamp` | Yes | ISO 8601 in UTC | `2026-10-12T08:40:21Z` |
| `username` | Yes | Account name (normalised to lower case) | `e.wilson` |
| `source_ip` | Yes | Address the authentication came from | `10.10.1.15` |
| `event_type` | Yes | See below | `LOGON` |
| `result` | Yes | `SUCCESS`, `FAILURE` or `INFO` | `FAILURE` |
| `hostname` | No | Host the account authenticated to | `LON-WS-005` |
| `event_code` | No | Equivalent Windows Security event ID | `4625` |
| `failure_reason` | No | Reason for a failure | `BAD_PASSWORD` |
| `logon_type` | No | `INTERACTIVE`, `NETWORK`, `VPN` | `INTERACTIVE` |

## Event types

| `event_type` | `result` | `event_code` | Meaning |
| --- | --- | --- | --- |
| `LOGON` | `SUCCESS` | 4624 | Successful logon |
| `LOGON` | `FAILURE` | 4625 | Failed logon |
| `LOGOFF` | `INFO` | 4634 | Logoff |
| `PASSWORD_CHANGE` | `SUCCESS` | 4723 | Password changed |
| `ACCOUNT_LOCKOUT` | `INFO` | 4740 | Account locked out by policy |
| `ACCOUNT_UNLOCK` | `INFO` | 4767 | Account unlocked (e.g. by the service desk) |

Failure reasons used by the generator are `BAD_PASSWORD`, `UNKNOWN_USER`, `ACCOUNT_LOCKED` and `EXPIRED_PASSWORD`.

## Validation rules

| Problem | Handling |
| --- | --- |
| File missing / is a directory | Error: `LogFileError` (CLI exit code 2, error banner in the dashboard) |
| File empty, or header with no rows | No error; zero events with a warning |
| Required column missing | Error naming the missing column(s) |
| Optional column missing | Filled with blanks; warning |
| Exact duplicate row | Removed and counted |
| Required field blank | Row rejected: `missing required field: <name>` |
| Unparseable timestamp | Row rejected: `invalid timestamp` |
| Unknown `event_type` / `result` | Row rejected |
| Same `event_id`, different content | First kept; others rejected |

Rejected rows and their reasons are shown in the dashboard's **Data Quality** tab.

## The synthetic environment

- **Organisation:** a fictional London office. There are 16 office staff on `LON-WS-0xx` workstations (`10.10.1.x`) and 4 remote staff who connect through `LON-VPN-01` from home addresses in `198.51.100.0/24`. VPN users get a static address in `10.20.0.x`.
- **Servers:** `LON-FS-01` (file), `LON-APP-01` (application), `LON-DC-01` (domain controller).
- **Automation:** `svc_backup` runs nightly from `10.10.5.20`. An authorised vulnerability scanner runs from `10.10.99.5`.
- **External sources** used in the simulated attacks are from `203.0.113.0/24`, which is reserved for documentation.

The generator appends four deliberately bad rows (one duplicate, an invalid timestamp, a missing username and an unknown event type) to demonstrate validation. Disable them with `--no-quality-issues`.

## Generating data

```bash
python -m soc_lab.cli generate                              # default: 14 days from 2026-10-05, seed 42
python -m soc_lab.cli generate --seed 7 --days 21 --output data/other.csv
python -m soc_lab.cli generate --start-date 2026-11-02 --no-quality-issues
```

Each run writes the log CSV and a `<name>_ground_truth.csv` that maps `event_id` to its scenario label. Scenarios that fall beyond the requested number of days are skipped.
