# Mini SOC Lab

A small, self-contained Security Operations Centre (SOC) lab that generates **synthetic authentication logs**, runs **configurable detection rules**, presents alerts in an **interactive Streamlit dashboard**, and produces **evidence-based investigation reports** that can be exported as Markdown and CSV.

It is a learning and portfolio project built to practise first-line (Tier 1) SOC analyst work: log analysis, alert triage, severity assessment, false-positive handling and incident write-ups.

> All data is fictional. Public-looking IP addresses come only from the RFC 5737 documentation ranges. The project does not connect to, scan or attack any system.

---

## Objectives

- Show how raw authentication events become actionable alerts.
- Keep **observed facts**, **hypotheses** and **conclusions** clearly separate.
- Treat every alert as a lead to investigate, not as proof of an attack.
- Show realistic false positives (forgotten passwords, service accounts, authorised scanners, on-call staff) next to simulated attacks.
- Back every feature with automated tests.

## Features

| Area | What it does |
| --- | --- |
| **Log generator** | 14 days of activity for 20 fictional staff plus service and scanner accounts, with planted scenarios and a separate ground-truth file. Reproducible with a seed. |
| **Real log formats** | Reads Linux `auth.log`, Windows Security events (binary `.evtx` files or XML exports) and Entra ID sign-in JSON, converts them to the lab schema and runs the same rules. Fictional example files for each format are included. See [docs/real_log_formats.md](docs/real_log_formats.md). |
| **Validation** | Rejects invalid timestamps, incomplete records, unknown event types and conflicting duplicate IDs; removes exact duplicates; reports all of it. |
| **Detection engine** | Six rules (R001-R006) with thresholds in `config/detection_rules.json`, from simple thresholds to a per-account behavioural baseline (R006: usual hours, networks, hosts, logon types and daily volume). Each alert records trigger criteria, severity rationale, supporting event IDs, facts, hypotheses and a possible MITRE ATT&CK mapping. |
| **Dashboard** | KPIs, alerts by severity, a timeline of failed logons and alerts, an alert queue, a searchable event explorer, filters (date, user, IP, event type, severity), live threshold tuning, and a data-quality view. |
| **Investigation** | For any alert: context checks, benign explanations, false-positive considerations, recommended steps, proposed containment, evidence timeline, evidence-based conclusion, limitations, status and analyst notes. Export to Markdown and CSV. |
| **IP enrichment (offline)** | Geolocation, ASN and threat-intelligence lookups from local, fictional files in `data/enrichment/` - nothing is sent to the internet. Shown in investigations, reports and the Event Explorer, plus a distance check for rapid source changes. See [docs/enrichment.md](docs/enrichment.md). |
| **Case correlation** | Related alerts (same account or source address, close in time) are grouped into cases, so one activity is triaged once. The 21 sample alerts become 10 cases, one per scenario. See [docs/correlation.md](docs/correlation.md). |
| **Rule export** | Detection as code: the same rules exported as **Sigma**, **Splunk SPL** and **Microsoft Sentinel KQL**, built from the current thresholds. Available in the dashboard (with downloads) and from the CLI. See [docs/rule_export.md](docs/rule_export.md). |
| **Triage store** | Incident status and analyst notes from the free investigation mode are saved in a local SQLite database (`case_store/triage.sqlite3`) with a full change history, shown in the alert queue and in cases, and used by the CLI report. See [docs/triage_store.md](docs/triage_store.md). |
| **Languages** | The whole interface - menus, alerts, playbooks, training questions, feedback and the Markdown report - is available in English (default) and Brazilian Portuguese, switched from the sidebar without losing answers or progress. The language is kept in the link (`?lang=pt-BR`), so a shared URL opens in the same language. Texts live in `soc_lab/locales/*.json`; log data, IDs and CSV exports are never translated. |
| **Training mode** | Practise triage before seeing the answer: 15 questions in five stages (understand, collect facts, add context, decide, communicate). The tool's analysis stays hidden until the analyst reveals it; each answer is then shown next to a reference and the ground-truth scenario, with a score: an automatic checklist of the key facts each answer should mention (see [docs/training_score.md](docs/training_score.md)). Answers are saved locally in `training_answers/` and included in the exported report. |
| **Terminal** | A real shell (Docker, on your own computer) inside the dashboard, bash or PowerShell, with 28 TryHackMe-style challenges that investigate the lab's own logs: `grep`, `awk`, `cut` and `jq` in bash; `Import-Csv`, `Where-Object`, `Group-Object` and `Get-WinEvent` (a lab version that reads `.evtx`) in PowerShell, for Windows events 4624, 4625, 4740 and 4767. Answers are checked at once, with hints and explained solutions. See [docs/terminal.md](docs/terminal.md). |
| **CLI** | `generate`, `analyse`, `report`, `triage`, `convert`, `export-rules`, `lookup-ip` and `terminal` commands for working without the dashboard. |
| **Tests** | 313 pytest tests covering rules, thresholds, validation, real log formats, metrics, filters, reporting, training mode, translations, rule export, case correlation, IP enrichment, the triage store, the CLI and dashboard tests. |

## Technology stack

- **Python 3.10+** (developed and tested on 3.13)
- **pandas** for data handling
- **Streamlit** for the dashboard (charts use **Altair**, which Streamlit installs)
- **pytest** for automated tests
- **Docker** (optional): only for the Terminal tab's practice shell (bash and PowerShell, in one Linux container)

No database server, no cloud services and no API keys.

## Architecture

```
CSV logs ──> log_loader (validate) ──> detection engine (R001-R006) ──> alerts
                    │                          ▲                          │
                    │               config/detection_rules.json           │
                    ▼                                                     ▼
             data-quality report                  metrics / filters / reporting
                                                          │
                                          Streamlit dashboard  &  CLI
```

```
mini-soc-lab/
├── streamlit_app.py           Dashboard (UI only - logic lives in soc_lab/)
├── config/detection_rules.json  Detection thresholds and environment settings
├── data/                      Sample synthetic dataset + ground-truth labels
│   ├── enrichment/            Fictional GeoIP / ASN and threat-intelligence files
│   ├── terminal/              challenges.json - Terminal tab challenges (all phases)
│   └── examples/              Fictional auth.log, Windows .evtx / XML and Entra ID JSON files
├── soc_lab/
│   ├── log_generator.py       Synthetic event and scenario generator
│   ├── log_loader.py          CSV loading and validation
│   ├── parsers.py             Linux auth.log / Windows .evtx and XML / Entra ID JSON to the lab schema
│   ├── evtx.py                Binary .evtx reader (standard library only)
│   ├── config.py              Configuration loading and validation
│   ├── detection/
│   │   ├── context.py         Internal networks, business hours, service accounts
│   │   ├── rules.py           The six detection rules (pure functions)
│   │   ├── playbooks.py       Analyst guidance per rule
│   │   ├── export.py          Sigma / Splunk SPL / Sentinel KQL export
│   │   └── engine.py          Runs enabled rules, assigns alert IDs
│   ├── metrics.py             Dashboard KPIs
│   ├── filters.py             Event and alert filtering
│   ├── reporting.py           Investigation reports and exports
│   ├── correlation.py         Groups related alerts into cases
│   ├── case_store.py          SQLite store for triage status, notes and history
│   ├── enrichment.py          Offline IP enrichment (geolocation, ASN, threat intel)
│   ├── training.py            Training-mode questionnaire and reference answers
│   ├── scoring.py             Training score (key-point checklist)
│   ├── challenges.py          Terminal challenges: loading, answer checking, progress
│   ├── terminal.py            Starts/stops the practice container, bash and PowerShell (Docker)
│   ├── i18n.py                Translation lookup (t() and Msg)
│   ├── locales/               en.json, pt-BR.json - every user-facing text
│   └── cli.py                 Command-line interface
├── terminal/                  Practice terminal image: Dockerfile, shell chooser, Get-WinEvent module (SocLab)
├── tests/                     pytest suite
└── docs/                      Architecture, log format, rules, limitations, guides
```

See [docs/architecture.md](docs/architecture.md) for design decisions.

## Installation

Requirements: Python 3.10 or newer, and `git` if you are cloning.

```bash
git clone <repository-url> mini-soc-lab
cd mini-soc-lab
python -m venv .venv
```

Activate the virtual environment:

- Windows (PowerShell): `.venv\Scripts\Activate.ps1`
- macOS / Linux: `source .venv/bin/activate`

Then install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Dashboard

```bash
streamlit run streamlit_app.py
```

Open http://localhost:8501. The sidebar lets you choose the bundled sample dataset, generate a new one with a different seed, or upload a CSV. See [docs/dashboard_guide.md](docs/dashboard_guide.md) for a walkthrough.

### Command line

```bash
# Generate a fresh dataset (overwrites data/sample_auth_logs.csv)
python -m soc_lab.cli generate --days 14 --seed 42

# Convert a real-format log to the lab CSV (analyse and report also accept these files directly)
python -m soc_lab.cli convert --input data/examples/linux_auth.log --year 2026
python -m soc_lab.cli analyse --input data/examples/entra_signins.json

# Validate and analyse (alerts and cases); optionally export them
python -m soc_lab.cli analyse --export-csv reports/alerts.csv --export-cases-csv reports/cases.csv

# Write an investigation report (Markdown + evidence CSV) to reports/
python -m soc_lab.cli report --alert-id ALR-0010
python -m soc_lab.cli report --all

# Record triage (the dashboard does the same); report then uses this status and these notes
python -m soc_lab.cli triage --alert-id ALR-0010 --status Escalated --notes "User did not sign in"
python -m soc_lab.cli triage

# Export the rules as Sigma, Splunk SPL and Sentinel KQL to rules_export/
python -m soc_lab.cli export-rules

# Look addresses up in the offline enrichment files
python -m soc_lab.cli lookup-ip 203.0.113.88 203.0.113.120

# Practice terminal, bash and PowerShell (needs Docker): start, status, stop
python -m soc_lab.cli terminal start
```

## Running tests

```bash
python -m pytest
```

Expected result: `313 passed` (`309 passed, 4 skipped` when Docker is not running: those four run the challenge solutions and the lab `Get-WinEvent` in the real terminal container). The dashboard smoke test uses Streamlit's built-in `AppTest` and does not need a browser.

## Sample detection scenarios

With the bundled dataset (`seed 42`) the engine produces **21 alerts** (1 Critical, 7 High, 13 Medium). Each planted scenario is detected, and normal activity on its own produces no alerts (both are checked by tests).

| Scenario (ground truth) | Alerts raised | What an analyst should conclude |
| --- | --- | --- |
| Simulated brute force against `m.jones` from 203.0.113.45, ending in lockout | R001 High, R003 High/Medium | Failed guessing; no success observed |
| Simulated password spray from 203.0.113.88; `l.taylor` succeeds | **R004 Critical**, R003 High, R006 High (first VPN logon ever for `l.taylor`) | Possible compromise of `l.taylor` - escalate |
| Simulated credential compromise of `r.khan`: 8 failures then evening VPN success | R001 High, R002 High, R006 High, R005 Medium | Possible compromise - verify with user, escalate |
| Two VPN logons for `s.ahmed` from different external IPs 7 minutes apart | R005 Medium | Ambiguous - verify with user |
| `c.evans` opens Remote Desktop to the domain controller at 23:12 from their usual workstation | R006 Medium (hour, host and logon type all new) | Ambiguous - check change tickets, ask user and IT |
| `e.wilson` forgot a recently changed password, locked out, unlocked by service desk | R001 Medium, R005 Medium | Likely benign - confirm ticket |
| Authorised internal vulnerability scan from 10.10.99.5 | R004 Medium, R003 Medium | Likely benign - confirm scan schedule |
| On-call engineer `d.brown` connects at 02:31 from a hotel | R005 Medium | Likely benign - confirm on-call rota |
| `svc_backup` retries with an expired password for two nights | R003 Medium (x4) | Benign misconfiguration - raise ticket |

The ground-truth file (`data/sample_auth_logs_ground_truth.csv`) exists for learning and testing only; detection never reads it.

## Example investigation

[docs/sample_incident_report.md](docs/sample_incident_report.md) is a report produced by the tool for the password spray alert (ALR-0010). It shows:

- 15 failed logons against 15 distinct accounts from one external address in about 15 minutes, 4 of them for account names that are not recognised.
- A successful logon for `l.taylor` from the same address during the activity. This account had no failed attempts, which is consistent with a spray that found a valid password.
- The cautious conclusion: *consistent with possible unauthorised access but does not confirm it*, with escalation recommended if the account owner cannot confirm the activity.

## Limitations

- Synthetic and example data only, with one kind of log (authentication). Real formats can be read, but there is no endpoint, email, proxy or EDR telemetry.
- Enrichment (geolocation, ASN, threat intelligence) uses small offline, fictional files, not real feeds.
- Business hours are in UTC, so UK daylight saving time is not modelled.
- Rules are threshold-based. They can be evaded by slow or distributed activity, and the thresholds need tuning per environment.
- Triage status and notes are saved in a local SQLite file. In the in-browser build (Cloudflare) they last only for the session. Training-mode answers are saved separately, as JSON files.

More detail: [docs/limitations_and_false_positives.md](docs/limitations_and_false_positives.md).

## Future improvements

- Unify account names across sources (`j.smith`, `EXAMPLE\j.smith` and `j.smith@example.com` are three accounts today).
- Model UK daylight saving time and shift patterns instead of fixed UTC business hours.
- Add another log source (for example Sysmon process events or proxy logs) so alerts can be followed beyond the logon.

## Ethical and safety considerations

- Only synthetic data is used. Names, hosts and addresses are fictional, and external IPs are from documentation-only ranges.
- The tool never contacts external systems and never takes automated action. Containment steps are written as proposals for a human to raise through proper processes.
- Alerts and reports avoid attributing malicious intent to users or IP addresses. An IP address does not identify a person, and every report lists benign explanations.
- If you adapt this tool to real logs, make sure you are authorised to process them, and handle personal data in line with UK GDPR and your organisation's policies.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Components, data flow, design decisions |
| [docs/log_format.md](docs/log_format.md) | Log schema, field values, validation rules, how to generate data |
| [docs/real_log_formats.md](docs/real_log_formats.md) | Linux auth.log, Windows .evtx / XML and Entra ID JSON: mapping, skipped records, examples |
| [docs/detection_rules.md](docs/detection_rules.md) | Every rule: criteria, parameters, severity logic, limitations |
| [docs/limitations_and_false_positives.md](docs/limitations_and_false_positives.md) | Known gaps and false-positive handling |
| [docs/dashboard_guide.md](docs/dashboard_guide.md) | Dashboard walkthrough and example uses |
| [docs/enrichment.md](docs/enrichment.md) | Offline IP enrichment: data files, what is shown where, and its limits |
| [docs/training_score.md](docs/training_score.md) | How the training score is calculated, and its limits |
| [docs/terminal.md](docs/terminal.md) | Terminal tab: setup, safety, PowerShell and the lab `Get-WinEvent`, challenges file format, the three phases |
| [docs/triage_store.md](docs/triage_store.md) | How triage status, notes and history are stored in SQLite |
| [docs/correlation.md](docs/correlation.md) | How alerts are grouped into cases, and the limits of that grouping |
| [docs/rule_export.md](docs/rule_export.md) | Sigma / SPL / KQL export, field mapping, differences from the lab |
| [docs/sample_incident_report.md](docs/sample_incident_report.md) | Example generated report |
| [docs/interview_prep.md](docs/interview_prep.md) | Demo script and interview Q&A |

## Licence

Released under the [MIT Licence](LICENSE).
