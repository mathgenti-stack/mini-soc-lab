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
| **Validation** | Rejects invalid timestamps, incomplete records, unknown event types and conflicting duplicate IDs; removes exact duplicates; reports all of it. |
| **Detection engine** | Five rules (R001-R005) with thresholds in `config/detection_rules.json`. Each alert records trigger criteria, severity rationale, supporting event IDs, facts, hypotheses and a possible MITRE ATT&CK mapping. |
| **Dashboard** | KPIs, alerts by severity, a timeline of failed logons and alerts, an alert queue, a searchable event explorer, filters (date, user, IP, event type, severity), live threshold tuning, and a data-quality view. |
| **Investigation** | For any alert: context checks, benign explanations, false-positive considerations, recommended steps, proposed containment, evidence timeline, evidence-based conclusion, limitations, status and analyst notes. Export to Markdown and CSV. |
| **Training mode** | Practise triage before seeing the answer: 15 questions in five stages (understand, collect facts, add context, decide, communicate), in Portuguese or English. The tool's analysis stays hidden until the analyst reveals it; each answer is then shown next to a reference and the ground-truth scenario. Answers are saved locally in `training_answers/` and included in the exported report. |
| **CLI** | `generate`, `analyse` and `report` commands for working without the dashboard. |
| **Tests** | 113 pytest tests covering rules, thresholds, validation, metrics, filters, reporting, training mode, the CLI and dashboard tests. |

## Technology stack

- **Python 3.10+** (developed and tested on 3.13)
- **pandas** for data handling
- **Streamlit** for the dashboard (charts use **Altair**, which Streamlit installs)
- **pytest** for automated tests

No database, no cloud services and no API keys.

## Architecture

```
CSV logs ──> log_loader (validate) ──> detection engine (R001-R005) ──> alerts
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
├── soc_lab/
│   ├── log_generator.py       Synthetic event and scenario generator
│   ├── log_loader.py          CSV loading and validation
│   ├── config.py              Configuration loading and validation
│   ├── detection/
│   │   ├── context.py         Internal networks, business hours, service accounts
│   │   ├── rules.py           The five detection rules (pure functions)
│   │   ├── playbooks.py       Analyst guidance per rule
│   │   └── engine.py          Runs enabled rules, assigns alert IDs
│   ├── metrics.py             Dashboard KPIs
│   ├── filters.py             Event and alert filtering
│   ├── reporting.py           Investigation reports and exports
│   └── cli.py                 Command-line interface
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

# Validate and analyse; optionally export the alert list
python -m soc_lab.cli analyse --export-csv reports/alerts.csv

# Write an investigation report (Markdown + evidence CSV) to reports/
python -m soc_lab.cli report --alert-id ALR-0010
python -m soc_lab.cli report --all
```

## Running tests

```bash
python -m pytest
```

Expected result: `113 passed`. The dashboard smoke test uses Streamlit's built-in `AppTest` and does not need a browser.

## Sample detection scenarios

With the bundled dataset (`seed 42`) the engine produces **18 alerts** (1 Critical, 5 High, 12 Medium). Each planted scenario is detected, and normal activity on its own produces no alerts (both are checked by tests).

| Scenario (ground truth) | Alerts raised | What an analyst should conclude |
| --- | --- | --- |
| Simulated brute force against `m.jones` from 203.0.113.45, ending in lockout | R001 High, R003 High/Medium | Failed guessing; no success observed |
| Simulated password spray from 203.0.113.88; `l.taylor` succeeds | **R004 Critical**, R003 High | Possible compromise of `l.taylor` - escalate |
| Simulated credential compromise of `r.khan`: 8 failures then evening VPN success | R001 High, R002 High, R005 Medium | Possible compromise - verify with user, escalate |
| Two VPN logons for `s.ahmed` from different external IPs 7 minutes apart | R005 Medium | Ambiguous - verify with user |
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

- Synthetic data only, with one log source (authentication). There is no endpoint, email, proxy or EDR telemetry.
- No geolocation, ASN or threat-intelligence enrichment.
- Business hours are in UTC, so UK daylight saving time is not modelled.
- Rules are threshold-based. They can be evaded by slow or distributed activity, and the thresholds need tuning per environment.
- Incident status and analyst notes are held in the browser session and are not persisted.

More detail: [docs/limitations_and_false_positives.md](docs/limitations_and_false_positives.md).

## Future improvements

- Ingest real-format logs (Windows Security EVTX exports, Linux `auth.log`, Entra ID sign-in logs) through parsers.
- Export rules as Sigma, or replicate them as Splunk SPL / Microsoft Sentinel KQL queries.
- Add enrichment (GeoIP, ASN, threat-intelligence lookups) with offline sample data.
- Persist case status and notes in SQLite.
- Correlate related alerts into a single incident.
- Per-user behavioural baselines that go beyond "seen before".

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
| [docs/detection_rules.md](docs/detection_rules.md) | Every rule: criteria, parameters, severity logic, limitations |
| [docs/limitations_and_false_positives.md](docs/limitations_and_false_positives.md) | Known gaps and false-positive handling |
| [docs/dashboard_guide.md](docs/dashboard_guide.md) | Dashboard walkthrough and example uses |
| [docs/sample_incident_report.md](docs/sample_incident_report.md) | Example generated report |
| [docs/interview_prep.md](docs/interview_prep.md) | Demo script and interview Q&A |

## Licence

Released under the [MIT Licence](LICENSE).
