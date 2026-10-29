# Architecture

## Data flow

1. **Input.** A CSV of authentication events comes from the bundled sample, a newly generated dataset or a user upload.
2. **Validation** (`soc_lab/log_loader.py`). All values are read as text, whitespace is trimmed, and usernames, event types and results are normalised. Exact duplicate rows are removed. Rows with missing required fields, invalid timestamps, unknown event types or unknown results are rejected with a reason. If two different rows share an `event_id`, the first is kept and the second is rejected. Timestamps are parsed as UTC and the events are sorted by time. The output is the clean events plus a `DataQualityReport`.
3. **Detection** (`soc_lab/detection/`). The engine loads each enabled rule from `config/detection_rules.json` and runs it over the clean events. Each rule is a pure function `(events, params, context) -> list[Alert]`. The engine drops exact repeats, sorts alerts by first-seen time and assigns IDs (`ALR-0001` ...).
4. **Presentation.** `metrics.py` calculates KPIs and `filters.py` applies the dashboard filters. `reporting.py` builds investigation reports. `streamlit_app.py` and `cli.py` are thin layers on top of these modules.

## Components

| Module | Responsibility | Depends on |
| --- | --- | --- |
| `models.py` | Schema constants, `Severity`, `Alert`, incident statuses | pandas |
| `config.py` | Load and validate JSON configuration; apply overrides | - |
| `log_generator.py` | Synthetic events, planted scenarios, ground truth | models |
| `log_loader.py` | Read CSV, validate, data-quality report | models |
| `detection/context.py` | Internal networks, business hours, service-account naming | config values |
| `detection/rules.py` | R001-R005 logic and alert wording | models, context |
| `detection/playbooks.py` | Benign explanations, FP notes, steps, containment, limitations | - |
| `detection/engine.py` | Rule registry, enable/disable, de-duplication, IDs | rules |
| `detection/export.py` | Sigma / Splunk SPL / Sentinel KQL export built from the configuration | config values |
| `metrics.py` / `filters.py` | KPIs, timeline, filtering | models |
| `reporting.py` | Context checks, conclusion, Markdown/CSV export | context, playbooks |
| `correlation.py` | Groups related alerts into cases | models |
| `cli.py` | Command-line entry point | all of the above |
| `streamlit_app.py` | Dashboard UI | all of the above |

## Design decisions

- **Thresholds live in configuration, not in code.** Analysts tune detections without editing Python. Bad values (for example a negative window or a rate above 1) are rejected when the configuration loads, so they cannot fail silently later.
- **Rules are pure functions.** They take a DataFrame and parameters and return alerts, with no global state, files or UI. This makes them easy to test with small hand-built datasets.
- **Analyst guidance lives apart from detection logic** (`playbooks.py`). The wording of recommendations can change without touching rule code.
- **Facts and hypotheses are separate fields** on every alert. Reports also add *context checks*, which are additional facts looked up around the alert. The conclusion is built from rules over those facts, not free text, so it cannot claim more than the data supports.
- **The generator writes ground truth to a separate file.** Real logs are not labelled. Keeping the labels out of the log file stops detection from depending on them by accident, while tests can still measure detection coverage.
- **Validation rejects bad data rather than repairing it,** and reports what was rejected. A SOC analyst needs to know when evidence is incomplete.
- **Sliding windows, not fixed buckets,** are used for R001 and R004, so a burst that straddles a bucket boundary is not missed.
- **The UI contains no business logic.** All filtering and calculation lives in `soc_lab/`, so the dashboard and the CLI give the same numbers and the logic is unit tested.

## Alert ID stability

Alert IDs are sequential, ordered by first-seen time, rule and entity. The same input and configuration always produce the same IDs. Changing thresholds or the data can renumber them, so treat IDs as stable only for a given dataset and configuration.
