# Triage store (SQLite)

A SOC records every decision about an alert in a case-management tool, so the work survives a restart and every change can be audited later. `soc_lab/case_store.py` does the same on a small scale, with SQLite from the Python standard library.

## What is stored

| Table | Contents |
| --- | --- |
| `alert_triage` | The current status and notes of each alert that was touched (one row per dataset and alert) |
| `triage_history` | One row per change: status, notes, time (UTC). Rows are only ever added, never changed or deleted |

Statuses are the usual ones: *New, In Progress, Escalated, Closed - True Positive, Closed - Benign True Positive, Closed - False Positive*. An alert nobody has touched has no row and counts as *New*. Saving the same status and notes again writes nothing.

The database is `case_store/triage.sqlite3` in the project folder (ignored by git). Set the `SOC_LAB_DB` environment variable to use another file; the tests do this so they never touch your data.

## How alerts and datasets are identified

- **Alerts by fingerprint, not by number.** Alert IDs (`ALR-0010`) are renumbered when a threshold changes or a rule is switched off. The store identifies an alert by rule, pattern, entity and time span instead, the same key the engine uses to remove duplicates. Notes therefore stay with the right alert. The last known alert ID is stored for display.
- **Datasets by name and content.** The key is the file name plus a hash of its content, so two different files called `logs.csv` never share notes, and a regenerated dataset starts empty.

## Where it is used

- **Dashboard:** in the free investigation mode, the status and notes are saved as soon as they change, and come back when the app is opened again. A caption shows when they were last saved, and **Change history** lists every change. The alert queue and the alerts of each case show the stored status. **Export triage status and notes (CSV)** downloads them.
- **CLI:** `python -m soc_lab.cli triage --alert-id ALR-0010 --status Escalated --notes "..."` records a decision, and `triage` alone lists every triaged alert. `report` uses the stored status and notes. The CLI and the dashboard share the database.

Training-mode answers are a separate thing: practice answers saved as JSON files in `training_answers/`.

## Limits

- **In-browser build (Cloudflare):** there is no permanent disk, so status and notes last only for the browser session. If `sqlite3` is not available, the store keeps everything in memory and the sidebar says so.
- **One analyst at a time.** There are no user accounts, assignment or locking: this is a single-user lab, not a ticketing system.
- **Local file.** Anyone who can read the project folder can read the notes. Do not write personal data in them.
