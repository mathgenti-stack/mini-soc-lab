"""Keep each alert's triage status and analyst notes in a local SQLite database.

Real SOCs record triage in a case-management tool so that work survives a restart and every change
can be audited. This store does the same on a small scale:

- alert_triage    the current status and notes of each alert
- triage_history  one row per change (status, notes, time), never updated or deleted

Alert IDs (ALR-0001, ...) are renumbered when thresholds change, so alerts are identified by a
fingerprint instead: rule, pattern, entity and time span - the same key the engine uses to remove
duplicates. Datasets are identified by name and a hash of their content, so two different files
with the same name never share notes.

The sqlite3 module is part of the Python standard library. If it is missing (some in-browser Python
builds), or the file cannot be opened, the store keeps everything in memory for the session instead.
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .models import INCIDENT_STATUSES, Alert

try:
    import sqlite3
except ImportError:  # pragma: no cover - depends on the Python build
    sqlite3 = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "case_store" / "triage.sqlite3"
DEFAULT_STATUS = "New"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_triage (
    dataset     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    alert_id    TEXT NOT NULL,
    status      TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (dataset, fingerprint)
);
CREATE TABLE IF NOT EXISTS triage_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    alert_id    TEXT NOT NULL,
    status      TEXT NOT NULL,
    notes       TEXT NOT NULL,
    changed_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS history_by_alert ON triage_history (dataset, fingerprint, id);
"""


@dataclass(frozen=True)
class TriageRecord:
    alert_id: str
    status: str
    notes: str
    updated_at: str


def alert_fingerprint(alert: Alert) -> str:
    """Stable identity of an alert across reruns and threshold changes."""
    parts = (alert.rule_id, alert.pattern, alert.entity, alert.first_seen.isoformat(), alert.last_seen.isoformat())
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:20]


def dataset_key(name: str, content: bytes) -> str:
    return f"{name}#{hashlib.sha256(content).hexdigest()[:12]}"


def default_db_path() -> Path:
    return Path(os.environ.get("SOC_LAB_DB", DEFAULT_DB_PATH))


class CaseStore:
    """Triage status and notes per (dataset, alert). Use `CaseStore(None)` for an in-memory store."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self.persistent = False
        self._connection = None
        if sqlite3 is not None:
            try:
                if self.path is not None:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    self._connection = sqlite3.connect(self.path, check_same_thread=False)
                    self.persistent = True
                else:
                    self._connection = sqlite3.connect(":memory:", check_same_thread=False)
                self._connection.executescript(SCHEMA)
            except (OSError, sqlite3.Error):
                self._connection, self.persistent = None, False
        self._memory: dict[tuple[str, str], TriageRecord] = {}
        self._memory_history: list[tuple[str, str, str, str, str, str]] = []

    # -- reading -------------------------------------------------------------
    def get(self, dataset: str, alert: Alert) -> TriageRecord | None:
        return self.all_for(dataset).get(alert_fingerprint(alert))

    def all_for(self, dataset: str) -> dict[str, TriageRecord]:
        if self._connection is None:
            return {fp: record for (ds, fp), record in self._memory.items() if ds == dataset}
        rows = self._connection.execute(
            "SELECT fingerprint, alert_id, status, notes, updated_at FROM alert_triage WHERE dataset = ?", (dataset,))
        return {fp: TriageRecord(alert_id, status, notes, updated) for fp, alert_id, status, notes, updated in rows}

    def status_of(self, dataset: str, alert: Alert) -> str:
        record = self.get(dataset, alert)
        return record.status if record else DEFAULT_STATUS

    def history(self, dataset: str, alert: Alert) -> list[dict]:
        fingerprint = alert_fingerprint(alert)
        if self._connection is None:
            rows = [row[2:] for row in self._memory_history if row[:2] == (dataset, fingerprint)]
        else:
            rows = self._connection.execute(
                "SELECT alert_id, status, notes, changed_at FROM triage_history "
                "WHERE dataset = ? AND fingerprint = ? ORDER BY id", (dataset, fingerprint)).fetchall()
        return [{"changed_at": changed, "alert_id": alert_id, "status": status, "notes": notes}
                for alert_id, status, notes, changed in rows]

    # -- writing -------------------------------------------------------------
    def save(self, dataset: str, alert: Alert, status: str, notes: str = "",
             now: pd.Timestamp | None = None) -> bool:
        """Store the triage of `alert`. Returns False (and writes nothing) when nothing changed."""
        if status not in INCIDENT_STATUSES:
            raise ValueError(f"Unknown incident status: {status}")
        notes = notes.strip()
        current = self.get(dataset, alert)
        if current is None and status == DEFAULT_STATUS and not notes:
            return False  # an untouched alert is not worth a row
        if current is not None and (current.status, current.notes) == (status, notes):
            return False
        changed_at = (now or pd.Timestamp.now(tz="UTC")).strftime("%Y-%m-%dT%H:%M:%SZ")
        fingerprint = alert_fingerprint(alert)
        if self._connection is None:
            self._memory[(dataset, fingerprint)] = TriageRecord(alert.alert_id, status, notes, changed_at)
            self._memory_history.append((dataset, fingerprint, alert.alert_id, status, notes, changed_at))
            return True
        with self._connection:  # one transaction: current state and history always agree
            self._connection.execute(
                "INSERT INTO alert_triage (dataset, fingerprint, alert_id, status, notes, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (dataset, fingerprint) DO UPDATE SET "
                "alert_id = excluded.alert_id, status = excluded.status, notes = excluded.notes, "
                "updated_at = excluded.updated_at",
                (dataset, fingerprint, alert.alert_id, status, notes, changed_at))
            self._connection.execute(
                "INSERT INTO triage_history (dataset, fingerprint, alert_id, status, notes, changed_at) "
                "VALUES (?, ?, ?, ?, ?, ?)", (dataset, fingerprint, alert.alert_id, status, notes, changed_at))
        return True

    def to_csv(self, dataset: str, alerts: list[Alert]) -> str:
        """Current triage of every alert in `alerts` (untouched alerts appear as New)."""
        records = self.all_for(dataset)
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["alert_id", "rule_id", "entity", "status", "notes", "updated_at"])
        for alert in alerts:
            record = records.get(alert_fingerprint(alert))
            writer.writerow([alert.alert_id, alert.rule_id, alert.entity, record.status if record else DEFAULT_STATUS,
                             record.notes if record else "", record.updated_at if record else ""])
        return buffer.getvalue()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "CaseStore":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
