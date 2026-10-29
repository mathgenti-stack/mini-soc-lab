"""Triage store: alert status and analyst notes kept in SQLite."""

import os
import sqlite3
from contextlib import closing
from pathlib import Path

import pandas as pd
import pytest

from soc_lab import case_store
from soc_lab.case_store import CaseStore, alert_fingerprint, dataset_key
from soc_lab.cli import main
from soc_lab.config import load_config, with_overrides
from soc_lab.detection import run_detection
from soc_lab.log_loader import load_events

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"
SAMPLE = ROOT / "data" / "sample_auth_logs.csv"
SAMPLE_KEY = dataset_key(SAMPLE.name, SAMPLE.read_bytes())
T0 = pd.Timestamp("2026-10-29T10:00:00Z")


@pytest.fixture(scope="module")
def alerts():
    return run_detection(load_events(SAMPLE).events, load_config())


@pytest.fixture
def open_store(tmp_path):
    stores = []

    def factory(path=None):
        stores.append(CaseStore(tmp_path / "t.sqlite3" if path is None else path))
        return stores[-1]
    yield factory
    for store in stores:
        store.close()


def by_id(alerts, alert_id):
    return next(a for a in alerts if a.alert_id == alert_id)


def test_save_and_read_back(tmp_path, open_store, alerts):
    path = tmp_path / "store" / "triage.sqlite3"
    store = open_store(path)
    assert store.persistent and path.exists()
    spray = by_id(alerts, "ALR-0010")
    assert store.status_of(SAMPLE_KEY, spray) == "New" and store.get(SAMPLE_KEY, spray) is None
    assert store.save(SAMPLE_KEY, spray, "In Progress", "  Checking with l.taylor.  ", now=T0)
    store.close()

    with CaseStore(path) as reopened:  # survives a restart
        record = reopened.get(SAMPLE_KEY, spray)
        other = reopened.get("other.csv#000000000000", spray)
    assert (record.alert_id, record.status, record.notes, record.updated_at) == (
        "ALR-0010", "In Progress", "Checking with l.taylor.", "2026-10-29T10:00:00Z")
    assert other is None  # datasets never share notes


def test_history_records_every_change_and_skips_no_ops(open_store, alerts):
    store = open_store()
    alert = by_id(alerts, "ALR-0007")
    assert not store.save(SAMPLE_KEY, alert, "New", "")  # untouched alert: no row
    assert store.save(SAMPLE_KEY, alert, "In Progress", "", now=T0)
    assert not store.save(SAMPLE_KEY, alert, "In Progress", " ", now=T0)  # same status, notes only whitespace
    assert store.save(SAMPLE_KEY, alert, "Closed - Benign True Positive", "Service desk ticket SD-1234.",
                      now=T0 + pd.Timedelta(minutes=5))
    assert [(h["status"], h["notes"], h["changed_at"]) for h in store.history(SAMPLE_KEY, alert)] == [
        ("In Progress", "", "2026-10-29T10:00:00Z"),
        ("Closed - Benign True Positive", "Service desk ticket SD-1234.", "2026-10-29T10:05:00Z")]
    with pytest.raises(ValueError):
        store.save(SAMPLE_KEY, alert, "Maybe", "")


def test_alerts_are_identified_by_fingerprint_not_by_number(open_store, alerts):
    """Disabling R001 renumbers the alerts; the notes must still follow the same alert."""
    store = open_store()
    spray = by_id(alerts, "ALR-0010")
    store.save(SAMPLE_KEY, spray, "Escalated", "Spray with a success.")
    renumbered = run_detection(load_events(SAMPLE).events, with_overrides(load_config(), {"R001": {"enabled": False}}))
    same_spray = next(a for a in renumbered if alert_fingerprint(a) == alert_fingerprint(spray))
    assert same_spray.alert_id != "ALR-0010"
    assert store.status_of(SAMPLE_KEY, same_spray) == "Escalated"
    assert store.status_of(SAMPLE_KEY, by_id(renumbered, "ALR-0010")) == "New"


def test_dataset_key_depends_on_content():
    assert dataset_key("logs.csv", b"a") != dataset_key("logs.csv", b"b")
    assert dataset_key("logs.csv", b"a") == dataset_key("logs.csv", b"a")


def test_csv_export(open_store, alerts):
    store = open_store()
    store.save(SAMPLE_KEY, by_id(alerts, "ALR-0010"), "Escalated", "Called the user, no answer", now=T0)
    lines = store.to_csv(SAMPLE_KEY, alerts[8:10]).splitlines()
    assert lines == ["alert_id,rule_id,entity,status,notes,updated_at",
                     "ALR-0009,R003,203.0.113.88,New,,",
                     "ALR-0010,R004,203.0.113.88,Escalated,\"Called the user, no answer\",2026-10-29T10:00:00Z"]


def test_falls_back_to_memory(tmp_path, alerts, monkeypatch):
    memory = CaseStore(None)
    memory.close()  # closing an in-memory store leaves the Python fallback working
    assert not memory.persistent
    alert = by_id(alerts, "ALR-0001")
    assert memory.save(SAMPLE_KEY, alert, "Escalated", "x") and memory.status_of(SAMPLE_KEY, alert) == "Escalated"

    monkeypatch.setattr(case_store, "sqlite3", None)  # a Python build without sqlite3
    no_sqlite = CaseStore(tmp_path / "never.sqlite3")
    assert not no_sqlite.persistent and not (tmp_path / "never.sqlite3").exists()
    assert no_sqlite.save(SAMPLE_KEY, alert, "In Progress", "y")
    assert no_sqlite.status_of(SAMPLE_KEY, alert) == "In Progress"
    assert [h["status"] for h in no_sqlite.history(SAMPLE_KEY, alert)] == ["In Progress"]


def test_database_schema(tmp_path):
    CaseStore(tmp_path / "t.sqlite3").close()
    with closing(sqlite3.connect(tmp_path / "t.sqlite3")) as connection:  # "with connect()" alone does not close
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"alert_triage", "triage_history"} <= tables


# ---------------------------------------------------------------------------
# CLI and dashboard
# ---------------------------------------------------------------------------
def test_cli_triage_and_report(tmp_path, capsys):
    assert main(["triage", "--alert-id", "ALR-0010", "--status", "Escalated", "--notes", "Tier 2 informed."]) == 0
    assert "ALR-0010: Escalated" in capsys.readouterr().out
    assert main(["triage", "--alert-id", "ALR-0010", "--status", "Escalated"]) == 0
    assert "(unchanged)" in capsys.readouterr().out
    assert main(["triage"]) == 0
    assert "1 of 18 alert(s) triaged" in capsys.readouterr().out
    assert main(["report", "--alert-id", "ALR-0010", "--output-dir", str(tmp_path)]) == 0
    report = (tmp_path / "INC-0010.md").read_text(encoding="utf-8")
    assert "| Incident status | Escalated |" in report and "Tier 2 informed." in report
    assert main(["triage", "--alert-id", "ALR-9999", "--status", "Escalated"]) == 1


@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    return lambda: testing.AppTest.from_file(str(APP_PATH), default_timeout=120)


def _open_free_investigation(app, alert_id="ALR-0010"):
    app.run()
    app.toggle(key="training_mode").set_value(False).run()
    next(s for s in app.selectbox if s.label.startswith("Select an alert")).set_value(alert_id).run()


def _status_key(alerts, alert_id):
    return f"status_free_{alert_fingerprint(by_id(alerts, alert_id))}"


def test_dashboard_saves_and_restores_triage(app, alerts):
    first = app()
    _open_free_investigation(first)
    key = _status_key(alerts, "ALR-0010")
    first.selectbox(key=key).set_value("Escalated").run()
    notes_key = key.replace("status_free_", "notes_")
    first.text_area(key=notes_key).set_value("l.taylor did not sign in.").run()
    assert not first.exception
    queue = next(f.value for f in first.dataframe if "alert_id" in f.value.columns and "status" in f.value.columns)
    assert queue.set_index("alert_id").loc["ALR-0010", "status"] == "Escalated"  # updated in the same run
    assert any("Change history (2)" in e.label for e in first.expander)

    with CaseStore(os.environ["SOC_LAB_DB"]) as stored:  # what a restart would find
        assert stored.get(SAMPLE_KEY, by_id(alerts, "ALR-0010")).notes == "l.taylor did not sign in."

    second = app()  # a new session: values come back from SQLite
    _open_free_investigation(second)
    assert second.selectbox(key=key).value == "Escalated"
    assert second.text_area(key=notes_key).value == "l.taylor did not sign in."
    second.segmented_control(key="lang").set_value("pt-BR").run()
    assert second.selectbox(key=key).value == "Escalated"
    case_members = [f.value for f in second.dataframe if "alert_id" in f.value.columns and "status" in f.value.columns]
    assert any("Escalado" in set(frame["status"]) for frame in case_members)


def test_dashboard_store_caption(app):
    session = app()
    session.run()
    assert any(c.value.startswith("Triage status and notes are saved in a local SQLite database") for c in session.caption)
