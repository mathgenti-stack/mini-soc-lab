import io

import pandas as pd
import pytest

from factories import at, event, failures, make_events
from soc_lab.detection import run_detection
from soc_lab.reporting import (
    alerts_to_csv, build_investigation_report, evidence_to_csv, render_markdown, save_report,
)

REQUIRED_SECTIONS = [
    "Incident ID", "Detection rule", "Severity", "Incident status", "First seen", "Last seen",
    "Affected account(s)", "Source IP address(es)", "Why this alert was generated", "Observed behaviour",
    "Hypotheses", "Potential benign explanations", "False-positive considerations", "Event timeline",
    "Recommended investigation steps", "Suggested containment actions", "Evidence-based conclusion",
    "Limitations of this investigation",
]


@pytest.fixture
def compromise(config):
    rows = failures(6, username="victim", source_ip="203.0.113.7") + [
        event(at(8), username="victim", source_ip="203.0.113.7", result="SUCCESS", hostname="LON-VPN-01")]
    events = make_events(rows)
    alerts = run_detection(events, config)
    alert = next(a for a in alerts if a.rule_id == "R002")
    return events, alerts, alert


def test_report_contains_all_required_sections(compromise, config):
    events, alerts, alert = compromise
    markdown = render_markdown(build_investigation_report(alert, events, config, alerts, status="In Progress"))
    for section in REQUIRED_SECTIONS:
        assert section in markdown, section
    assert "INC-" in markdown and "In Progress" in markdown


def test_report_evidence_matches_alert(compromise, config):
    events, alerts, alert = compromise
    report = build_investigation_report(alert, events, config, alerts)
    assert report.evidence["event_id"].tolist() == alert.evidence_event_ids
    assert report.incident_id == alert.alert_id.replace("ALR", "INC")
    assert report.related_alert_ids  # R001 for the same account


def test_external_success_conclusion_is_cautious(compromise, config):
    events, alerts, alert = compromise
    conclusion = build_investigation_report(alert, events, config, alerts).conclusion
    assert "possible unauthorised access" in conclusion
    assert "does not confirm" in conclusion


def test_benign_indicators_are_reported(config):
    rows = [event(at(-60), event_type="PASSWORD_CHANGE", result="SUCCESS")] + failures(6)
    events = make_events(rows)
    alert = run_detection(events, config)[0]
    report = build_investigation_report(alert, events, config)
    assert any("password change" in b for b in report.benign_indicators)
    assert "possible benign explanation" in report.conclusion


def test_unsuccessful_external_attempts_conclusion(config):
    events = make_events(failures(6, source_ip="203.0.113.9"))
    alert = run_detection(events, config)[0]
    conclusion = build_investigation_report(alert, events, config).conclusion
    assert "appear to have been unsuccessful" in conclusion


def test_analyst_notes_are_included(compromise, config):
    events, alerts, alert = compromise
    report = build_investigation_report(alert, events, config, analyst_notes="Called user; not recognised.")
    assert "Called user; not recognised." in render_markdown(report)


def test_invalid_status_rejected(compromise, config):
    events, alerts, alert = compromise
    with pytest.raises(ValueError):
        build_investigation_report(alert, events, config, status="Solved")


def test_evidence_csv_export(compromise, config):
    events, alerts, alert = compromise
    report = build_investigation_report(alert, events, config)
    frame = pd.read_csv(io.StringIO(evidence_to_csv(report)))
    assert len(frame) == alert.event_count
    assert set(frame["incident_id"]) == {report.incident_id}
    assert frame["timestamp"].str.endswith("Z").all()


def test_alert_list_csv_export(compromise):
    _events, alerts, _alert = compromise
    frame = pd.read_csv(io.StringIO(alerts_to_csv(alerts)))
    assert frame["alert_id"].tolist() == [a.alert_id for a in alerts]
    assert pd.read_csv(io.StringIO(alerts_to_csv([])), dtype=str).empty


def test_save_report_writes_markdown_and_csv(compromise, config, tmp_path):
    events, alerts, alert = compromise
    md_path, csv_path = save_report(build_investigation_report(alert, events, config), tmp_path / "out")
    assert md_path.exists() and csv_path.exists()
    assert md_path.read_text(encoding="utf-8").startswith("# Incident Investigation Report")


def test_long_evidence_is_truncated_in_markdown_but_not_csv(config):
    events = make_events(failures(60, every_minutes=0.1, source_ip="203.0.113.9"))
    alert = next(a for a in run_detection(events, config) if a.rule_id == "R001")
    report = build_investigation_report(alert, events, config)
    assert "further event(s) omitted" in render_markdown(report)
    assert len(pd.read_csv(io.StringIO(evidence_to_csv(report)))) == 60
