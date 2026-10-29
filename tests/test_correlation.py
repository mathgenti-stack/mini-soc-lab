"""Case correlation: grouping related alerts."""

from pathlib import Path

import pandas as pd
import pytest

from soc_lab.cli import main
from soc_lab.config import ConfigError, load_config, validate_config
from soc_lab.correlation import (DEFAULT_WINDOW_MINUTES, case_for_alert, cases_to_csv, cases_to_frame,
                                 correlate_alerts, correlation_window)
from soc_lab.detection import run_detection
from soc_lab.i18n import LANGUAGES, t, tr
from soc_lab.log_loader import load_events
from soc_lab.models import Alert, Severity

from factories import at

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"
SAMPLE = ROOT / "data" / "sample_auth_logs.csv"


def alert(alert_id, start, end=None, users=("a.user",), ips=("10.10.1.50",), severity=Severity.MEDIUM, rule="R001"):
    return Alert(rule_id=rule, rule_name="rule", title=f"title {alert_id}", severity=severity, entity_type="user",
                 entity=users[0] if users else ips[0], first_seen=pd.Timestamp(at(start)),
                 last_seen=pd.Timestamp(at(start if end is None else end)), evidence_event_ids=[f"E-{alert_id}"],
                 usernames=list(users), source_ips=list(ips), hostnames=[], trigger_reason="", observed_facts=[],
                 hypotheses=[], alert_id=alert_id, mitre_attack=f"T{rule}")


def groups(cases):
    return [case.alert_ids for case in cases]


@pytest.fixture(scope="module")
def sample_alerts():
    return run_detection(load_events(SAMPLE).events, load_config())


def test_sample_dataset_groups_alerts_by_scenario(sample_alerts):
    cases = correlate_alerts(sample_alerts)
    assert groups(cases) == [
        ["ALR-0001", "ALR-0002", "ALR-0003"],  # brute force against m.jones
        ["ALR-0004"],                          # on-call engineer
        ["ALR-0005", "ALR-0006"],              # authorised scan
        ["ALR-0007", "ALR-0008"],              # e.wilson forgot a password
        ["ALR-0009", "ALR-0010"],              # password spray
        ["ALR-0011", "ALR-0012", "ALR-0013"],  # r.khan compromise
        ["ALR-0014"],                          # rapid source change
        ["ALR-0015", "ALR-0016"],              # svc_backup, first night
        ["ALR-0017", "ALR-0018"],              # svc_backup, second night
    ]
    assert [case.case_id for case in cases] == [f"CASE-{n:04d}" for n in range(1, 10)]
    assert case_for_alert(cases, "ALR-0010").severity == Severity.CRITICAL
    assert sorted(a for case in cases for a in case.alert_ids) == sorted(a.alert_id for a in sample_alerts)


def test_every_case_matches_a_single_ground_truth_scenario(generated_analysis):
    _events, _quality, alerts, truth = generated_analysis
    for case in correlate_alerts(alerts):
        scenarios = {truth[event_id] for event_id in case.event_ids} - {"normal"}
        assert len(scenarios) == 1, (case.case_id, scenarios)


def test_alerts_need_a_shared_account_or_address():
    cases = correlate_alerts([alert("A", 0, users=("x",), ips=("1.1.1.1",)),
                              alert("B", 0, users=("y",), ips=("2.2.2.2",))])
    assert groups(cases) == [["A"], ["B"]]


def test_window_decides_how_far_apart_alerts_can_be():
    near_and_far = [alert("A", 0, 10), alert("B", 100), alert("C", 400)]
    assert groups(correlate_alerts(near_and_far, 90)) == [["A", "B"], ["C"]]
    assert groups(correlate_alerts(near_and_far, 89)) == [["A"], ["B"], ["C"]]
    assert groups(correlate_alerts(near_and_far, 300)) == [["A", "B", "C"]]
    overlapping = [alert("A", 0, 60), alert("B", 30, 40)]
    assert groups(correlate_alerts(overlapping, 0)) == [["A", "B"]]  # overlapping alerts always qualify


def test_links_are_transitive_and_explained():
    chain = [alert("A", 0, users=("x",), ips=("1.1.1.1",)), alert("B", 5, users=("y",), ips=("1.1.1.1",)),
             alert("C", 10, users=("y",), ips=("2.2.2.2",))]
    (case,) = correlate_alerts(chain)
    assert case.alert_ids == ["A", "B", "C"]  # A and C share nothing, but both share something with B
    assert [str(link.reason) for link in case.links] == ["A and B share source address 1.1.1.1",
                                                        "B and C share account y"]
    assert tr(case.links[0].reason, "pt-BR") == "A e B têm em comum o endereço de origem 1.1.1.1"


def test_case_summary():
    case, = correlate_alerts([alert("A", 0, 5, severity=Severity.LOW, rule="R003"),
                              alert("B", 2, 30, severity=Severity.HIGH, rule="R001", ips=("10.10.1.50", "9.9.9.9"))])
    assert case.severity == Severity.HIGH  # the highest, never raised further
    assert (case.first_seen, case.last_seen) == (pd.Timestamp(at(0)), pd.Timestamp(at(30)))
    assert case.rule_ids == ["R001", "R003"] and case.source_ips == ["10.10.1.50", "9.9.9.9"]
    assert case.event_ids == ["E-A", "E-B"] and case.mitre_attack == ["TR003", "TR001"]
    assert str(case.title) == "2 related alerts: a.user"
    assert tr(case.title, "pt-BR") == "2 alertas relacionados: a.user"
    single, = correlate_alerts([alert("A", 0)])
    assert str(single.title) == "Single alert: a.user" and single.links == []


def test_long_lists_are_shortened():
    users = tuple(f"u{n}" for n in range(8))
    case, = correlate_alerts([alert("A", 0, users=users), alert("B", 1, users=users)])
    assert str(case.links[0].reason).endswith("share source address 10.10.1.50; account u0, u1, u2, u3, u4 (+3)")


def test_no_alerts_no_cases():
    assert correlate_alerts([]) == []
    assert cases_to_frame([]).empty and cases_to_csv([]).startswith("case_id,severity,alert_count")


def test_csv_export(sample_alerts):
    csv = cases_to_csv(correlate_alerts(sample_alerts)).splitlines()
    assert csv[0] == ("case_id,severity,alert_count,alert_ids,rule_ids,title,entities,first_seen,last_seen,"
                      "event_count,usernames,source_ips,mitre_attack")
    assert csv[1].startswith('CASE-0001,High,3,"ALR-0001, ALR-0002, ALR-0003","R001, R003"')
    assert len(csv) == 10
    assert all(type(value) is str for value in cases_to_frame(correlate_alerts(sample_alerts))["title"])


def test_window_comes_from_the_configuration(config):
    assert correlation_window(config) == 120 == DEFAULT_WINDOW_MINUTES
    del config["correlation"]
    validate_config(config)  # the section is optional
    assert correlation_window(config) == DEFAULT_WINDOW_MINUTES
    for bad in (-1, "60", True, None):
        config["correlation"] = {"window_minutes": bad}
        with pytest.raises(ConfigError):
            validate_config(config)


def test_cli_prints_and_exports_cases(tmp_path, capsys):
    assert main(["analyse", "--input", str(SAMPLE), "--export-cases-csv", str(tmp_path / "cases.csv")]) == 0
    output = capsys.readouterr().out
    assert "Cases: 9 (alerts sharing an account or address, at most 120 min apart)" in output
    assert "CASE-0005  Critical  ALR-0009, ALR-0010" in output
    assert (tmp_path / "cases.csv").read_text(encoding="utf-8").startswith("case_id,")


@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    return testing.AppTest.from_file(str(APP_PATH), default_timeout=120)


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_dashboard_cases_tab(app, lang):
    app.run()
    app.segmented_control(key="lang").set_value(lang).run()
    assert t("ui.tab.cases", lang) in [tab.label for tab in app.tabs]
    assert {m.label: m.value for m in app.metric}[t("ui.kpi.cases", lang)] == "9"
    assert any(s.value == t("ui.cases.header", lang, count=9) for s in app.subheader)

    case_select = app.selectbox(key="case_select_sample_auth_logs_csv")
    case_select.set_value("CASE-0005").run()
    assert not app.exception
    reason = t("case.link", lang, a="ALR-0009", b="ALR-0010",
               shared=t("case.shared.ips", lang, values="203.0.113.88"))
    assert any(reason in m.value for m in app.markdown)

    app.number_input(key="thr_correlation_window").set_value(0).run()
    assert {m.label: m.value for m in app.metric}[t("ui.kpi.cases", lang)] == "10"  # e.wilson's alerts split


def test_filters_never_split_a_case(app):
    app.run()
    app.multiselect(key="filter_severity").set_value(["Critical"]).run()
    assert {m.label: m.value for m in app.metric}["Cases"] == "1"
    app.selectbox(key="case_select_sample_auth_logs_csv").set_value("CASE-0005").run()
    assert {m.label: m.value for m in app.metric}["Alerts"] == "2"  # ALR-0009 (High) is kept in its case


def test_investigation_shows_the_case(app):
    app.run()
    app.toggle(key="training_mode").set_value(False).run()
    next(s for s in app.selectbox if s.label.startswith("Select an alert")).set_value("ALR-0010").run()
    assert any(i.value == t("ui.inv.case", case="CASE-0005", others="ALR-0009") for i in app.info)
