from datetime import date

from factories import at, event, failures, make_events
from soc_lab.detection import run_detection
from soc_lab.filters import filter_alerts, filter_events
from soc_lab.log_loader import empty_events_frame
from soc_lab.metrics import alerts_to_frame, compute_kpis, logon_timeline, severity_breakdown, top_failure_sources


def _sample():
    rows = (failures(5, username="victim", source_ip="203.0.113.7")
            + [event(at(10), username="victim", source_ip="203.0.113.7", result="SUCCESS"),
               event(at(11), username="b.user", source_ip="10.10.1.60", result="SUCCESS"),
               event(at(12), username="b.user", source_ip="10.10.1.60", result="INFO", event_type="LOGOFF"),
               event(at(13), username="victim", result="INFO", event_type="ACCOUNT_LOCKOUT")])
    return make_events(rows)


def test_kpis_are_calculated_from_events(config):
    events = _sample()
    alerts = run_detection(events, config)
    kpis = compute_kpis(events, alerts)
    assert kpis["total_events"] == 9
    assert kpis["successful_logins"] == 2
    assert kpis["failed_logins"] == 5
    assert kpis["account_lockouts"] == 1
    assert kpis["failure_rate"] == 5 / 7
    assert kpis["unique_users"] == 2
    assert kpis["total_alerts"] == len(alerts)
    assert sum(kpis["alerts_by_severity"].values()) == len(alerts)


def test_kpis_on_empty_data():
    kpis = compute_kpis(empty_events_frame(), [])
    assert kpis["total_events"] == 0
    assert kpis["failure_rate"] == 0.0
    assert kpis["alerts_by_severity"] == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}


def test_severity_breakdown_orders_highest_first(config):
    alerts = run_detection(_sample(), config)
    assert list(severity_breakdown(alerts)) == ["Critical", "High", "Medium", "Low"]


def test_timeline_buckets_by_hour():
    timeline = logon_timeline(_sample())
    assert timeline["count"].sum() == 7  # LOGON events only
    assert set(timeline["result"]) == {"SUCCESS", "FAILURE"}


def test_top_failure_sources():
    top = top_failure_sources(_sample())
    assert top.iloc[0]["source_ip"] == "203.0.113.7"
    assert top.iloc[0]["failed_logins"] == 5


def test_alerts_frame_has_one_row_per_alert(config):
    alerts = run_detection(_sample(), config)
    frame = alerts_to_frame(alerts)
    assert len(frame) == len(alerts)
    assert alerts_to_frame([]).empty


def test_filter_events_by_each_dimension():
    events = _sample()
    assert len(filter_events(events, usernames=["b.user"])) == 2
    assert len(filter_events(events, source_ips=["203.0.113.7"])) == 6
    assert len(filter_events(events, event_types=["LOGOFF"])) == 1
    assert len(filter_events(events, search="lockout")) == 1
    assert len(filter_events(events, start=date(2026, 10, 8))) == 0
    assert len(filter_events(events, start=date(2026, 10, 7), end=date(2026, 10, 7))) == len(events)
    assert len(filter_events(events)) == len(events)


def test_filter_alerts(config):
    alerts = run_detection(_sample(), config)
    assert alerts
    assert filter_alerts(alerts, usernames=["b.user"]) == []
    assert len(filter_alerts(alerts, source_ips=["203.0.113.7"])) == len(alerts)
    high = filter_alerts(alerts, severities=["High"])
    assert all(a.severity.value == "High" for a in high)
    assert filter_alerts(alerts, start=date(2026, 10, 8)) == []
