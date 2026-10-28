from datetime import datetime, timezone

import pytest

from factories import at, event, failures, make_events
from soc_lab.config import with_overrides
from soc_lab.detection import run_detection
from soc_lab.detection.rules import find_bursts
from soc_lab.models import Severity

EXTERNAL_IP = "203.0.113.10"


def _rule(alerts, rule_id, pattern=""):
    return [a for a in alerts if a.rule_id == rule_id and a.pattern == pattern]


def _only(config, *rule_ids):
    """Config with only the given rules enabled."""
    return with_overrides(config, {r: {"enabled": r in rule_ids} for r in ("R001", "R002", "R003", "R004", "R005")})


# --- helper ----------------------------------------------------------------
def test_find_bursts_counts_peak_within_window():
    import pandas as pd
    times = [pd.Timestamp("2026-10-07 10:00") + pd.Timedelta(minutes=m) for m in (0, 1, 2, 3, 4, 30)]
    assert find_bursts(times, pd.Timedelta(minutes=10), 5) == [(0, 4, 5)]
    assert find_bursts(times, pd.Timedelta(minutes=10), 6) == []


# --- R001 multiple failed logons --------------------------------------------
def test_r001_detects_failures_within_window(config):
    alerts = _rule(run_detection(make_events(failures(5)), _only(config, "R001")), "R001")
    assert len(alerts) == 1
    assert alerts[0].entity == "a.user"
    assert alerts[0].event_count == 5
    assert alerts[0].severity == Severity.MEDIUM  # internal source


def test_r001_ignores_failures_below_threshold(config):
    assert run_detection(make_events(failures(4)), _only(config, "R001")) == []


def test_r001_ignores_failures_spread_beyond_window(config):
    # 6 failures, one every 4 minutes: never 5 inside any 10-minute window.
    assert run_detection(make_events(failures(6, every_minutes=4)), _only(config, "R001")) == []


def test_r001_threshold_is_configurable(config):
    events = make_events(failures(4))
    stricter = with_overrides(_only(config, "R001"), {"R001": {"failure_threshold": 3}})
    assert len(run_detection(events, stricter)) == 1
    looser = with_overrides(_only(config, "R001"), {"R001": {"failure_threshold": 8}})
    assert run_detection(events, looser) == []


def test_r001_window_is_configurable(config):
    events = make_events(failures(6, every_minutes=4))
    wider = with_overrides(_only(config, "R001"), {"R001": {"window_minutes": 20}})
    assert len(run_detection(events, wider)) == 1


def test_r001_external_source_raises_severity(config):
    alerts = run_detection(make_events(failures(5, source_ip=EXTERNAL_IP)), _only(config, "R001"))
    assert alerts[0].severity == Severity.HIGH


def test_r001_separate_accounts_are_not_combined(config):
    rows = failures(3, username="user.one") + failures(3, username="user.two")
    assert run_detection(make_events(rows), _only(config, "R001")) == []


# --- R002 success after failures --------------------------------------------
def test_r002_detects_success_after_failures(config):
    rows = failures(3) + [event(at(5), result="SUCCESS")]
    alerts = run_detection(make_events(rows), _only(config, "R002"))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "R002"
    assert alerts[0].event_count == 4
    assert alerts[0].severity == Severity.MEDIUM


def test_r002_normal_typo_does_not_alert(config):
    rows = failures(1) + [event(at(1), result="SUCCESS")]
    assert run_detection(make_events(rows), _only(config, "R002")) == []


def test_r002_ignores_failures_outside_lookback(config):
    rows = failures(3) + [event(at(45), result="SUCCESS")]  # lookback is 30 minutes
    assert run_detection(make_events(rows), _only(config, "R002")) == []


def test_r002_success_resets_failure_count(config):
    rows = failures(2) + [event(at(3), result="SUCCESS")] + failures(2, start=4) + [event(at(8), result="SUCCESS")]
    assert run_detection(make_events(rows), _only(config, "R002")) == []


def test_r002_external_success_after_many_failures_is_critical(config):
    rows = failures(10, source_ip=EXTERNAL_IP, every_minutes=0.5) + [event(at(6), source_ip=EXTERNAL_IP, result="SUCCESS")]
    alerts = run_detection(make_events(rows), _only(config, "R002"))
    assert alerts[0].severity == Severity.CRITICAL


# --- R003 high failure rate -------------------------------------------------
def test_r003_detects_high_failure_rate(config):
    rows = failures(15, every_minutes=20) + [event(at(400), result="SUCCESS")]
    alerts = run_detection(make_events(rows), _only(config, "R003"))
    entities = {a.entity_type for a in alerts}
    assert entities == {"source_ip", "user"}
    assert all(a.extra["attempts"] == 16 for a in alerts)


def test_r003_requires_minimum_attempts(config):
    # 100% failure rate, but only 5 attempts: too little data to call it a rate.
    assert run_detection(make_events(failures(5, every_minutes=30)), _only(config, "R003")) == []


def test_r003_low_failure_rate_does_not_alert(config):
    rows = failures(4, every_minutes=30) + [event(at(10 + n * 20), result="SUCCESS") for n in range(16)]
    assert run_detection(make_events(rows), _only(config, "R003")) == []


# --- R004 one IP many accounts ----------------------------------------------
def _spray(accounts, ip=EXTERNAL_IP):
    return [event(at(n), username=f"user{n}", source_ip=ip) for n in range(accounts)]


def test_r004_detects_one_ip_against_many_accounts(config):
    alerts = run_detection(make_events(_spray(5)), _only(config, "R004"))
    assert len(alerts) == 1
    assert alerts[0].entity == EXTERNAL_IP
    assert alerts[0].severity == Severity.HIGH  # external source


def test_r004_many_failures_on_one_account_is_not_spraying(config):
    assert run_detection(make_events(failures(20, source_ip=EXTERNAL_IP)), _only(config, "R004")) == []


def test_r004_success_from_same_ip_is_critical(config):
    rows = _spray(5) + [event(at(6), username="lucky.user", source_ip=EXTERNAL_IP, result="SUCCESS")]
    alerts = run_detection(make_events(rows), _only(config, "R004"))
    assert alerts[0].severity == Severity.CRITICAL
    assert any("lucky.user" in fact for fact in alerts[0].observed_facts)


# --- R005 suspicious patterns -----------------------------------------------
def test_r005_lockout_then_success(config):
    rows = [event(at(0), event_type="ACCOUNT_LOCKOUT", result="INFO"),
            event(at(20), event_type="ACCOUNT_UNLOCK", result="INFO", source_ip="10.10.1.30"),
            event(at(22), result="SUCCESS")]
    alerts = _rule(run_detection(make_events(rows), _only(config, "R005")), "R005", "lockout_then_success")
    assert len(alerts) == 1
    assert alerts[0].event_count == 3
    assert any("unlock" in fact for fact in alerts[0].observed_facts)


def _night(day, hour, minute=0):
    return datetime(2026, 10, day, hour, minute, tzinfo=timezone.utc)


def test_r005_off_hours_new_source_after_learning_period(config):
    rows = [event(_night(5, 9), result="SUCCESS"),                                  # baseline, day 1
            event(_night(8, 9), result="SUCCESS"),                                  # known source, business hours
            event(_night(8, 2), result="SUCCESS", source_ip="198.51.100.99")]       # new source at 02:00
    alerts = _rule(run_detection(make_events(rows), _only(config, "R005")), "R005", "off_hours_new_source")
    assert len(alerts) == 1
    assert alerts[0].source_ips == ["198.51.100.99"]


def test_r005_off_hours_known_source_does_not_alert(config):
    rows = [event(_night(5, 9), result="SUCCESS"), event(_night(8, 2), result="SUCCESS")]
    assert _rule(run_detection(make_events(rows), _only(config, "R005")), "R005", "off_hours_new_source") == []


def test_r005_no_alerts_during_learning_period(config):
    rows = [event(_night(5, 9), result="SUCCESS"), event(_night(5, 23), result="SUCCESS", source_ip="198.51.100.99")]
    assert _rule(run_detection(make_events(rows), _only(config, "R005")), "R005", "off_hours_new_source") == []


def test_r005_rapid_external_source_change(config):
    rows = [event(at(0), result="SUCCESS", source_ip="198.51.100.20"),
            event(at(5), result="SUCCESS", source_ip="203.0.113.20")]
    alerts = _rule(run_detection(make_events(rows), _only(config, "R005")), "R005", "rapid_source_change")
    assert len(alerts) == 1


@pytest.mark.parametrize("gap_minutes", [30, 120])
def test_r005_source_change_after_window_does_not_alert(config, gap_minutes):
    rows = [event(at(0), result="SUCCESS", source_ip="198.51.100.20"),
            event(at(gap_minutes), result="SUCCESS", source_ip="203.0.113.20")]
    assert _rule(run_detection(make_events(rows), _only(config, "R005")), "R005", "rapid_source_change") == []


# --- normal activity ---------------------------------------------------------
def test_normal_working_day_generates_no_alerts(config):
    rows = []
    for n, user in enumerate(["a.user", "b.user", "c.user"]):
        ip = f"10.10.1.{50 + n}"
        rows += [event(at(n), username=user, source_ip=ip, result="FAILURE"),     # one typo
                 event(at(n + 0.5), username=user, source_ip=ip, result="SUCCESS"),
                 event(at(120 + n), username=user, source_ip=ip, result="SUCCESS", hostname="LON-FS-01",
                       logon_type="NETWORK"),
                 event(at(480 + n), username=user, source_ip=ip, result="INFO", event_type="LOGOFF")]
    assert run_detection(make_events(rows), config) == []
