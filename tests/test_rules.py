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
    return with_overrides(config, {r: {"enabled": r in rule_ids}
                                   for r in ("R001", "R002", "R003", "R004", "R005", "R006")})


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


# --- R006: logon unusual for the account ------------------------------------
OFFICE = {"source_ip": "10.10.1.50", "hostname": "LON-WS-001", "logon_type": "INTERACTIVE"}


def _routine(days=range(5, 13), user="a.user"):
    """Two logons per working day for a week and a bit: 08:30 at the desk, 14:00 to the file server."""
    rows = []
    for day in days:
        rows.append(event(_night(day, 8, 30), username=user, result="SUCCESS", **OFFICE))
        rows.append(event(_night(day, 14), username=user, result="SUCCESS", source_ip=OFFICE["source_ip"],
                          hostname="LON-FS-01", logon_type="NETWORK"))
    return rows


def _r006(config, rows, **params):
    cfg = _only(config, "R006")
    if params:
        cfg = with_overrides(cfg, {"R006": params})
    return _rule(run_detection(make_events(rows), cfg), "R006")


def test_r006_routine_alone_does_not_alert(config):
    assert _r006(config, _routine()) == []


def test_r006_three_differences_from_the_usual_pattern(config):
    """23:10 Remote Desktop to the domain controller, from the usual internal address."""
    unusual = event(_night(14, 23, 10), result="SUCCESS", source_ip="10.10.1.50", hostname="LON-DC-01",
                    logon_type="REMOTE_INTERACTIVE")
    alerts = _r006(config, _routine() + [unusual])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.extra["deviations"] == ["hour", "host", "logon_type"]
    assert alert.severity == Severity.MEDIUM  # three differences, internal source
    assert alert.extra["baseline_logons"] == 16
    facts = " ".join(alert.observed_facts)
    assert "08:00-08:59, 14:00-14:59" in facts           # what is usual is shown next to what differed
    assert "LON-DC-01" in facts and "LON-FS-01" in facts
    assert "source network" in facts and "daily volume" in facts  # the checks that matched are listed too


def test_r006_two_differences_external_is_raised_one_level(config):
    """New external network and new logon type at a usual hour: Low, raised to Medium for the external source."""
    unusual = event(_night(14, 9), result="SUCCESS", source_ip=EXTERNAL_IP, hostname="LON-WS-001", logon_type="VPN")
    alerts = _r006(config, _routine() + [unusual])
    assert [a.extra["deviations"] for a in alerts] == [["network", "logon_type"]]
    assert alerts[0].severity == Severity.MEDIUM
    assert "external" in alerts[0].severity_reason


def test_r006_one_difference_is_not_enough(config):
    late = event(_night(14, 22), result="SUCCESS", **OFFICE)  # only the hour is new
    assert _r006(config, _routine() + [late]) == []
    assert len(_r006(config, _routine() + [late], min_deviations=1)) == 1


def test_r006_same_network_new_address_is_not_a_difference(config):
    moved = event(_night(14, 22), result="SUCCESS", source_ip="10.10.1.99", hostname="LON-WS-001",
                  logon_type="INTERACTIVE")  # new address in the usual /24, at a new hour: one difference
    assert _r006(config, _routine() + [moved]) == []


def test_r006_hour_tolerance(config):
    nearby = event(_night(14, 15, 30), result="SUCCESS", source_ip="10.10.1.50", hostname="LON-DC-01",
                   logon_type="NETWORK")  # 15:30 is within one hour of the usual 14:00 logons
    assert _r006(config, _routine() + [nearby]) == []
    assert _r006(config, _routine() + [nearby], hour_tolerance=0)[0].extra["deviations"] == ["hour", "host"]


def test_r006_needs_enough_history(config):
    unusual = event(_night(8, 23), result="SUCCESS", source_ip=EXTERNAL_IP, hostname="LON-DC-01", logon_type="VPN")
    assert _r006(config, _routine(days=range(5, 8)) + [unusual]) == []  # 3 days, 6 logons: still learning
    assert len(_r006(config, _routine(days=range(5, 8)) + [unusual], baseline_learning_days=1,
                     min_baseline_logons=6)) == 1


def test_r006_only_uses_earlier_logons(config):
    """The profile never looks ahead: logons after the unusual one cannot make it look normal."""
    unusual = event(_night(14, 23, 10), result="SUCCESS", source_ip="10.10.1.50", hostname="LON-DC-01",
                    logon_type="REMOTE_INTERACTIVE")
    later_same = [event(_night(day, 23, 10), result="SUCCESS", source_ip="10.10.1.50", hostname="LON-DC-01",
                        logon_type="REMOTE_INTERACTIVE") for day in (15, 16)]
    alerts = _r006(config, _routine() + [unusual] + later_same)
    assert [a.first_seen.day for a in alerts] == [14]  # once it is in the baseline it is no longer new


def test_r006_unusual_daily_volume(config):
    """A usual two logons a day gives a limit of 2 + 3 x 1 = 5; only the logon that crosses it counts."""
    busy = [event(_night(14, 9, n), result="SUCCESS", source_ip="10.10.1.50", hostname="LON-FS-01",
                  logon_type="NETWORK") for n in range(5)]
    sixth = event(_night(14, 9, 30), result="SUCCESS", source_ip="10.10.1.50", hostname="LON-APP-01",
                  logon_type="NETWORK")  # crosses the limit, and to a new host
    seventh = event(_night(14, 9, 40), result="SUCCESS", source_ip="10.10.1.50", hostname="LON-DC-01",
                    logon_type="NETWORK")  # new host, but the limit was already crossed: one difference only
    alerts = _r006(config, _routine() + busy + [sixth, seventh])
    assert [a.extra["deviations"] for a in alerts] == [["host", "volume"]]
    assert "averaged 2.0 per day (limit 5.0)" in " ".join(alerts[0].observed_facts)


def test_r006_ignores_service_accounts(config):
    rows = _routine(user="svc_backup") + [event(_night(14, 23), username="svc_backup", result="SUCCESS",
                                                source_ip=EXTERNAL_IP, hostname="LON-DC-01", logon_type="VPN")]
    assert _r006(config, rows) == []


def test_r006_failures_are_not_part_of_the_profile(config):
    rows = _routine() + [event(_night(14, 23), result="FAILURE", source_ip=EXTERNAL_IP, hostname="LON-DC-01",
                               logon_type="VPN")]
    assert _r006(config, rows) == []


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
