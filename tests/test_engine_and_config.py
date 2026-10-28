import json

import pytest

from factories import at, event, failures, make_events
from soc_lab.config import ConfigError, load_config, validate_config, with_overrides
from soc_lab.detection import run_detection
from soc_lab.log_loader import empty_events_frame


# --- engine --------------------------------------------------------------------
def test_empty_events_produce_no_alerts(config):
    assert run_detection(empty_events_frame(), config) == []


def test_disabled_rule_does_not_run(config):
    events = make_events(failures(6))
    assert any(a.rule_id == "R001" for a in run_detection(events, config))
    disabled = with_overrides(config, {"R001": {"enabled": False}})
    assert not any(a.rule_id == "R001" for a in run_detection(events, disabled))


def test_alert_ids_are_sequential_and_time_ordered(config):
    rows = failures(5, username="later", start=60) + failures(5, username="earlier", start=0)
    alerts = run_detection(make_events(rows), config)
    assert [a.alert_id for a in alerts] == [f"ALR-{n:04d}" for n in range(1, len(alerts) + 1)]
    assert [a.first_seen for a in alerts] == sorted(a.first_seen for a in alerts)
    assert alerts[0].entity == "earlier"


def test_detection_is_deterministic(config):
    events = make_events(failures(6) + [event(at(7), result="SUCCESS")])
    first = [(a.alert_id, a.rule_id, a.evidence_event_ids) for a in run_detection(events, config)]
    second = [(a.alert_id, a.rule_id, a.evidence_event_ids) for a in run_detection(events, config)]
    assert first == second


def test_every_alert_references_existing_events(generated_analysis):
    events, _quality, alerts, _truth = generated_analysis
    known_ids = set(events["event_id"])
    for alert in alerts:
        assert alert.evidence_event_ids
        assert set(alert.evidence_event_ids) <= known_ids
        assert alert.observed_facts and alert.hypotheses and alert.trigger_reason


# --- config --------------------------------------------------------------------
def test_default_config_is_valid():
    config = load_config()
    assert set(config["rules"]) == {"R001", "R002", "R003", "R004", "R005"}


def test_missing_config_file_raises(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.json")


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(path)


@pytest.mark.parametrize("rule_id, param, value", [
    ("R001", "failure_threshold", 0),
    ("R001", "window_minutes", -5),
    ("R002", "min_failures", "three"),
    ("R003", "failure_rate_threshold", 1.5),
    ("R003", "entity_fields", ["hostname"]),
    ("R005", "baseline_learning_days", -1),
])
def test_invalid_parameter_values_are_rejected(config, rule_id, param, value):
    with pytest.raises(ConfigError):
        with_overrides(config, {rule_id: {param: value}})


def test_missing_rule_parameter_is_rejected(config):
    del config["rules"]["R004"]["min_distinct_accounts"]
    with pytest.raises(ConfigError, match="min_distinct_accounts"):
        validate_config(config)


def test_invalid_business_hours_rejected(config):
    config["environment"]["business_hours"] = {"start_hour": 19, "end_hour": 7}
    with pytest.raises(ConfigError, match="business_hours"):
        validate_config(config)


def test_with_overrides_does_not_modify_original(config):
    original = json.dumps(config, sort_keys=True)
    updated = with_overrides(config, {"R001": {"failure_threshold": 9}})
    assert updated["rules"]["R001"]["failure_threshold"] == 9
    assert json.dumps(config, sort_keys=True) == original
