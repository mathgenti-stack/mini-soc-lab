import ipaddress

import pandas as pd
import pytest

from soc_lab.config import load_config
from soc_lab.detection import run_detection
from soc_lab.log_generator import SCENARIO_DESCRIPTIONS, GeneratorSettings, generate_events, write_dataset
from soc_lab.log_loader import load_events, validate_events
from soc_lab.models import ALL_COLUMNS

ALLOWED_NETWORKS = [ipaddress.ip_network(n) for n in
                    ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

# Which rule(s) each planted scenario is expected to trigger with the default configuration.
EXPECTED_DETECTIONS = {
    "simulated_brute_force": {"R001", "R003"},
    "simulated_password_spray": {"R003", "R004"},
    "simulated_credential_compromise": {"R001", "R002", "R005"},
    "ambiguous_rapid_source_change": {"R005"},
    "benign_forgotten_password": {"R001", "R005"},
    "benign_authorised_scan": {"R003", "R004"},
    "benign_on_call_engineer": {"R005"},
    "benign_service_account_expired": {"R003"},
}


def test_generation_is_reproducible_with_seed():
    first = generate_events(GeneratorSettings(seed=123))
    second = generate_events(GeneratorSettings(seed=123))
    pd.testing.assert_frame_equal(first, second)
    assert not first.equals(generate_events(GeneratorSettings(seed=124)))


def test_schema_and_unique_ids(generated):
    assert list(generated.columns) == list(ALL_COLUMNS) + ["scenario"]
    clean = generated[generated["scenario"] != "data_quality_test"]
    assert clean["event_id"].is_unique
    assert set(generated["scenario"]) <= set(SCENARIO_DESCRIPTIONS)


def test_only_private_or_documentation_ip_ranges_are_used(generated):
    for ip in generated["source_ip"].unique():
        address = ipaddress.ip_address(ip)
        assert any(address in network for network in ALLOWED_NETWORKS), ip


def test_quality_issues_are_injected_and_caught(generated_analysis):
    _events, quality, _alerts, _truth = generated_analysis
    assert quality.exact_duplicates_removed == 1
    assert quality.rows_rejected == 3


def test_quality_issues_can_be_disabled():
    events = generate_events(GeneratorSettings(inject_quality_issues=False))
    _clean, quality = validate_events(events.drop(columns="scenario").astype(str))
    assert quality.rows_rejected == 0 and quality.exact_duplicates_removed == 0


@pytest.mark.parametrize("scenario, expected_rules", EXPECTED_DETECTIONS.items())
def test_each_planted_scenario_is_detected(generated_analysis, scenario, expected_rules):
    _events, _quality, alerts, truth = generated_analysis
    triggered = {a.rule_id for a in alerts if any(truth[e] == scenario for e in a.evidence_event_ids)}
    assert expected_rules <= triggered


def test_normal_activity_alone_generates_no_alerts(generated):
    normal = generated[generated["scenario"] == "normal"].drop(columns="scenario").astype(str)
    events, _ = validate_events(normal)
    assert run_detection(events, load_config()) == []


def test_write_dataset_keeps_labels_out_of_logs(tmp_path, generated):
    log_path, truth_path = write_dataset(generated, tmp_path / "logs.csv")
    assert "scenario" not in pd.read_csv(log_path).columns
    assert list(pd.read_csv(truth_path).columns) == ["event_id", "scenario"]
    assert load_events(log_path).quality.rows_accepted > 900


def test_invalid_days_rejected():
    with pytest.raises(ValueError):
        generate_events(GeneratorSettings(days=0))


def test_short_dataset_skips_later_scenarios():
    events = generate_events(GeneratorSettings(days=3))
    assert "simulated_password_spray" not in set(events["scenario"])
    assert "simulated_brute_force" in set(events["scenario"])
