import pytest

from soc_lab.config import load_config
from soc_lab.detection import run_detection
from soc_lab.log_generator import generate_events
from soc_lab.log_loader import validate_events


@pytest.fixture(autouse=True)
def isolated_triage_db(tmp_path, monkeypatch):
    """Every test gets its own SQLite file, so tests never write into the project folder."""
    monkeypatch.setenv("SOC_LAB_DB", str(tmp_path / "triage.sqlite3"))


@pytest.fixture
def config():
    return load_config()


@pytest.fixture(scope="session")
def generated():
    """Default synthetic dataset (with ground-truth labels), generated once per test session."""
    return generate_events()


@pytest.fixture(scope="session")
def generated_analysis(generated):
    events, quality = validate_events(generated.drop(columns="scenario").astype(str))
    alerts = run_detection(events, load_config())
    first_rows = generated.drop_duplicates("event_id", keep="first")  # the injected duplicate reuses an ID
    truth = dict(zip(first_rows["event_id"], first_rows["scenario"]))
    return events, quality, alerts, truth
