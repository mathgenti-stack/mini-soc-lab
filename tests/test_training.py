from pathlib import Path

import pytest

from soc_lab import training
from soc_lab.models import INCIDENT_STATUSES
from soc_lab.reporting import build_investigation_report

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"
GROUND_TRUTH = ROOT / "data" / "sample_auth_logs_ground_truth.csv"


def test_questions_are_complete_and_unique():
    stage_ids = {stage.id for stage in training.STAGES}
    assert len(training.QUESTION_IDS) == len(set(training.QUESTION_IDS))
    for question in training.QUESTIONS:
        assert question.stage in stage_ids
        assert question.pt and question.en and question.hint_pt and question.hint_en
    assert all(training.questions_for_stage(stage) for stage in stage_ids)


def test_time_hint_uses_configured_business_hours():
    question = next(q for q in training.QUESTIONS if q.id == "time")
    assert "07:00" in question.hint("pt", start=7, end=19) and "19:00" in question.hint("en", start=7, end=19)


def test_scenario_guides_use_valid_statuses():
    for guide in training.SCENARIO_GUIDES.values():
        assert guide.expected_statuses and set(guide.expected_statuses) <= set(INCIDENT_STATUSES)


def test_every_generated_alert_maps_to_a_known_scenario(generated_analysis):
    _, _, alerts, truth = generated_analysis
    for alert in alerts:
        assert training.scenario_for_alert(alert, truth) in training.SCENARIO_GUIDES


def test_sample_dataset_gabarito_matches_readme():
    from soc_lab.config import load_config
    from soc_lab.detection import run_detection
    from soc_lab.log_loader import load_events

    result = load_events((ROOT / "data" / "sample_auth_logs.csv").read_bytes(), "sample")
    alerts = {a.alert_id: a for a in run_detection(result.events, load_config())}
    truth = training.load_ground_truth(GROUND_TRUTH)
    assert training.scenario_for_alert(alerts["ALR-0010"], truth) == "simulated_password_spray"
    assert training.scenario_for_alert(alerts["ALR-0001"], truth) == "simulated_brute_force"


def test_scenario_for_alert_handles_unknown_and_normal(generated_analysis):
    _, _, alerts, _ = generated_analysis
    alert = alerts[0]
    assert training.scenario_for_alert(alert, {}) is None
    assert training.scenario_for_alert(alert, {eid: "normal" for eid in alert.evidence_event_ids}) == "normal"


@pytest.mark.parametrize("lang", training.LANGUAGES)
def test_reference_answers_exist_for_every_question(generated_analysis, config, lang):
    events, _, alerts, _ = generated_analysis
    for alert in alerts:
        report = build_investigation_report(alert, events, config, all_alerts=alerts)
        for question_id in training.QUESTION_IDS:
            points = training.reference_answers(question_id, alert, report, config, lang)
            assert points and all(isinstance(p, str) and p for p in points)


def test_reference_answers_reject_unknown_question(generated_analysis, config):
    events, _, alerts, _ = generated_analysis
    report = build_investigation_report(alerts[0], events, config)
    with pytest.raises(KeyError):
        training.reference_answers("nope", alerts[0], report, config)


def test_progress_round_trip(tmp_path):
    path = training.answers_path(tmp_path, "sample_auth_logs.csv", "ALR-0001")
    assert training.load_progress(path) == {"answers": {}, "status": None, "revealed": False}
    training.save_progress(path, {"verdict": "Ataque", "summary": "  ", "bogus": "x"}, "Escalated", True)
    loaded = training.load_progress(path)
    assert loaded == {"answers": {"verdict": "Ataque"}, "status": "Escalated", "revealed": True}


def test_load_progress_tolerates_corrupt_file(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    assert training.load_progress(path)["answers"] == {}


def test_answers_to_markdown_groups_by_stage():
    text = training.answers_to_markdown({"rule": "R001", "verdict": "Ataque provável"}, "pt")
    assert "### 1. Entender o alerta" in text and "### 4. Decidir" in text
    assert "Ataque provável" in text and "2. Coletar os fatos" not in text
    assert training.answers_to_markdown({}, "en") == ""


def test_dataset_token_is_safe():
    assert training.dataset_token("generated (seed 7, 14 days)") == "generated_seed_7_14_days"


def test_dashboard_training_flow(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    app = testing.AppTest.from_file(str(APP_PATH), default_timeout=120).run()
    assert not app.exception
    next(s for s in app.selectbox if s.label.startswith("Select an alert")).set_value("ALR-0010").run()

    # The tool's conclusion is hidden until the analyst reveals it.
    assert not any("Evidence-based conclusion" in m.value for m in app.markdown)
    reveal = next(t for t in app.toggle if t.label.startswith("Mostrar resposta"))
    assert reveal.disabled

    verdict = next(t for t in app.text_area if t.label.startswith("Qual é o seu veredito"))
    verdict.set_value("Ataque provável: password spray com sucesso em l.taylor.").run()
    next(s for s in app.selectbox if s.label.startswith("Status do incidente")).set_value("Escalated").run()
    next(t for t in app.toggle if t.label.startswith("Mostrar resposta")).set_value(True).run()
    assert not app.exception
    assert any("Evidence-based conclusion" in m.value for m in app.markdown)
    assert any("Escalated ✅" in s.value for s in app.success)

    saved = training.load_progress(training.answers_path(tmp_path, "sample_auth_logs.csv", "ALR-0010"))
    assert saved["revealed"] and saved["status"] == "Escalated" and "l.taylor" in saved["answers"]["verdict"]
