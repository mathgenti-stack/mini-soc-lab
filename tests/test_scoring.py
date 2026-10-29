"""Training score: keyword checklist built from each alert's own data."""

from pathlib import Path

import pytest

from soc_lab import training
from soc_lab.config import load_config
from soc_lab.detection import run_detection
from soc_lab.i18n import LANGUAGES, has_key, t, tr
from soc_lab.log_loader import load_events
from soc_lab.reporting import build_investigation_report
from soc_lab.scoring import expected_verdict, normalise, score_answers

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"
SAMPLE = ROOT / "data" / "sample_auth_logs.csv"

SPRAY_EN = {
    "rule": "R004 fired: one address failing against many accounts, a password spray.",
    "scope": "Source 203.0.113.88; accounts a.patel, admin, administrator and others.",
    "counts": "15 failed logons against 15 accounts in about 15 minutes.",
    "success": "Yes - l.taylor logged in successfully from the same address.",
    "source": "External, from the internet, never seen before.",
    "time": "Monday morning, within business hours.",
    "account_events": "No lockout, unlock or password change.",
    "account_type": "User accounts of people, plus default names like admin.",
    "benign": "An authorised scan or a misconfigured tool, but none is known.",
    "missing": "Confirm with l.taylor and the service desk whether the logon was theirs.",
    "verdict": "Likely attack: a password spray that compromised l.taylor.",
    "severity": "Critical, because an account was accessed.",
    "mitre": "T1110.003 Password Spraying, then T1078 Valid Accounts.",
    "action": "Escalate to Tier 2 and propose to reset the password of l.taylor and revoke sessions.",
    "summary": "An external address tried 15 accounts. The account l.taylor logged in from 203.0.113.88. "
               "I recommend escalation and a password reset.",
}
SPRAY_PT = {
    "rule": "A regra R004 disparou: um endereço errando senha em muitas contas.",
    "scope": "Origem 203.0.113.88; contas a.patel, admin, administrator e outras.",
    "counts": "Foram 15 falhas contra 15 contas em cerca de 15 minutos.",
    "success": "Sim, a conta l.taylor entrou com sucesso pelo mesmo endereço.",
    "source": "Externo, da internet.",
    "time": "Segunda de manhã, dentro do horário comercial.",
    "account_events": "Não houve bloqueio nem troca de senha.",
    "account_type": "Contas de usuários, pessoas.",
    "benign": "Poderia ser uma varredura autorizada.",
    "missing": "Confirmar com o usuário l.taylor e com o service desk.",
    "verdict": "Provável ataque: password spray que comprometeu a conta l.taylor.",
    "severity": "Crítica.",
    "mitre": "T1110.003",
    "action": "Escalar para o nível 2 e propor redefinir a senha da l.taylor.",
    "summary": "Um endereço externo tentou 15 contas. A conta l.taylor entrou a partir de 203.0.113.88. "
               "Recomendo escalar o caso.",
}


@pytest.fixture(scope="module")
def sample():
    events = load_events(SAMPLE).events
    config = load_config()
    alerts = run_detection(events, config)
    truth = training.load_ground_truth(ROOT / "data" / "sample_auth_logs_ground_truth.csv")

    def get(alert_id):
        alert = next(a for a in alerts if a.alert_id == alert_id)
        report = build_investigation_report(alert, events, config, all_alerts=alerts)
        return alert, report, training.scenario_for_alert(alert, truth)
    return get, config


def score(sample, alert_id, answers, status=None, use_truth=True):
    get, config = sample
    alert, report, scenario = get(alert_id)
    return score_answers(answers, alert, report, config, scenario if use_truth else None, status)


def labels(card, passed):
    return [c.label.key.removeprefix("score.check.") for c in card.checks if c.passed is passed]


def test_normalise_removes_case_and_accents():
    assert normalise("Não HOUVE Bloqueio às 09h") == "nao houve bloqueio as 09h"


@pytest.mark.parametrize("answers", [SPRAY_EN, SPRAY_PT], ids=["en", "pt"])
def test_complete_answers_get_every_point(sample, answers):
    card = score(sample, "ALR-0010", answers, status="Escalated")
    assert labels(card, False) == []
    assert (card.earned, card.total, card.percent) == (20, 20, 100)


def test_empty_answers_get_nothing(sample):
    card = score(sample, "ALR-0010", {}, status="New")
    assert card.earned == 0 and card.total == 20 and card.percent == 0


def test_missing_facts_are_reported(sample):
    answers = dict(SPRAY_EN, counts="Many failed logons.", success="Not sure.", mitre="Brute force.")
    failed = labels(score(sample, "ALR-0010", answers, status="Closed - False Positive"), False)
    assert failed == ["failure_count", "account_count", "success_yes", "technique", "status"]


def test_benign_scenario_expects_a_benign_verdict_and_closing(sample):
    _get, _ = sample
    answers = {"verdict": "Benign: e.wilson forgot the new password; the service desk unlocked the account.",
               "action": "Close it as benign after checking the ticket.",
               "account_events": "Locked out, then unlocked; the password was changed days before."}
    card = score(sample, "ALR-0008", answers, status="Closed - Benign True Positive")
    passed = labels(card, True)
    assert {"verdict_benign", "action_close", "status", "lockout", "unlock", "password_change"} <= set(passed)
    assert "containment" not in labels(card, False)  # containment is only expected for attacks
    attack = score(sample, "ALR-0008", dict(answers, verdict="A brute force attack."))
    assert "verdict_benign" in labels(attack, False)


def test_ambiguous_scenario_expects_verification(sample):
    answers = {"verdict": "Uncertain: two addresses in 7 minutes, I need to confirm with s.ahmed.",
               "action": "Verify with the user before closing."}
    passed = labels(score(sample, "ALR-0014", answers, status="In Progress"), True)
    assert {"verdict_uncertain", "action_verify", "status"} <= set(passed)


def test_service_account_is_expected_to_be_recognised(sample):
    card = score(sample, "ALR-0016", {"account_type": "svc_backup is a service account used by the backup job."})
    assert "service" in labels(card, True)


def test_without_ground_truth_the_tool_conclusion_sets_the_verdict(sample):
    get, _config = sample
    _alert, report, _scenario = get("ALR-0010")
    assert expected_verdict(None, report) == "attack"
    assert expected_verdict("benign_authorised_scan", report) == "benign"
    card = score(sample, "ALR-0010", SPRAY_EN, use_truth=False)
    assert "status" not in labels(card, True) + labels(card, False)  # no expected status without ground truth
    assert card.total == 19


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_every_check_has_a_translation(sample, lang):
    for alert_id in ("ALR-0001", "ALR-0004", "ALR-0008", "ALR-0010", "ALR-0014", "ALR-0016"):
        for check in score(sample, alert_id, SPRAY_EN, status="New").checks:
            assert has_key(check.label.key) and tr(check.label, lang)


@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    return testing.AppTest.from_file(str(APP_PATH), default_timeout=120)


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_dashboard_shows_the_score_after_reveal(app, lang):
    app.run()
    app.segmented_control(key="lang").set_value(lang).run()
    next(s for s in app.selectbox if s.label.startswith(t("ui.inv.select_alert", lang))).set_value("ALR-0010").run()
    prefix = "ans_sample_auth_logs_csv_ALR-0010_"
    for question_id in ("verdict", "counts", "mitre"):
        app.text_area(key=prefix + question_id).set_value(SPRAY_EN[question_id]).run()
    title = t("ui.score.title", lang)
    assert not any(m.value.startswith(f"### {title}") for m in app.markdown)  # hidden before reveal

    app.toggle(key="reveal_sample_auth_logs_csv_ALR-0010").set_value(True).run()
    assert not app.exception
    heading = next(m.value for m in app.markdown if m.value.startswith(f"### {title}:"))
    assert heading.endswith("%")
    checklist = "\n".join(m.value for m in app.markdown if t("ui.score.checklist", lang) in m.value)
    assert "✅ " + t("score.check.failure_count", lang, count=15) in checklist
    assert "❌ " + t("score.check.success_yes", lang, users="l.taylor") in checklist
    assert any(c.value.startswith(t("ui.score.average", lang, count=1, percent=0)[:20]) for c in app.caption)
