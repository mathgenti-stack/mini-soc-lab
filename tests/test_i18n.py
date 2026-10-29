"""Translations: catalog consistency, the Msg type, translated reports and the dashboard language switch."""

import json
import pickle
import re
import string
import warnings
from pathlib import Path

import pytest

from soc_lab import i18n, training
from soc_lab.i18n import LANGUAGES, Msg, catalog, t, tr
from soc_lab.reporting import build_investigation_report, evidence_to_csv, render_markdown

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"
OTHER_LANGUAGES = [lang for lang in LANGUAGES if lang != i18n.DEFAULT_LANGUAGE]


def _fields(text: str) -> list[str]:
    return sorted(field for _, field, _, _ in string.Formatter().parse(text) if field)


# ---------------------------------------------------------------------------
# Catalogs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("lang", OTHER_LANGUAGES)
def test_every_language_has_the_same_keys_and_placeholders(lang):
    english, other = catalog("en"), catalog(lang)
    assert set(other) == set(english), "missing: %s / extra: %s" % (set(english) - set(other), set(other) - set(english))
    for key, text in english.items():
        assert other[key].strip(), key
        assert _fields(other[key]) == _fields(text), key


def test_locale_files_are_valid_json():
    for lang in LANGUAGES:
        json.loads((i18n.LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def test_every_key_used_in_the_code_exists():
    sources = [APP_PATH, *(ROOT / "soc_lab").rglob("*.py")]
    pattern = re.compile(r"""\b(?:Msg|T|t)\(\s*"([a-z0-9_]+\.[A-Za-z0-9_.:\- ]+)\"""")
    used = {key for path in sources for key in pattern.findall(path.read_text(encoding="utf-8"))}
    assert len(used) > 150
    assert sorted(key for key in used if not i18n.has_key(key)) == []


def test_unknown_language_and_missing_key_fall_back_to_english():
    assert t("ui.tab.overview", "xx") == "Overview"
    with pytest.raises(KeyError):
        t("no.such.key")


# ---------------------------------------------------------------------------
# Msg
# ---------------------------------------------------------------------------
def test_msg_is_the_english_text_and_renders_other_languages():
    msg = Msg("r001.title", user="j.smith")
    assert msg == "Multiple failed logons for account j.smith" and isinstance(msg, str)
    assert msg.render("pt-BR") == "Várias falhas de login na conta j.smith"
    assert tr("plain data", "pt-BR") == "plain data"


def test_nested_and_joined_msgs_translate_every_part():
    kind = Msg("ip.external")
    joined = Msg.join([Msg("rule.severity.base"), Msg("r003.severity.external")])
    assert joined == "Base severity for this rule. Raised one level: activity involved an external address."
    assert joined.render("pt-BR") == ("Severidade base desta regra. "
                                      "Elevada um nível: a atividade envolveu um endereço externo.")
    assert Msg("common.ip_with_kind", ip="203.0.113.7", kind=kind).render("pt-BR") == "203.0.113.7 (externo)"
    assert Msg("r003.severity.medium", rate=0.8).render("pt-BR") == "Elevada para Média: a taxa de falhas chegou a 80%."


def test_msg_survives_pickling_as_used_by_the_streamlit_cache():
    original = Msg.join([Msg("r002.title", count=6, user="victim"), Msg("conclusion.basis")])
    copy = pickle.loads(pickle.dumps(original))
    assert copy == original and copy.render("pt-BR") == original.render("pt-BR")


# ---------------------------------------------------------------------------
# Alerts and reports in every language
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_every_alert_and_report_renders(generated_analysis, config, lang):
    events, _, alerts, _ = generated_analysis
    for alert in alerts:
        texts = [alert.title, alert.rule_name, alert.trigger_reason, alert.severity_reason,
                 *alert.observed_facts, *alert.hypotheses]
        assert all(isinstance(text, Msg) and tr(text, lang) for text in texts)
        report = build_investigation_report(alert, events, config, all_alerts=alerts)
        assert all(isinstance(text, Msg) for text in [report.conclusion, *report.context_findings,
                                                      *report.limitations, *report.benign_indicators])
        assert render_markdown(report, lang)


def test_portuguese_report_is_translated_but_keeps_the_data(generated_analysis, config):
    events, _, alerts, _ = generated_analysis
    alert = next(a for a in alerts if a.rule_id == "R002")
    report = build_investigation_report(alert, events, config, all_alerts=alerts, status="Escalated")
    english, portuguese = render_markdown(report), render_markdown(report, "pt-BR")
    assert "## 10. Evidence-based conclusion" in english and "| Incident status | Escalated |" in english
    assert "## 10. Conclusão baseada em evidências" in portuguese and "| Status do incidente | Escalado |" in portuguese
    assert "Evidence-based conclusion" not in portuguese
    for value in (report.incident_id, alert.alert_id, alert.rule_id, *alert.evidence_event_ids[:3], *alert.source_ips):
        assert value in portuguese
    assert render_markdown(report, "en") == english
    assert evidence_to_csv(report).splitlines()[0].startswith("incident_id,timestamp,event_id")


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_training_texts_exist_for_every_language(lang):
    for stage in training.STAGES:
        assert stage.label(lang)
    for guide in training.SCENARIO_GUIDES.values():
        assert guide.verdict(lang) and guide.explanation(lang)
    assert all(name and meaning for name, meaning in training.status_explanations(lang))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    return testing.AppTest.from_file(str(APP_PATH), default_timeout=120)


def _switch(app, lang):
    app.segmented_control(key="lang").set_value(lang).run()
    assert not app.exception


def _visible_texts(app) -> set[str]:
    texts = set()
    for kind in ("markdown", "caption", "info", "warning", "success", "subheader", "title"):
        texts |= {element.value for element in getattr(app, kind)}
    for kind in ("metric", "selectbox", "multiselect", "text_area", "text_input", "toggle", "radio", "date_input",
                 "number_input", "checkbox", "slider"):
        texts |= {element.label for element in getattr(app, kind)}
    texts |= {tab.label for tab in app.tabs}
    return texts


def test_dashboard_defaults_to_english(app):
    app.run()
    assert not app.exception
    assert app.segmented_control(key="lang").value == "en"
    assert [tab.label for tab in app.tabs] == ["Overview", "Alerts", "Event Explorer", "Investigation",
                                              "Data Quality", "About"]


def test_portuguese_dashboard_has_no_english_interface_text_left(app):
    app.run()
    next(s for s in app.selectbox if s.label.startswith("Select an alert")).set_value("ALR-0010").run()
    verdict = next(ta for ta in app.text_area if ta.label.startswith("What is your verdict"))
    verdict.set_value("Ataque provável.").run()
    next(tg for tg in app.toggle if tg.label.startswith("Show answer")).set_value(True).run()
    _switch(app, "pt-BR")

    english, portuguese = catalog("en"), catalog("pt-BR")
    english_only = {text for key, text in english.items() if key.startswith("ui.") and text != portuguese[key]}
    leftovers = {text for text in _visible_texts(app) if text in english_only}
    assert leftovers == set()
    assert {m.label for m in app.metric} >= {"Eventos analisados", "Alertas gerados", "Severidade"}
    assert any("Conclusão baseada em evidências" in m.value for m in app.markdown)
    assert any("Escalado" in w.value for w in app.warning)  # "Your status: New - expected: Escalated"


def test_switching_language_keeps_answers_filters_and_progress(app, tmp_path):
    app.run()
    app.multiselect(key="filter_severity").set_value(["Critical", "High"]).run()
    next(s for s in app.selectbox if s.label.startswith("Select an alert")).set_value("ALR-0010").run()
    verdict_key = "ans_sample_auth_logs_csv_ALR-0010_verdict"
    app.text_area(key=verdict_key).set_value("Password spray com sucesso em l.taylor.").run()
    app.text_area(key="ans_sample_auth_logs_csv_ALR-0010_rule").set_value("R004").run()
    app.selectbox(key="status_sample_auth_logs_csv_ALR-0010").set_value("Escalated").run()
    app.toggle(key="reveal_sample_auth_logs_csv_ALR-0010").set_value(True).run()
    app.session_state["main_tabs_en"] = "Investigation"
    app.run()
    assert app.session_state["active_tab"] == "investigation"

    for lang in ("pt-BR", "en", "pt-BR"):
        _switch(app, lang)
        assert app.text_area(key=verdict_key).value == "Password spray com sucesso em l.taylor."
        assert app.text_area(key="ans_sample_auth_logs_csv_ALR-0010_rule").value == "R004"
        assert app.selectbox(key="status_sample_auth_logs_csv_ALR-0010").value == "Escalated"
        assert app.toggle(key="reveal_sample_auth_logs_csv_ALR-0010").value is True
        assert app.selectbox(key="investigate_alert_sample_auth_logs_csv").value == "ALR-0010"
        assert app.multiselect(key="filter_severity").value == ["Critical", "High"]
        assert app.session_state["active_tab"] == "investigation"
        assert app.session_state[f"main_tabs_{lang}"] == {"en": "Investigation", "pt-BR": "Investigação"}[lang]

    status_text = {"en": "Your status: Escalated ✅", "pt-BR": "Seu status: Escalado ✅"}
    assert any(s.value == status_text["pt-BR"] for s in app.success)
    saved = training.load_progress(training.answers_path(tmp_path, "sample_auth_logs.csv", "ALR-0010"))
    assert saved == {"answers": {"rule": "R004", "verdict": "Password spray com sucesso em l.taylor."},
                     "status": "Escalated", "revealed": True}


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_every_data_source_and_mode_renders_in_every_language(app, lang):
    app.run()
    _switch(app, lang)
    app.toggle(key="training_mode").set_value(False).run()
    assert not app.exception and app.dataframe  # free investigation mode
    app.radio(key="data_source").set_value("generate").run()
    assert not app.exception and app.metric
    app.radio(key="data_source").set_value("upload").run()
    assert not app.exception
    assert app.info[0].value == t("ui.source.upload_prompt", lang)


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_dataframes_sent_to_the_browser_contain_only_plain_strings(app, monkeypatch, lang):
    """The in-browser build serialises tables with fastparquet, which rejects str subclasses such as Msg."""
    import pandas as pd
    from streamlit import dataframe_util

    offenders = []

    def strict(original):
        def check(data, *args, **kwargs):
            if isinstance(data, pd.DataFrame):
                for column in data.columns:
                    offenders.extend(f"{column}: {type(v).__name__}" for v in data[column]
                                     if isinstance(v, str) and type(v) is not str)
            return original(data, *args, **kwargs)
        return check

    for name in ("convert_pandas_df_to_arrow_bytes", "convert_anything_to_arrow_bytes"):
        monkeypatch.setattr(dataframe_util, name, strict(getattr(dataframe_util, name)))
    # pandas 3 would silently turn str subclasses into its own string dtype; the browser build keeps
    # object columns, so string inference is switched off to reproduce what fastparquet receives there.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if "infer_string" not in dir(pd.options.future):  # removed in pandas 4
            pytest.skip("this pandas version cannot keep object string columns")
        with pd.option_context("future.infer_string", False):
            app.run()
            _switch(app, lang)
            alert_selector = next(s for s in app.selectbox if s.label.startswith(t("ui.inv.select_alert", lang)))
            alert_selector.set_value("ALR-0010").run()
            app.toggle(key="training_mode").set_value(False).run()
    assert not app.exception
    assert sorted(set(offenders)) == []
