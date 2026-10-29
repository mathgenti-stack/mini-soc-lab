"""Rule export: Sigma, Splunk SPL and Sentinel KQL built from the detection configuration."""

import io
import re
import uuid
import zipfile
from pathlib import Path

import pytest

from soc_lab.cli import main
from soc_lab.config import with_overrides
from soc_lab.detection.export import DETECTIONS, FORMATS, export_rules, export_zip, to_yaml
from soc_lab.i18n import LANGUAGES, t

APP_PATH = Path(__file__).resolve().parent.parent / "streamlit_app.py"
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}


def _by_path(exported):
    return {rule.path: rule for rule in exported}


def _code(rule) -> str:
    """The query without its comments."""
    if rule.fmt == "spl":
        return re.sub(r"```.*?```", "", rule.text, flags=re.S)
    prefix = "#" if rule.fmt == "sigma" else "//"
    return "\n".join(line.split(prefix, 1)[0] if rule.fmt == "kql" else line
                     for line in rule.text.splitlines() if not line.lstrip().startswith(prefix))


def test_every_detection_is_exported_in_every_format(config):
    exported = export_rules(config)
    assert len(exported) == len(DETECTIONS) * len(FORMATS) == 21
    assert len(_by_path(exported)) == 21
    assert all(rule.text.strip() for rule in exported)
    unsupported = sorted(rule.path for rule in exported if not rule.supported)
    assert unsupported == ["sigma/R003_high_failure_rate.yml", "sigma/R005_off_hours_new_source.yml"]


def test_thresholds_come_from_the_configuration(config):
    tuned = with_overrides(config, {"R001": {"failure_threshold": 8, "window_minutes": 20},
                                    "R004": {"min_distinct_accounts": 7}})
    files = _by_path(export_rules(tuned))
    assert "gte: 8" in files["sigma/R001_multiple_failed_logons.yml"].text
    assert 'timespan: "20m"' in files["sigma/R001_multiple_failed_logons.yml"].text
    assert "| where peak_failures >= 8" in files["spl/R001_multiple_failed_logons.spl"].text
    assert "time_window=20m" in files["spl/R001_multiple_failed_logons.spl"].text
    assert "_time - previous_time > 1200" in files["spl/R001_multiple_failed_logons.spl"].text
    assert "let failure_threshold = 8;" in files["kql/R001_multiple_failed_logons.kql"].text
    assert "let window = 20m;" in files["kql/R001_multiple_failed_logons.kql"].text
    assert "gte: 7" in files["sigma/R004_single_ip_many_accounts.yml"].text
    assert "peak_distinct_accounts >= 7" in files["spl/R004_single_ip_many_accounts.spl"].text
    assert "let min_distinct_accounts = 7;" in files["kql/R004_single_ip_many_accounts.kql"].text
    default = _by_path(export_rules(config))
    assert "| where peak_failures >= 5" in default["spl/R001_multiple_failed_logons.spl"].text


def test_environment_settings_are_used(config):
    custom = with_overrides(config, {})
    custom["environment"]["internal_networks"] = ["10.0.0.0/8", "192.168.0.0/16"]
    custom["environment"]["business_hours"].update(start_hour=8, end_hour=18, weekdays=[0, 1, 2])
    files = _by_path(export_rules(custom))
    assert 'cidrmatch("10.0.0.0/8", IpAddress) OR cidrmatch("192.168.0.0/16", IpAddress)' in \
        files["spl/R002_success_after_failures.spl"].text
    assert 'dynamic(["10.0.0.0/8", "192.168.0.0/16"])' in files["kql/R002_success_after_failures.kql"].text
    assert '- "192.168.0.0/16"' in files["sigma/R005_rapid_source_change.yml"].text
    off_hours_spl = files["spl/R005_off_hours_new_source.spl"].text
    assert "(weekday=0 OR weekday=1 OR weekday=2) AND hour >= 8 AND hour < 18" in off_hours_spl
    assert "dynamic([0, 1, 2])" in files["kql/R005_off_hours_new_source.kql"].text


def test_entity_fields_of_r003_are_respected(config):
    only_ip = with_overrides(config, {"R003": {"entity_fields": ["source_ip"]}})
    files = _by_path(export_rules(only_ip))
    assert 'mvappend("source_ip=" . IpAddress)' in files["spl/R003_high_failure_rate.spl"].text
    assert "username=" not in _code(files["kql/R003_high_failure_rate.kql"])


def test_disabled_rules_are_not_exported(config):
    exported = export_rules(with_overrides(config, {"R005": {"enabled": False}}))
    assert {rule.detection.rule_id for rule in exported} == {"R001", "R002", "R003", "R004"}
    nothing = with_overrides(config, {rule: {"enabled": False} for rule in ("R001", "R002", "R003", "R004", "R005")})
    assert export_rules(nothing) == []


def test_export_is_deterministic(config):
    first, second = export_rules(config), export_rules(config)
    assert [r.text for r in first] == [r.text for r in second]
    assert export_zip(first) == export_zip(second)


def test_zip_contains_every_file(config):
    exported = export_rules(config)
    with zipfile.ZipFile(io.BytesIO(export_zip(exported))) as archive:
        assert sorted(archive.namelist()) == sorted(["README.txt", *(rule.path for rule in exported)])
        assert archive.read("spl/R001_multiple_failed_logons.spl").decode() == exported[1].text
        assert "TargetUserName" in archive.read("README.txt").decode()


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------
def test_yaml_writer_quotes_what_yaml_would_misread():
    assert to_yaml({"a": "yes", "b": "10.0.0.0/8", "c": "x: y", "d": "plain_name", "e": 4625, "f": 0.5}) == (
        'a: "yes"\nb: "10.0.0.0/8"\nc: "x: y"\nd: plain_name\ne: 4625\nf: 0.5')
    assert to_yaml({"list": ["one", {"k": "v", "n": 1}]}) == "list:\n  - one\n  - k: v\n    n: 1"


def _sigma_documents(text: str) -> list[list[str]]:
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    documents, current = [], []
    for line in lines:
        if line == "---":
            documents.append(current)
            current = []
        else:
            current.append(line)
    return [doc for doc in [*documents, current] if doc]


def _top_level(doc: list[str]) -> dict[str, str]:
    return {line.split(":", 1)[0]: line.split(":", 1)[1].strip().strip('"')
            for line in doc if line and not line.startswith(" ")}


def test_sigma_rules_have_the_required_fields(config):
    ids, names = set(), set()
    for rule in export_rules(config, ["sigma"]):
        documents = _sigma_documents(rule.text)
        if not rule.supported:
            assert documents == [] and "Not expressible in Sigma" in rule.text
            assert f"{rule.detection.slug}.spl" in rule.text
            continue
        defined = []
        for doc in documents:
            fields = _top_level(doc)
            assert {"title", "id", "name", "status", "date", "level"} <= set(fields), rule.path
            assert fields["level"] in SIGMA_LEVELS
            assert uuid.UUID(fields["id"]) and fields["id"] not in ids
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", fields["date"])
            ids.add(fields["id"])
            names.add(fields["name"])
            if "correlation" in fields:
                body = "\n".join(doc)
                referenced = re.findall(r"^    - (\S+)$", body.split("rules:", 1)[1].split("group-by:")[0], re.M)
                assert referenced and set(referenced) <= set(defined), rule.path  # base rules come first
                assert re.search(r"^  type: (event_count|value_count|temporal_ordered)$", body, re.M)
                assert re.search(r'^  timespan: "\d+m"$', body, re.M)
            else:
                assert {"logsource", "detection"} <= set(fields)
                assert "  condition: " in "\n".join(doc)
            defined.append(fields["name"])
        final = _top_level(documents[-1])
        assert "correlation" in final and final["level"] == rule.detection.level
        assert all(re.fullmatch(r"attack\.[a-z0-9.\-]+", tag) for tag in rule.detection.tags)
    assert len(names) == len(ids)  # names are unique across files, so all rules can be loaded together


# ---------------------------------------------------------------------------
# SPL and KQL
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fmt", ["spl", "kql"])
def test_queries_have_balanced_brackets_and_quotes(config, fmt):
    pairs = {")": "(", "]": "[", "}": "{"}
    for rule in export_rules(config, [fmt]):
        code = _code(rule)
        assert code.count('"') % 2 == 0, rule.path
        stack = []
        for char in re.sub(r'"[^"]*"', '""', code):
            if char in "([{":
                stack.append(char)
            elif char in pairs:
                assert stack and stack.pop() == pairs[char], rule.path
        assert stack == [], rule.path


def test_spl_searches_start_with_the_data_source(config):
    for rule in export_rules(config, ["spl"]):
        code = _code(rule).strip()
        assert code.startswith('index=wineventlog sourcetype="XmlWinEventLog:Security" '), rule.path
        assert all(line.startswith(("| ", "    ")) for line in code.splitlines()[1:] if line), rule.path


def test_kql_let_statements_are_terminated(config):
    for rule in export_rules(config, ["kql"]):
        code = _code(rule)
        statements = [s.strip() for s in code.split(";")]
        assert all(s.startswith("let ") for s in statements[:-1]), rule.path
        assert statements[-1] and not statements[-1].startswith("let "), rule.path  # the query itself


def test_every_query_mentions_its_rule_and_the_untested_warning(config):
    for rule in export_rules(config):
        assert f"Mini SOC Lab {rule.detection.rule_id}" in rule.text
        assert "not run on a live SIEM" in rule.text


# ---------------------------------------------------------------------------
# CLI and dashboard
# ---------------------------------------------------------------------------
def test_cli_writes_every_file(tmp_path, capsys):
    assert main(["export-rules", "--output-dir", str(tmp_path)]) == 0
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert len(written) == 21 and "kql/R004_single_ip_many_accounts.kql" in written
    assert "21 file(s) written" in capsys.readouterr().out
    assert main(["export-rules", "--format", "sigma", "--output-dir", str(tmp_path / "only")]) == 0
    assert len(list((tmp_path / "only").rglob("*.yml"))) == 7


@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    return testing.AppTest.from_file(str(APP_PATH), default_timeout=120)


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_dashboard_export_tab(app, lang):
    app.run()
    app.segmented_control(key="lang").set_value(lang).run()
    assert t("ui.tab.export", lang) in [tab.label for tab in app.tabs]
    assert app.selectbox(key="export_rule").value == "R001_multiple_failed_logons"
    assert app.code[0].value.startswith("# Mini SOC Lab R001")
    assert app.code[0].language == "yaml"

    app.radio(key="export_format").set_value("kql").run()
    assert not app.exception
    assert "let failure_threshold = 5;" in app.code[0].value and app.code[0].language == "kusto"

    app.number_input(key="thr_R001_failure_threshold").set_value(9).run()
    assert "let failure_threshold = 9;" in app.code[0].value  # sidebar thresholds are exported

    app.radio(key="export_format").set_value("sigma").run()
    app.selectbox(key="export_rule").set_value("R003_high_failure_rate").run()
    assert not app.exception
    assert any(w.value == t("ui.export.not_expressible", lang) for w in app.warning)
