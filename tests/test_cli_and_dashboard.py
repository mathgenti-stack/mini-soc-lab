from pathlib import Path

import pytest

from soc_lab.cli import main

APP_PATH = Path(__file__).resolve().parent.parent / "streamlit_app.py"


def test_cli_end_to_end(tmp_path, capsys):
    logs = tmp_path / "logs.csv"
    assert main(["generate", "--output", str(logs), "--days", "14", "--seed", "42"]) == 0
    assert main(["analyse", "--input", str(logs), "--export-csv", str(tmp_path / "alerts.csv")]) == 0
    output = capsys.readouterr().out
    assert "ALR-0001" in output and (tmp_path / "alerts.csv").exists()
    assert main(["report", "--input", str(logs), "--alert-id", "ALR-0001", "--output-dir", str(tmp_path)]) == 0
    assert (tmp_path / "INC-0001.md").exists() and (tmp_path / "INC-0001_evidence.csv").exists()


def test_cli_unknown_alert_id(tmp_path):
    logs = tmp_path / "logs.csv"
    main(["generate", "--output", str(logs), "--days", "3"])
    assert main(["report", "--input", str(logs), "--alert-id", "ALR-9999", "--output-dir", str(tmp_path)]) == 1


def test_cli_missing_input_file(tmp_path, capsys):
    assert main(["analyse", "--input", str(tmp_path / "missing.csv")]) == 2
    assert "not found" in capsys.readouterr().err


def test_cli_empty_input_file(tmp_path, capsys):
    empty = tmp_path / "empty.csv"
    empty.write_text("", encoding="utf-8")
    assert main(["analyse", "--input", str(empty)]) == 0
    assert "Alerts: 0" in capsys.readouterr().out


def test_dashboard_renders_without_errors():
    testing = pytest.importorskip("streamlit.testing.v1")
    app = testing.AppTest.from_file(str(APP_PATH), default_timeout=120).run()
    assert not app.exception
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Alerts generated"] != "0"
    assert int(metrics["Events analysed"].replace(",", "")) > 900

    selector = next(s for s in app.selectbox if s.label.startswith("Select an alert"))
    selector.set_value("ALR-0010").run()  # Critical password-spray alert in the sample dataset
    assert not app.exception
    assert {m.label: m.value for m in app.metric}["Severity"] == "Critical"


def test_static_site_lists_every_file_the_app_needs():
    """index.html (the in-browser build) only serves the files it lists; a missing module breaks the site."""
    import re
    root = APP_PATH.parent
    listed = set(re.findall(r'^\s*"([^"]+)",$', (root / "index.html").read_text(encoding="utf-8"), re.M))
    needed = {"streamlit_app.py", "config/detection_rules.json",
              *(p.relative_to(root).as_posix() for p in (root / "soc_lab").rglob("*.py") if "__pycache__" not in p.parts),
              *(p.relative_to(root).as_posix() for p in (root / "soc_lab" / "locales").glob("*.json")),
              *(p.relative_to(root).as_posix() for folder in ("enrichment", "examples")
                for p in (root / "data" / folder).iterdir())}
    assert sorted(needed - listed) == []
    assert sorted(path for path in listed if not (root / path).is_file()) == []
