"""Real-world log formats: Linux auth.log, Windows Security XML and Entra ID sign-in JSON."""

import ipaddress
import json
import re
from pathlib import Path

import pytest

from soc_lab.cli import main
from soc_lab.config import load_config
from soc_lab.detection import run_detection
from soc_lab.i18n import LANGUAGES, t
from soc_lab.log_loader import load_events
from soc_lab.parsers import ConversionError, convert, detect_format

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"
EXAMPLES = ROOT / "data" / "examples"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def rows(result):
    return result.events.to_dict("records")


def analyse(path: Path):
    conversion = convert(path.read_bytes(), "auto", path.name, 2026)
    loaded = load_events(conversion.to_csv_bytes(), path.name)
    return conversion, loaded, run_detection(loaded.events, load_config())


def win_event(event_id, data, time="2026-10-21T09:10:00.1234567Z", record=1, computer="LON-DC-01"):
    items = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID><TimeCreated SystemTime="{time}"/>'
            f"<EventRecordID>{record}</EventRecordID><Computer>{computer}</Computer></System>"
            f"<EventData>{items}</EventData></Event>")


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name, expected", [("linux_auth.log", "linux_auth"), ("windows_security.xml", "windows_xml"),
                                            ("entra_signins.json", "entra_json")])
def test_detects_the_example_formats(name, expected):
    data = (EXAMPLES / name).read_bytes()
    assert detect_format(data, name) == expected
    assert detect_format(data) == expected  # from the contents alone


def test_detects_lab_csv():
    sample = (ROOT / "data" / "sample_auth_logs.csv").read_bytes()
    assert detect_format(sample, "sample_auth_logs.csv") == "lab_csv"
    assert convert(sample).fmt == "lab_csv" and convert(sample).events.empty  # read by load_events instead


# ---------------------------------------------------------------------------
# Linux auth.log
# ---------------------------------------------------------------------------
def test_linux_auth_lines():
    log = "\n".join([
        "Oct 20 13:05:00 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 40100 ssh2",
        "Oct 20 13:05:01 web-01 sshd[2]: Invalid user admin from 203.0.113.45 port 40101",
        "Oct 20 13:05:01 web-01 sshd[2]: Failed password for invalid user admin from 203.0.113.45 port 40101 ssh2",
        "Oct  2 08:00:00 web-01 sshd[3]: Accepted publickey for deploy from 10.10.2.5 port 5000 ssh2: ED25519 SHA256:x",
        "2026-10-20T14:00:00.123456+02:00 web-01 sshd[4]: Accepted password for m.jones from 198.51.100.23 port 1 ssh2",
        "Oct 20 13:09:00 web-01 sshd[5]: pam_faillock(sshd:auth): Consecutive login failures for user root account "
        "temporarily locked",
        "Oct 20 18:45:00 web-01 passwd[6]: pam_unix(passwd:chauthtok): password changed for m.jones",
        "Oct 20 19:00:00 web-01 sshd[7]: pam_unix(sshd:session): session closed for user m.jones",
        "Oct 20 19:01:00 web-01 CRON[8]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "this is not a syslog line",
    ])
    result = convert(log.encode(), "linux_auth", year=2026)
    events = rows(result)
    assert [(e["event_type"], e["result"], e["username"], e["failure_reason"]) for e in events] == [
        ("LOGON", "FAILURE", "root", "BAD_PASSWORD"),
        ("LOGON", "FAILURE", "admin", "UNKNOWN_USER"),
        ("LOGON", "SUCCESS", "deploy", ""),
        ("LOGON", "SUCCESS", "m.jones", ""),
        ("ACCOUNT_LOCKOUT", "INFO", "root", ""),
        ("PASSWORD_CHANGE", "SUCCESS", "m.jones", ""),
        ("LOGOFF", "INFO", "m.jones", ""),
    ]
    assert events[0]["timestamp"] == "2026-10-20T13:05:00Z" and events[0]["event_code"] == "4625"
    assert events[2]["timestamp"] == "2026-10-02T08:00:00Z"  # single-digit day in classic syslog
    assert events[3]["timestamp"] == "2026-10-20T12:00:00Z"  # RFC 3339 offset converted to UTC
    assert events[0]["hostname"] == "web-01" and events[0]["logon_type"] == "SSH"
    assert events[4]["source_ip"] == "-"
    assert result.records_read == 10
    assert dict(result.skipped) == {"duplicate_ssh_line": 1, "not_auth_event": 1, "invalid_record": 1}
    assert len({e["event_id"] for e in events}) == len(events)


def test_classic_syslog_uses_the_given_year():
    line = b"Oct 20 13:05:00 web-01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"
    assert rows(convert(line, "linux_auth", year=2024))[0]["timestamp"] == "2024-10-20T13:05:00Z"


# ---------------------------------------------------------------------------
# Windows Security XML
# ---------------------------------------------------------------------------
def test_windows_events():
    xml = "<Events>" + "".join([
        win_event(4625, {"TargetUserName": "J.Smith", "SubStatus": "0xc000006a", "Status": "0xc000006d",
                         "LogonType": "10", "IpAddress": "203.0.113.9"}, record=7),
        win_event(4625, {"TargetUserName": "ghost", "SubStatus": "0x0", "Status": "0xC0000064", "LogonType": "3",
                         "IpAddress": "10.10.1.40"}),
        win_event(4624, {"TargetUserName": "j.smith", "LogonType": "2", "IpAddress": "-"}),
        win_event(4647, {"TargetUserName": "j.smith"}),
        win_event(4740, {"TargetUserName": "j.smith"}),
        win_event(4767, {"TargetUserName": "j.smith", "SubjectUserName": "h.wright"}),
        win_event(4624, {"TargetUserName": "LON-WS-002$", "LogonType": "3"}),
        win_event(4624, {"TargetUserName": "ANONYMOUS LOGON", "LogonType": "3"}),
        win_event(4672, {"SubjectUserName": "j.smith"}),
    ]) + "</Events>"
    result = convert(xml.encode(), "windows_xml")
    events = rows(result)
    assert [(e["event_code"], e["event_type"], e["result"]) for e in events] == [
        ("4625", "LOGON", "FAILURE"), ("4625", "LOGON", "FAILURE"), ("4624", "LOGON", "SUCCESS"),
        ("4647", "LOGOFF", "INFO"), ("4740", "ACCOUNT_LOCKOUT", "INFO"), ("4767", "ACCOUNT_UNLOCK", "INFO")]
    first = events[0]
    assert first["event_id"] == "WIN-7" and first["timestamp"] == "2026-10-21T09:10:00Z"
    assert (first["failure_reason"], first["logon_type"], first["source_ip"], first["hostname"]) == (
        "BAD_PASSWORD", "REMOTE_INTERACTIVE", "203.0.113.9", "LON-DC-01")
    assert events[1]["failure_reason"] == "UNKNOWN_USER"  # Status is used when SubStatus is 0x0
    assert events[4]["source_ip"] == "-" and events[4]["logon_type"] == ""
    assert dict(result.skipped) == {"machine_account": 1, "anonymous_logon": 1, "unsupported_event_id": 1}


def test_windows_single_event_and_utf16():
    xml = '<?xml version="1.0" encoding="UTF-16"?>' + win_event(4624, {"TargetUserName": "a.patel", "LogonType": "2",
                                                                        "IpAddress": "10.10.1.11"})
    events = rows(convert(xml.encode("utf-16"), "auto", "export.xml"))
    assert [e["username"] for e in events] == ["a.patel"]


def test_windows_bad_xml_is_refused():
    with pytest.raises(ConversionError):
        convert(b"<Events><Event>", "windows_xml")
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><Events>&a;</Events>'
    with pytest.raises(ConversionError, match="DOCTYPE"):
        convert(bomb, "windows_xml")


# ---------------------------------------------------------------------------
# Entra ID sign-ins
# ---------------------------------------------------------------------------
def signin(code=0, user="l.taylor@example.com", **extra):
    return {"id": f"id-{code}-{user}", "createdDateTime": "2026-10-22T11:13:05Z", "userPrincipalName": user,
            "ipAddress": "203.0.113.88", "appDisplayName": "Azure Portal", "clientAppUsed": "Browser",
            "status": {"errorCode": code}, **extra}


def test_entra_sign_ins():
    document = {"value": [signin(0), signin(50126), signin(50034, "admin@example.com"), signin(50053), signin(50074),
                          signin(90099), {"userPrincipalName": "missing.date@example.com"}]}
    result = convert(json.dumps(document).encode(), "entra_json")
    events = rows(result)
    assert [(e["result"], e["failure_reason"]) for e in events] == [
        ("SUCCESS", ""), ("FAILURE", "BAD_PASSWORD"), ("FAILURE", "UNKNOWN_USER"), ("FAILURE", "ACCOUNT_LOCKED"),
        ("FAILURE", "ENTRA_90099")]
    assert events[0]["username"] == "l.taylor@example.com" and events[0]["hostname"] == "Azure Portal"
    assert events[0]["event_code"] == "4624" and events[1]["event_code"] == "4625"
    assert events[0]["event_id"] == "ENTRA-id-0-l.taylor@example.com"
    assert dict(result.skipped) == {"mfa_interrupt": 1, "invalid_record": 1}
    plain_list = convert(json.dumps([signin(0)]).encode(), "entra_json")
    assert len(plain_list.events) == 1


def test_entra_bad_json_is_refused():
    with pytest.raises(ConversionError):
        convert(b"{not json", "entra_json")
    with pytest.raises(ConversionError):
        convert(b'{"value": 5}', "entra_json")


# ---------------------------------------------------------------------------
# Example files end to end
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name, expected_alerts", [
    ("linux_auth.log", [("R001", "High"), ("R003", "High"), ("R004", "High"), ("R002", "High")]),
    ("windows_security.xml", [("R001", "Medium"), ("R002", "Medium"), ("R005", "Medium")]),
    ("entra_signins.json", [("R004", "Critical")]),
])
def test_example_files_raise_the_expected_alerts(name, expected_alerts):
    conversion, loaded, alerts = analyse(EXAMPLES / name)
    assert loaded.quality.rows_rejected == 0 and loaded.quality.rows_accepted == len(conversion.events) > 0
    assert [(a.rule_id, a.severity.value) for a in alerts] == expected_alerts


def test_example_conversion_counts():
    counts = {name: analyse(EXAMPLES / name)[0] for name in ("linux_auth.log", "windows_security.xml",
                                                             "entra_signins.json")}
    assert (counts["linux_auth.log"].records_read, len(counts["linux_auth.log"].events)) == (45, 25)
    assert dict(counts["linux_auth.log"].skipped) == {"duplicate_ssh_line": 17, "not_auth_event": 3}
    assert (counts["windows_security.xml"].records_read, len(counts["windows_security.xml"].events)) == (17, 14)
    assert (counts["entra_signins.json"].records_read, len(counts["entra_signins.json"].events)) == (16, 15)


def test_example_files_are_fictional():
    allowed = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for path in EXAMPLES.iterdir():
        text = path.read_text(encoding="utf-8")
        addresses = {ipaddress.ip_address(ip) for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)}
        assert addresses and all(any(ip in net for net in allowed) for ip in addresses), path.name
        domains = set(re.findall(r"\w@([\w.-]+)", text)) | set(re.findall(r"\.(example\.\w+)", text))
        assert domains <= {"example.com", "example.local"}, (path.name, domains)


# ---------------------------------------------------------------------------
# CLI and dashboard
# ---------------------------------------------------------------------------
def test_cli_convert_and_analyse(tmp_path, capsys):
    output = tmp_path / "converted.csv"
    assert main(["convert", "--input", str(EXAMPLES / "linux_auth.log"), "--year", "2026",
                 "--output", str(output)]) == 0
    printed = capsys.readouterr().out
    assert "Converted from linux_auth: 45 records read, 25 events, 20 skipped" in printed
    assert output.read_text(encoding="utf-8").startswith("event_id,timestamp,username")
    assert main(["analyse", "--input", str(EXAMPLES / "entra_signins.json")]) == 0
    assert "ALR-0001  Critical  R004" in capsys.readouterr().out
    assert main(["convert", "--input", str(ROOT / "data" / "sample_auth_logs.csv")]) == 0
    assert "already a lab CSV" in capsys.readouterr().out
    assert main(["analyse", "--input", str(tmp_path / "missing.xml")]) == 2


@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    return testing.AppTest.from_file(str(APP_PATH), default_timeout=120)


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_dashboard_examples(app, lang):
    app.run()
    app.segmented_control(key="lang").set_value(lang).run()
    app.radio(key="data_source").set_value("examples").run()
    expected = {"linux_auth.log": 4, "windows_security.xml": 3, "entra_signins.json": 1}
    for name, alert_count in expected.items():
        app.selectbox(key="example_file").set_value(name).run()
        assert not app.exception, name
        assert {m.label: m.value for m in app.metric}[t("ui.kpi.alerts", lang)] == str(alert_count)
        assert any(t("ui.quality.conversion", lang, format="").split("{")[0].strip() in m.value
                   for m in app.markdown), name
    assert {m.label: m.value for m in app.metric}[t("ui.quality.records_skipped", lang)] == "1"  # MFA interrupt
