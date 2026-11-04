"""Terminal tab (bash and PowerShell): challenges file, answer checking, Docker control and the dashboard tab."""

import csv
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import pytest

from soc_lab import challenges, evtx, terminal
from soc_lab.challenges import ChallengeError, load_challenges, normalise_answer
from soc_lab.i18n import LANGUAGES, t

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"


@pytest.fixture(scope="module")
def challenge_set():
    return load_challenges()


def _lines(path):
    return (ROOT / path).read_text(encoding="utf-8").splitlines()


def _csv_rows():
    with open(ROOT / "data" / "sample_auth_logs.csv", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


# Each answer worked out in Python, independently of the shell command the challenge teaches.
AUTH = "data/examples/linux_auth.log"
EXPECTED = {
    "linux-01": lambda: str(len(_lines(AUTH))),
    "linux-02": lambda: _lines(AUTH)[0].split()[3],
    "linux-03": lambda: str(sum("Failed password" in line for line in _lines(AUTH))),
    "linux-04": lambda: Counter(m[1] for line in _lines(AUTH)
                                if (m := re.search(r"Failed password for (?:invalid user )?\S+ from (\S+)", line))
                                ).most_common(1)[0][0],
    "linux-05": lambda: str(len({m[1] for line in _lines(AUTH) if (m := re.search(r"Invalid user (\S+)", line))})),
    "linux-06": lambda: next(m[1] for line in _lines(AUTH)
                             if (m := re.search(r"for user (\S+) account temporarily locked", line))),
    "linux-07": lambda: next(line.split("COMMAND=")[1] for line in _lines(AUTH) if "COMMAND=" in line),
    "linux-08": lambda: str(sum(r["event_type"] == "LOGON" and r["result"] == "FAILURE" for r in _csv_rows())),
    "linux-09": lambda: Counter(r["source_ip"] for r in _csv_rows()
                                if r["result"] == "FAILURE" and not r["source_ip"].startswith("10.")).most_common(1)[0][0],
    "linux-10": lambda: str(len({r["username"] for r in _csv_rows()
                                 if r["source_ip"] == "203.0.113.88" and r["result"] == "FAILURE"})),
    "linux-11": lambda: next(r["username"] for r in _csv_rows()
                             if r["source_ip"] == "203.0.113.88" and r["result"] == "SUCCESS"),
    "linux-12": lambda: next(r["hostname"] for r in _csv_rows()
                             if r["username"] == "c.evans" and r["logon_type"] == "REMOTE_INTERACTIVE"),
    "linux-13": lambda: str(sum(s["status"]["errorCode"] == 50126 for s in json.loads(
        (ROOT / "data/examples/entra_signins.json").read_text(encoding="utf-8"))["value"])),
    "linux-14": lambda: str(sum("<EventID>4625</EventID>" in line for line in _lines("data/examples/windows_security.xml"))),
}


def _windows_xml():
    return ET.parse(ROOT / "data/examples/windows_security.xml").getroot()


def _evtx_events():
    records = evtx.read_evtx((ROOT / "data/examples/windows_security.evtx").read_bytes()).records
    return [ET.fromstring(record) for record in records]


def _event_id(event):
    return event.find(f"{NS}System/{NS}EventID").text


def _data(event, name):
    return next(d.text for d in event.iter(f"{NS}Data") if d.get("Name") == name)


def _failures():
    return [r for r in _csv_rows() if r["event_code"] == "4625"]


NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
POWERSHELL_EXPECTED = {
    "ps-01": lambda: str(len(load_challenges().files("powershell"))),
    "ps-02": lambda: str(len(_csv_rows())),
    "ps-03": lambda: next(col for col in _csv_rows()[0] if all(r[col].isdigit() and len(r[col]) == 4 for r in _csv_rows())),
    "ps-04": lambda: str(len(_failures())),
    "ps-05": lambda: Counter(r["username"] for r in _failures()).most_common(1)[0][0],
    "ps-06": lambda: "".join({r["failure_reason"] for r in _failures() if r["username"] == "svc_backup"}),
    "ps-07": lambda: str(len(_windows_xml())),
    "ps-08": lambda: _data(next(e for e in _windows_xml() if _event_id(e) == "4767"), "SubjectUserName"),
    "ps-09": lambda: next(r["username"] for r in _csv_rows()
                          if r["event_code"] == "4740" and not r["source_ip"].startswith("10.")),
    "ps-10": lambda: str(sum(r["username"] == "e.wilson" and r["timestamp"].startswith("2026-10-12") for r in _failures())),
    "ps-11": lambda: next(r["timestamp"] for r in _csv_rows()
                          if r["source_ip"] == "203.0.113.88" and r["event_code"] == "4624"),
    "ps-12": lambda: str(sum(_event_id(e) == "4625" for e in _evtx_events())),
    "ps-13": lambda: next(e for e in _evtx_events() if _event_id(e) == "4740").find(
        f"{NS}System/{NS}TimeCreated").get("SystemTime")[11:19],
    "ps-14": lambda: next(s["userPrincipalName"] for s in json.loads(
        (ROOT / "data/examples/entra_signins.json").read_text(encoding="utf-8"))["value"]
        if s["ipAddress"] == "203.0.113.88" and s["status"]["errorCode"] == 0),
}
CMD_EXPECTED = {
    "cmd-01": lambda: str(len(load_challenges().files("cmd"))),
    "cmd-02": lambda: str(sum("Failed password" in line for line in _lines(AUTH))),
    "cmd-03": lambda: str(sum("invalid user" in line.lower() for line in _lines(AUTH))),
    "cmd-04": lambda: str(sum("Accepted" in line or "Invalid" in line for line in _lines(AUTH))),
    "cmd-05": lambda: str(sum(r["event_code"] == "4740" for r in _csv_rows())),
    "cmd-06": lambda: str(sum(r["source_ip"] == "203.0.113.88" and r["result"] == "FAILURE" for r in _csv_rows())),
    "cmd-07": lambda: str(sum(any(d.text == "j.smith" for d in e.iter(f"{NS}Data")) for e in _windows_xml())),
    "cmd-08": lambda: next(line.split()[8] for line in _lines(AUTH) if "Accepted password" in line),
}
ALL_EXPECTED = {**EXPECTED, **POWERSHELL_EXPECTED, **CMD_EXPECTED}
BY_ENVIRONMENT = {"linux": EXPECTED, "powershell": POWERSHELL_EXPECTED, "cmd": CMD_EXPECTED}


# ---------------------------------------------------------------------------
# Challenges file
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("environment", challenges.ENVIRONMENTS)
def test_challenges_file_is_complete(challenge_set, environment):
    items = challenge_set.for_environment(environment)
    assert [c.id for c in items] == sorted(BY_ENVIRONMENT[environment])
    assert [c.level for c in items] == sorted(c.level for c in items)  # easiest first
    assert all(path.is_file() for path in challenge_set.files(environment).values())
    assert t(f"ui.terminal.env.{environment}") != f"ui.terminal.env.{environment}"
    for challenge in items:
        assert challenges.languages_missing(challenge) == [], challenge.id
        assert challenge.hints and challenge.solution and challenge.files
        assert t(f"ui.terminal.topic.{challenge.topic}") != f"ui.terminal.topic.{challenge.topic}"


@pytest.mark.parametrize("challenge_id", sorted(ALL_EXPECTED))
def test_answers_match_the_lab_data(challenge_set, challenge_id):
    """If the logs or the generator change, the answers must be updated: this test says which ones."""
    challenge = challenge_set.get(challenge_id)
    expected = ALL_EXPECTED[challenge_id]()
    assert challenge.check(expected), (challenge_id, expected, challenge.answers)


def test_solutions_only_use_files_of_the_challenge(challenge_set):
    for challenge in challenge_set.challenges:
        used = {u.replace("\\", "/") for u in re.findall(r"logs[/\\][\w.]+", challenge.solution)}
        assert used <= set(challenge.files), challenge.id
        assert used or challenge.topic == "basics", challenge.id  # only a first look at the folder uses no file


def test_answer_checking_is_forgiving_about_form_only(challenge_set):
    challenge = challenge_set.get("linux-07")
    for answer in ("/usr/bin/apt update", "  /USR/BIN/APT   update ", "`apt update`", "'apt update'"):
        assert challenge.check(answer), answer
    for answer in ("", "   ", "apt", "apt upgrade"):
        assert not challenge.check(answer), answer
    assert normalise_answer("  Ação  ") == "acao"


@pytest.mark.parametrize("change, message", [
    (lambda d: d["challenges"].append(dict(d["challenges"][0])), "unique"),
    (lambda d: d["challenges"][0].update(answers=[" "]), "answer"),
    (lambda d: d["challenges"][0].update(files=["logs/missing.log"]), "files"),
    (lambda d: d["challenges"][0].update(environments=["zsh"]), "environment"),
    (lambda d: d["challenges"][0].pop("solution"), "solution"),
    (lambda d: d["challenges"][0]["title"].pop("en"), "en"),
])
def test_invalid_challenge_files_are_refused(tmp_path, change, message):
    document = json.loads(challenges.CHALLENGES_PATH.read_text(encoding="utf-8"))
    change(document)
    path = tmp_path / "challenges.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ChallengeError, match=message):
        load_challenges(path)


def test_progress_round_trip(tmp_path):
    path = challenges.progress_path(tmp_path / "answers", "linux")
    assert challenges.load_progress(path) == {"solved": set(), "revealed": set()}
    challenges.save_progress(path, {"solved": {"linux-02", "linux-01"}, "revealed": {"linux-05"}})
    assert challenges.load_progress(path) == {"solved": {"linux-01", "linux-02"}, "revealed": {"linux-05"}}
    path.write_text("not json", encoding="utf-8")
    assert challenges.load_progress(path)["solved"] == set()  # a damaged file is not fatal


# ---------------------------------------------------------------------------
# Docker control (no Docker needed)
# ---------------------------------------------------------------------------
def test_container_is_local_only_and_locked_down(challenge_set):
    files = challenge_set.files()
    args = terminal.run_arguments(files, 7681)
    joined = " ".join(args)
    assert args[0] == "run" and args[-1] == terminal.IMAGE
    assert "--publish 127.0.0.1:7681:7681" in joined  # never on all interfaces
    assert "--rm" in args and "--cap-drop ALL" in joined and "--security-opt no-new-privileges" in joined
    assert "--memory 512m" in joined and "--pids-limit 256" in joined
    mounts = [arg for arg in args if arg.startswith("type=bind")]
    assert len(mounts) == len(files) + len(terminal.SUPPORT_FILES)
    assert all(mount.endswith(",readonly") for mount in mounts)
    assert f"target={terminal.HOME}/logs/linux_auth.log" in joined
    assert f"target={terminal.HOME}/logs/windows_security.evtx" in joined
    assert "target=/opt/soc-lab/lib/evtx.py" in joined  # the reader behind Get-WinEvent


def test_one_container_serves_every_environment(challenge_set):
    union = challenge_set.files()
    for environment in challenges.ENVIRONMENTS:
        assert challenge_set.files(environment).items() <= union.items()
    assert terminal.terminal_url(7681) == "http://localhost:7681"
    assert terminal.terminal_url(7681, "powershell") == "http://localhost:7681/?arg=powershell"


def test_lab_shell_accepts_only_known_shells():
    script = (ROOT / "terminal" / "lab-shell").read_text(encoding="utf-8")
    assert "powershell) exec pwsh" in script and "*) exec bash --login" in script
    assert "--url-arg" in (ROOT / "terminal" / "Dockerfile").read_text(encoding="utf-8")


def test_docker_status_without_docker(monkeypatch):
    monkeypatch.setattr(terminal.shutil, "which", lambda name: None)
    assert terminal.docker_status().state == "no_docker"


def test_docker_status_engine_down(monkeypatch):
    monkeypatch.setattr(terminal.shutil, "which", lambda name: "docker")
    monkeypatch.setattr(terminal, "_docker", lambda *a, **k: subprocess.CompletedProcess(
        a, 1, "", "error during connect\nDocker Desktop is unable to start"))
    status = terminal.docker_status()
    assert (status.state, status.detail) == ("engine_down", "Docker Desktop is unable to start")
    monkeypatch.setattr(terminal, "_docker", lambda *a, **k: subprocess.CompletedProcess(a, 0, "windows\n", ""))
    assert terminal.docker_status().state == "engine_down"  # Windows containers cannot run this image


def test_build_hash_ignores_line_endings(tmp_path):
    (tmp_path / "Dockerfile").write_bytes(b"FROM debian\nRUN true\n")
    first = terminal.build_hash(tmp_path)
    (tmp_path / "Dockerfile").write_bytes(b"FROM debian\r\nRUN true\r\n")
    assert terminal.build_hash(tmp_path) == first
    (tmp_path / "Dockerfile").write_bytes(b"FROM debian\nRUN false\n")
    assert terminal.build_hash(tmp_path) != first


def test_terminal_port_from_environment(monkeypatch):
    monkeypatch.setenv("SOC_LAB_TERMINAL_PORT", "7700")
    assert terminal.terminal_url() == "http://localhost:7700"
    monkeypatch.setenv("SOC_LAB_TERMINAL_PORT", "abc")
    assert terminal.terminal_port() == terminal.DEFAULT_PORT


def test_image_files_use_unix_line_endings():
    for path in (ROOT / "terminal").rglob("*"):
        if path.is_file():
            assert b"\r\n" not in path.read_bytes(), path.name  # bash inside the container rejects CRLF scripts


# ---------------------------------------------------------------------------
# Dashboard tab
# ---------------------------------------------------------------------------
@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    monkeypatch.setattr(terminal.shutil, "which", lambda name: None)  # behave as if Docker were not installed
    app = testing.AppTest.from_file(str(APP_PATH), default_timeout=120)
    app.session_state["active_tab"] = "terminal"
    return app


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_terminal_tab_without_docker(app, lang, tmp_path):
    app.run()
    app.segmented_control(key="lang").set_value(lang).run()
    assert not app.exception
    assert t("ui.tab.terminal", lang) in [tab.label for tab in app.tabs]
    app.segmented_control(key="terminal_mode").set_value("docker").run()  # the simulated terminal is the default
    assert any(w.value == t("ui.terminal.no_docker", lang) for w in app.warning)
    assert any("wsl --install" in m.value for m in app.markdown)

    app.selectbox(key="terminal_challenge_linux").set_value("linux-01").run()
    app.text_input(key="terminal_answer_linux-01").set_value("45")
    next(b for b in app.button if b.label == t("ui.terminal.check", lang)).click().run()
    assert any(s.value.startswith(t("ui.terminal.correct", lang)[:8]) for s in app.success)
    assert any(c.value == "wc -l < logs/linux_auth.log" for c in app.code)  # the solution appears once solved
    saved = challenges.load_progress(challenges.progress_path(tmp_path, "linux"))
    assert saved["solved"] == {"linux-01"}


def test_wrong_answer_and_reveal(app):
    app.run()
    app.selectbox(key="terminal_challenge_linux").set_value("linux-04").run()
    app.text_input(key="terminal_answer_linux-04").set_value("10.10.2.5")
    next(b for b in app.button if b.label == "Check").click().run()
    assert any(e.value == t("ui.terminal.wrong") for e in app.error)
    assert not [c for c in app.code if c.language == "bash"]  # (other tabs show YAML / SPL code)
    app.button(key="terminal_reveal_linux-04").click().run()
    assert any("uniq -c" in c.value for c in app.code)
    assert app.session_state["terminal_progress_linux"]["solved"] == set()


def screen_text(app, environment):
    """The simulated terminal's screen (an st.html element) as plain text."""
    import html as html_module

    screens = [e for e in app.get("html") if "<pre" in e.proto.body]
    assert screens, "no simulated terminal on the page"
    return html_module.unescape(re.sub(r"<[^>]+>", "", screens[-1].proto.body))


@pytest.mark.parametrize("environment, command, expected", [
    ("linux", "wc -l < logs/linux_auth.log", "45"),
    ("powershell", "(Import-Csv logs/sample_auth_logs.csv).Count", "1017"),
    ("cmd", 'type logs\\linux_auth.log | find /c "Failed password"', "19"),
])
def test_simulated_terminal_in_the_tab(app, environment, command, expected):
    app.run()
    app.segmented_control(key="terminal_env").set_value(environment).run()
    assert not app.exception
    app.chat_input(key=f"sim_input_{environment}").set_value(command).run()
    assert not app.exception
    text = screen_text(app, environment)
    assert command in text and f"\n{expected}\n" in text
    app.chat_input(key=f"sim_input_{environment}").set_value("nosuchcommand").run()
    assert "nosuchcommand" in screen_text(app, environment).split(command, 1)[1]
    app.button(key=f"sim_reset_{environment}").click().run()
    assert command not in screen_text(app, environment)  # a fresh session


def test_cmd_has_no_docker_mode(app):
    app.run()
    app.segmented_control(key="terminal_env").set_value("cmd").run()
    assert not app.exception
    assert not [s for s in app.segmented_control if s.key == "terminal_mode"]
    assert any(c.value == t("ui.terminal.cmd_note") for c in app.caption)


def test_powershell_challenges_in_the_tab(app, tmp_path):
    app.run()
    app.segmented_control(key="terminal_env").set_value("powershell").run()
    assert not app.exception
    app.selectbox(key="terminal_challenge_powershell").set_value("ps-04").run()
    app.text_input(key="terminal_answer_ps-04").set_value("165")
    next(b for b in app.button if b.label == "Check").click().run()
    assert any(c.language == "powershell" and "Where-Object" in c.value for c in app.code)
    assert challenges.load_progress(challenges.progress_path(tmp_path, "powershell"))["solved"] == {"ps-04"}
    assert challenges.load_progress(challenges.progress_path(tmp_path, "linux"))["solved"] == set()  # kept apart


# ---------------------------------------------------------------------------
# The real container (skipped when Docker is not available)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def running_terminal(challenge_set):
    if not terminal.docker_status().ready:
        pytest.skip("Docker engine not available")
    was_running = terminal.container_running()
    terminal.start(challenge_set.files())
    yield
    if not was_running:
        terminal.stop()


@pytest.mark.parametrize("environment", terminal.DOCKER_ENVIRONMENTS)
def test_every_solution_prints_the_answer_in_the_real_shell(running_terminal, challenge_set, environment):
    for challenge in challenge_set.for_environment(environment):
        result = terminal.run_in_container(challenge.solution, environment)
        assert result.returncode == 0, (challenge.id, result.stderr)
        assert challenge.check(result.stdout), (challenge.id, result.stdout, challenge.answers)


def _pwsh(command):
    result = terminal.run_in_container(command, "powershell")
    assert result.returncode == 0, (command, result.stderr)
    return result.stdout.strip()


def test_lab_get_winevent_behaves_like_windows(running_terminal):
    """The lab version reads the .evtx with the dashboard's reader and returns events newest first."""
    path = "$HOME/logs/windows_security.evtx"
    records = _evtx_events()
    assert _pwsh(f"(Get-WinEvent -Path {path}).Count") == str(len(records))
    newest = records[-1].find(f"{NS}System/{NS}EventRecordID").text
    oldest = records[0].find(f"{NS}System/{NS}EventRecordID").text
    assert _pwsh(f"(Get-WinEvent -Path {path} -MaxEvents 1).RecordId") == newest
    assert _pwsh(f"(Get-WinEvent -Path {path} -Oldest -MaxEvents 1).RecordId") == oldest
    assert _pwsh(f"(Get-WinEvent -FilterHashtable @{{Path=\"{path}\"; TargetUserName='adminstrator'}}).Id") == "4625"
    assert _pwsh(f"(Get-WinEvent -FilterHashtable @{{Path=\"{path}\"; Id=4624,4625}}).Count") == str(
        sum(_event_id(e) in ("4624", "4625") for e in records))
    assert _pwsh(f"([xml](Get-WinEvent -FilterHashtable @{{Path=\"{path}\"; Id=4767}}).ToXml()).Event.System.EventID") == "4767"
    assert "failed to log on" in _pwsh(f"(Get-WinEvent -Path {path} -MaxEvents 3 | Where-Object Id -eq 4625).Message")
    for command in ("Get-WinEvent -LogName Security", "Get-WinEvent -Path logs/windows_security.xml"):
        result = terminal.run_in_container(command, "powershell")
        assert result.returncode != 0 and ".evtx" in result.stderr, command
    result = terminal.run_in_container(f"Get-WinEvent -FilterHashtable @{{Path=\"{path}\"; Id=9999}}", "powershell")
    assert "No events were found" in result.stderr


def test_container_is_unprivileged_and_logs_are_read_only(running_terminal):
    assert terminal.run_in_container("id -u").stdout.strip() != "0"
    assert terminal.run_in_container("touch logs/linux_auth.log").returncode != 0
    assert terminal.run_in_container("echo x > logs/new.txt").returncode != 0
    assert terminal.run_in_container("echo x > notes.txt && cat notes.txt").stdout.strip() == "x"  # home is writable
    published = subprocess.run(["docker", "port", terminal.CONTAINER], capture_output=True, text=True).stdout
    assert published.strip().startswith("7681/tcp -> 127.0.0.1:")
