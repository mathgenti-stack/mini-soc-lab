"""Simulated Command Prompt (Terminal tab, phase 3): commands, the challenges and agreement with cmd.exe."""

import shutil
import subprocess
import sys

import pytest

from soc_lab import challenges
from soc_lab.sim import new_shell
from soc_lab.sim.core import HOME


@pytest.fixture(scope="module")
def challenge_set():
    return challenges.load_challenges()


@pytest.fixture
def cmd(challenge_set):
    return new_shell("cmd", challenge_set.files("cmd"))


def run(shell, line):
    result = shell.run(line)
    return result.output, result.error


def test_every_cmd_challenge_works_in_the_simulator(cmd, challenge_set):
    for challenge in challenge_set.for_environment("cmd"):
        output, error = run(cmd, challenge.solution)
        assert not error, (challenge.id, error)
        assert challenge.check(output), (challenge.id, output, challenge.answers)


def test_paths_prompt_and_navigation(cmd):
    assert cmd.prompt() == "C:\\Users\\analyst>"
    assert run(cmd, "cd") == ("C:\\Users\\analyst\\n".replace("\\n", "\n"), "")
    run(cmd, "cd LOGS")  # Windows paths ignore case
    assert cmd.cwd == f"{HOME}/logs" and cmd.prompt() == "C:\\Users\\analyst\\logs>"
    run(cmd, "cd ..")
    assert run(cmd, "type C:\\Users\\analyst\\logs\\linux_auth.log | find /c \"sudo\"") == ("1\n", "")
    output, _ = run(cmd, "dir logs")
    assert " Directory of C:\\Users\\analyst\\logs" in output and "5 File(s)" in output and "95,571" in output


@pytest.mark.parametrize("line, expected", [
    ('find /c "Failed password" logs\\linux_auth.log', "\n---------- LOGS\\LINUX_AUTH.LOG: 19\n"),
    ('type logs\\linux_auth.log | find /c "invalid user"', "5\n"),
    ('type logs\\linux_auth.log | find /c /v ""', "45\n"),
    ('findstr /n sudo logs\\linux_auth.log', "43:Oct 20 18:42:00 LON-WEB-01 sudo[2143]: m.jones : TTY=pts/0 ; "
                                             "PWD=/home/m.jones ; USER=root ; COMMAND=/usr/bin/apt update\n"),
    ('findstr /i /c:"accepted password" logs\\linux_auth.log | find /c /v ""', "1\n"),
    ('for /f "skip=1 tokens=3 delims=," %u in (logs\\sample_auth_logs.csv) do @echo %u | find /c "svc_backup"', "45\n"),
    ("echo %USERNAME% on %COMPUTERNAME%", "analyst on SOC-LAB\n"),
    # Like cmd.exe, echo keeps the space before & (checked against the real one).
    ("echo first> notes.txt & echo second>> notes.txt & type notes.txt", "first \nsecond \n"),
    ('find /c "x" missing.txt || echo not found', "not found\n"),
    ("set /a 6*7", "42\n"),
    ("if exist logs\\linux_auth.log (echo yes) else (echo no)", "yes\n"),
    ("whoami", "soc-lab\\analyst\n"),
])
def test_commands(cmd, line, expected):
    assert run(cmd, line)[0] == expected, line


@pytest.mark.parametrize("line, message", [
    ("foo", "'foo' is not recognized as an internal or external command"),
    ("grep x logs\\linux_auth.log", "In CMD use find or findstr"),
    ("find x logs\\linux_auth.log", "FIND: Parameter format not correct"),
    ("type nothing.txt", "The system cannot find the file specified."),
    ('find "x" nothing.txt', "File not found - NOTHING.TXT"),
    ("del logs\\linux_auth.log", "Access is denied."),
    ("echo x > logs\\new.txt", "Access is denied."),
    ("cd nowhere", "The system cannot find the path specified."),
    ("powershell", "choose it in the Shell selector"),
    ("ipconfig", "not available in the simulated terminal"),
])
def test_errors_look_like_cmd(cmd, line, message):
    assert message in run(cmd, line)[1], line


def test_help_and_clear(cmd):
    assert "FINDSTR" in run(cmd, "help")[0]
    assert "/C  Displays only the count" in run(cmd, "find /?")[0]
    assert cmd.run("cls").clear


# ---------------------------------------------------------------------------
# Same output as the real cmd.exe (only on Windows)
# ---------------------------------------------------------------------------
SAME_AS_REAL = [
    'type logs\\linux_auth.log | find /c "Failed password"',
    'find /c "Failed password" logs\\linux_auth.log',
    'find /n "sudo" logs\\linux_auth.log',
    'find /i /c "INVALID USER" logs\\linux_auth.log',
    'find /v /c "Failed" logs\\linux_auth.log',
    'type logs\\sample_auth_logs.csv | find "203.0.113.88" | find /c "FAILURE"',
    'findstr "Accepted Invalid" logs\\linux_auth.log',
    'findstr /c:"Accepted password" logs\\linux_auth.log',
    'findstr /n /i "c.evans" logs\\sample_auth_logs.csv',
    'findstr /r "^Oct.20.13:0[5-6]" logs\\linux_auth.log',
    'findstr /v "Failed pam_unix" logs\\linux_auth.log',
    'findstr /m 4625 logs\\*.xml logs\\*.log',
    'findstr sudo logs\\*.log logs\\*.xml',
    'for /f "tokens=9" %a in (\'findstr /c:"Accepted password" logs\\linux_auth.log\') do @echo %a',
    'for /f "tokens=1,3 delims=," %a in (\'findstr ",4740," logs\\sample_auth_logs.csv\') do @echo %b at %a',
    'type logs\\linux_auth.log | find "Invalid user" | sort',
    'type logs\\linux_auth.log | find "Invalid user" | sort /r',
    'more +43 logs\\linux_auth.log',
    'dir /b logs',
    'echo hello & echo world',
    'find "x" nothing.txt',
    'nosuchcommand',
]


@pytest.fixture(scope="module")
def real_cmd(tmp_path_factory, challenge_set):
    if sys.platform != "win32" or shutil.which("cmd") is None:
        pytest.skip("cmd.exe exists only on Windows")
    folder = tmp_path_factory.mktemp("cmdlab")
    (folder / "logs").mkdir()
    for relative, source in challenge_set.files("cmd").items():
        shutil.copyfile(source, folder / relative)
    return folder


def test_simulator_matches_the_real_cmd(real_cmd, cmd):
    for line in SAME_AS_REAL:
        cmd.cwd = HOME
        simulated = cmd.run(line)
        # A string, not a list: cmd.exe has its own quoting rules, so the line must reach it unchanged.
        real = subprocess.run("cmd /d /q /c " + line, cwd=real_cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        assert simulated.output == real.stdout.replace("\r", ""), line
        assert bool(simulated.error) == bool(real.stderr.strip()), line
