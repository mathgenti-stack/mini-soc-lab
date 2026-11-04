"""Simulated bash (Terminal tab, phase 3): commands, the challenges and agreement with the real container."""

import pytest

from soc_lab import challenges, terminal
from soc_lab.sim.bash import BashShell
from soc_lab.sim.core import HOME, VirtualFS, lab_files


@pytest.fixture(scope="module")
def challenge_set():
    return challenges.load_challenges()


@pytest.fixture
def bash(challenge_set):
    return BashShell(VirtualFS(lab_files(challenge_set.files())))


def run(shell, line):
    result = shell.run(line)
    return result.output, result.error


def test_every_linux_challenge_works_in_the_simulator(bash, challenge_set):
    for challenge in challenge_set.for_environment("linux"):
        output, error = run(bash, challenge.solution)
        assert not error, (challenge.id, error)
        assert challenge.check(output), (challenge.id, output, challenge.answers)


@pytest.mark.parametrize("line, expected", [
    ("pwd", f"{HOME}\n"),
    ("cd logs; pwd", f"{HOME}/logs\n"),
    ("echo 'a  b' \"$HOME\"", f"a  b {HOME}\n"),
    ("x=$(grep -c Failed logs/linux_auth.log); echo \"failures: $x\"", "failures: 19\n"),
    ("wc -l < logs/linux_auth.log", "45\n"),
    ("head -2 logs/sample_auth_logs.csv | cut -d, -f3", "username\nsvc_backup\n"),
    ("printf 'b\\na\\nb\\n' | sort | uniq -c", "      1 a\n      2 b\n"),
    ("echo 10 9 100 | tr ' ' '\\n' | sort -n | head -1", "9\n"),
    ("echo 10 9 100 | tr ' ' '\\n' | sort -rn | head -1", "100\n"),
    ("echo Hello | tr a-z A-Z", "HELLO\n"),
    ("echo 'a,b,c' | awk -F, '{print $NF, NF}'", "c 3\n"),
    ("echo '1 2 3' | awk '{s=0; for (i=1; i<=NF; i++) s+=$i; print s}'", "6\n"),
    ("echo 'x' | sed 's/x/y/'", "y\n"),
    ("jq -r '.value[0].userPrincipalName' logs/entra_signins.json", "a.patel@example.com\n"),
    ("grep -c 4625 logs/*.xml", "7\n"),
    ("false || echo fallback", "fallback\n"),
    ("false && echo never", ""),
    ("echo one; echo two", "one\ntwo\n"),
    ("echo hi # a comment", "hi\n"),
])
def test_commands(bash, line, expected):
    output, error = run(bash, line)
    assert (output, error) == (expected, "")


@pytest.mark.parametrize("line, message", [
    ("cat missing.log", "cat: missing.log: No such file or directory"),
    ("grep x missing.log", "grep: missing.log: No such file or directory"),
    ("nosuchcommand", "nosuchcommand: command not found"),
    ("cd nowhere", "bash: cd: nowhere: No such file or directory"),
    ("touch logs/new.txt", "touch: cannot touch 'logs/new.txt': Read-only file system"),
    ("echo x > logs/linux_auth.log", "Read-only file system"),
    ("rm logs/linux_auth.log", "rm: cannot remove 'logs/linux_auth.log': Read-only file system"),
    ("sudo cat /etc/shadow", "analyst is not in the sudoers file"),
    ("grep -P x logs/linux_auth.log", "not supported in the simulated terminal"),
    ("vim notes.txt", "not available in the simulated terminal"),
    ("echo 'unterminated", "unexpected EOF"),
    ("awk '{print $1' logs/linux_auth.log", "awk:"),
])
def test_errors_look_like_bash(bash, line, message):
    output, error = run(bash, line)
    assert message in error, (line, error)


def test_home_is_writable_and_logs_are_not(bash):
    run(bash, "echo first > notes.txt; echo second >> notes.txt")
    assert run(bash, "cat notes.txt") == ("first\nsecond\n", "")
    assert run(bash, "cat logs/linux_auth.log | wc -l") == ("45\n", "")  # the logs did not change
    run(bash, "rm notes.txt")
    assert "No such file" in run(bash, "cat notes.txt")[1]


def test_globs_history_and_clear(bash):
    output, _ = run(bash, "echo logs/*.log")
    assert output == "logs/linux_auth.log\n"
    run(bash, "pwd")
    assert run(bash, "history")[0].endswith("    3  history\n")
    assert bash.run("clear").clear
    assert "awk" in run(bash, "help")[0] and "Example" in run(bash, "man awk")[0]


def test_binary_and_huge_outputs_are_safe(bash):
    output, _ = run(bash, "grep Logon logs/windows_security.evtx")
    assert output == "grep: logs/windows_security.evtx: binary file matches\n"
    assert run(bash, "file logs/windows_security.evtx")[0].startswith("logs/windows_security.evtx: MS Windows")
    output = bash.run("for i in 1; do cat logs/sample_auth_logs.csv; done").error  # loops are not supported
    assert output
    long_output = bash.run("cat logs/sample_auth_logs.csv logs/sample_auth_logs.csv logs/sample_auth_logs.csv").output
    assert "more lines not shown" in long_output


# ---------------------------------------------------------------------------
# Same output as the real bash in the Docker container
# ---------------------------------------------------------------------------
SAME_AS_REAL = [
    "head logs/linux_auth.log", "tail -3 logs/linux_auth.log", "tail -n +1015 logs/sample_auth_logs.csv",
    "wc -l logs/*.log logs/*.csv", "wc -w < logs/linux_auth.log",
    "grep -i 'failed' logs/linux_auth.log | head -3", "grep -n sudo logs/linux_auth.log",
    "grep -o 'from [0-9.]*' logs/linux_auth.log | sort | uniq -c", "grep -E 'Invalid|Accepted' logs/linux_auth.log | wc -l",
    "grep -c 4625 logs/*", "grep -l c.evans logs/*", "grep -w root logs/linux_auth.log | head -2",
    "grep 'Failed password for \\(invalid user \\)\\?root' logs/linux_auth.log | wc -l",
    "grep -A1 'temporarily locked' logs/linux_auth.log", "grep -B2 -n 'Accepted' logs/linux_auth.log",
    "grep -r 203.0.113.88 logs | wc -l", "cut -d, -f3 logs/sample_auth_logs.csv | sort | uniq -c | sort -rn | head -5",
    "sort -t, -k4,4 logs/sample_auth_logs.csv | head -3", "sort -t, -k2 -r logs/sample_auth_logs.csv | head -2",
    "awk -F, 'NR>1 {print $5}' logs/sample_auth_logs.csv | sort | uniq -c",
    "awk -F, '$6==\"FAILURE\" {c[$3]++} END {for (u in c) print c[u], u}' logs/sample_auth_logs.csv | sort -rn | head -3",
    "awk '{printf \"%-12s %s\\n\", $5, $6}' logs/linux_auth.log | head -3",
    "awk -F, 'NR>1 && $2 > \"2026-10-12\" && $2 < \"2026-10-13\"' logs/sample_auth_logs.csv | wc -l",
    "sed -n '2,4p' logs/linux_auth.log", "sed -E 's/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/x.x.x.x/g' logs/linux_auth.log | head -2",
    "sed '1d' logs/sample_auth_logs.csv | wc -l", "tr ',' ' ' < logs/sample_auth_logs.csv | head -2",
    "jq '.value[0]' logs/entra_signins.json",
    "jq -c '.value[] | {u: .userPrincipalName, e: .status.errorCode}' logs/entra_signins.json | head -3",
    "jq -r '.value | group_by(.ipAddress)[] | \"\\(length) \\(.[0].ipAddress)\"' logs/entra_signins.json",
    "tree logs", "sort -u -t, -k3,3 logs/sample_auth_logs.csv | wc -l", "cat -n logs/linux_auth.log | tail -1",
    "sort -k2,2n -t, logs/sample_auth_logs.csv | head -1", "ls -l logs | wc -l", "cat missing.txt",
]


@pytest.fixture(scope="module")
def running_terminal(challenge_set):
    if not terminal.docker_status().ready:
        pytest.skip("Docker engine not available")
    was_running = terminal.container_running()
    terminal.start(challenge_set.files())
    yield
    if not was_running:
        terminal.stop()


def test_simulator_matches_the_real_bash(running_terminal, bash):
    for line in SAME_AS_REAL:
        bash.cwd = HOME
        simulated = bash.run(line)
        real = terminal.run_in_container(line)
        # The Windows checkout can give the real files CRLF line endings; the simulator reads them as in git (LF).
        assert simulated.output == real.stdout.replace("\r", ""), line
        assert bool(simulated.error) == bool(real.stderr.strip()), line
