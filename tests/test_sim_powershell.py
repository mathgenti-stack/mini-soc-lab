"""Simulated PowerShell (Terminal tab, phase 3): objects, the challenges and agreement with the real pwsh."""

import pytest

from soc_lab import challenges, terminal
from soc_lab.sim.core import HOME, VirtualFS, lab_files
from soc_lab.sim.powershell import PowerShellShell

CSV = "Import-Csv logs/sample_auth_logs.csv"
EVTX = '"$HOME/logs/windows_security.evtx"'


@pytest.fixture(scope="module")
def challenge_set():
    return challenges.load_challenges()


@pytest.fixture
def ps(challenge_set):
    return PowerShellShell(VirtualFS(lab_files(challenge_set.files())))


def run(shell, line):
    result = shell.run(line)
    return result.output, result.error


def test_every_powershell_challenge_works_in_the_simulator(ps, challenge_set):
    for challenge in challenge_set.for_environment("powershell"):
        output, error = run(ps, challenge.solution)
        assert not error, (challenge.id, error)
        assert challenge.check(output), (challenge.id, output, challenge.answers)


@pytest.mark.parametrize("line, expected", [
    ("1 + 2 * 3", "7"),
    ("'5' + 5; 5 + '5'", "55\n10"),
    ("7 / 2; 6 / 2; 10 % 3", "3.5\n3\n1"),
    ("[math]::Round(2.5); [math]::Round(3.14159, 2)", "2\n3.14"),
    ("'{0} of {1}' -f 3, 4", "3 of 4"),
    ("'abc' -like 'A*'; 'abc' -clike 'A*'", "True\nFalse"),
    ("'user=bob' -match 'user=(\\w+)'; $Matches[1]", "True\nbob"),
    ("1, 2, 3, 4 -gt 2", "3\n4"),
    ("'a', 'b' -contains 'B'; 'x' -in 'a', 'b'", "True\nFalse"),
    ("'10.10.1.5' -replace '\\d+$', 'x'", "10.10.1.x"),
    ("('a,b,,c' -split ',').Count", "4"),
    ("$x = @(1, 2, 3); $x += 4; $x.Count; $x[-1]", "4\n4"),
    ("$h = @{ a = 1; b = 'x' }; $h.a; $h['B']; $h.Count", "1\nx\n2"),
    ("[int]'42' + 1", "43"),
    ("$d = [datetime]'2026-10-21T09:12:45'; $d.ToString('yyyy-MM-dd HH:mm'); $d.AddHours(2).Hour; $d.DayOfWeek",
     "2026-10-21 09:12\n11\nWednesday"),
    ("(New-TimeSpan -Start '2026-10-12T08:43:06' -End '2026-10-12T09:20:44').TotalMinutes", "37.6333333333333"),
    ("foreach ($i in 1..3) { $i * 2 }", "2\n4\n6"),
    ("if (5 -gt 3) { 'yes' } else { 'no' }", "yes"),
    ("$n = 0; while ($n -lt 3) { $n++ }; $n", "3"),
    ("'hello'.ToUpper(); 'a-b-c'.Split('-')[1]; '  x '.Trim().Length", "HELLO\nb\n1"),
    ("(1..5 | Measure-Object -Sum).Sum", "15"),
    ("(1..10).Where({ $_ % 2 -eq 0 }).Count", "5"),
    ("\"Home: $HOME, count: $(1 + 1)\"", f"Home: {HOME}, count: 2"),
    (f"({CSV} | Where-Object result -eq FAILURE | Select-Object -ExpandProperty username -Unique).Count", "23"),
    (f"{CSV} | Where-Object event_code -eq 4740 | ForEach-Object {{ $_.username }}", "m.jones\ne.wilson"),
    (f"({CSV} | Group-Object event_code | Sort-Object Name).Name -join ','", "4624,4625,4634,4723,4740,4767"),
    ("(Get-WinEvent -Path logs/windows_security.evtx -MaxEvents 1).Id", "4634"),
    ("(Get-WinEvent -Path logs/windows_security.evtx -Oldest -MaxEvents 1).RecordId", "48201"),
    (f"(Get-WinEvent -FilterHashtable @{{ Path = {EVTX}; TargetUserName = 'adminstrator' }}).Id", "4625"),
    (f"(Get-WinEvent -FilterHashtable @{{ Path = {EVTX}; Id = 4624, 4625 }}).Count", "12"),
    (f"([xml](Get-WinEvent -FilterHashtable @{{ Path = {EVTX}; Id = 4767 }}).ToXml()).Event.System.EventID", "4767"),
    ("Get-Content logs/linux_auth.log | grep -c 'Failed password'", "19"),
    ("Test-Path logs/linux_auth.log; Test-Path nothing", "True\nFalse"),
    ("Set-Location logs; (Get-Location).Path", f"{HOME}/logs"),
])
def test_expressions_and_pipelines(ps, line, expected):
    output, error = run(ps, line)
    assert not error, (line, error)
    assert output.strip("\n") == expected, line


def test_tables_and_lists(ps):
    output, _ = run(ps, f"{CSV} | Select-Object -First 3 username, event_code, result")
    assert output.split("\n")[1:4] == ["username   event_code result", "--------   ---------- ------",
                                      "svc_backup 4624       SUCCESS"]
    output, _ = run(ps, f"{CSV} | Select-Object -First 1")
    assert "event_id       : EVT-000001" in output  # more than four properties: a list
    output, _ = run(ps, f"{CSV} | Group-Object event_code -NoElement")
    assert "  634 4624" in output
    output, _ = run(ps, "Get-ChildItem logs")
    assert "Directory: /home/analyst/logs" in output and "linux_auth.log" in output
    output, _ = run(ps, f"{CSV} | Select-Object -First 1 | Get-Member -MemberType NoteProperty")
    assert "event_code     NoteProperty string event_code=4624" in output


@pytest.mark.parametrize("line, message", [
    ("Get-Content nope.txt", "Get-Content: Cannot find path '/home/analyst/nope.txt' because it does not exist."),
    ("Get-Foo", "Get-Foo: The term 'Get-Foo' is not recognized"),
    ("$null.Trim()", "You cannot call a method on a null-valued expression."),
    ("Get-ChildItem -Bogus", "A parameter cannot be found that matches parameter name 'Bogus'."),
    ("Get-WinEvent -LogName Security", "Live logs such as 'Security' exist only on Windows."),
    ("Get-WinEvent -Path logs/windows_security.xml", "For an exported XML file use"),
    (f"Get-WinEvent -FilterHashtable @{{ Path = {EVTX}; Id = 9999 }}", "No events were found"),
    ("'x' | Out-File logs/new.txt", "Access to the path '/home/analyst/logs/new.txt' is denied."),
    ("1 +", "ParserError"),
    ("Invoke-WebRequest https://example.com", "not available in the simulated terminal"),
    ("[foo]'x'", "Unable to find type [foo]."),
])
def test_errors_look_like_powershell(ps, line, message):
    _, error = run(ps, line)
    assert message in error, (line, error)


def test_files_in_home_and_variables_between_commands(ps):
    run(ps, "$failures = Import-Csv logs/sample_auth_logs.csv | Where-Object result -eq FAILURE")
    assert run(ps, "$failures.Count") == ("165\n", "")
    run(ps, "$failures | Select-Object -First 2 username, source_ip | Export-Csv failures.csv -NoTypeInformation")
    assert run(ps, "(Import-Csv failures.csv).Count") == ("2\n", "")
    assert run(ps, "Get-Content failures.csv -TotalCount 1") == ('"username","source_ip"\n', "")
    assert ps.run("Clear-Host").clear
    assert "Get-WinEvent" in run(ps, "Get-Help")[0] and "-FilterHashtable" in run(ps, "Get-Help Get-WinEvent")[0]


# ---------------------------------------------------------------------------
# Same output as the real PowerShell in the Docker container
# ---------------------------------------------------------------------------
SAME_AS_REAL = [
    f"{CSV} | Select-Object -First 2",
    f"{CSV} | Where-Object event_code -eq 4740 | Group-Object username",
    f"{CSV} | Group-Object event_code -NoElement",
    f"{CSV} | Select-Object -First 1 | Get-Member",
    f"{CSV} | Measure-Object",
    "(Get-Content logs/entra_signins.json -Raw | ConvertFrom-Json).value[0]",
    "$log = [xml](Get-Content logs/windows_security.xml -Raw); $log.Events.Event[0]",
    "$log = [xml](Get-Content logs/windows_security.xml -Raw); $log.Events.Event[0].System",
    "$log = [xml](Get-Content logs/windows_security.xml -Raw); $log.Events.Event[0].EventData.Data",
    f"{CSV} | Select-Object -First 3 username, event_code, result",
    f"{CSV} | Measure-Object -Property event_code -Sum -Average -Maximum",
    f"{CSV} | Where-Object result -eq FAILURE | Group-Object source_ip | Sort-Object Count -Descending | Select-Object -First 3 Count, Name",
    f"{CSV} | Where-Object username -eq 'c.evans' | Where-Object logon_type -eq REMOTE_INTERACTIVE | Format-Table timestamp, hostname, source_ip",
    f"{CSV} | Select-Object -Last 2 | Format-List username, timestamp",
    "Get-WinEvent -Path logs/windows_security.evtx -MaxEvents 3",
    f"Get-WinEvent -FilterHashtable @{{ Path = {EVTX}; Id = 4740 }} | Format-List Id, TimeCreated, Message",
    f"{CSV} | Select-Object -ExpandProperty username -Unique | Measure-Object | Select-Object -ExpandProperty Count",
    "Get-ChildItem logs | Select-Object Name, Length",
    f"{CSV} | Select-Object -First 1 | ConvertTo-Json",
    "$c = 0; Get-Content logs/linux_auth.log | ForEach-Object { if ($_ -match 'Invalid user (\\S+)') { $c++ } }; $c",
    "$s = Get-Content logs/entra_signins.json -Raw | ConvertFrom-Json; $s.value | Where-Object { $_.status.errorCode -eq 50126 } | Select-Object -ExpandProperty ipAddress -Unique",
    "Get-Date -Date '2026-10-21T09:12:45'",
    "Get-Content nope.txt",
]


def normalise(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r", "").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


@pytest.fixture(scope="module")
def running_terminal(challenge_set):
    if not terminal.docker_status().ready:
        pytest.skip("Docker engine not available")
    was_running = terminal.container_running()
    terminal.start(challenge_set.files())
    yield
    if not was_running:
        terminal.stop()


def test_simulator_matches_the_real_powershell(running_terminal, ps):
    for line in SAME_AS_REAL:
        ps.cwd = HOME
        simulated = ps.run(line)
        real = terminal.run_in_container(
            "$PSStyle.OutputRendering = 'PlainText'; " + line + " | Out-String -Width 120 -Stream", "powershell")
        assert normalise(simulated.output) == normalise(real.stdout), line
        assert bool(simulated.error) == bool(real.stderr.strip()), line
