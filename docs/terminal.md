# Terminal: practise on a real shell

The **Terminal** tab works like a TryHackMe room. On one side is a list of challenges. On the other is a real shell where you investigate **this lab's own logs** with the commands an analyst uses every day. Choose the shell at the top of the tab:

- **Linux (bash)**: `grep`, `awk`, `sort | uniq -c`, `cut`, `jq`.
- **PowerShell**: `Import-Csv`, `Where-Object`, `Group-Object`, `[xml]`, `ConvertFrom-Json` and `Get-WinEvent`, for Windows security events (4624, 4625, 4740, 4767).
 You type the answer in the dashboard and it is checked at once. Hints and the solution, with an explanation of why it matters, are there when you need them.

The tab is built in three phases. The challenges live in one file, `data/terminal/challenges.json`, shared by all three.

| Phase | Terminal | Where it runs | Status |
| --- | --- | --- | --- |
| 1 | Linux (bash) in a Docker container, shown in the page by `ttyd` | Your own computer, with Docker | **Done** |
| 2 | PowerShell 7 in the same Linux container, for Windows events (4624, 4625, 4740) | Your own computer, with Docker | **Done** |
| 3 | Simulated Linux, PowerShell and CMD terminal written in JavaScript | Any browser, mobile and the Cloudflare site, no server | Planned |

## Setting it up (Windows)

Docker Desktop runs Linux containers through WSL 2, which also works on Windows Home:

1. Install WSL once: open PowerShell **as administrator**, run `wsl --install` and restart the computer.
2. Install and open **Docker Desktop**, and wait until it shows *Engine running*.
3. In the dashboard, open **Terminal** and press **Start terminal**. The first start builds the image from `terminal/Dockerfile` (Debian with PowerShell, about 500 MB, a few minutes, needs the internet once). Later starts take seconds.

From the command line:

```bash
python -m soc_lab.cli terminal start    # builds the image if needed, then starts it
python -m soc_lab.cli terminal status
python -m soc_lab.cli terminal stop
```

The terminal is at http://localhost:7681 (bash) and http://localhost:7681/?arg=powershell (PowerShell). To use another port, set `SOC_LAB_TERMINAL_PORT` before starting the dashboard. You can also type `pwsh` in bash, and `exit` to go back.

## What is inside

- Debian with `bash`, `grep`, `gawk`, `sed`, `less`, `jq`, `file`, `tree`, `nano` and `vim`.
- **PowerShell 7.6** (LTS), the official Linux build, pinned to a version and checked against its published SHA-256.
- A lab version of **`Get-WinEvent`** (see below), and `python3`, which runs the `.evtx` reader behind it.
- The lab's files, in `~/logs`, **read-only**:

| In the terminal | Lab file |
| --- | --- |
| `~/logs/linux_auth.log` | `data/examples/linux_auth.log` |
| `~/logs/windows_security.xml` | `data/examples/windows_security.xml` |
| `~/logs/windows_security.evtx` | `data/examples/windows_security.evtx` (the same events, binary) |
| `~/logs/entra_signins.json` | `data/examples/entra_signins.json` |
| `~/logs/sample_auth_logs.csv` | `data/sample_auth_logs.csv` (the two-week dataset) |

The files are mounted when the container starts, so the terminal always shows the current data.

On Windows, `ls -l logs` shows the files as `rwxrwxrwx`. The Windows file system does not store Linux permissions, so Docker shows everything as allowed. The mount itself is still read-only: `touch logs/linux_auth.log` fails with *Read-only file system*, and the tests check this.

## PowerShell on Linux, and `Get-WinEvent`

Windows Home cannot run Windows containers, so PowerShell runs in the same Linux container. Almost everything works as on Windows: `Import-Csv`, `Where-Object`, `Group-Object`, `Sort-Object`, `Select-Object`, `[xml]`, `ConvertFrom-Json`, `Get-Member`.

The exception is **`Get-WinEvent`**, which exists only in PowerShell on Windows. The terminal has a **lab version** of it (module `terminal/SocLab`). It reads `.evtx` files with the dashboard's own reader (`soc_lab/evtx.py`, mounted read-only into the container) and returns objects shaped like the real ones (`TimeCreated`, `Id`, `LevelDisplayName`, `Message`, `RecordId`, `Properties`, `ToXml()`), newest first:

```powershell
Get-WinEvent -Path ~/logs/windows_security.evtx -MaxEvents 5
Get-WinEvent -FilterHashtable @{ Path = "$HOME/logs/windows_security.evtx"; Id = 4625 }
Get-WinEvent -FilterHashtable @{ Path = "$HOME/logs/windows_security.evtx"; TargetUserName = 'j.smith' }
```

| Supported | Not supported |
| --- | --- |
| `-Path`, `-MaxEvents`, `-Oldest` | Live logs: `-LogName`, `-ListLog` (they exist only on Windows) |
| `-FilterHashtable` with `Path`, `Id`, `StartTime`, `EndTime`, `ProviderName`, `Level`, `Keywords`, `Data` and event data names (`TargetUserName`...) | `-FilterXPath`, `-FilterXml`, `-ComputerName` |

`Message` is a one-line description followed by the event data, not the full Windows text. On Windows, the same filters read the live log with `@{ LogName = 'Security'; Id = 4625 }`.

## Safety

The container is a practice box on a personal computer, and it is locked down accordingly (`soc_lab/terminal.py`):

- The port is published on **127.0.0.1 only**: other machines on the network cannot reach the shell.
- You are the user `analyst`, not root, and there is no `sudo`.
- All Linux capabilities are dropped and privilege escalation is blocked (`--cap-drop ALL`, `no-new-privileges`).
- Memory (512 MB, PowerShell needs more than bash), CPU (1) and the number of processes (256) are limited.
- The page address chooses the shell (`?arg=powershell`). `terminal/lab-shell` accepts only bash or PowerShell; any other value opens bash.
- The logs are read-only. The container is deleted when it stops (`--rm`), so anything you create there disappears.

Limits: the container can still reach the internet (publishing a port needs a network). Do not paste real logs or secrets into it. It is a lab for synthetic data.

## The challenges

There are 14 Linux challenges and 14 PowerShell challenges.

**Linux**, in four levels: **basics** (`wc`, `head`), **searching and pipes** (`grep`, `awk`, `sort | uniq -c`), **investigation on the two-week dataset** (CSV columns with `awk -F,` and `cut`), and **other formats** (Entra ID JSON with `jq`, Windows XML). Each one follows a scenario the dashboard also detects: the SSH brute force, the password spray that found `l.taylor`, and `c.evans`'s unusual Remote Desktop logon (R006).

**PowerShell**, in four levels: **objects** (`Get-ChildItem`, `Import-Csv`, `Get-Member`), **filtering and grouping** (`Where-Object`, `Group-Object`, the noisy service account with an expired password), **investigation** (the two lockouts 4740 compared, the unlock 4767 in the Windows XML, the time the password spray got in), and **`Get-WinEvent`** on the `.evtx` file and Entra ID JSON with `ConvertFrom-Json`.

Progress is saved per shell, in `training_answers/terminal_linux.json` and `training_answers/terminal_powershell.json`. A challenge counts as solved only when answered. Showing the solution marks it 👁️ but does not count it as solved.

### Format of `challenges.json`

```json
{
  "environments": {"linux": {"home": "/home/analyst", "files": {"logs/linux_auth.log": "data/examples/linux_auth.log"}}},
  "challenges": [{
    "id": "linux-03", "environments": ["linux"], "level": 2, "topic": "grep",
    "files": ["logs/linux_auth.log"],
    "title": {"en": "...", "pt-BR": "..."}, "question": {"en": "...", "pt-BR": "..."},
    "hints": [{"en": "...", "pt-BR": "..."}],
    "answers": ["19"],
    "solution": "grep -c 'Failed password' logs/linux_auth.log",
    "explanation": {"en": "...", "pt-BR": "..."}
  }]
}
```

- Texts are inside the file, in every language, so phase 3 (JavaScript) can use it without the Python translation files.
- `answers` lists every accepted answer. Case, accents, surrounding quotes and extra spaces are ignored.
- `solution` must print exactly the answer. With Docker running, `tests/test_terminal.py` runs every solution in the real container (in bash or PowerShell, by environment) and checks it. Without Docker, it checks every answer against the lab data in Python. If the logs or the generator change, these tests say which answers to update.
- Environments today: `linux` and `powershell`. Phase 3 adds `cmd`. One container serves both shells, so it mounts the files of every environment.
