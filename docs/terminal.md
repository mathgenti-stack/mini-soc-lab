# Terminal: practise on a real Linux shell

The **Terminal** tab works like a TryHackMe room. On one side is a list of challenges. On the other is a real Linux shell where you investigate **this lab's own logs** with the commands an analyst uses every day: `grep`, `awk`, `sort | uniq -c`, `cut`, `jq`. You type the answer in the dashboard and it is checked at once. Hints and the solution, with an explanation of why it matters, are there when you need them.

The tab is built in three phases. The challenges live in one file, `data/terminal/challenges.json`, shared by all three.

| Phase | Terminal | Where it runs | Status |
| --- | --- | --- | --- |
| 1 | Linux (bash) in a Docker container, shown in the page by `ttyd` | Your own computer, with Docker | **Done** |
| 2 | PowerShell in the same Linux container, for Windows events (4624, 4625, 4740) | Your own computer, with Docker | Planned |
| 3 | Simulated Linux, PowerShell and CMD terminal written in JavaScript | Any browser, mobile and the Cloudflare site, no server | Planned |

## Setting it up (Windows)

Docker Desktop runs Linux containers through WSL 2, which also works on Windows Home:

1. Install WSL once: open PowerShell **as administrator**, run `wsl --install` and restart the computer.
2. Install and open **Docker Desktop**, and wait until it shows *Engine running*.
3. In the dashboard, open **Terminal** and press **Start terminal**. The first start builds the image from `terminal/Dockerfile` (Debian, a few minutes, needs the internet once). Later starts take seconds.

From the command line:

```bash
python -m soc_lab.cli terminal start    # builds the image if needed, then starts it
python -m soc_lab.cli terminal status
python -m soc_lab.cli terminal stop
```

The terminal is at http://localhost:7681. To use another port, set `SOC_LAB_TERMINAL_PORT` before starting the dashboard.

## What is inside

- Debian with `bash`, `grep`, `gawk`, `sed`, `less`, `jq`, `file`, `tree`, `nano` and `vim`.
- The lab's files, in `~/logs`, **read-only**:

| In the terminal | Lab file |
| --- | --- |
| `~/logs/linux_auth.log` | `data/examples/linux_auth.log` |
| `~/logs/windows_security.xml` | `data/examples/windows_security.xml` |
| `~/logs/entra_signins.json` | `data/examples/entra_signins.json` |
| `~/logs/sample_auth_logs.csv` | `data/sample_auth_logs.csv` (the two-week dataset) |

The files are mounted when the container starts, so the terminal always shows the current data.

On Windows, `ls -l logs` shows the files as `rwxrwxrwx`. The Windows file system does not store Linux permissions, so Docker shows everything as allowed. The mount itself is still read-only: `touch logs/linux_auth.log` fails with *Read-only file system*, and the tests check this.

## Safety

The container is a practice box on a personal computer, and it is locked down accordingly (`soc_lab/terminal.py`):

- The port is published on **127.0.0.1 only**: other machines on the network cannot reach the shell.
- You are the user `analyst`, not root, and there is no `sudo`.
- All Linux capabilities are dropped and privilege escalation is blocked (`--cap-drop ALL`, `no-new-privileges`).
- Memory (256 MB), CPU (1) and the number of processes (256) are limited.
- The logs are read-only. The container is deleted when it stops (`--rm`), so anything you create there disappears.

Limits: the container can still reach the internet (publishing a port needs a network). Do not paste real logs or secrets into it. It is a lab for synthetic data.

## The challenges

There are 14 Linux challenges in four levels: **basics** (`wc`, `head`), **searching and pipes** (`grep`, `awk`, `sort | uniq -c`), **investigation on the two-week dataset** (CSV columns with `awk -F,` and `cut`), and **other formats** (Entra ID JSON with `jq`, Windows XML). Each one follows a scenario the dashboard also detects: the SSH brute force, the password spray that found `l.taylor`, and `c.evans`'s unusual Remote Desktop logon (R006).

Progress is saved in `training_answers/terminal_linux.json`. A challenge counts as solved only when answered. Showing the solution marks it 👁️ but does not count it as solved.

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
- `solution` must print exactly the answer. With Docker running, `tests/test_terminal.py` runs every solution in the real container and checks it. Without Docker, it checks every answer against the lab data in Python. If the logs or the generator change, these tests say which answers to update.
- Phases 2 and 3 add environments (`powershell`, `cmd`) and list them in each challenge's `environments`.
