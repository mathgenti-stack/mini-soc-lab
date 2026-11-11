# Terminal: practise on a shell

The **Terminal** tab works like a TryHackMe room. On one side is a list of challenges. On the other is a shell where you investigate **this lab's own logs** with the commands an analyst uses every day. Choose the shell at the top of the tab:

- **Linux (bash)**: `grep`, `awk`, `sort | uniq -c`, `cut`, `jq`.
- **PowerShell**: `Import-Csv`, `Where-Object`, `Group-Object`, `[xml]`, `ConvertFrom-Json` and `Get-WinEvent`, for Windows security events (4624, 4625, 4740, 4767).
- **CMD (Windows)**: `type`, `find`, `findstr`, `for /f`, the Command Prompt that is still on every Windows server.

You type the answer in the dashboard and it is checked at once. Hints and the solution, with an explanation of why it matters, are there when you need them.

There are two kinds of terminal:

- **Simulated** (the default): written in Python, it runs inside the page itself. It works everywhere the dashboard works: on a computer without Docker, on the Cloudflare site and on a phone. It has the three shells.
- **Real (Docker)**: a real Debian Linux with bash and PowerShell 7, in a container on your own computer. Choose *Real (Docker)* above the terminal. It is not offered on the website or for CMD.

The tab was built in three phases. The challenges live in one file, `data/terminal/challenges.json`, shared by all of them.

| Phase | Terminal | Where it runs | Status |
| --- | --- | --- | --- |
| 1 | Linux (bash) in a Docker container, shown in the page by `ttyd` | Your own computer, with Docker | **Done** |
| 2 | PowerShell 7 in the same Linux container, for Windows events (4624, 4625, 4740) | Your own computer, with Docker | **Done** |
| 3 | Simulated bash, PowerShell and CMD, in Python (`soc_lab/sim`) | Anywhere: computer, phone, the Cloudflare site, no server | **Done** |

## The simulated terminal

Type a command in the box under the screen and press Enter. `help` (bash and CMD) or `Get-Help` (PowerShell) lists the commands it knows. *Reset terminal* starts a fresh session.

It is a simulation, written for the lab in `soc_lab/sim/` with the Python standard library only, so it also runs in the browser build (stlite/Pyodide):

| Shell | Module | What it does |
| --- | --- | --- |
| bash | `bash.py`, `awk.py`, `jq.py`, `regex.py` | Quotes, `$VAR`, `$(...)`, globs, pipes, `< > >>`, `; && \|\|`; `ls cd cat head tail wc grep sort uniq cut tr sed awk jq file tree echo printf` and more, with GNU's output format. `awk` and `jq` are small versions of the real ones. |
| PowerShell | `ps_parser.py`, `powershell.py`, `ps_values.py`, `ps_format.py` | A parser and an interpreter where commands pass **objects**: about fifty cmdlets (`Import-Csv`, `Where-Object`, `Select-Object`, `Group-Object`, `Get-WinEvent`...), `-eq -like -match`, `$_`, script blocks, `[xml]`, hashtables, methods. Results print as tables and lists like PowerShell 7. Aliases (`ls`, `cat`, `where`, `%`) work as on Windows, and `grep`, `wc`... run as native programs, as in PowerShell on Linux. |
| CMD | `cmd.py` | `C:\Users\analyst`, `%VARIABLES%`, `^`, pipes, `& && \|\|`, and `dir cd type more find findstr sort echo set for /f if tree` and more. Paths and commands ignore case. |

How close it is, and how that is checked:

- Every challenge solution runs in the simulator (`tests/test_sim_*.py`).
- A list of everyday commands is run in **both** the simulator and the real shell, and the outputs must be identical: bash and PowerShell against the Docker container, CMD against `cmd.exe` on Windows. These tests are skipped when Docker or Windows is not available.
- What it does not do: processes, the network, editors (`vim`, `nano`), job control, scripts and functions, `switch`, `try`, XPath. These commands answer with a clear *not supported in the simulated terminal* instead of failing silently. Very long outputs are cut at 2,000 lines.
- The logs are read-only, as in the container. You can create files in the home folder (`echo x > notes.txt`, `Export-Csv`); they live in memory until you reset or leave the page.

## The real terminal (Docker)

### Setting it up (Windows)

Docker Desktop runs Linux containers through WSL 2, which also works on Windows Home:

1. Install WSL once: open PowerShell **as administrator**, run `wsl --install` and restart the computer.
2. Install and open **Docker Desktop**, and wait until it shows *Engine running*.
3. In the dashboard, open **Terminal**, choose *Real (Docker)* and press **Start terminal**. The first start builds the image from `terminal/Dockerfile` (Debian with PowerShell, about 500 MB, a few minutes, needs the internet once). Later starts take seconds.

From the command line:

```bash
python -m soc_lab.cli terminal start    # builds the image if needed, then starts it
python -m soc_lab.cli terminal status
python -m soc_lab.cli terminal stop
```

The terminal is at http://localhost:7681 (bash) and http://localhost:7681/?arg=powershell (PowerShell). To use another port, set `SOC_LAB_TERMINAL_PORT` before starting the dashboard. You can also type `pwsh` in bash, and `exit` to go back.

### What is inside

- Debian with `bash`, `grep`, `gawk`, `sed`, `less`, `jq`, `file`, `tree`, `nano` and `vim`.
- **PowerShell 7.6** (LTS), the official Linux build, pinned to a version and checked against its published SHA-256.
- A lab version of **`Get-WinEvent`** (see below), and `python3`, which runs the `.evtx` reader behind it.
- The lab's files, in `~/logs`, **read-only** (the simulated terminal has the same files):

| In the terminal | Lab file |
| --- | --- |
| `~/logs/linux_auth.log` | `data/examples/linux_auth.log` |
| `~/logs/windows_security.xml` | `data/examples/windows_security.xml` |
| `~/logs/windows_security.evtx` | `data/examples/windows_security.evtx` (the same events, binary) |
| `~/logs/entra_signins.json` | `data/examples/entra_signins.json` |
| `~/logs/sample_auth_logs.csv` | `data/sample_auth_logs.csv` (the two-week dataset) |
| `~/logs/sysmon.json` | `data/examples/sysmon.json` (Sysmon events of `l.taylor`'s computer, 14 October) |
| `~/logs/proxy.csv` | `data/examples/proxy.csv` (web proxy log, 14 October) |

The files are mounted when the container starts, so the terminal always shows the current data.

On Windows, `ls -l logs` shows the files as `rwxrwxrwx`. The Windows file system does not store Linux permissions, so Docker shows everything as allowed. The mount itself is still read-only: `touch logs/linux_auth.log` fails with *Read-only file system*, and the tests check this.

### PowerShell on Linux, and `Get-WinEvent`

Windows Home cannot run Windows containers, so PowerShell runs in the same Linux container. Almost everything works as on Windows: `Import-Csv`, `Where-Object`, `Group-Object`, `Sort-Object`, `Select-Object`, `[xml]`, `ConvertFrom-Json`, `Get-Member`.

The exception is **`Get-WinEvent`**, which exists only in PowerShell on Windows. The terminal has a **lab version** of it (module `terminal/SocLab`; the simulated PowerShell has the same one). It reads `.evtx` files with the dashboard's own reader (`soc_lab/evtx.py`, mounted read-only into the container) and returns objects shaped like the real ones (`TimeCreated`, `Id`, `LevelDisplayName`, `Message`, `RecordId`, `Properties`, `ToXml()`), newest first:

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

### Safety

The container is a practice box on a personal computer, and it is locked down accordingly (`soc_lab/terminal.py`):

- The port is published on **127.0.0.1 only**: other machines on the network cannot reach the shell.
- You are the user `analyst`, not root, and there is no `sudo`.
- All Linux capabilities are dropped and privilege escalation is blocked (`--cap-drop ALL`, `no-new-privileges`).
- Memory (512 MB, PowerShell needs more than bash), CPU (1) and the number of processes (256) are limited.
- The page address chooses the shell (`?arg=powershell`). `terminal/lab-shell` accepts only bash or PowerShell; any other value opens bash.
- The logs are read-only. The container is deleted when it stops (`--rm`), so anything you create there disappears.

Limits: the container can still reach the internet (publishing a port needs a network). Do not paste real logs or secrets into it. It is a lab for synthetic data.

## The challenges

There are 44 challenges: 17 for Linux, 17 for PowerShell and 10 for CMD.

**Linux**, in four levels: **basics** (`wc`, `head`), **searching and pipes** (`grep`, `awk`, `sort | uniq -c`), **investigation on the two-week dataset** (CSV columns with `awk -F,` and `cut`), and **other formats** (Entra ID JSON with `jq`, Windows XML). Each one follows a scenario the dashboard also detects: the SSH brute force, the password spray that found `l.taylor`, and `c.evans`'s unusual Remote Desktop logon (R006).

**PowerShell**, in four levels: **objects** (`Get-ChildItem`, `Import-Csv`, `Get-Member`), **filtering and grouping** (`Where-Object`, `Group-Object`, the noisy service account with an expired password), **investigation** (the two lockouts 4740 compared, the unlock 4767 in the Windows XML, the time the password spray got in), and **`Get-WinEvent`** on the `.evtx` file and Entra ID JSON with `ConvertFrom-Json`.

**CMD**, in four levels: counting with `find /c` (and the `find /c /v ""` trick that counts lines), case with `/i`, several words at once with `findstr`, CSV values with their commas, chains of `find` as an AND, a user's events in the Windows XML, and cutting a line into words with `for /f`.

**After the logon** (the last challenges of each shell): two days after the password spray, `l.taylor` opens an invoice on `LON-WS-006`. `logs/sysmon.json` (Sysmon events 1, 3, 11, 13 and 22) shows Word starting an encoded PowerShell, which downloads a DLL run by `rundll32.exe`; the DLL runs discovery commands, sets a Run key and zips a folder. `logs/proxy.csv` shows the download, a beacon every minute to `cdn-update.example.net` and a 46 MB upload to `files.example.org`. The challenges find the parent process, the child process, the commands the malware ran, the beacon, the volume sent and the blocked requests. Attacker domains use `example.net` and `example.org` (RFC 2606), like the IP addresses use the documentation ranges.

### The study pages (`estudar.html`)

The course's explanations live next to the lab on the website, in `estudar.html` (in Portuguese): topics with an explanation, a checklist and a quiz, plus review tools (recap, flashcards, scenarios, diagrams, glossary). The path has two phases: **phase 1, Service Desk / IT Support** (the foundation: computers, Windows, networks, command line, user support, troubleshooting, accounts and Microsoft 365) and **phase 2, SOC**. Phase 1 has its own practice, the **ticket queue** (*Fila de chamados*, menu *Chamados*): 14 fictional tickets worked in five steps (triage with impact × urgency, questions to the user, diagnosis in a terminal with ready-made outputs, the fix or escalation, and the ticket note, checked for key items). Tickets live in `curso/chamados.py`, the engine in `curso/chamados.js`; `python curso/montar.py` writes both into the page, and the build refuses a ticket whose model note fails its own check. A topic's *Praticar* step lists its lab challenges and its tickets. It is a single page with no server. Open it from the **Study** button in the dashboard's sidebar. Study and practice point to each other:

- **From a challenge to the explanation.** Under the hints, each challenge shows *Stuck on the idea?*, with links to the topics that explain it (for example `linux-03` → Linux basics and Operating system security). The page opens directly on that topic (`estudar.html#linux`).
- **From a topic to the challenges.** Each topic with exercises has a *Praticar* (practise) tab listing them, read from `challenges.json`. Each one opens the lab directly on that challenge with `?challenge=<id>`: the Terminal tab, the right shell and the challenge chosen. The link is read once and then removed from the address.
- **Progress.** On the website, the lab saves its progress in the browser: `index.html` keeps `/mnt` in IndexedDB (`idbfsMountpoints`) and points `SOC_LAB_ANSWERS_DIR` at `/mnt/soclab`, so solved challenges survive a reload. `estudar.html` reads those files (read-only), shows ✅ next to solved challenges and ticks the topic's "Praticar no SOC Lab" checklist item when all are solved. The study page keeps its own progress in `localStorage`. Without an account, both stay in that browser.

#### Editing the course

The topics are organised as a path of 7 modules (*Trilha*). Inside a topic, a step bar leads the learner through **read → practise in the lab → quiz → checklist**, and the *Hoje* (today) page always shows where to continue. The topics that were added from what junior SOC job ads ask for (PowerShell, logs, SIEM queries, phishing, triage and incident response) live as sources in `curso/`:

- `curso/topicos_novos.py`: the new topics (text, checklist), their 1-minute summaries and the path (`TRILHA`).
- `curso/quiz_novo.py`: their quiz questions, with why each wrong answer is wrong.
- `curso/visual.css`: the look of the page.

After editing them, run `python curso/montar.py`: it writes them into `estudar.html` between `/* >>> curso */` and `/* <<< curso */` marks and can be run again safely. A test fails if the page is not up to date. The older topics are edited directly in `estudar.html`.

#### Optional account: progress in the cloud (`conta.js`)

People can sign in with their e-mail to keep their progress in the cloud and continue on another computer. There is no password: [Supabase](https://supabase.com) Auth sends a 6-digit code (`signInWithOtp` + `verifyOtp`). Everything still works without signing in.

- **What is stored.** One row per person in `public.progress`: `course` (the study page's `localStorage` state) and `lab` (the files under `/mnt/soclab`, as text). Row level security lets each person read and change only their own row. The schema is recorded in `supabase/migrations/`.
- **When it syncs.** The study page merges with the cloud when it opens, when you come back to its tab, and a moment after each change. The lab writes the cloud copy into `/mnt/soclab` *before* it starts (the lab reads the folder once, at start-up), then sends changes every 15 seconds and when its tab is hidden. If the server does not answer within 5 seconds, the lab opens with what is in the browser.
- **How conflicts are solved.** Solved and revealed challenges are merged (solved anywhere counts as solved). Training answers keep the newest version (`updated`). For the study page, the first sign-in on a browser merges both copies; after that, the browser's copy wins if it has unsent changes, otherwise the cloud's.
- **Sign out** keeps the progress in the cloud and empties this browser (shared computers). **Apagar minha conta** (delete my account) calls `delete_my_account()`, which deletes the user; the progress row goes with it.
- **Privacy.** `privacidade.html` explains what is stored, where (Supabase, United States) and how to delete it.
- **Feedback.** A *Feedback* button (bottom right, on the study pages and in the lab) sends a message with where the person was (topic and tab, or the lab tab and challenge) to `public.feedback`. Anyone can send, signed in or not; only the admin can read it.
- **Admin page.** The admin (e-mails listed in `public.admins`, a table the API cannot read) gets a *Painel do admin* button in the account window (or opens `estudar.html#admin`). It lists every account with last access, checklist progress, quiz answers and accuracy, lab challenges solved, study days and topics in progress, plus the feedback (mark as resolved, delete). The data comes from `admin_overview()`, which refuses anyone who is not an admin. The page code is `admin.js`.
- **Keys.** The site contains only the project's public (*publishable*) key. It gives access to nothing beyond what the row level security policies allow. The secret key is never used in the site.

E-mail delivery needs two settings in the Supabase dashboard: the *Magic link* e-mail template must contain `{{ .Token }}` (so the e-mail carries the code), and a custom SMTP server, because the built-in one only sends to the project's team, a few times per hour.

To try both together on your computer, serve the folder as a static site: `python -m http.server 8000`, then open http://localhost:8000/ (the lab) and http://localhost:8000/estudar.html. The Streamlit dashboard (`streamlit run`) links to the study pages on the website instead.

Progress is saved per shell, in `training_answers/terminal_<shell>.json` (`linux`, `powershell`, `cmd`). A challenge counts as solved only when answered. Showing the solution marks it 👁️ but does not count it as solved.

### Format of `challenges.json`

```json
{
  "environments": {"linux": {"home": "/home/analyst", "files": {"logs/linux_auth.log": "data/examples/linux_auth.log"}}},
  "challenges": [{
    "id": "linux-03", "environments": ["linux"], "level": 2, "topic": "grep",
    "files": ["logs/linux_auth.log"],
    "roadmap": ["linux", "segso"],
    "title": {"en": "...", "pt-BR": "..."}, "question": {"en": "...", "pt-BR": "..."},
    "hints": [{"en": "...", "pt-BR": "..."}],
    "answers": ["19"],
    "solution": "grep -c 'Failed password' logs/linux_auth.log",
    "explanation": {"en": "...", "pt-BR": "..."}
  }]
}
```

- Texts are inside the file, in every language, so any terminal can use it without the Python translation files.
- `answers` lists every accepted answer. Case, accents, surrounding quotes and extra spaces are ignored.
- `solution` must print exactly the answer. `tests/test_terminal.py` checks every answer against the lab data in Python; the simulator tests run every solution in the simulated shell; with Docker running, the bash and PowerShell solutions also run in the real container. If the logs or the generator change, these tests say which answers to update.
- `roadmap` lists the study page topics (`estudar.html`) that explain the challenge. They must be declared in the top-level `roadmap.topics` (a plain lowercase id and a name per language), and `roadmap.url` must be `https://`.
- Environments: `linux`, `powershell` and `cmd`. One container serves bash and PowerShell, so it mounts the files of every environment.
