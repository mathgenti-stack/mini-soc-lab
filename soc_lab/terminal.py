"""Terminal tab: a real Linux shell (phase 1) and PowerShell 7 (phase 2) in a local Docker container,
shown in the browser by ttyd.

The dashboard builds the image from terminal/Dockerfile, starts one container and embeds
http://localhost:<port>; the address picks the shell (`?arg=powershell` for PowerShell, see
terminal/lab-shell). Windows Home cannot run Windows containers, so PowerShell runs on Linux too:
its Get-WinEvent is a lab version that reads .evtx files (terminal/SocLab). Everything goes through the `docker` command line, so no extra Python
package is needed. The container is locked down for a practice box on a personal computer:

- the port is published on 127.0.0.1 only, so other machines on the network cannot reach the shell;
- the lab's log files are bind-mounted read-only, and the container runs as an ordinary user;
- all Linux capabilities are dropped, privilege escalation is blocked, and memory, CPU and the
  number of processes are limited;
- the container is removed when it stops (`--rm`): files created inside it do not survive.

This needs Docker on the computer running the dashboard. The in-browser build (Pyodide) has no
processes at all; phase 3 will add a simulated terminal for it.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import PROJECT_ROOT

IMAGE = "mini-soc-lab-terminal"
CONTAINER = "mini-soc-lab-terminal"
DOCKER_DIR = PROJECT_ROOT / "terminal"
HOME = "/home/analyst"
DEFAULT_PORT = 7681
DOCKER_ENVIRONMENTS = ("linux", "powershell")  # CMD exists only in the simulated terminal
# Lab code the container needs at run time, mounted read-only: the .evtx reader behind Get-WinEvent.
SUPPORT_FILES = {"/opt/soc-lab/lib/evtx.py": PROJECT_ROOT / "soc_lab" / "evtx.py"}
HASH_LABEL = "mini-soc-lab.build-hash"
IS_BROWSER = sys.platform == "emscripten"  # stlite / Pyodide: no subprocesses, no Docker


@dataclass(frozen=True)
class DockerStatus:
    state: str  # "browser", "no_docker", "engine_down" or "ready"
    detail: str = ""

    @property
    def ready(self) -> bool:
        return self.state == "ready"


class TerminalError(RuntimeError):
    """A docker command failed; the message is docker's own output."""


def terminal_port() -> int:
    try:
        return int(os.environ.get("SOC_LAB_TERMINAL_PORT", DEFAULT_PORT))
    except ValueError:
        return DEFAULT_PORT


def terminal_url(port: int | None = None, environment: str = "linux") -> str:
    """Address of the shell for an environment: bash by default, PowerShell with ?arg=powershell."""
    url = f"http://localhost:{port or terminal_port()}"
    return f"{url}/?arg=powershell" if environment == "powershell" else url


def _docker(*args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0  # no console window flashes
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=flags)


def docker_status() -> DockerStatus:
    if IS_BROWSER:
        return DockerStatus("browser")
    if shutil.which("docker") is None:
        return DockerStatus("no_docker")
    try:
        result = _docker("info", "--format", "{{.OSType}}", timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DockerStatus("engine_down", str(exc))
    if result.returncode != 0:
        output = (result.stderr or result.stdout).strip().splitlines()
        return DockerStatus("engine_down", output[-1] if output else "")
    if result.stdout.strip() != "linux":
        return DockerStatus("engine_down", f"Docker is running {result.stdout.strip()} containers; "
                                           "switch Docker Desktop to Linux containers.")
    return DockerStatus("ready")


# ---------------------------------------------------------------------------
# Image
# ---------------------------------------------------------------------------
def build_hash(docker_dir: Path = DOCKER_DIR) -> str:
    """Hash of the files the image is built from: a change to any of them means the image must be rebuilt."""
    digest = hashlib.sha256()
    for path in sorted(p for p in docker_dir.rglob("*") if p.is_file()):
        digest.update(path.relative_to(docker_dir).as_posix().encode())
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()[:16]


def image_up_to_date() -> bool:
    result = _docker("image", "inspect", IMAGE, "--format", f'{{{{ index .Config.Labels "{HASH_LABEL}" }}}}')
    return result.returncode == 0 and result.stdout.strip() == build_hash()


def build_image(timeout: float = 900) -> None:
    result = _docker("build", "--pull", "--tag", IMAGE, "--label", f"{HASH_LABEL}={build_hash()}", str(DOCKER_DIR),
                     timeout=timeout)
    if result.returncode != 0:
        raise TerminalError(_tail(result))


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------
def run_arguments(files: dict[str, Path], port: int) -> list[str]:
    """The `docker run` arguments: hardened, local-only, logs mounted read-only."""
    args = ["run", "--detach", "--rm", "--name", CONTAINER,
            "--publish", f"127.0.0.1:{port}:7681",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
            "--hostname", "soc-lab"]
    mounts = {f"{HOME}/{target}": source for target, source in files.items()} | SUPPORT_FILES
    for target, source in sorted(mounts.items()):
        args += ["--mount", f"type=bind,source={Path(source).resolve()},target={target},readonly"]
    return [*args, IMAGE]


def container_running() -> bool:
    result = _docker("ps", "--filter", f"name=^{CONTAINER}$", "--format", "{{.Names}}")
    return result.returncode == 0 and CONTAINER in result.stdout.split()


def start(files: dict[str, Path], port: int | None = None) -> None:
    """Build the image if it is missing or out of date, then start the container (if not already running)."""
    missing = [str(path) for path in [*files.values(), *SUPPORT_FILES.values()] if not Path(path).is_file()]
    if missing:
        raise TerminalError(f"missing log file(s): {', '.join(missing)}")
    if container_running():
        return
    if not image_up_to_date():
        build_image()
    _docker("rm", "--force", CONTAINER)  # a stopped leftover with the same name would block the start
    result = _docker(*run_arguments(files, port or terminal_port()), timeout=60)
    if result.returncode != 0:
        raise TerminalError(_tail(result))


def stop() -> None:
    result = _docker("stop", "-t", "2", CONTAINER, timeout=30)
    if result.returncode != 0 and container_running():
        raise TerminalError(_tail(result))


def run_in_container(command: str, environment: str = "linux", timeout: float = 30) -> subprocess.CompletedProcess:
    """Run a command as the analyst, from the home directory, in bash or PowerShell (used by the tests)."""
    if environment == "powershell":
        shell = ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]
    else:
        shell = ["bash", "-c", command]
    return _docker("exec", "--workdir", HOME, CONTAINER, *shell, timeout=timeout)


def _tail(result: subprocess.CompletedProcess, lines: int = 6) -> str:
    output = (result.stderr or result.stdout or "").strip().splitlines()
    return "\n".join(output[-lines:]) or f"docker exited with code {result.returncode}"
