"""Simulated terminal (Terminal tab, phase 3): bash, PowerShell and CMD written in Python.

It runs wherever the dashboard runs, including the browser build (stlite / Pyodide) on the
Cloudflare site and on phones, so the challenges can be practised without Docker.
"""

from __future__ import annotations

from pathlib import Path

from .bash import BashShell
from .cmd import CmdShell
from .core import Result, Shell, VirtualFS, lab_files
from .powershell import PowerShellShell

SHELLS = {"linux": BashShell, "powershell": PowerShellShell, "cmd": CmdShell}


def new_shell(environment: str, files: dict[str, Path]) -> Shell:
    """A fresh simulated shell for an environment, with the lab's files in ~/logs."""
    return SHELLS[environment](VirtualFS(lab_files(files)))


__all__ = ["SHELLS", "Result", "Shell", "new_shell"]
