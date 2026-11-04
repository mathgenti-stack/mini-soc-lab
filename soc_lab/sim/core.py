"""Shared pieces of the simulated terminal: the in-memory file system, results and the shell interface.

The simulated terminal (Terminal tab, phase 3) runs entirely in Python, so it works wherever the
dashboard works: on a computer without Docker, and in the browser build (stlite / Pyodide) on the
Cloudflare site and on a phone. It imitates bash, PowerShell and CMD closely enough for the
challenges and for the everyday commands an analyst types on logs. It is not a real shell: no
processes, no network, and only the lab's files.
"""

from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

HOME = "/home/analyst"
LOGS = f"{HOME}/logs"
USER = "analyst"
HOST = "soc-lab"
MAX_OUTPUT_LINES = 2000  # longer outputs are cut, so a `cat` of the big CSV stays readable on a phone


class ShellError(Exception):
    """A message the shell prints as an error, e.g. "grep: x: No such file or directory"."""


class Unsupported(ShellError):
    """A command or option the simulator does not know (the message says so, in the shell's style)."""


@dataclass
class Result:
    output: str = ""
    error: str = ""
    clear: bool = False  # `clear` / `cls` / `Clear-Host`: the terminal empties its screen

    @property
    def ok(self) -> bool:
        return not self.error


class VirtualFS:
    """Files of the simulated terminal, by absolute POSIX path. The logs folder is read-only."""

    def __init__(self, files: dict[str, bytes] | None = None):
        self.files: dict[str, bytes] = {}
        self.dirs: set[str] = {"/", "/home", HOME, LOGS}
        for path, data in (files or {}).items():
            self.files[path] = data
            self._add_parents(path)

    def _add_parents(self, path: str) -> None:
        parent = posixpath.dirname(path)
        while parent not in self.dirs:
            self.dirs.add(parent)
            parent = posixpath.dirname(parent)

    def is_file(self, path: str) -> bool:
        return path in self.files

    def is_dir(self, path: str) -> bool:
        return path in self.dirs

    def exists(self, path: str) -> bool:
        return self.is_file(path) or self.is_dir(path)

    def read_bytes(self, path: str) -> bytes:
        return self.files[path]

    def read_text(self, path: str) -> str:
        return decode(self.files[path])

    def is_binary(self, path: str) -> bool:
        return b"\x00" in self.files[path][:4096]

    def size(self, path: str) -> int:
        return len(self.files[path]) if path in self.files else 4096

    def listdir(self, path: str) -> list[str]:
        prefix = path.rstrip("/") + "/"
        names = {p[len(prefix):].split("/")[0] for p in [*self.files, *self.dirs] if p.startswith(prefix) and p != prefix}
        return sorted(names)

    def writable(self, path: str) -> bool:
        return path.startswith(HOME + "/") and not (path == LOGS or path.startswith(LOGS + "/"))

    def write(self, path: str, data: bytes, append: bool = False) -> None:
        if not self.writable(path):
            raise PermissionError(path)
        if self.is_dir(path):
            raise IsADirectoryError(path)
        if not self.is_dir(posixpath.dirname(path)):
            raise FileNotFoundError(path)
        self.files[path] = (self.files.get(path, b"") if append else b"") + data

    def remove(self, path: str) -> None:
        if not self.writable(path):
            raise PermissionError(path)
        del self.files[path]

    def glob(self, pattern: str) -> list[str]:
        """Absolute paths matching a pattern with * ? [..] in its last part (enough for logs/*.log)."""
        folder, name = posixpath.split(pattern)
        if not self.is_dir(folder):
            return []
        return [posixpath.join(folder, entry) for entry in self.listdir(folder) if fnmatch.fnmatchcase(entry, name)]


def decode(data: bytes) -> str:
    """Text of a file; a binary file (the .evtx) shows its printable characters only, like `cat` would garble it."""
    if b"\x00" in data[:4096]:
        return "".join(ch if ch.isprintable() or ch in "\n\t" else "" for ch in data.decode("latin-1"))
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n")


def lab_files(files: dict[str, Path]) -> dict[str, bytes]:
    """{path relative to the home directory: lab file} (from challenges.json) -> {absolute path: bytes}."""
    return {posixpath.join(HOME, relative): Path(source).read_bytes() for relative, source in files.items()}


def limit_lines(text: str, limit: int = MAX_OUTPUT_LINES) -> str:
    lines = text.split("\n")
    if len(lines) <= limit + 1:
        return text
    return "\n".join(lines[:limit]) + f"\n... ({len(lines) - limit} more lines not shown in the simulated terminal)"


@dataclass
class Shell:
    """Interface of the three simulated shells."""

    fs: VirtualFS
    cwd: str = HOME
    history: list[str] = field(default_factory=list)

    name = "shell"

    def prompt(self) -> str:
        raise NotImplementedError

    def execute(self, line: str) -> Result:
        raise NotImplementedError

    def run(self, line: str) -> Result:
        """Run one command line, never raising: errors become the shell's error text."""
        line = line.rstrip("\n")
        if line.strip():
            self.history.append(line)
        try:
            result = self.execute(line)
        except ShellError as exc:
            result = Result(error=str(exc))
        except RecursionError:
            result = Result(error="The command is too deeply nested for the simulated terminal.")
        result.output = limit_lines(result.output)
        return result
