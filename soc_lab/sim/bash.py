"""Simulated bash: the command line and the text tools an analyst uses on logs.

Quoting, $VAR and $(...), globs (logs/*.log), pipes, < > >> 2>, ; && || and these commands:
ls cd pwd cat less more head tail wc grep sort uniq cut tr sed awk jq file tree echo printf tac nl
rev touch mkdir rm cp mv clear history whoami id hostname uname date which type help man sudo exit.
Outputs follow GNU coreutils, so answers match the real Docker terminal.
"""

from __future__ import annotations

import functools
import json
import math
import posixpath
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import awk as awk_module
from . import jq as jq_module
from .core import HOME, HOST, LOGS, USER, Result, Shell, ShellError, Unsupported
from .regex import compile_posix

OPERATORS = ("2>&1", "2>>", "&&", "||", ">>", "2>", "&>", "|", ";", "<", ">", "&")
DESCRIPTIONS = {
    "ls": "list files", "cd": "change directory", "pwd": "print the current directory",
    "cat": "print files", "less": "read a file (prints it here)", "more": "read a file (prints it here)",
    "head": "first lines", "tail": "last lines", "wc": "count lines, words and bytes",
    "grep": "search lines with a pattern", "sort": "sort lines", "uniq": "collapse repeated lines (-c counts)",
    "cut": "pick columns", "tr": "translate or delete characters", "sed": "edit lines (s/old/new/)",
    "awk": "fields and small programs", "jq": "query JSON", "file": "guess a file's type",
    "tree": "show folders as a tree", "echo": "print text", "printf": "print formatted text",
    "tac": "print lines in reverse order", "nl": "number lines", "rev": "reverse each line",
    "touch": "create an empty file", "mkdir": "create a folder", "rm": "remove a file", "cp": "copy a file",
    "mv": "move a file", "clear": "clear the screen", "history": "commands typed so far",
    "whoami": "your user name", "id": "your user and groups", "hostname": "this computer's name",
    "uname": "system information", "date": "current date and time", "which": "where a command is",
    "type": "what a command is", "help": "this list", "man": "short help for a command",
    "column": "align columns (-t)", "xargs": "build commands from input (echo only)", "basename": "file name of a path",
    "dirname": "folder of a path", "true": "do nothing, successfully", "false": "do nothing, unsuccessfully",
}


@dataclass
class Word:
    text: str
    glob: bool = False


@dataclass
class Op:
    text: str


@dataclass
class Cmd:
    """Input and environment of one command in a pipeline."""

    shell: "BashShell"
    args: list[str]
    stdin: str | None
    tty: bool  # output goes to the screen (not a pipe or a file)
    err: list[str] = field(default_factory=list)

    def error(self, message: str) -> None:
        self.err.append(message)


class Exit(Exception):
    def __init__(self, status: int, output: str = ""):
        self.status = status
        self.output = output


def parse_options(cmd: Cmd, flags: str = "", valued: str = "", long: dict | None = None,
                  numeric: bool = False) -> tuple[dict, list[str]]:
    """GNU-style options: -abc, -n5, -n 5, --long, --long=value, -- ; returns ({flag: value}, operands)."""
    name = cmd.args[0]
    long = long or {}
    options: dict = {}
    operands: list[str] = []
    args = cmd.args[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            operands += args[i:]
            break
        if arg.startswith("--") and len(arg) > 2:
            key, _, value = arg[2:].partition("=")
            if key not in long:
                if key in ("color", "colour"):
                    continue
                if key == "help":
                    raise Exit(0, f"{name}: {DESCRIPTIONS.get(name, '')}. Type 'man {name}' for the options the simulated terminal knows.\n")
                raise Unsupported(f"{name}: unrecognized option '--{key}' (not supported in the simulated terminal)")
            short = long[key]
            if short in valued:
                if not value:
                    if i >= len(args):
                        raise ShellError(f"{name}: option '--{key}' requires an argument")
                    value = args[i]
                    i += 1
                options[short] = options.get(short, []) + [value]
            else:
                options[short] = True
            continue
        if arg.startswith("-") and len(arg) > 1 and not (numeric and arg[1:].isdigit()) and arg != "-":
            j = 1
            while j < len(arg):
                ch = arg[j]
                if ch in valued:
                    value = arg[j + 1:]
                    if not value:
                        if i >= len(args):
                            raise ShellError(f"{name}: option requires an argument -- '{ch}'")
                        value = args[i]
                        i += 1
                    options[ch] = options.get(ch, []) + [value]
                    break
                if ch in flags:
                    options[ch] = True
                    j += 1
                    continue
                raise Unsupported(f"{name}: invalid option -- '{ch}' (or not supported in the simulated terminal)")
            continue
        if numeric and arg.startswith("-") and arg[1:].isdigit():
            options["n"] = options.get("n", []) + [arg[1:]]
            continue
        operands.append(arg)
    return options, operands


def last(options: dict, key: str, default=None):
    value = options.get(key)
    return value[-1] if isinstance(value, list) else default if value is None else value


def lines_of(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def join_lines(lines: list[str]) -> str:
    return "".join(line + "\n" for line in lines)


class BashShell(Shell):
    name = "linux"

    def __init__(self, fs, cwd: str = HOME):
        super().__init__(fs, cwd)
        self.env = {"HOME": HOME, "USER": USER, "LOGNAME": USER, "SHELL": "/bin/bash", "HOSTNAME": HOST,
                    "LANG": "C.UTF-8", "TERM": "xterm-256color", "PATH": "/usr/local/bin:/usr/bin:/bin"}
        self.status = 0
        self.previous_dir = HOME

    # -----------------------------------------------------------------------
    def prompt(self) -> str:
        where = "~" + self.cwd[len(HOME):] if self.cwd == HOME or self.cwd.startswith(HOME + "/") else self.cwd
        return f"{USER}@{HOST}:{where}$ "

    def resolve(self, path: str) -> str:
        if path == "~" or path.startswith("~/"):
            path = HOME + path[1:]
        return posixpath.normpath(posixpath.join(self.cwd, path)) if path else self.cwd

    def display(self, path: str) -> str:
        return path

    # tokens ------------------------------------------------------------------
    def tokenize(self, line: str) -> list:
        tokens: list = []
        buf: list[str] = []
        in_word = False
        glob = False
        i = 0
        n = len(line)

        def flush():
            nonlocal buf, in_word, glob
            if in_word:
                tokens.append(Word("".join(buf), glob))
            buf, in_word, glob = [], False, False

        while i < n:
            ch = line[i]
            if ch in " \t\n":
                flush()
                i += 1
                continue
            if ch == "#" and not in_word:
                break
            op = next((o for o in OPERATORS if line.startswith(o, i)), None)
            if op and op.startswith("2") and in_word:
                op = None  # the 2 of "file2>x" belongs to the word
            if op:
                flush()
                if op == "&":
                    raise Unsupported("bash: background jobs (&) are not supported in the simulated terminal")
                tokens.append(Op(op))
                i += len(op)
                continue
            in_word = True
            if ch == "'":
                end = line.find("'", i + 1)
                if end == -1:
                    raise ShellError("bash: unexpected EOF while looking for matching `''")
                buf.append(line[i + 1:end])
                i = end + 1
            elif ch == '"':
                i += 1
                while i < n and line[i] != '"':
                    if line[i] == "\\" and i + 1 < n and line[i + 1] in '"\\$`':
                        buf.append(line[i + 1])
                        i += 2
                    elif line[i] == "$":
                        text, i = self.expand_dollar(line, i)
                        buf.append(text)
                    else:
                        buf.append(line[i])
                        i += 1
                if i >= n:
                    raise ShellError('bash: unexpected EOF while looking for matching `"\'')
                i += 1
            elif ch == "\\":
                if i + 1 < n:
                    buf.append(line[i + 1])
                i += 2
            elif ch == "$":
                text, i = self.expand_dollar(line, i)
                buf.append(text)
            elif ch == "~" and not buf and (i + 1 == n or line[i + 1] in "/ \t"):
                buf.append(HOME)
                i += 1
            elif ch == "`":
                end = line.find("`", i + 1)
                if end == -1:
                    raise ShellError("bash: unexpected EOF while looking for matching ``'")
                buf.append(self.substitute(line[i + 1:end]))
                i = end + 1
            else:
                if ch in "*?[":
                    glob = True
                buf.append(ch)
                i += 1
        flush()
        return tokens

    def expand_dollar(self, line: str, i: int) -> tuple[str, int]:
        if line.startswith("$(", i):
            depth = 0
            j = i + 1
            while j < len(line):
                if line[j] == "(":
                    depth += 1
                elif line[j] == ")":
                    depth -= 1
                    if depth == 0:
                        return self.substitute(line[i + 2:j]), j + 1
                j += 1
            raise ShellError("bash: unexpected EOF while looking for matching `)'")
        if line.startswith("${", i):
            end = line.find("}", i)
            if end == -1:
                raise ShellError("bash: bad substitution")
            return self.variable(line[i + 2:end]), end + 1
        match = re.match(r"\$([A-Za-z_]\w*|\?|\$|#|[0-9])", line[i:])
        if match:
            return self.variable(match.group(1)), i + len(match.group(0))
        return "$", i + 1

    def variable(self, name: str) -> str:
        if name == "?":
            return str(self.status)
        if name == "$":
            return "4242"
        if name == "PWD":
            return self.cwd
        return self.env.get(name, "")

    def substitute(self, command: str) -> str:
        output, _, _ = self.run_list(command, capture=True)
        return output.rstrip("\n")

    # execution ---------------------------------------------------------------
    def execute(self, line: str) -> Result:
        if not line.strip():
            return Result()
        try:
            output, error, clear = self.run_list(line)
        except Exit as stop:
            return Result(output=stop.output)
        return Result(output=output, error=error, clear=clear)

    def split_list(self, line: str) -> list[tuple[str, str]]:
        """Split at ; && || outside quotes and $(...), before any expansion: [(link, text)]."""
        parts: list[tuple[str, str]] = []
        link = ";"
        start = 0
        depth = 0
        quote = ""
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == "\\" and quote == '"':
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in "'\"`":
                quote = ch
            elif ch == "\\":
                i += 2
                continue
            elif ch == "#" and (i == 0 or line[i - 1] in " \t;") and depth == 0:
                break
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(depth - 1, 0)
            elif depth == 0 and (line.startswith("&&", i) or line.startswith("||", i) or ch == ";"):
                op = ";" if ch == ";" else line[i:i + 2]
                text = line[start:i]
                if not text.strip():
                    raise ShellError(f"bash: syntax error near unexpected token `{op}'")
                parts.append((link, text))
                link = op
                i += len(op)
                start = i
                continue
            i += 1
        text = line[start:i]
        if text.strip():
            parts.append((link, text))
        elif link in ("&&", "||"):
            raise ShellError(f"bash: syntax error near unexpected token `{link}'")
        return parts

    def run_list(self, line: str, capture: bool = False) -> tuple[str, str, bool]:
        out, err = [], []
        clear = False
        for link, text in self.split_list(line):
            if link == "&&" and self.status != 0:
                continue
            if link == "||" and self.status == 0:
                continue
            text, error, status, cleared = self.run_pipeline(self.tokenize(text), capture)
            self.status = status
            if cleared:
                out, clear = [], True
            out.append(text)
            if error:
                err.append(error)
        return "".join(out), "\n".join(err), clear

    def run_pipeline(self, tokens: list, capture: bool) -> tuple[str, str, int, bool]:
        segments: list[list] = [[]]
        for token in tokens:
            if isinstance(token, Op) and token.text == "|":
                if not segments[-1]:
                    raise ShellError("bash: syntax error near unexpected token `|'")
                segments.append([])
            else:
                segments[-1].append(token)
        if not segments[-1]:
            raise ShellError("bash: syntax error near unexpected token `|'")
        data: str | None = None
        errors: list[str] = []
        status = 0
        clear = False
        for index, segment in enumerate(segments):
            words, stdin_file, stdout_file, append, hide_errors, merge = self.redirections(segment)
            stdin = data if index > 0 else None
            if stdin_file is not None:
                path = self.resolve(stdin_file)
                if not self.fs.is_file(path):
                    errors.append(f"bash: {stdin_file}: No such file or directory")
                    data, status = "", 1
                    continue
                stdin = self.fs.read_text(path)
            is_last = index == len(segments) - 1
            cmd = Cmd(self, words, stdin, tty=is_last and stdout_file is None and not capture)
            if not words:
                data, status = "", 0
                continue
            try:
                data, status = self.call(cmd)
            except Exit as stop:
                data, status = stop.output, stop.status
            except ShellError as exc:
                cmd.error(str(exc))
                data, status = "", 2 if isinstance(exc, Unsupported) else 1
            if words[0] in ("clear", "reset"):
                clear = True
            if merge:
                data = data + "".join(e + "\n" for e in cmd.err)
            elif not hide_errors:
                errors += cmd.err
            if stdout_file is not None:
                path = self.resolve(stdout_file)
                if stdout_file == "/dev/null":
                    pass
                else:
                    try:
                        self.fs.write(path, data.encode("utf-8"), append=append)
                    except PermissionError:
                        errors.append(f"bash: {stdout_file}: " + ("Read-only file system" if path.startswith(LOGS)
                                                                  else "Permission denied"))
                        status = 1
                    except IsADirectoryError:
                        errors.append(f"bash: {stdout_file}: Is a directory")
                        status = 1
                    except FileNotFoundError:
                        errors.append(f"bash: {stdout_file}: No such file or directory")
                        status = 1
                data = ""
        return data or "", "\n".join(errors), status, clear

    def redirections(self, segment: list):
        words: list[str] = []
        stdin_file = stdout_file = None
        append = hide_errors = merge = False
        i = 0
        while i < len(segment):
            token = segment[i]
            if isinstance(token, Op):
                if token.text == "2>&1":
                    merge = True
                    i += 1
                    continue
                if i + 1 >= len(segment) or not isinstance(segment[i + 1], Word):
                    raise ShellError("bash: syntax error near unexpected token `newline'")
                target = segment[i + 1].text
                if token.text == "<":
                    stdin_file = target
                elif token.text in (">", ">>", "&>"):
                    stdout_file, append = target, token.text == ">>"
                    merge = merge or token.text == "&>"
                elif token.text in ("2>", "2>>"):
                    if target == "/dev/null":
                        hide_errors = True
                    else:
                        raise Unsupported("bash: saving errors to a file is not supported in the simulated terminal")
                i += 2
                continue
            words += self.expand_glob(token)
            i += 1
        while words and re.match(r"^[A-Za-z_]\w*=", words[0]) and len(words) >= 1:
            name, _, value = words[0].partition("=")
            if len(words) == 1:
                self.env[name] = value
            words = words[1:]
        return words, stdin_file, stdout_file, append, hide_errors, merge

    def expand_glob(self, word: Word) -> list[str]:
        if not word.glob:
            return [word.text]
        absolute = word.text.startswith("/")
        pattern = self.resolve(word.text)
        matches = self.fs.glob(pattern)
        if not matches:
            return [word.text]  # like bash: an unmatched pattern stays as typed
        if absolute:
            return matches
        prefix = word.text.rsplit("/", 1)[0] + "/" if "/" in word.text else ""
        return [prefix + posixpath.basename(m) for m in matches]

    def call(self, cmd: Cmd) -> tuple[str, int]:
        name = cmd.args[0]
        handler = getattr(self, "cmd_" + name.replace("-", "_"), None) if re.fullmatch(r"[a-z][a-z0-9_-]*", name) else None
        if handler is None:
            if name in ("vim", "vi", "nano", "emacs", "top", "htop", "watch", "ssh", "nc", "curl", "wget", "python3",
                        "python", "pwsh", "powershell", "apt", "apt-get", "docker", "ping", "find", "zcat", "gzip"):
                hint = {"pwsh": " To use PowerShell, choose it in the Shell selector above the terminal.",
                        "powershell": " To use PowerShell, choose it in the Shell selector above the terminal.",
                        "find": " Try: ls -R, or grep -r PATTERN logs"}.get(name, "")
                raise Unsupported(f"bash: {name}: not available in the simulated terminal.{hint}")
            raise ShellError(f"{name}: command not found")
        return handler(cmd)

    # files -------------------------------------------------------------------
    def read_operands(self, cmd: Cmd, operands: list[str]) -> list[tuple[str, str | None]]:
        """[(name, text or None if unreadable)]; stdin when there are no operands (or '-')."""
        name = cmd.args[0]
        out = []
        if not operands:
            operands = ["-"]
        for operand in operands:
            if operand == "-":
                out.append(("(standard input)", cmd.stdin or ""))
                continue
            path = self.resolve(operand)
            if self.fs.is_dir(path):
                cmd.error(f"{name}: {operand}: Is a directory")
                out.append((operand, None))
            elif not self.fs.is_file(path):
                cmd.error(f"{name}: {operand}: No such file or directory")
                out.append((operand, None))
            else:
                out.append((operand, self.fs.read_text(path)))
        return out

    def status_of(self, cmd: Cmd) -> int:
        return 1 if cmd.err else 0

    # commands: navigation ----------------------------------------------------
    def cmd_pwd(self, cmd: Cmd):
        return self.cwd + "\n", 0

    def cmd_cd(self, cmd: Cmd):
        target = cmd.args[1] if len(cmd.args) > 1 else HOME
        if target == "-":
            target = self.previous_dir
        path = self.resolve(target)
        if not self.fs.exists(path):
            raise ShellError(f"bash: cd: {target}: No such file or directory")
        if not self.fs.is_dir(path):
            raise ShellError(f"bash: cd: {target}: Not a directory")
        self.previous_dir, self.cwd = self.cwd, path
        return "", 0

    def _ls_fields(self, path: str, name: str, human: bool) -> list[str]:
        is_dir = self.fs.is_dir(path)
        root_owned = path == LOGS or path.startswith(LOGS + "/") or not path.startswith(HOME)
        owner = "root" if root_owned else USER
        if is_dir:
            mode = "drwx------" if path == HOME else "drwxr-xr-x"
        else:
            mode = "-rw-r--r--"
        size = self.fs.size(path)
        return [mode, "1", owner, owner, human_size(size) if human else str(size), "Oct 27 09:00", name]

    def _ls_long(self, entries: list[list[str]]) -> list[str]:
        widths = [max(len(e[i]) for e in entries) for i in range(6)] if entries else []
        return [f"{e[0]} {e[1]:>{widths[1]}} {e[2]:<{widths[2]}} {e[3]:<{widths[3]}} {e[4]:>{widths[4]}} {e[5]} {e[6]}"
                for e in entries]

    def cmd_ls(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="lah1RtrSdF", long={"all": "a", "human-readable": "h",
                                                                        "recursive": "R"})
        targets = operands or ["."]
        out: list[str] = []
        files = [t for t in targets if self.fs.is_file(self.resolve(t))]
        dirs = [t for t in targets if self.fs.is_dir(self.resolve(t))]
        for t in targets:
            if not self.fs.exists(self.resolve(t)):
                cmd.error(f"ls: cannot access '{t}': No such file or directory")

        def listing(names_paths: list[tuple[str, str]]) -> list[str]:
            if options.get("S"):
                names_paths.sort(key=lambda np: -self.fs.size(np[1]))
            if options.get("r"):
                names_paths.reverse()
            if options.get("l"):
                total = sum((self.fs.size(p) + 4095) // 4096 * 4 for _, p in names_paths)
                total_text = f"{total}K" if options.get("h") and total else str(total)
                rows = [self._ls_fields(p, n, bool(options.get("h"))) for n, p in names_paths]
                return ([f"total {total_text}"] if not files_only else []) + self._ls_long(rows)
            names = [n + ("/" if options.get("F") and self.fs.is_dir(p) else "") for n, p in names_paths]
            if cmd.tty and not options.get("1"):
                return ["  ".join(names)] if names else []
            return names

        files_only = True
        if files:
            out += listing([(f, self.resolve(f)) for f in files])
        files_only = False
        queue = list(dirs)
        first = True
        while queue:
            directory = queue.pop(0)
            path = self.resolve(directory)
            entries = self.fs.listdir(path)
            if not options.get("a"):
                entries = [e for e in entries if not e.startswith(".")]
            elif options.get("a"):
                entries = [".", ".."] + entries
            if len(targets) > 1 or options.get("R"):
                if not first or files:
                    out.append("")
                out.append(f"{directory}:")
            first = False
            pairs = [(e, posixpath.normpath(posixpath.join(path, e))) for e in entries]
            out += listing(pairs)
            if options.get("R"):
                queue += [posixpath.join(directory, e) for e, p in pairs if e not in (".", "..") and self.fs.is_dir(p)]
        return join_lines(out), self.status_of(cmd) and 2

    def cmd_tree(self, cmd: Cmd):
        _, operands = parse_options(cmd, flags="a")
        root = operands[0] if operands else "."
        path = self.resolve(root)
        if not self.fs.is_dir(path):
            return f"{root}  [error opening dir]\n\n0 directories, 0 files\n", 2
        out = [root]
        counts = {"dirs": 0, "files": 0}

        def walk(folder: str, indent: str):
            entries = self.fs.listdir(folder)
            for index, entry in enumerate(entries):
                child = posixpath.join(folder, entry)
                last_one = index == len(entries) - 1
                out.append(indent + ("└── " if last_one else "├── ") + entry)
                if self.fs.is_dir(child):
                    counts["dirs"] += 1
                    walk(child, indent + ("    " if last_one else "│   "))
                else:
                    counts["files"] += 1

        walk(path, "")
        counts["dirs"] += 1  # tree counts the folder it starts from
        directories = "directory" if counts["dirs"] == 1 else "directories"
        file_word = "file" if counts["files"] == 1 else "files"
        out += ["", f"{counts['dirs']} {directories}, {counts['files']} {file_word}"]
        return join_lines(out), 0

    def cmd_file(self, cmd: Cmd):
        _, operands = parse_options(cmd, flags="b")
        out = []
        for operand in operands:
            path = self.resolve(operand)
            if self.fs.is_dir(path):
                kind = "directory"
            elif not self.fs.is_file(path):
                kind = f"cannot open `{operand}' (No such file or directory)"
            else:
                data = self.fs.read_bytes(path)
                if data.startswith(b"ElfFile\x00"):
                    chunks = int.from_bytes(data[42:44], "little")
                    in_use = int.from_bytes(data[16:24], "little")
                    next_record = int.from_bytes(data[24:32], "little")
                    kind = (f"MS Windows Vista-8.1 Event Log, {chunks} chunks (no. {in_use} in use), "
                            f"next record no. {next_record}")
                else:
                    text = data.decode("utf-8", errors="replace")
                    longest = max((len(line) for line in text.split("\n")), default=0)
                    encoding = "ASCII text" if data.isascii() else "Unicode text, UTF-8 text"
                    stripped = text.lstrip()
                    if stripped.startswith("<?xml"):
                        kind = f"XML 1.0 document, {encoding}"
                    elif stripped.startswith(("{", "[")):
                        kind = "JSON text data"
                    elif operand.endswith(".csv"):
                        kind = f"CSV {encoding}"
                    else:
                        kind = encoding
                    if longest > 300 and not kind.startswith("JSON"):
                        kind += f", with very long lines ({longest})"
            out.append((operand, kind))
        if not operands:
            raise ShellError("Usage: file [-b] FILE...")
        width = max(len(name) for name, _ in out) + 1
        return join_lines(f"{(name + ':'):<{width}} {kind}" for name, kind in out), 0

    # commands: reading -------------------------------------------------------
    def cmd_cat(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="nAE", long={"number": "n"})
        out = []
        number = 0
        for _, text in self.read_operands(cmd, operands):
            if text is None:
                continue
            if options.get("n"):
                for line in lines_of(text):
                    number += 1
                    out.append(f"{number:6d}\t{line}\n")
            else:
                out.append(text)
        return "".join(out), self.status_of(cmd)

    cmd_less = cmd_more = cmd_cat

    def cmd_tac(self, cmd: Cmd):
        _, operands = parse_options(cmd)
        out = []
        for _, text in self.read_operands(cmd, operands):
            if text is not None:
                out += reversed(lines_of(text))
        return join_lines(out), self.status_of(cmd)

    def cmd_rev(self, cmd: Cmd):
        _, operands = parse_options(cmd)
        out = []
        for _, text in self.read_operands(cmd, operands):
            if text is not None:
                out += [line[::-1] for line in lines_of(text)]
        return join_lines(out), self.status_of(cmd)

    def cmd_nl(self, cmd: Cmd):
        _, operands = parse_options(cmd, valued="b")
        out = []
        number = 0
        for _, text in self.read_operands(cmd, operands):
            for line in lines_of(text or ""):
                if line.strip():
                    number += 1
                    out.append(f"{number:6d}\t{line}")
                else:
                    out.append("")
        return join_lines(out), self.status_of(cmd)

    def _head_tail(self, cmd: Cmd, head: bool):
        name = cmd.args[0]
        options, operands = parse_options(cmd, flags="qvf", valued="nc", long={"lines": "n", "bytes": "c"},
                                          numeric=True)
        if options.get("f"):
            raise Unsupported(f"{name}: -f (follow) is not supported in the simulated terminal")
        count_text = last(options, "n", "10")
        from_start = count_text.startswith("+")
        try:
            count = int(count_text.lstrip("+"))
        except ValueError:
            raise ShellError(f"{name}: invalid number of lines: '{count_text}'") from None
        sources = self.read_operands(cmd, operands)
        out = []
        for index, (source, text) in enumerate(sources):
            if text is None:
                continue
            if len(sources) > 1 and not options.get("q"):
                out.append(("\n" if index else "") + f"==> {source} <==\n")
            if "c" in options:
                size = int(last(options, "c"))
                out.append(text[:size] if head else text[-size:])
                continue
            lines = lines_of(text)
            if head:
                chosen = lines[:count] if count >= 0 else lines[:count]
            elif from_start:
                chosen = lines[max(count - 1, 0):]
            else:
                chosen = lines[-count:] if count else []
            out.append(join_lines(chosen))
        return "".join(out), self.status_of(cmd)

    def cmd_head(self, cmd: Cmd):
        return self._head_tail(cmd, head=True)

    def cmd_tail(self, cmd: Cmd):
        return self._head_tail(cmd, head=False)

    def cmd_wc(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="lwcm", long={"lines": "l", "words": "w", "bytes": "c",
                                                                  "chars": "m"})
        wanted = [k for k in "lwmc" if options.get(k)] or ["l", "w", "c"]
        rows = []
        for name, text in self.read_operands(cmd, operands):
            if text is None:
                continue
            counts = {"l": text.count("\n"), "w": len(text.split()), "m": len(text),
                      "c": len(text.encode("utf-8"))}
            rows.append(([counts[k] for k in wanted], "" if name == "(standard input)" else name))
        if len(rows) > 1:
            rows.append(([sum(r[0][i] for r in rows) for i in range(len(wanted))], "total"))
        if not rows:
            return "", 1
        single = len(wanted) == 1 and len(rows) == 1
        from_stdin = not operands
        total_bytes = sum(self.fs.size(self.resolve(o)) for o in operands if self.fs.is_file(self.resolve(o)))
        width = 1 if single else 7 if from_stdin else len(str(total_bytes))
        out = [" ".join(f"{v:>{width}}" for v in values) + (f" {name}" if name else "") for values, name in rows]
        return join_lines(out), self.status_of(cmd)

    # commands: searching -----------------------------------------------------
    def cmd_grep(self, cmd: Cmd):
        options, operands = parse_options(
            cmd, flags="cinvoEFwxhHlLqsrRIaGz", valued="emABC",
            long={"count": "c", "ignore-case": "i", "line-number": "n", "invert-match": "v", "only-matching": "o",
                  "extended-regexp": "E", "fixed-strings": "F", "word-regexp": "w", "line-regexp": "x",
                  "no-filename": "h", "with-filename": "H", "files-with-matches": "l", "quiet": "q",
                  "recursive": "r", "regexp": "e", "max-count": "m", "after-context": "A", "before-context": "B",
                  "context": "C", "files-without-match": "L"})
        if options.get("z"):
            raise Unsupported("grep: -z is not supported in the simulated terminal")
        patterns = options.get("e") or []
        if not patterns:
            if not operands:
                raise ShellError("Usage: grep [OPTION]... PATTERNS [FILE]...")
            patterns = [operands.pop(0)]
        patterns = [p for pattern in patterns for p in pattern.split("\n")]
        flags = re.IGNORECASE if options.get("i") else 0
        regexes = []
        for pattern in patterns:
            if options.get("F"):
                body = re.escape(pattern)
            else:
                body = compile_posix(pattern, extended=bool(options.get("E")), ignore_case=bool(flags)).pattern
            if options.get("w"):
                body = rf"(?<!\w)(?:{body})(?!\w)"
            if options.get("x"):
                body = rf"^(?:{body})$"
            regexes.append(re.compile(body, flags))
        recursive = options.get("r") or options.get("R")
        if recursive and not operands:
            operands = ["."]
        if recursive:
            expanded = []
            for operand in operands:
                path = self.resolve(operand)
                if self.fs.is_dir(path):
                    prefix = path.rstrip("/") + "/"
                    for file_path in sorted(p for p in self.fs.files if p.startswith(prefix)):
                        relative = file_path[len(prefix):]
                        expanded.append(relative if operand == "." else posixpath.join(operand, relative))
                else:
                    expanded.append(operand)
            operands = expanded
        sources = self.read_operands(cmd, operands)
        show_names = (len(sources) > 1 or recursive) and not options.get("h") or options.get("H")
        max_count = int(last(options, "m", "-1"))
        after = int(last(options, "A", last(options, "C", "0")))
        before = int(last(options, "B", last(options, "C", "0")))
        out: list[str] = []
        any_match = False
        for name, text in sources:
            if text is None:
                continue
            path = self.resolve(name) if name != "(standard input)" else None
            if path and self.fs.is_binary(path) and not options.get("a"):
                if any(r.search(text) for r in regexes) != bool(options.get("v")) and not options.get("c"):
                    any_match = True
                    if not options.get("q") and not options.get("l"):
                        out.append(f"grep: {name}: binary file matches")
                    elif options.get("l"):
                        out.append(name)
                    continue
            lines = lines_of(text)
            matches = 0
            last_printed = -1
            pending_after = 0
            prefix = f"{name}:" if show_names else ""
            for number, line in enumerate(lines, start=1):
                hit = any(r.search(line) for r in regexes) != bool(options.get("v"))
                if hit and (max_count < 0 or matches < max_count):
                    matches += 1
                    any_match = True
                    if options.get("c") or options.get("l") or options.get("L") or options.get("q"):
                        continue
                    if before or after:
                        start = max(number - 1 - before, last_printed + 1)
                        if out and last_printed >= 0 and start > last_printed + 1:
                            out.append("--")
                        for k in range(start, number - 1):
                            out.append(f"{name}-" * bool(show_names) + (f"{k + 1}-" if options.get("n") else "") + lines[k])
                    line_prefix = prefix + (f"{number}:" if options.get("n") else "")
                    if options.get("o") and not options.get("v"):
                        for r in regexes:
                            out += [line_prefix + m.group(0) for m in r.finditer(line) if m.group(0)]
                    else:
                        out.append(line_prefix + line)
                    last_printed = number - 1
                    pending_after = after
                elif pending_after and not (options.get("c") or options.get("l")):
                    out.append(f"{name}-" * bool(show_names) + (f"{number}-" if options.get("n") else "") + line)
                    last_printed = number - 1
                    pending_after -= 1
            if options.get("c"):
                out.append(prefix + str(matches))
            elif options.get("l") and matches:
                out.append(name)
            elif options.get("L") and not matches:
                out.append(name)
        if options.get("q"):
            return "", 0 if any_match else 1
        status = 2 if cmd.err and not options.get("s") else 0 if any_match else 1
        if options.get("s"):
            cmd.err.clear()
        return join_lines(out), status

    # commands: transforming --------------------------------------------------
    def cmd_sort(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="nrufbhVsMgR", valued="ktoT",
                                          long={"numeric-sort": "n", "reverse": "r", "unique": "u",
                                                "ignore-case": "f", "key": "k", "field-separator": "t",
                                                "human-numeric-sort": "h", "version-sort": "V", "stable": "s"})
        if "o" in options:
            raise Unsupported("sort: -o is not supported in the simulated terminal; use > instead")
        separator = last(options, "t")
        if separator is not None and len(separator) != 1:
            separator = {"\\t": "\t"}.get(separator, separator)
            if len(separator) != 1:
                raise ShellError("sort: multi-character tab")
        keys = [parse_sort_key(k) for k in options.get("k") or []]
        global_opts = {k for k in "nrfbhVg" if options.get(k)}
        lines = []
        for _, text in self.read_operands(cmd, operands):
            if text is not None:
                lines += lines_of(text)

        def fields_of(line: str) -> list[str]:
            if separator is not None:
                return line.split(separator)
            return re.findall(r"\s*\S+", line) or [line]

        def key_text(line: str, key) -> str:
            start_field, start_char, end_field, end_char, _ = key
            parts = fields_of(line)
            sep = separator or ""
            if start_field > len(parts):
                return ""
            if end_field is None:
                text = sep.join(parts[start_field - 1:])
            else:
                text = sep.join(parts[start_field - 1:end_field])
                if end_char:
                    text = text[:end_char] if start_field == end_field else text
            if start_char:
                text = text[start_char - 1:]
            return text

        def compare_texts(a: str, b: str, opts: set) -> int:
            if "b" in opts or "n" in opts or "h" in opts or "g" in opts:
                a, b = a.lstrip(), b.lstrip()
            if "n" in opts or "g" in opts or "h" in opts:
                x, y = number_of(a, "h" in opts), number_of(b, "h" in opts)
                if x != y:
                    return -1 if x < y else 1
                return 0
            if "V" in opts:
                x, y = version_key(a), version_key(b)
                return (x > y) - (x < y)
            if "f" in opts:
                a, b = a.upper(), b.upper()
            return (a > b) - (a < b)

        def compare(a: str, b: str) -> int:
            for key in keys:
                opts = key[4] or global_opts
                result = compare_texts(key_text(a, key), key_text(b, key), opts)
                if result:
                    return -result if "r" in opts else result
            if not keys:
                result = compare_texts(a, b, global_opts)
                if result:
                    return -result if "r" in global_opts else result
            if options.get("u") or options.get("s"):
                return 0
            result = (a > b) - (a < b)
            return -result if "r" in global_opts else result

        ordered = sorted(lines, key=functools.cmp_to_key(compare))
        if options.get("u"):
            unique = []
            for line in ordered:
                if not unique or compare(unique[-1], line) != 0:
                    unique.append(line)
            ordered = unique
        return join_lines(ordered), self.status_of(cmd)

    def cmd_uniq(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="cdui", valued="fs", long={"count": "c", "repeated": "d",
                                                                              "unique": "u", "ignore-case": "i"})
        _, text = self.read_operands(cmd, operands[:1])[0]
        if text is None:
            return "", 1
        groups: list[list] = []
        for line in lines_of(text):
            key = line.lower() if options.get("i") else line
            if groups and groups[-1][0] == key:
                groups[-1][2] += 1
            else:
                groups.append([key, line, 1])
        out = []
        for _, line, count in groups:
            if options.get("d") and count < 2 or options.get("u") and count > 1:
                continue
            out.append(f"{count:7d} {line}" if options.get("c") else line)
        return join_lines(out), 0

    def cmd_cut(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="s", valued="dfcb", long={"delimiter": "d", "fields": "f",
                                                                             "characters": "c", "only-delimited": "s",
                                                                             "output-delimiter": "O"})
        delimiter = last(options, "d", "\t")
        if len(delimiter) != 1:
            raise ShellError("cut: the delimiter must be a single character")
        spec = last(options, "f") or last(options, "c") or last(options, "b")
        if spec is None:
            raise ShellError("cut: you must specify a list of bytes, characters, or fields")
        wanted = parse_ranges(spec)
        out = []
        for _, text in self.read_operands(cmd, operands):
            if text is None:
                continue
            for line in lines_of(text):
                if "f" in options:
                    if delimiter not in line:
                        if not options.get("s"):
                            out.append(line)
                        continue
                    parts = line.split(delimiter)
                    out.append(delimiter.join(p for i, p in enumerate(parts, 1) if wanted(i)))
                else:
                    out.append("".join(ch for i, ch in enumerate(line, 1) if wanted(i)))
        return join_lines(out), self.status_of(cmd)

    def cmd_tr(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="dsc")
        if not operands:
            raise ShellError("tr: missing operand")
        text = cmd.stdin or ""
        first = expand_tr_set(operands[0])
        if options.get("c"):
            raise Unsupported("tr: -c is not supported in the simulated terminal")
        if options.get("d"):
            text = "".join(ch for ch in text if ch not in first)
            if options.get("s") and len(operands) > 1:
                text = squeeze(text, expand_tr_set(operands[1]))
            return text, 0
        if len(operands) > 1:
            second = expand_tr_set(operands[1])
            if second:
                second = second + second[-1] * max(0, len(first) - len(second))
                table = {ord(a): b for a, b in zip(first, second)}
                text = text.translate(table)
            if options.get("s"):
                text = squeeze(text, second)
        elif options.get("s"):
            text = squeeze(text, first)
        else:
            raise ShellError("tr: missing operand after '" + operands[0] + "'")
        return text, 0

    def cmd_sed(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="nEri", valued="e", long={"quiet": "n", "regexp-extended": "E",
                                                                             "expression": "e"})
        if options.get("i"):
            raise Unsupported("sed: -i (edit in place) is not supported: the logs are read-only")
        scripts = options.get("e") or ([operands.pop(0)] if operands else [])
        if not scripts:
            raise ShellError("Usage: sed [OPTION]... {script} [input-file]...")
        program = parse_sed("\n".join(scripts), extended=bool(options.get("E") or options.get("r")))
        text = "".join(t for _, t in self.read_operands(cmd, operands) if t is not None)
        return run_sed(program, lines_of(text), quiet=bool(options.get("n"))), self.status_of(cmd)

    def cmd_awk(self, cmd: Cmd):
        options, operands = parse_options(cmd, valued="Fvf", long={"field-separator": "F", "assign": "v"})
        if "f" in options:
            raise Unsupported("awk: -f is not supported in the simulated terminal; write the program in quotes")
        if not operands:
            raise ShellError("usage: awk [-F fs][-v var=value][prog | -f progfile][file ...]")
        program = operands.pop(0)
        assignments = {}
        for item in options.get("v") or []:
            name, _, value = item.partition("=")
            assignments[name] = value
        separator = last(options, "F")
        if separator is not None:
            separator = separator.replace("\\t", "\t")
        inputs = [(n if n != "(standard input)" else "", t) for n, t in self.read_operands(cmd, operands) if t is not None]
        return awk_module.run_awk(program, inputs, separator, assignments), self.status_of(cmd)

    cmd_gawk = cmd_mawk = cmd_awk

    def cmd_jq(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="rcSsnej", valued="", long={"raw-output": "r",
                                                                                "compact-output": "c",
                                                                                "sort-keys": "S", "slurp": "s",
                                                                                "null-input": "n", "join-output": "j",
                                                                                "arg": "A"})
        if "A" in options:
            raise Unsupported("jq: --arg is not supported in the simulated terminal")
        if not operands:
            raise ShellError("Usage: jq [OPTIONS] FILTER [FILES...]")
        program = operands.pop(0)
        documents = []
        if options.get("n"):
            documents = [None]
        else:
            for name, text in self.read_operands(cmd, operands):
                if text is None:
                    continue
                try:
                    documents += parse_json_stream(text)
                except ValueError as exc:
                    raise ShellError(f"jq: error (at {name}): {exc}") from None
            if options.get("s"):
                documents = [documents]
        output = jq_module.run_jq(program, documents, raw=bool(options.get("r") or options.get("j")),
                                  compact=bool(options.get("c")), sort_keys=bool(options.get("S")),
                                  join=bool(options.get("j")))
        return output, self.status_of(cmd)

    def cmd_column(self, cmd: Cmd):
        options, operands = parse_options(cmd, flags="t", valued="s")
        separator = last(options, "s")
        rows = []
        for _, text in self.read_operands(cmd, operands):
            if text is not None:
                rows += [(line.split(separator) if separator else line.split()) for line in lines_of(text)]
        if not options.get("t"):
            return join_lines([" ".join(r) for r in rows]), 0
        widths = [max((len(r[i]) for r in rows if i < len(r)), default=0) for i in range(max(map(len, rows), default=0))]
        out = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in rows]
        return join_lines(out), 0

    # commands: output and the rest --------------------------------------------
    def cmd_echo(self, cmd: Cmd):
        args = cmd.args[1:]
        newline, escapes = True, False
        while args and re.fullmatch(r"-[neE]+", args[0]):
            newline = newline and "n" not in args[0]
            escapes = "e" in args[0]
            args = args[1:]
        text = " ".join(args)
        if escapes:
            text = text.encode("utf-8").decode("unicode_escape")
        return text + ("\n" if newline else ""), 0

    def cmd_printf(self, cmd: Cmd):
        if len(cmd.args) < 2:
            raise ShellError("printf: usage: printf format [arguments]")
        fmt = cmd.args[1].encode("utf-8").decode("unicode_escape")
        values = cmd.args[2:]
        out = []
        while True:
            used = [0]

            def convert(match):
                spec = match.group(0)
                if spec == "%%":
                    return "%"
                value = values[used[0]] if used[0] < len(values) else ""
                used[0] += 1
                if spec[-1] in "di":
                    return (spec[:-1] + "d") % int(awk_module.to_num(value))
                if spec[-1] in "fegx":
                    number = awk_module.to_num(value)
                    return spec % (int(number) if spec[-1] == "x" else number)
                return (spec[:-1] + "s") % value

            out.append(re.sub(r"%[-+ 0#]*\d*(?:\.\d+)?[sdifegx%]", convert, fmt))
            values = values[used[0]:]
            if not values or not used[0]:
                break
        return "".join(out), 0

    def cmd_xargs(self, cmd: Cmd):
        args = cmd.args[1:] or ["echo"]
        if args[0] != "echo":
            raise Unsupported("xargs: only 'xargs echo' is supported in the simulated terminal")
        words = (cmd.stdin or "").split()
        return " ".join(args[1:] + words) + "\n", 0

    def cmd_basename(self, cmd: Cmd):
        return join_lines([posixpath.basename(a.rstrip("/")) for a in cmd.args[1:2]]), 0

    def cmd_dirname(self, cmd: Cmd):
        return join_lines([posixpath.dirname(a.rstrip("/")) or "." for a in cmd.args[1:2]]), 0

    def cmd_touch(self, cmd: Cmd):
        for operand in cmd.args[1:]:
            path = self.resolve(operand)
            if self.fs.is_file(path):
                if not self.fs.writable(path):
                    cmd.error(f"touch: cannot touch '{operand}': Read-only file system")
                continue
            try:
                self.fs.write(path, b"")
            except PermissionError:
                cmd.error(f"touch: cannot touch '{operand}': " + ("Read-only file system" if path.startswith(LOGS)
                                                                  else "Permission denied"))
            except FileNotFoundError:
                cmd.error(f"touch: cannot touch '{operand}': No such file or directory")
        return "", self.status_of(cmd)

    def cmd_mkdir(self, cmd: Cmd):
        _, operands = parse_options(cmd, flags="p")
        for operand in operands:
            path = self.resolve(operand)
            if self.fs.exists(path):
                cmd.error(f"mkdir: cannot create directory '{operand}': File exists")
            elif not self.fs.writable(path):
                cmd.error(f"mkdir: cannot create directory '{operand}': " + (
                    "Read-only file system" if path.startswith(LOGS) else "Permission denied"))
            else:
                self.fs.dirs.add(path)
                self.fs._add_parents(path)
        return "", self.status_of(cmd)

    def cmd_rm(self, cmd: Cmd):
        _, operands = parse_options(cmd, flags="rfi")
        for operand in operands:
            path = self.resolve(operand)
            if not self.fs.exists(path):
                cmd.error(f"rm: cannot remove '{operand}': No such file or directory")
            elif not self.fs.writable(path):
                cmd.error(f"rm: cannot remove '{operand}': " + ("Read-only file system" if path.startswith(LOGS)
                                                                else "Permission denied"))
            elif self.fs.is_dir(path):
                cmd.error(f"rm: cannot remove '{operand}': Is a directory")
            else:
                self.fs.remove(path)
        return "", self.status_of(cmd)

    def _copy(self, cmd: Cmd, move: bool):
        name = cmd.args[0]
        _, operands = parse_options(cmd, flags="rfiv")
        if len(operands) != 2:
            raise ShellError(f"{name}: missing destination file operand")
        source, target = (self.resolve(o) for o in operands)
        if not self.fs.is_file(source):
            raise ShellError(f"{name}: cannot stat '{operands[0]}': No such file or directory")
        if self.fs.is_dir(target):
            target = posixpath.join(target, posixpath.basename(source))
        if move and not self.fs.writable(source):
            raise ShellError(f"{name}: cannot move '{operands[0]}': Read-only file system")
        try:
            self.fs.write(target, self.fs.read_bytes(source))
        except PermissionError:
            raise ShellError(f"{name}: cannot create regular file '{operands[1]}': " + (
                "Read-only file system" if target.startswith(LOGS) else "Permission denied")) from None
        if move:
            self.fs.remove(source)
        return "", 0

    def cmd_cp(self, cmd: Cmd):
        return self._copy(cmd, move=False)

    def cmd_mv(self, cmd: Cmd):
        return self._copy(cmd, move=True)

    def cmd_clear(self, cmd: Cmd):
        return "", 0

    cmd_reset = cmd_clear

    def cmd_history(self, cmd: Cmd):
        return join_lines(f"{i:5d}  {line}" for i, line in enumerate(self.history, 1)), 0

    def cmd_whoami(self, cmd: Cmd):
        return USER + "\n", 0

    def cmd_id(self, cmd: Cmd):
        return "uid=1000(analyst) gid=1000(analyst) groups=1000(analyst)\n", 0

    def cmd_hostname(self, cmd: Cmd):
        return HOST + "\n", 0

    def cmd_uname(self, cmd: Cmd):
        if "-a" in cmd.args:
            return f"Linux {HOST} 6.6.87-simulated #1 SMP x86_64 GNU/Linux\n", 0
        return "Linux\n", 0

    def cmd_date(self, cmd: Cmd):
        now = datetime.now(timezone.utc)
        if len(cmd.args) > 1 and cmd.args[1].startswith("+"):
            return now.strftime(cmd.args[1][1:]) + "\n", 0
        return now.strftime("%a %b %e %H:%M:%S UTC %Y") + "\n", 0

    def cmd_true(self, cmd: Cmd):
        return "", 0

    def cmd_false(self, cmd: Cmd):
        return "", 1

    def cmd_export(self, cmd: Cmd):
        for arg in cmd.args[1:]:
            name, _, value = arg.partition("=")
            self.env[name] = value
        return "", 0

    def cmd_env(self, cmd: Cmd):
        return join_lines(f"{k}={v}" for k, v in sorted(self.env.items())), 0

    def cmd_which(self, cmd: Cmd):
        out = []
        for name in cmd.args[1:]:
            if hasattr(self, "cmd_" + name) and name not in ("cd", "help", "history", "export"):
                out.append(f"/usr/bin/{name}")
        return join_lines(out), 0 if out else 1

    def cmd_type(self, cmd: Cmd):
        out = []
        for name in cmd.args[1:]:
            if name in ("cd", "echo", "pwd", "history", "help", "export", "type", "printf", "true", "false"):
                out.append(f"{name} is a shell builtin")
            elif hasattr(self, "cmd_" + name):
                out.append(f"{name} is /usr/bin/{name}")
            else:
                cmd.error(f"bash: type: {name}: not found")
        return join_lines(out), self.status_of(cmd)

    def cmd_sudo(self, cmd: Cmd):
        raise ShellError(f"{USER} is not in the sudoers file.  This incident will be reported.")

    def cmd_su(self, cmd: Cmd):
        raise ShellError("su: Authentication failure")

    def cmd_exit(self, cmd: Cmd):
        raise Exit(0, "This is the simulated terminal: there is nothing to exit. Type 'clear' to clean the screen.\n")

    cmd_logout = cmd_exit

    def cmd_help(self, cmd: Cmd):
        width = max(len(n) for n in DESCRIPTIONS)
        lines = ["Simulated bash: the commands below work here, with their usual options.",
                 "Pipes (|), redirection (< > >>), quotes, $VARIABLES and $(...) work too.", ""]
        lines += [f"  {name:<{width}}  {text}" for name, text in DESCRIPTIONS.items()]
        lines += ["", "Type 'man COMMAND' for the options of a command."]
        return join_lines(lines), 0

    def cmd_man(self, cmd: Cmd):
        if len(cmd.args) < 2:
            return "What manual page do you want?\nFor example, try 'man grep'.\n", 1
        name = cmd.args[1]
        if name not in MAN_PAGES:
            if name in DESCRIPTIONS:
                return f"{name} - {DESCRIPTIONS[name]}\n", 0
            raise ShellError(f"No manual entry for {name} in the simulated terminal")
        return MAN_PAGES[name] + "\n", 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def human_size(size: int) -> str:
    """Like ls -h: rounded up, one decimal below 10 (8410 -> 8.3K, 95571 -> 94K)."""
    if size < 1024:
        return str(size)
    value = float(size)
    for unit in ("K", "M", "G", "T"):
        value /= 1024
        if value < 1024 or unit == "T":
            if value < 10:
                return f"{math.ceil(value * 10) / 10:.1f}{unit}"
            return f"{math.ceil(value)}{unit}"
    return str(size)


def parse_ranges(spec: str):
    """cut -f 1,3-5,7- -> a function telling whether a 1-based index is selected."""
    ranges = []
    for part in spec.split(","):
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                ranges.append((int(start) if start else 1, int(end) if end else 10 ** 9))
            except ValueError:
                raise ShellError(f"cut: invalid field range") from None
        else:
            try:
                value = int(part)
            except ValueError:
                raise ShellError(f"cut: invalid field value '{part}'") from None
            if value < 1:
                raise ShellError("cut: fields are numbered from 1")
            ranges.append((value, value))
    return lambda i: any(a <= i <= b for a, b in ranges)


def parse_sort_key(spec: str):
    match = re.fullmatch(r"(\d+)(?:\.(\d+))?([a-zA-Z]*)(?:,(\d+)(?:\.(\d+))?([a-zA-Z]*))?", spec)
    if not match:
        raise ShellError(f"sort: invalid key: '{spec}'")
    start, start_char, opts1, end, end_char, opts2 = match.groups()
    opts = set((opts1 or "") + (opts2 or ""))
    return (int(start), int(start_char or 0), int(end) if end else None, int(end_char or 0), opts)


def number_of(text: str, human: bool = False) -> float:
    match = re.match(r"-?\d+(\.\d+)?", text)
    value = float(match.group(0)) if match else 0.0
    if human and match:
        suffix = text[match.end():match.end() + 1].upper()
        value *= 1024 ** ("KMGTP".index(suffix) + 1) if suffix and suffix in "KMGTP" else 1
    return value


def version_key(text: str):
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.findall(r"\d+|\D+", text)]


def expand_tr_set(spec: str) -> str:
    classes = {"[:upper:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "[:lower:]": "abcdefghijklmnopqrstuvwxyz",
               "[:digit:]": "0123456789", "[:space:]": " \t\n\r\f\v", "[:blank:]": " \t",
               "[:punct:]": "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
               "[:alpha:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
               "[:alnum:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"}
    out = []
    i = 0
    while i < len(spec):
        matched = next((c for c in classes if spec.startswith(c, i)), None)
        if matched:
            out.append(classes[matched])
            i += len(matched)
            continue
        ch = spec[i]
        if ch == "\\" and i + 1 < len(spec):
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(spec[i + 1], spec[i + 1]))
            i += 2
            continue
        if i + 2 < len(spec) and spec[i + 1] == "-":
            out.append("".join(chr(c) for c in range(ord(ch), ord(spec[i + 2]) + 1)))
            i += 3
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def squeeze(text: str, chars: str) -> str:
    out = []
    for ch in text:
        if out and ch == out[-1] and ch in chars:
            continue
        out.append(ch)
    return "".join(out)


def parse_json_stream(text: str) -> list:
    decoder = json.JSONDecoder()
    values = []
    i = 0
    text = text.strip()
    while i < len(text):
        value, end = decoder.raw_decode(text, i)
        values.append(value)
        i = end
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
    return values


# sed --------------------------------------------------------------------------
def parse_sed(script: str, extended: bool):
    commands = []
    i = 0
    n = len(script)

    def address(i):
        if i < n and script[i].isdigit():
            match = re.match(r"\d+", script[i:])
            return ("line", int(match.group(0))), i + len(match.group(0))
        if i < n and script[i] == "$":
            return ("last",), i + 1
        if i < n and script[i] == "/":
            end = i + 1
            while end < n and script[end] != "/":
                end += 2 if script[end] == "\\" else 1
            return ("regex", compile_posix(script[i + 1:end], extended)), end + 1
        return None, i

    while i < n:
        while i < n and script[i] in " \t\n;":
            i += 1
        if i >= n:
            break
        first, i = address(i)
        second = None
        if first and i < n and script[i] == ",":
            second, i = address(i + 1)
        negate = False
        if i < n and script[i] == "!":
            negate, i = True, i + 1
        if i >= n:
            raise ShellError("sed: -e expression #1: missing command")
        command = script[i]
        i += 1
        if command == "s":
            delimiter = script[i]
            parts = []
            j = i + 1
            buf = []
            while j < n and len(parts) < 2:
                if script[j] == "\\" and j + 1 < n:
                    buf.append(script[j:j + 2] if script[j + 1] != delimiter else delimiter)
                    j += 2
                    continue
                if script[j] == delimiter:
                    parts.append("".join(buf))
                    buf = []
                else:
                    buf.append(script[j])
                j += 1
            if len(parts) < 2:
                raise ShellError("sed: -e expression #1: unterminated `s' command")
            flags_match = re.match(r"[gpI0-9]*", script[j:])
            flags = flags_match.group(0)
            i = j + len(flags)
            pattern = compile_posix(parts[0], extended, ignore_case="I" in flags)
            replacement = re.sub(r"\\(\d)", r"\\g<\1>", parts[1].replace("\\&", "\x00")).replace("&", r"\g<0>")
            replacement = replacement.replace("\x00", "&").replace("\\n", "\n")
            count = 0 if "g" in flags else int(re.sub(r"\D", "", flags) or 1)
            commands.append((first, second, negate, "s", (pattern, replacement, count, "p" in flags)))
        elif command in "pdq=":
            commands.append((first, second, negate, command, None))
        else:
            raise Unsupported(f"sed: command '{command}' is not supported in the simulated terminal")
    return commands


def run_sed(commands, lines: list[str], quiet: bool) -> str:
    out = []
    active = {}
    for index, line in enumerate(lines):
        number = index + 1
        is_last = index == len(lines) - 1
        deleted = False
        stop = False

        def matches(addr):
            if addr is None:
                return True
            if addr[0] == "line":
                return number == addr[1]
            if addr[0] == "last":
                return is_last
            return bool(addr[1].search(line))

        for position, (first, second, negate, command, data) in enumerate(commands):
            if second is None:
                selected = matches(first)
            elif active.get(position):
                selected = True
                if (second[0] == "line" and number >= second[1]) or (second[0] != "line" and matches(second)):
                    active[position] = False
            else:
                selected = matches(first)
                if selected:
                    active[position] = not ((second[0] == "line" and number >= second[1]))
            if negate:
                selected = not selected
            if not selected:
                continue
            if command == "s":
                pattern, replacement, count, print_it = data
                if count > 1:
                    occurrences = list(pattern.finditer(line))
                    if len(occurrences) >= count:
                        m = occurrences[count - 1]
                        line = line[:m.start()] + m.expand(replacement) + line[m.end():]
                        if print_it:
                            out.append(line)
                    continue
                new, made = pattern.subn(replacement, line, count=count)
                line = new
                if made and print_it:
                    out.append(line)
            elif command == "p":
                out.append(line)
            elif command == "=":
                out.append(str(number))
            elif command == "d":
                deleted = True
                break
            elif command == "q":
                stop = True
                break
        if not deleted and not quiet:
            out.append(line)
        if stop:
            break
    return join_lines(out)


MAN_PAGES = {
    "grep": "grep [OPTIONS] PATTERN [FILE...] - print lines that match PATTERN\n"
            "  -i ignore case    -v lines that do NOT match   -c count matching lines\n"
            "  -n line numbers   -o only the matching part    -E extended regex (a|b, +, ?)\n"
            "  -F fixed text     -w whole words               -h/-H hide/show file names\n"
            "  -l file names     -r search folders            -A/-B/-C N lines of context",
    "awk": "awk [-F SEP] 'PATTERN { ACTION }' [FILE...] - process fields\n"
           "  $1, $2 ... fields; $0 the line; NF number of fields ($NF the last); NR line number\n"
           "  -F, splits on commas.  Example: awk -F, '$6==\"FAILURE\" {print $3}' logs/sample_auth_logs.csv\n"
           "  Counting: awk '{c[$1]++} END {for (k in c) print c[k], k}'",
    "sort": "sort [OPTIONS] [FILE...] - sort lines\n"
            "  -n numeric   -r reverse   -u unique   -k N sort by field N   -t SEP field separator",
    "uniq": "uniq [OPTIONS] - collapse REPEATED NEIGHBOUR lines (sort first!)\n"
            "  -c count   -d only repeated   -u only unique",
    "cut": "cut -d SEP -f LIST [FILE...] - pick fields\n  Example: cut -d, -f3,4 logs/sample_auth_logs.csv",
    "wc": "wc [-l|-w|-c] [FILE...] - count lines, words, bytes.  'wc -l < FILE' prints only the number",
    "head": "head [-n N] [FILE...] - first N lines (10 by default); head -5 works too",
    "tail": "tail [-n N] [FILE...] - last N lines; tail -n +2 starts at line 2 (skips a CSV header)",
    "jq": "jq [-r] [-c] FILTER [FILE...] - query JSON\n"
          "  .value[] each item   .status.errorCode a nested field   select(COND) keep matching items\n"
          "  length   map(...)   group_by(...)   sort_by(...)   -r prints strings without quotes",
    "sed": "sed [-n] [-E] SCRIPT [FILE...] - edit lines\n"
           "  s/old/new/ replace (g = all)   -n '5,10p' print lines 5 to 10   '/regex/d' delete lines",
    "tr": "tr SET1 SET2 - translate characters;  tr -d SET deletes;  tr -s ' ' squeezes repeats\n"
          "  Example: tr ',' '\\n'  or  tr 'a-z' 'A-Z'",
    "ls": "ls [-l] [-a] [-h] [-R] [PATH...] - list files (-l details, -h human sizes)",
    "cat": "cat [-n] [FILE...] - print files (-n numbers the lines)",
    "file": "file FILE... - guess what a file contains",
}
