"""Simulated Windows Command Prompt (cmd.exe): the classic commands for reading logs on Windows.

The home folder is C:\\Users\\analyst, with the lab's logs in logs\\. Supported: %VARIABLES%, quotes
and ^ escapes, pipes, < > >> 2>nul, & && ||, and dir, cd, type, more, find, findstr, sort, echo, set,
for /f, if, tree, cls, ver, whoami, hostname, date /t, time /t, copy, del, mkdir, help and exit.
Paths and command names ignore case, as on Windows.
"""

from __future__ import annotations

import posixpath
import re
from datetime import datetime, timezone

from .core import HOME, HOST, LOGS, USER, Result, Shell, ShellError, Unsupported

WIN_HOME = "C:\\Users\\analyst"
NOT_RECOGNIZED = "'{0}' is not recognized as an internal or external command,\noperable program or batch file."
HELP = {
    "cd": "Displays the name of or changes the current directory.", "cls": "Clears the screen.",
    "date": "Displays the date (date /t).", "dir": "Displays a list of files and subdirectories in a directory.",
    "echo": "Displays messages.", "exit": "Quits the CMD.EXE program (not here: this is a simulation).",
    "find": "Searches for a text string in a file or files.",
    "findstr": "Searches for strings in files (several words = any of them; /c:\"a phrase\").",
    "for": "Runs a command for each line or token (for /f).", "help": "Provides Help information for commands.",
    "if": "Performs conditional processing.", "more": "Displays output one screen at a time.",
    "set": "Displays or sets environment variables.", "sort": "Sorts input.", "time": "Displays the time (time /t).",
    "tree": "Graphically displays the folder structure.", "type": "Displays the contents of a text file.",
    "ver": "Displays the Windows version.", "whoami": "Displays the current user.",
    "hostname": "Displays the computer name.", "copy": "Copies a file.", "del": "Deletes a file you created.",
    "mkdir": "Creates a directory.",
}
USAGE = {
    "find": "Searches for a text string in a file or files.\n\nFIND [/V] [/C] [/N] [/I] \"string\" [[drive:][path]filename[ ...]]\n\n"
            "  /V  Displays all lines NOT containing the specified string.\n"
            "  /C  Displays only the count of lines containing the string.\n"
            "  /N  Displays line numbers with the displayed lines.\n"
            "  /I  Ignores the case of characters when searching for the string.\n"
            "  \"string\"  The text string to find (always in double quotes).",
    "findstr": "Searches for strings in files.\n\nFINDSTR [/B] [/E] [/L] [/R] [/I] [/X] [/V] [/N] [/M] [/C:string] strings [files]\n\n"
               "  /B  Matches pattern if at the beginning of a line.   /E  ... at the end of a line.\n"
               "  /L  Uses search strings literally.                   /R  Uses search strings as regular expressions.\n"
               "  /I  Case-insensitive.   /X  Whole line.   /V  Lines that do not match.   /N  Line numbers.\n"
               "  /M  Only the file names.   /C:string  A literal search string (use it for phrases with spaces).\n"
               "  strings  Text to be searched for: several words separated by spaces match ANY of them.",
    "for": "FOR /F [\"options\"] %variable IN ('command' | (file) | (\"text\")) DO command\n\n"
           "  options: tokens=1,3 or tokens=2-4 (which words to take), delims=, (separators; default space and tab),\n"
           "           skip=1 (lines to skip), eol=; (comment character).\n"
           "  Example: for /f \"tokens=3 delims=,\" %a in (logs\\sample_auth_logs.csv) do @echo %a",
}


class CmdShell(Shell):
    name = "cmd"

    def __init__(self, fs, cwd: str = HOME):
        super().__init__(fs, cwd)
        self.env = {"USERPROFILE": WIN_HOME, "USERNAME": USER, "COMPUTERNAME": HOST.upper(), "HOMEDRIVE": "C:",
                    "HOMEPATH": "\\Users\\analyst", "OS": "Windows_NT", "PROMPT": "$P$G", "SYSTEMROOT": "C:\\Windows",
                    "COMSPEC": "C:\\Windows\\system32\\cmd.exe", "PATHEXT": ".COM;.EXE;.BAT;.CMD"}
        self.errorlevel = 0
        self.cleared = False

    # paths ------------------------------------------------------------------------
    def prompt(self) -> str:
        return f"{to_windows(self.cwd)}>"

    def resolve(self, path: str) -> str:
        """A Windows path (any case) -> the POSIX path of the simulated file system."""
        path = path.strip('"').replace("/", "\\")
        if re.match(r"^[A-Za-z]:", path):
            drive, rest = path[:2], path[2:]
            if drive.upper() != "C:":
                raise ShellError("The system cannot find the drive specified.")
            base = "/" if rest.startswith("\\") else self.cwd
            path = rest
        elif path.startswith("\\"):
            base = "/"
        else:
            base = self.cwd
        parts = [p for p in path.split("\\") if p and p != "."]
        current = base
        for part in parts:
            if part == "..":
                current = posixpath.dirname(current) or "/"
                continue
            if current == "/" and part.lower() == "users":
                current = "/home"
                continue
            entries = self.fs.listdir(current) if self.fs.is_dir(current) else []
            actual = next((e for e in entries if e.lower() == part.lower()), part)
            current = posixpath.join(current, actual)
        return current

    # line parsing --------------------------------------------------------------------
    def expand(self, line: str) -> str:
        def replace(match):
            name = match.group(1)
            upper = name.upper()
            if upper == "CD":
                return to_windows(self.cwd)
            if upper == "ERRORLEVEL":
                return str(self.errorlevel)
            if upper == "DATE":
                return datetime.now(timezone.utc).strftime("%a %m/%d/%Y")
            if upper == "TIME":
                return datetime.now(timezone.utc).strftime("%H:%M:%S.00")
            if upper == "RANDOM":
                return "4242"
            for key, value in self.env.items():
                if key.upper() == upper:
                    return value
            return match.group(0)  # an unknown %NAME% stays as typed, like cmd.exe at the prompt

        return re.sub(r"%([A-Za-z_][\w()]*)%", replace, line)

    @staticmethod
    def split(line: str, separators: tuple[str, ...]) -> list[tuple[str, str]]:
        """Split at operators outside quotes and ^ escapes: [(operator before, text)]."""
        parts = []
        current = []
        link = ""
        quoted = False
        depth = 0
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"':
                quoted = not quoted
            elif ch == "^" and not quoted and i + 1 < len(line):
                current.append(line[i:i + 2])
                i += 2
                continue
            elif ch == "(" and not quoted:
                depth += 1
            elif ch == ")" and not quoted:
                depth = max(depth - 1, 0)
            if not quoted and depth == 0:
                op = next((s for s in separators if line.startswith(s, i)), None)
                if op:
                    parts.append((link, "".join(current)))
                    current, link = [], op
                    i += len(op)
                    continue
            current.append(ch)
            i += 1
        parts.append((link, "".join(current)))
        return parts

    def execute(self, line: str) -> Result:
        self.cleared = False
        if not line.strip():
            return Result()
        output, errors = self.run_line(self.expand(line))
        return Result(output=output, error="\n".join(errors), clear=self.cleared)

    def run_line(self, line: str) -> tuple[str, list[str]]:
        out, errors = [], []
        for link, chunk in self.split(line, ("&&", "||", "&")):
            if link == "&&" and self.errorlevel != 0:
                continue
            if link == "||" and self.errorlevel == 0:
                continue
            if not chunk.strip():
                if link:
                    errors.append(f"{link} was unexpected at this time.")
                    self.errorlevel = 255
                continue
            text, errs = self.run_pipeline(chunk)
            if self.cleared:
                out = []
            out.append(text)
            errors += errs
        return "".join(out), errors

    def run_pipeline(self, chunk: str) -> tuple[str, list[str]]:
        stages = [text for _, text in self.split(chunk, ("|",))]
        data: str | None = None
        errors: list[str] = []
        for index, stage in enumerate(stages):
            words, stdin_file, stdout_file, append, hide_errors = self.redirections(stage)
            if stdin_file is not None:
                path = self.resolve(stdin_file)
                if not self.fs.is_file(path):
                    errors.append("The system cannot find the file specified.")
                    data = ""
                    self.errorlevel = 1
                    continue
                data = self.fs.read_text(path)
            stage_errors: list[str] = []
            if not words:
                data = ""
                continue
            try:
                data, self.errorlevel = self.call(words, data if index > 0 or stdin_file else None, stage_errors,
                                                  raw=stage)
            except ShellError as exc:
                stage_errors.append(str(exc))
                data, self.errorlevel = "", 1
            if not hide_errors:
                errors += stage_errors
            if stdout_file is not None:
                if stdout_file.lower() == "nul":
                    data = ""
                    continue
                path = self.resolve(stdout_file)
                try:
                    self.fs.write(path, data.encode("utf-8"), append=append)
                except (PermissionError, IsADirectoryError):
                    errors.append("Access is denied.")
                    self.errorlevel = 1
                except FileNotFoundError:
                    errors.append("The system cannot find the path specified.")
                    self.errorlevel = 1
                data = ""
        return data or "", errors

    def redirections(self, stage: str):
        words = tokenize(stage)
        out = []
        stdin_file = stdout_file = None
        append = hide_errors = False
        i = 0
        while i < len(words):
            word = words[i]
            match = re.fullmatch(r"(2>>|2>|>>|>|<)(.*)", word)
            if match and not word.startswith('"'):
                op, target = match.groups()
                if not target:
                    if i + 1 >= len(words):
                        raise ShellError("The syntax of the command is incorrect.")
                    target = words[i + 1]
                    i += 1
                if op == "<":
                    stdin_file = target
                elif op in (">", ">>"):
                    stdout_file, append = target, op == ">>"
                elif target.lower() == "nul" or target == "&1":
                    hide_errors = target.lower() == "nul"
                else:
                    raise Unsupported("Saving errors to a file is not supported in the simulated terminal.")
                i += 1
                continue
            out.append(word)
            i += 1
        return out, stdin_file, stdout_file, append, hide_errors

    # commands ----------------------------------------------------------------------
    def call(self, words: list[str], stdin: str | None, errors: list[str], raw: str = "") -> tuple[str, int]:
        name = words[0]
        quiet = name.startswith("@")
        if quiet:
            name = name[1:]
            words = [name] + words[1:]
        lower = name.lower()
        if lower.startswith("echo.") or lower == "echo.":
            return (name[5:] + "\n"), 0
        if lower.endswith(".exe"):
            lower = lower[:-4]
        if len(words) > 1 and words[1] == "/?":
            return (USAGE.get(lower) or HELP.get(lower, "")) + "\n", 0
        handler = getattr(self, "c_" + lower, None) if re.fullmatch(r"[a-z]+", lower) else None
        if handler is None:
            if lower in ("powershell", "pwsh"):
                raise Unsupported("To use PowerShell, choose it in the Shell selector above the terminal.")
            if lower in ("grep", "awk", "ls", "cat", "wc", "head", "tail"):
                raise ShellError(NOT_RECOGNIZED.format(name) + f"\n(Hint: '{lower}' is a Linux command. In CMD use "
                                 + {"grep": "find or findstr", "ls": "dir", "cat": "type", "wc": "find /c /v \"\"",
                                    "head": "more", "tail": "more +N", "awk": "for /f"}[lower] + ".)")
            if lower in ("netstat", "ipconfig", "tasklist", "wevtutil", "net", "reg", "sc", "schtasks", "ping",
                         "nslookup", "systeminfo", "certutil", "wmic", "notepad", "start"):
                raise Unsupported(f"{name}: not available in the simulated terminal (no network, processes or "
                                  f"system configuration here).")
            raise ShellError(NOT_RECOGNIZED.format(name))
        return handler(words[1:], stdin, errors, raw)

    @staticmethod
    def switches(args: list[str], valued: tuple[str, ...] = ()) -> tuple[dict, list[str]]:
        options: dict = {}
        rest = []
        for arg in args:
            if arg.startswith("/") and len(arg) > 1:
                body = arg[1:]
                key, sep, value = body.partition(":")
                key = key.lower()
                if key in valued or sep:
                    options.setdefault(key, []).append(value)
                else:
                    for ch in key if len(key) > 1 and key not in ("ad", "ah", "on", "od", "os") else [key]:
                        options[ch] = True
            else:
                rest.append(arg)
        return options, rest

    def read(self, name: str, errors: list[str]) -> str | None:
        path = self.resolve(name)
        if self.fs.is_dir(path):
            errors.append("Access is denied.")
            return None
        if not self.fs.is_file(path):
            return None
        return self.fs.read_text(path)

    def c_cd(self, args, stdin, errors, raw=""):
        target = " ".join(a for a in args if a.lower() != "/d").strip('"')
        if not target:
            return to_windows(self.cwd) + "\n", 0
        path = self.resolve(target)
        if not self.fs.is_dir(path):
            raise ShellError("The system cannot find the path specified.")
        self.cwd = path
        return "", 0

    c_chdir = c_cd

    def c_dir(self, args, stdin, errors, raw=""):
        options, targets = self.switches(args)
        targets = targets or ["."]
        out = []
        found_any = False
        for target in targets:
            pattern = None
            path = self.resolve(target)
            if not self.fs.exists(path) and any(ch in target for ch in "*?"):
                pattern = re.compile("^" + re.escape(posixpath.basename(path)).replace(r"\*", ".*").replace(r"\?", ".")
                                     + "$", re.IGNORECASE)
                path = posixpath.dirname(path)
            if not self.fs.exists(path):
                errors.append("File Not Found")
                continue
            folders = [path] if self.fs.is_dir(path) else []
            single = [path] if self.fs.is_file(path) else []
            if options.get("s"):
                queue = list(folders)
                folders = []
                while queue:
                    folder = queue.pop(0)
                    folders.append(folder)
                    queue += [posixpath.join(folder, e) for e in self.fs.listdir(folder)
                              if self.fs.is_dir(posixpath.join(folder, e))]
            for folder in folders or [posixpath.dirname(path)]:
                entries = single if single else [posixpath.join(folder, e) for e in self.fs.listdir(folder)]
                if pattern:
                    entries = [e for e in entries if pattern.match(posixpath.basename(e))]
                if options.get("a") is None and not options.get("b"):
                    pass
                files = [e for e in entries if self.fs.is_file(e)]
                dirs = [e for e in entries if self.fs.is_dir(e)]
                if not entries and not options.get("b"):
                    continue
                found_any = found_any or bool(entries)
                if options.get("b"):
                    for e in dirs + files if not options.get("s") else entries:
                        out.append(to_windows(e) if options.get("s") else posixpath.basename(e))
                    continue
                if not out:
                    out += [" Volume in drive C has no label.", " Volume Serial Number is 5A1C-3E7F", ""]
                out.append(f" Directory of {to_windows(folder)}")
                out.append("")
                listing = sorted(dirs, key=str.lower) + sorted(files, key=str.lower)
                if not single and not pattern:
                    out.append("10/27/2026  09:00 AM    <DIR>          .")
                    out.append("10/27/2026  09:00 AM    <DIR>          ..")
                for entry in listing:
                    name = posixpath.basename(entry)
                    if self.fs.is_dir(entry):
                        out.append(f"10/27/2026  09:00 AM    <DIR>          {name}")
                    else:
                        out.append(f"10/27/2026  09:00 AM    {self.fs.size(entry):>14,} {name}")
                total = sum(self.fs.size(f) for f in files)
                dir_count = len(dirs) + (0 if single or pattern else 2)
                out.append(f"{len(files):>16} File(s) {total:>14,} bytes")
                out.append(f"{dir_count:>16} Dir(s)  {104_857_600:>14,} bytes free")
                out.append("")
        if not found_any and not out:
            if not errors:
                errors.append("File Not Found")
            return "", 1
        return "".join(line + "\n" for line in out), 0

    def c_type(self, args, stdin, errors, raw=""):
        if not args:
            raise ShellError("The syntax of the command is incorrect.")
        out = []
        for name in args:
            text = self.read(name, errors)
            if text is None:
                if not errors:
                    errors.append("The system cannot find the file specified.")
                continue
            if len(args) > 1:
                errors.append(f"\n{name}\n\n")
            out.append(text if text.endswith("\n") or not text else text + "\n")
        return "".join(out), 1 if errors and not out else 0

    def c_more(self, args, stdin, errors, raw=""):
        skip = 0
        files = []
        for arg in args:
            if re.fullmatch(r"\+\d+", arg):
                skip = int(arg[1:])
            elif arg.startswith("/"):
                continue
            else:
                files.append(arg)
        if files:
            texts = []
            for name in files:
                text = self.read(name, errors)
                if text is None:
                    raise ShellError(f"Cannot access file {to_windows(self.resolve(name))}")
                texts.append(text)
            text = "".join(texts)
        else:
            text = stdin or ""
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        return "".join(line + "\n" for line in lines[skip:]), 0

    def c_find(self, args, stdin, errors, raw=""):
        options = {}
        operands = []
        for arg in args:
            if arg.startswith("/") and len(arg) == 2 and arg[1].lower() in "vcni":
                options[arg[1].lower()] = True
            elif arg.startswith("/off"):
                continue
            elif arg.startswith("/"):
                raise ShellError(f"FIND: Invalid switch")
            else:
                operands.append(arg)
        if not operands or not operands[0].startswith('"') or not operands[0].endswith('"') or len(operands[0]) < 2:
            raise ShellError("FIND: Parameter format not correct")
        needle = operands[0][1:-1].replace('""', '"')
        files = operands[1:]

        def matches(line: str) -> bool:
            # An empty string matches no line, which is why find /c /v "" counts every line.
            found = bool(needle) and (needle.lower() in line.lower() if options.get("i") else needle in line)
            return found != bool(options.get("v"))

        def lines_of(text: str) -> list[str]:
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            return lines

        out = []
        any_match = False
        if not files:
            lines = lines_of(stdin or "")
            hits = [(n, line) for n, line in enumerate(lines, 1) if matches(line)]
            any_match = bool(hits)
            if options.get("c"):
                out.append(str(len(hits)))
            else:
                out += [f"[{n}]{line}" if options.get("n") else line for n, line in hits]
            return "".join(l + "\n" for l in out), 0 if any_match else 1
        for name in files:
            expanded = self.expand_wildcards(name)
            if not expanded:
                errors.append(f"File not found - {name.upper()}")
                continue
            for actual_name, path in expanded:
                text = self.fs.read_text(path)
                hits = [(n, line) for n, line in enumerate(lines_of(text), 1) if matches(line)]
                any_match = any_match or bool(hits)
                header = f"---------- {actual_name.upper()}"
                if options.get("c"):
                    out.append("")
                    out.append(f"{header}: {len(hits)}")
                else:
                    out.append("")
                    out.append(header)
                    out += [f"[{n}]{line}" if options.get("n") else line for n, line in hits]
        return "".join(l + "\n" for l in out), 0 if any_match else 1

    def expand_wildcards(self, name: str) -> list[tuple[str, str]]:
        path = self.resolve(name)
        if self.fs.is_file(path):
            return [(name, path)]
        if any(ch in name for ch in "*?"):
            folder = posixpath.dirname(path)
            regex = re.compile("^" + re.escape(posixpath.basename(path)).replace(r"\*", ".*").replace(r"\?", ".") + "$",
                               re.IGNORECASE)
            prefix = name.replace("/", "\\").rsplit("\\", 1)[0] + "\\" if "\\" in name.replace("/", "\\") else ""
            return [(prefix + e, posixpath.join(folder, e)) for e in self.fs.listdir(folder)
                    if regex.match(e) and self.fs.is_file(posixpath.join(folder, e))]
        return []

    def c_findstr(self, args, stdin, errors, raw=""):
        literal_strings = []
        flags = set()
        operands = []
        for arg in args:
            if arg.startswith("/") and len(arg) > 1:
                body = arg[1:]
                if body[:2].lower() == "c:":
                    literal_strings.append(unquote(body[2:]))
                    continue
                if body[:2].lower() in ("g:", "f:", "d:", "a:"):
                    raise Unsupported(f"FINDSTR: /{body[:1]} is not supported in the simulated terminal")
                for ch in body.lower():
                    if ch not in "belrsixvnmop":
                        raise ShellError(f"FINDSTR: /{ch} ignored" if False else f"FINDSTR: Bad command line")
                    flags.add(ch)
            else:
                operands.append(arg)
        if not literal_strings:
            if not operands:
                raise ShellError("FINDSTR: Bad command line")
            strings = unquote(operands.pop(0)).split()
        else:
            strings = literal_strings
        regex_mode = "r" in flags or ("l" not in flags and not literal_strings)
        case = 0 if "i" not in flags else re.IGNORECASE
        patterns = []
        for text in strings:
            body = findstr_regex(text) if regex_mode else re.escape(text)
            if "b" in flags:
                body = "^(?:" + body + ")"
            if "e" in flags:
                body = "(?:" + body + ")$"
            if "x" in flags:
                body = "^(?:" + body + ")$"
            patterns.append(re.compile(body, case))

        def hit(line: str) -> bool:
            return any(p.search(line) for p in patterns) != ("v" in flags)

        def lines_of(text: str) -> list[str]:
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            return lines

        out = []
        found = False
        if not operands:
            for number, line in enumerate(lines_of(stdin or ""), 1):
                if hit(line):
                    found = True
                    out.append(f"{number}:{line}" if "n" in flags else line)
            return "".join(l + "\n" for l in out), 0 if found else 1
        sources = []
        for name in operands:
            expanded = self.expand_wildcards(name)
            if not expanded:
                errors.append(f"FINDSTR: Cannot open {name}")
            sources += expanded
        many = len(sources) > 1
        for name, path in sources:
            matched_file = False
            for number, line in enumerate(lines_of(self.fs.read_text(path)), 1):
                if hit(line):
                    found = matched_file = True
                    if "m" in flags:
                        break
                    prefix = (f"{name}:" if many else "") + (f"{number}:" if "n" in flags else "")
                    out.append(prefix + line)
            if "m" in flags and matched_file:
                out.append(name)
        return "".join(l + "\n" for l in out), 0 if found else 1

    def c_sort(self, args, stdin, errors, raw=""):
        options, files = self.switches(args)
        text = stdin or ""
        if files:
            text = self.read(files[0], errors)
            if text is None:
                raise ShellError("The system cannot find the file specified.")
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        column = 0
        for arg in args:
            if re.fullmatch(r"/\+\d+", arg):
                column = int(arg[2:]) - 1
        lines.sort(key=lambda l: l[column:].lower(), reverse=bool(options.get("r")))
        return "".join(l + "\n" for l in lines), 0

    def c_echo(self, args, stdin, errors, raw=""):
        # Like cmd.exe, keep the spaces before & and > ("echo hi > f" writes "hi ").
        text = re.sub(r"^\s*@?echo(\.|\s)?", "", raw, flags=re.IGNORECASE)
        text = re.sub(r"(2>>|2>|>>|>|<)\s*\S+", "", text) if re.search(r"(>|<)", text) else text
        text = re.sub(r"\^(.)", r"\1", text)
        if text.strip().lower() in ("on", "off"):
            return "", 0
        if not text.strip() and not raw.lstrip().lower().startswith(("echo.", "@echo.")):
            return "ECHO is on.\n", 0
        return text + "\n", 0

    def c_set(self, args, stdin, errors, raw=""):
        text = re.sub(r"^\s*set\s*", "", raw.strip(), flags=re.IGNORECASE)
        if text.lower().startswith("/a"):
            expression = text[2:].strip().strip('"')
            name, _, formula = expression.partition("=")
            if not re.fullmatch(r"[\d\s+\-*/()%A-Za-z_]+", formula or name):
                raise ShellError("Missing operand.")
            value = eval_arithmetic(formula or name, self.env)
            if formula:
                self.env[name.strip()] = str(value)
            return f"{value}\n", 0
        if text.lower().startswith("/p"):
            raise Unsupported("set /p (asking for input) is not supported in the simulated terminal.")
        if "=" in text:
            name, _, value = text.strip('"').partition("=")
            if value:
                self.env[name] = value
            else:
                self.env.pop(name, None)
            return "", 0
        items = sorted(self.env.items(), key=lambda kv: kv[0].lower())
        if text:
            items = [(k, v) for k, v in items if k.lower().startswith(text.lower())]
            if not items:
                raise ShellError(f"Environment variable {text} not defined")
        return "".join(f"{k}={v}\n" for k, v in items), 0

    def c_for(self, args, stdin, errors, raw=""):
        match = re.match(r'^\s*@?for\s+/f\s+(?:"([^"]*)"\s+)?%%?([A-Za-z])\s+in\s+\((.*)\)\s+do\s+(.+)$', raw.strip(),
                         re.IGNORECASE | re.DOTALL)
        if not match:
            if re.match(r"^\s*@?for\s+%%?[A-Za-z]\s+in", raw, re.IGNORECASE):
                raise Unsupported("Only 'for /f' is supported in the simulated terminal. Type 'for /?' for help.")
            raise ShellError("The syntax of the command is incorrect.")
        options_text, letter, source, command = match.groups()
        options = parse_for_options(options_text or "")
        source = source.strip()
        if source.startswith("'") and source.endswith("'"):
            inner = source[1:-1].replace("^|", "|").replace("^&", "&").replace("^>", ">")
            text, errs = self.run_line(inner)
            errors += errs
        elif source.startswith('"') and source.endswith('"') and not options.get("usebackq"):
            text = source[1:-1] + "\n"
        else:
            text = ""
            for name in tokenize(source):
                content = self.read(name, errors)
                if content is None:
                    raise ShellError(f"The system cannot find the file {name}.")
                text += content
        lines = [l for l in text.split("\n") if l.strip()]
        lines = lines[options.get("skip", 0):]
        out = []
        letters = [chr(ord(letter) + i) for i in range(26) if ord(letter) + i <= ord("z" if letter.islower() else "Z")]
        for line in lines:
            if options.get("eol") and line.startswith(options["eol"]):
                continue
            tokens = for_tokens(line, options)
            if not tokens or tokens[0] is None:
                continue
            body = command
            for i, value in enumerate(tokens):
                if i < len(letters):
                    body = re.sub(r"%%?" + letters[i] + r"\b", lambda _m, v=value or "": v, body)
            quiet = body.lstrip().startswith("@")
            if not quiet:
                out.append("\n" + self.prompt() + body.strip() + "\n")
            text, errs = self.run_line(body.lstrip().lstrip("@"))
            out.append(text)
            errors += errs
        return "".join(out), 0

    def c_if(self, args, stdin, errors, raw=""):
        text = re.sub(r"^\s*@?if\s+", "", raw.strip(), flags=re.IGNORECASE)
        ignore_case = False
        negate = False
        while True:
            if text.lower().startswith("/i "):
                ignore_case, text = True, text[3:].lstrip()
            elif text.lower().startswith("not "):
                negate, text = True, text[4:].lstrip()
            else:
                break
        exists = re.match(r"^exist\s+(\"[^\"]*\"|\S+)\s+(.+)$", text, re.IGNORECASE)
        if exists:
            result = self.fs.exists(self.resolve(exists.group(1)))
            rest = exists.group(2)
        else:
            compare = re.match(r'^("[^"]*"|\S+?)\s*(==|\s+EQU\s+|\s+NEQ\s+|\s+GTR\s+|\s+LSS\s+|\s+GEQ\s+|\s+LEQ\s+)\s*'
                               r'("[^"]*"|\S+)\s+(.+)$', text, re.IGNORECASE)
            if not compare:
                raise ShellError("The syntax of the command is incorrect.")
            left, op, right, rest = compare.groups()
            op = op.strip().upper()
            a, b = (left.lower(), right.lower()) if ignore_case else (left, right)
            if op == "==":
                result = a == b
            else:
                try:
                    x, y = int(a.strip('"')), int(b.strip('"'))
                except ValueError:
                    x, y = a, b
                result = {"EQU": x == y, "NEQ": x != y, "GTR": x > y, "LSS": x < y, "GEQ": x >= y, "LEQ": x <= y}[op]
        if negate:
            result = not result
        else_part = None
        else_match = re.match(r"^\((.*)\)\s+else\s+\((.*)\)$", rest.strip(), re.IGNORECASE | re.DOTALL)
        if else_match:
            rest, else_part = else_match.groups()
        if result:
            text, errs = self.run_line(rest.strip().strip("()"))
        elif else_part is not None:
            text, errs = self.run_line(else_part)
        else:
            return "", 0
        errors += errs
        return text, 0

    def c_tree(self, args, stdin, errors, raw=""):
        options, targets = self.switches(args)
        root = self.resolve(targets[0]) if targets else self.cwd
        if not self.fs.is_dir(root):
            raise ShellError("Invalid path - " + (targets[0] if targets else ""))
        ascii_art = bool(options.get("a"))
        branch, last_branch, pipe = ("+---", "\\---", "|   ") if ascii_art else ("├───", "└───", "│   ")
        out = ["Folder PATH listing", "Volume serial number is 5A1C-3E7F", to_windows(root).upper()]

        def walk(folder: str, indent: str):
            entries = self.fs.listdir(folder)
            dirs = [e for e in entries if self.fs.is_dir(posixpath.join(folder, e))]
            files = [e for e in entries if self.fs.is_file(posixpath.join(folder, e))]
            if options.get("f"):
                for f in files:
                    out.append(indent + (pipe if dirs else "    ") + f)
                if files:
                    out.append(indent + (pipe if dirs else "    "))
            for index, d in enumerate(dirs):
                last_one = index == len(dirs) - 1
                out.append(indent + (last_branch if last_one else branch) + d)
                walk(posixpath.join(folder, d), indent + ("    " if last_one else pipe))

        walk(root, "")
        if len(out) == 3:
            out.append("No subfolders exist")
        return "".join(l + "\n" for l in out) + "\n", 0

    def c_cls(self, args, stdin, errors, raw=""):
        self.cleared = True
        return "", 0

    def c_ver(self, args, stdin, errors, raw=""):
        return "\nMicrosoft Windows [Version 10.0.26100.1 (simulated)]\n", 0

    def c_whoami(self, args, stdin, errors, raw=""):
        return f"{HOST}\\{USER}\n", 0

    def c_hostname(self, args, stdin, errors, raw=""):
        return HOST.upper() + "\n", 0

    def c_date(self, args, stdin, errors, raw=""):
        if not any(a.lower() == "/t" for a in args):
            raise Unsupported("Changing the date is not supported; use 'date /t' to show it.")
        return datetime.now(timezone.utc).strftime("%a %m/%d/%Y") + "\n", 0

    def c_time(self, args, stdin, errors, raw=""):
        if not any(a.lower() == "/t" for a in args):
            raise Unsupported("Changing the time is not supported; use 'time /t' to show it.")
        return datetime.now(timezone.utc).strftime("%I:%M %p") + "\n", 0

    def c_title(self, args, stdin, errors, raw=""):
        return "", 0

    def c_rem(self, args, stdin, errors, raw=""):
        return "", 0

    def c_copy(self, args, stdin, errors, raw=""):
        _, operands = self.switches(args)
        if len(operands) != 2:
            raise ShellError("The syntax of the command is incorrect.")
        source = self.resolve(operands[0])
        target = self.resolve(operands[1])
        if not self.fs.is_file(source):
            raise ShellError("The system cannot find the file specified.")
        if self.fs.is_dir(target):
            target = posixpath.join(target, posixpath.basename(source))
        try:
            self.fs.write(target, self.fs.read_bytes(source))
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            raise ShellError("Access is denied.\n        0 file(s) copied.") from None
        return "        1 file(s) copied.\n", 0

    def c_del(self, args, stdin, errors, raw=""):
        _, operands = self.switches(args)
        for name in operands:
            path = self.resolve(name)
            if not self.fs.is_file(path):
                errors.append(f"Could Not Find {to_windows(path)}")
            elif not self.fs.writable(path):
                errors.append(f"{to_windows(path)}\nAccess is denied.")
            else:
                self.fs.remove(path)
        return "", 1 if errors else 0

    c_erase = c_del

    def c_mkdir(self, args, stdin, errors, raw=""):
        for name in args:
            path = self.resolve(name)
            if self.fs.exists(path):
                errors.append(f"A subdirectory or file {name} already exists.")
            elif not self.fs.writable(path):
                errors.append("Access is denied.")
            else:
                self.fs.dirs.add(path)
                self.fs._add_parents(path)
        return "", 1 if errors else 0

    c_md = c_mkdir

    def c_help(self, args, stdin, errors, raw=""):
        if args:
            name = args[0].lower()
            if name in USAGE or name in HELP:
                return (USAGE.get(name) or HELP[name]) + "\n", 0
            return f"This command is not supported by the help utility.  Try \"{args[0]} /?\".\n", 1
        lines = ["For more information on a specific command, type HELP command-name.",
                 "These commands work in the simulated Command Prompt:", ""]
        lines += [f"{name.upper():<10}{text}" for name, text in sorted(HELP.items())]
        lines += ["", "Pipes (|), redirection (> >>), & && || and %VARIABLES% work too."]
        return "".join(l + "\n" for l in lines), 0

    def c_exit(self, args, stdin, errors, raw=""):
        return "This is the simulated terminal: there is nothing to exit. Type 'cls' to clear the screen.\n", 0

    def c_doskey(self, args, stdin, errors, raw=""):
        if any(a.lower() == "/history" for a in args):
            return "".join(line + "\n" for line in self.history[:-1]), 0
        raise Unsupported("doskey: only /history is supported in the simulated terminal.")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def to_windows(path: str) -> str:
    if path == HOME or path.startswith(HOME + "/"):
        return WIN_HOME + path[len(HOME):].replace("/", "\\")
    if path == "/home" or path.startswith("/home/"):
        return "C:\\Users" + path[len("/home"):].replace("/", "\\")
    return "C:" + path.replace("/", "\\") if path != "/" else "C:\\"


def tokenize(text: str) -> list[str]:
    """Split a command into words: spaces separate, quotes are kept (find needs to see them), ^ escapes.
    Redirections (>, >>, <, 2>) become their own words, followed by their target."""
    words: list[str] = []
    current: list[str] = []
    quoted = False
    i = 0

    def flush():
        if current:
            words.append("".join(current))
            current.clear()

    while i < len(text):
        ch = text[i]
        if ch == "^" and not quoted and i + 1 < len(text):
            current.append(text[i + 1])
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
            current.append(ch)
        elif ch in " \t" and not quoted:
            flush()
        elif ch in "<>" and not quoted:
            prefix = "2" if current == ["2"] else ""
            if prefix:
                current.clear()
            flush()
            op = ">>" if text.startswith(">>", i) else ch
            words.append(prefix + op)
            i += len(op)
            continue
        else:
            current.append(ch)
        i += 1
    flush()
    return words

def unquote(text: str) -> str:
    return text[1:-1] if len(text) >= 2 and text[0] == '"' and text[-1] == '"' else text.strip('"')


def findstr_regex(text: str) -> str:
    """FINDSTR's small regular expressions: . * ^ $ [class] [^class] \\< \\> and \\x escapes."""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(r"\b" if nxt in "<>" else re.escape(nxt))
            i += 2
            continue
        if ch in ".*^$":
            out.append(ch)
        elif ch == "[":
            end = text.find("]", i + 1)
            if end == -1:
                out.append(re.escape(ch))
            else:
                out.append("[" + text[i + 1:end].replace("\\", "\\\\") + "]")
                i = end
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def parse_for_options(text: str) -> dict:
    options: dict = {"delims": " \t", "tokens": [1], "rest": False, "eol": ";", "skip": 0}
    for match in re.finditer(r"(tokens|delims|skip|eol|usebackq)(?:=((?:[^ ]| (?=$)|(?<=delims=) )*))?", text,
                             re.IGNORECASE):
        key = match.group(1).lower()
        value = match.group(2) if match.group(2) is not None else ""
        if key == "delims":
            options["delims"] = value
        elif key == "skip":
            options["skip"] = int(value or 0)
        elif key == "eol":
            options["eol"] = value[:1]
        elif key == "usebackq":
            options["usebackq"] = True
        elif key == "tokens":
            tokens = []
            rest = value.endswith("*")
            for part in value.rstrip("*").split(","):
                if not part:
                    continue
                if "-" in part:
                    a, b = part.split("-")
                    tokens += list(range(int(a), int(b) + 1))
                else:
                    tokens.append(int(part))
            options["tokens"] = tokens or [1]
            options["rest"] = rest
    delims_match = re.search(r"delims=([^\"]*?)(?:\s+(?:tokens|skip|eol|usebackq)=|$)", text, re.IGNORECASE)
    if delims_match:
        options["delims"] = delims_match.group(1)
    return options


def for_tokens(line: str, options: dict) -> list:
    delims = options["delims"]
    if delims:
        parts = [p for p in re.split("[" + re.escape(delims) + "]+", line) if p != ""]
    else:
        parts = [line]
    wanted = options["tokens"]
    values = [parts[t - 1] if t - 1 < len(parts) else None for t in wanted]
    if options["rest"]:
        last = wanted[-1] if wanted else 0
        remainder_parts = parts[last:]
        values.append(" ".join(remainder_parts) if remainder_parts else None)
    if all(v is None for v in values):
        return []
    return values


def eval_arithmetic(expression: str, env: dict) -> int:
    def variable(match):
        return env.get(match.group(0), "0") if not match.group(0).isdigit() else match.group(0)

    text = re.sub(r"[A-Za-z_]\w*", variable, expression)
    if not re.fullmatch(r"[\d\s+\-*/()%]+", text) or "**" in text or len(text) > 200:
        raise ShellError("Missing operand.")
    try:
        value = eval(text.replace("/", "//"), {"__builtins__": {}}, {})  # digits and operators only (checked above)
    except Exception:
        raise ShellError("Missing operand.") from None
    return int(value)
