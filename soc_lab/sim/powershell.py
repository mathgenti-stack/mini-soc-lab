"""Simulated PowerShell 7: objects in the pipeline, as on a Windows analyst workstation.

It runs the parsed line (ps_parser) with PowerShell's rules: commands pass objects, expressions use
-eq -like -match -and..., $_ is the current object, [xml] and ConvertFrom-Json build objects, and
what is left at the end is printed as a table or a list (ps_format). Common aliases (ls, cat, where,
select, sort, %, ?) work as on Windows. Linux tools (grep, wc...) run through the simulated bash,
as native programs do in PowerShell on Linux.
"""

from __future__ import annotations

import csv
import io
import json
import math
import posixpath
import re
import statistics
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .. import evtx
from .core import HOME, HOST, LOGS, USER, Result, Shell, ShellError, Unsupported
from .ps_format import format_list, format_output, format_table, properties, value_of
from .ps_parser import PSParseError, parse
from .ps_values import (CIDict, FormattedText, MISSING, PSError, PSObject, ScriptBlock, TimeSpan, TypeLiteral, XmlNode,
                        add, arithmetic, as_list, compare_scalar, convert, date_format, equals, format_number,
                        is_number, is_type, net_format, net_regex, ordering, parse_date, to_bool, to_number,
                        to_string, type_of, unwrap, utc_now, wildcard_regex, local_name, TYPE_NAMES)

VERSION = "7.6.9"
MAX_ITEMS = 200_000


class BreakLoop(Exception):
    pass


class ContinueLoop(Exception):
    pass


class ReturnFlow(Exception):
    def __init__(self, values):
        self.values = values


@dataclass
class P:
    name: str
    switch: bool = False
    position: int | None = None
    aliases: tuple = ()
    rest: bool = False  # collects every remaining positional argument


@dataclass
class Cmdlet:
    name: str
    method: str
    params: list[P] = field(default_factory=list)
    synopsis: str = ""


def _c(name, synopsis, *params):
    return Cmdlet(name, "c_" + name.lower().replace("-", "_"), list(params), synopsis)


CMDLETS = [
    _c("Get-ChildItem", "List the files in a folder.", P("Path", position=0, aliases=("LiteralPath",)), P("Filter", position=1),
       P("Recurse", True, aliases=("s",)), P("File", True), P("Directory", True, aliases=("ad",)), P("Name", True),
       P("Force", True), P("Include"), P("Exclude"), P("Depth")),
    _c("Get-Item", "Get one file or folder.", P("Path", position=0)),
    _c("Set-Location", "Change the current folder.", P("Path", position=0)),
    _c("Get-Location", "Show the current folder."),
    _c("Get-Content", "Read a file, line by line (-Raw: as one text).", P("Path", position=0), P("Raw", True),
       P("TotalCount", aliases=("Head", "First")), P("Tail", aliases=("Last",)), P("Encoding"), P("ReadCount")),
    _c("Import-Csv", "Read a CSV file as objects, one per row.", P("Path", position=0), P("Delimiter", position=1),
       P("Header"), P("Encoding")),
    _c("ConvertFrom-Csv", "Turn CSV text into objects.", P("InputObject", position=0), P("Delimiter", position=1),
       P("Header")),
    _c("ConvertTo-Csv", "Turn objects into CSV text.", P("InputObject", position=0), P("NoTypeInformation", True),
       P("Delimiter", position=1), P("UseQuotes")),
    _c("Export-Csv", "Save objects to a CSV file.", P("Path", position=0), P("InputObject"),
       P("NoTypeInformation", True), P("Delimiter"), P("Append", True), P("Encoding")),
    _c("ConvertFrom-Json", "Turn JSON text into objects.", P("InputObject", position=0), P("AsHashtable", True),
       P("Depth"), P("NoEnumerate", True)),
    _c("ConvertTo-Json", "Turn objects into JSON text.", P("InputObject", position=0), P("Depth"), P("Compress", True),
       P("AsArray", True)),
    _c("Where-Object", "Keep only the objects that match a condition."),
    _c("Select-Object", "Pick properties, or the first/last objects.", P("Property", position=0),
       P("ExpandProperty"), P("First"), P("Last"), P("Skip"), P("Unique", True), P("Index"), P("ExcludeProperty")),
    _c("Sort-Object", "Sort objects by one or more properties.", P("Property", position=0),
       P("Descending", True), P("Unique", True), P("CaseSensitive", True), P("Top"), P("Bottom")),
    _c("Group-Object", "Group objects by a property and count each group.", P("Property", position=0),
       P("NoElement", True), P("AsHashTable", True), P("AsString", True), P("CaseSensitive", True)),
    _c("Measure-Object", "Count objects; sum, average, minimum and maximum of a property.",
       P("Property", position=0), P("Sum", True), P("Average", True), P("Maximum", True), P("Minimum", True),
       P("AllStats", True), P("Line", True), P("Word", True), P("Character", True), P("StandardDeviation", True)),
    _c("ForEach-Object", "Run a script block for each object ($_).", P("Process", position=0, rest=True),
       P("Begin"), P("End"), P("MemberName"), P("ArgumentList")),
    _c("Get-Member", "List the properties and methods of objects.", P("Name", position=0),
       P("MemberType", aliases=("Type",)), P("Static", True), P("Force", True)),
    _c("Format-Table", "Show objects as a table.", P("Property", position=0), P("AutoSize", True), P("Wrap", True),
       P("HideTableHeaders", True), P("GroupBy")),
    _c("Format-List", "Show each property on its own line.", P("Property", position=0)),
    _c("Out-String", "Turn objects into text.", P("Width"), P("Stream", True)),
    _c("Out-Host", "Print objects.", P("Paging", True)),
    _c("Out-Null", "Discard the output."),
    _c("Out-File", "Save the output to a file.", P("FilePath", position=0, aliases=("Path",)), P("Append", True),
       P("Encoding"), P("Width")),
    _c("Set-Content", "Write text to a file.", P("Path", position=0), P("Value", position=1), P("Encoding")),
    _c("Add-Content", "Add text to a file.", P("Path", position=0), P("Value", position=1), P("Encoding")),
    _c("Select-String", "Search text for a pattern (like grep).", P("Pattern", position=0), P("Path", position=1),
       P("SimpleMatch", True), P("CaseSensitive", True), P("NotMatch", True), P("AllMatches", True), P("List", True),
       P("Quiet", True), P("InputObject"), P("Context"), P("Raw", True)),
    _c("Get-WinEvent", "Read Windows events from an .evtx file (lab version).", P("Path", position=0),
       P("FilterHashtable"), P("MaxEvents"), P("Oldest", True), P("LogName"), P("ListLog"), P("FilterXPath"),
       P("ComputerName")),
    _c("Write-Output", "Send objects down the pipeline.", P("InputObject", position=0, rest=True), P("NoEnumerate", True)),
    _c("Write-Host", "Print text on the screen.", P("Object", position=0, rest=True), P("NoNewline", True),
       P("ForegroundColor"), P("BackgroundColor"), P("Separator")),
    _c("Get-Date", "The current date and time, or a date you give.", P("Date", position=0), P("Format"),
       P("UFormat"), P("Year"), P("Month"), P("Day")),
    _c("New-TimeSpan", "The time between two dates.", P("Start", position=0), P("End", position=1), P("Days"),
       P("Hours"), P("Minutes"), P("Seconds")),
    _c("Clear-Host", "Clear the screen."),
    _c("Get-Help", "Help for a command.", P("Name", position=0), P("Examples", True), P("Full", True), P("Detailed", True)),
    _c("Get-Command", "List the commands you can use.", P("Name", position=0), P("Verb"), P("Noun")),
    _c("Get-History", "The commands typed so far.", P("Count", position=0)),
    _c("Test-Path", "Does a file or folder exist?", P("Path", position=0), P("PathType")),
    _c("Get-Unique", "Remove repeated neighbours (sort first).", P("AsString", True)),
    _c("Join-Path", "Join folder and file names.", P("Path", position=0), P("ChildPath", position=1, rest=True)),
    _c("Split-Path", "The folder or the file name of a path.", P("Path", position=0), P("Leaf", True),
       P("Parent", True), P("Extension", True), P("LeafBase", True)),
    _c("Resolve-Path", "The full path of a file.", P("Path", position=0)),
    _c("Start-Sleep", "Wait (does nothing here).", P("Seconds", position=0), P("Milliseconds")),
    _c("Get-Alias", "List aliases (ls, cat, where...).", P("Name", position=0)),
    _c("Get-Variable", "List variables.", P("Name", position=0), P("ValueOnly", True)),
    _c("Remove-Item", "Delete a file you created.", P("Path", position=0), P("Force", True), P("Recurse", True)),
    _c("New-Item", "Create a file or folder.", P("Path", position=0), P("ItemType"), P("Value"), P("Force", True)),
    _c("Write-Error", "Write an error.", P("Message", position=0)),
    _c("Compare-Object", "Compare two lists.", P("ReferenceObject", position=0), P("DifferenceObject", position=1),
       P("Property"), P("IncludeEqual", True), P("ExcludeDifferent", True)),
    _c("Get-Random", "A random number or item.", P("Maximum", position=0), P("Minimum"), P("InputObject"), P("Count")),
]
COMMANDS = {c.name.lower(): c for c in CMDLETS}

ALIASES = {
    "ls": "Get-ChildItem", "dir": "Get-ChildItem", "gci": "Get-ChildItem", "gi": "Get-Item",
    "cd": "Set-Location", "sl": "Set-Location", "chdir": "Set-Location", "pwd": "Get-Location", "gl": "Get-Location",
    "cat": "Get-Content", "gc": "Get-Content", "type": "Get-Content", "ipcsv": "Import-Csv", "epcsv": "Export-Csv",
    "?": "Where-Object", "where": "Where-Object", "select": "Select-Object", "sort": "Sort-Object",
    "group": "Group-Object", "measure": "Measure-Object", "%": "ForEach-Object", "foreach": "ForEach-Object",
    "gm": "Get-Member", "ft": "Format-Table", "fl": "Format-List", "sls": "Select-String", "echo": "Write-Output",
    "write": "Write-Output", "cls": "Clear-Host", "clear": "Clear-Host", "h": "Get-History", "history": "Get-History",
    "ghy": "Get-History", "help": "Get-Help", "man": "Get-Help", "gcm": "Get-Command", "gu": "Get-Unique",
    "rvpa": "Resolve-Path", "sleep": "Start-Sleep", "gal": "Get-Alias", "gv": "Get-Variable", "rm": "Remove-Item",
    "del": "Remove-Item", "ni": "New-Item", "compare": "Compare-Object", "diff": "Compare-Object",
}
NATIVE = {"grep", "wc", "head", "tail", "awk", "sed", "cut", "uniq", "tr", "jq", "file", "tree", "less", "more", "tac",
          "nl", "column", "whoami", "hostname", "uname", "id"}
UNAVAILABLE = {"invoke-webrequest", "iwr", "invoke-restmethod", "irm", "curl", "wget", "start-process", "saps",
               "get-process", "gps", "ps", "stop-process", "kill", "get-service", "gsv", "invoke-expression", "iex",
               "invoke-command", "icm", "enter-pssession", "new-object", "add-type", "out-gridview", "ogv",
               "get-eventlog", "set-executionpolicy", "install-module", "import-module", "get-ciminstance",
               "get-wmiobject", "gwmi", "get-localuser", "get-aduser", "get-netipaddress", "test-netconnection",
               "resolve-dnsname", "notepad", "vim", "nano", "pwsh", "powershell", "bash", "sudo"}
LEVEL_NAMES = {0: "Information", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
EVENT_DESCRIPTIONS = {
    4624: "An account was successfully logged on.", 4625: "An account failed to log on.",
    4634: "An account was logged off.", 4647: "User initiated logoff.",
    4648: "A logon was attempted using explicit credentials.", 4672: "Special privileges assigned to new logon.",
    4720: "A user account was created.", 4722: "A user account was enabled.",
    4723: "An attempt was made to change an account's password.",
    4724: "An attempt was made to reset an account's password.", 4725: "A user account was disabled.",
    4726: "A user account was deleted.", 4728: "A member was added to a security-enabled global group.",
    4732: "A member was added to a security-enabled local group.", 4740: "A user account was locked out.",
    4767: "A user account was unlocked.", 4768: "A Kerberos authentication ticket (TGT) was requested.",
    4771: "Kerberos pre-authentication failed.",
    4776: "The computer attempted to validate the credentials for an account.",
}
WHERE_OPERATORS = {op: op for op in (
    "eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains", "notcontains", "in",
    "notin", "is", "isnot")}
WHERE_OPERATORS.update({"c" + op: "c" + op for op in list(WHERE_OPERATORS) if op not in ("is", "isnot")})
WHERE_OPERATORS.update({"i" + op: op for op in list(WHERE_OPERATORS) if not op.startswith("c") and op not in ("is", "isnot")})
WHERE_OPERATORS.update({"value": "value", "property": "property", "filterscript": "filterscript", "not": "not"})
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$")


def enumerate_value(value) -> list:
    if value is None or value is MISSING:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def flatten(values: list) -> list:
    out = []
    for value in values:
        if isinstance(value, list):
            out.extend(value)
        else:
            out.append(value)
    return out


class PowerShellShell(Shell):
    name = "powershell"

    def __init__(self, fs, cwd: str = HOME):
        super().__init__(fs, cwd)
        self.variables: CIDict = CIDict()
        self.env = CIDict({"HOME": HOME, "USER": USER, "PATH": "/opt/microsoft/powershell/7:/usr/local/bin:/usr/bin",
                           "TERM": "xterm-256color", "LANG": "C.UTF-8", "HOSTNAME": HOST})
        self.item_stack: list = []
        self.errors: list[str] = []
        self.cleared = False
        self.depth = 0
        self._evtx_cache: dict = {}
        self._bash = None

    # -----------------------------------------------------------------------
    def prompt(self) -> str:
        where = "~" + self.cwd[len(HOME):] if self.cwd == HOME or self.cwd.startswith(HOME + "/") else self.cwd
        return f"PS {USER}@{HOST}:{where}> "

    def execute(self, line: str) -> Result:
        if not line.strip():
            return Result()
        self.errors = []
        self.cleared = False
        try:
            tree = parse(line)
        except PSParseError as exc:
            return Result(error=str(exc))
        texts = []
        for statement in tree[1]:
            try:
                values = self.run_statement(statement)
                texts.append(format_output(values))
            except ReturnFlow as flow:
                texts.append(format_output(flow.values))
                break
            except (BreakLoop, ContinueLoop):
                break
            except PSError as exc:
                texts.append(format_output(getattr(exc, "partial", [])))
                self.errors.append(str(exc))
            except ShellError as exc:
                self.errors.append(str(exc))
            if self.cleared:
                texts = []
        return Result(output="".join(texts), error="\n".join(self.errors), clear=self.cleared)

    # statements -----------------------------------------------------------------
    def run_script(self, script) -> list:
        out = []
        for statement in script[1]:
            out += self.run_statement(statement)
        return out

    def run_statement(self, node) -> list:
        kind = node[0]
        if kind == "assign":
            self.assign(node)
            return []
        if kind == "pipeline":
            return self.run_pipeline(node)
        if kind == "if":
            for condition, body in node[1]:
                if to_bool(self.statement_value(condition)):
                    return self.run_script(body)
            return self.run_script(node[2]) if node[2] else []
        if kind == "foreach":
            out = []
            for item in enumerate_value(self.statement_value(node[2])):
                self.variables[node[1]] = item
                try:
                    out += self.run_script(node[3])
                except BreakLoop:
                    break
                except ContinueLoop:
                    continue
            return out
        if kind in ("for", "while"):
            out = []
            if kind == "for" and node[1] is not None:
                self.run_statement(node[1])
            condition = node[2] if kind == "for" else node[1]
            body = node[4] if kind == "for" else node[2]
            turns = 0
            while condition is None or to_bool(self.statement_value(condition)):
                turns += 1
                if turns > 100_000:
                    raise PSError("The loop was stopped after 100000 turns (simulated terminal limit).")
                try:
                    out += self.run_script(body)
                except BreakLoop:
                    break
                except ContinueLoop:
                    pass
                if kind == "for" and node[3] is not None:
                    self.run_statement(node[3])
            return out
        if kind == "break":
            raise BreakLoop()
        if kind == "continue":
            raise ContinueLoop()
        if kind == "return":
            raise ReturnFlow(self.run_statement(node[1]) if node[1] else [])
        if kind == "throw":
            message = to_string(self.statement_value(node[1])) if node[1] else "ScriptHalted"
            raise PSError(f"Exception: {message}")
        if kind in ("postinc", "preinc"):
            self.eval(node)
            return []
        return enumerate_value(self.eval(node))

    def statement_value(self, node):
        """A statement used as a value (inside parentheses, a condition, the right side of =)."""
        if node[0] in ("pipeline", "assign", "if", "foreach", "for", "while"):
            if node[0] == "assign":
                return self.assign(node)
            return unwrap(self.run_statement(node))
        return self.eval(node)

    def assign(self, node):
        _, op, target, value_node = node
        value = self.statement_value(value_node)
        if op != "=":
            value = arithmetic(op[0], self.eval(target), value)
        self.store(target, value)
        return value

    def store(self, target, value):
        kind = target[0]
        if kind == "var":
            name = target[1]
            if name.startswith("env:"):
                self.env[name[4:]] = to_string(value)
            elif name in ("true", "false", "null", "home", "pwd", "_", "psitem", "psversiontable"):
                raise PSError(f"SessionStateUnauthorizedAccessException: Cannot overwrite variable {name} because "
                              f"it is read-only or constant.")
            else:
                self.variables[name] = value
            return
        if kind == "member":
            obj = self.eval(target[1])
            name = self.member_name(target[2])
            if isinstance(obj, CIDict):
                obj[name] = value
            elif isinstance(obj, PSObject) and name in obj.props:
                obj.props[name] = value
            elif obj is None:
                raise PSError("InvalidOperation: The property '" + name + "' cannot be found on this object. "
                              "Verify that the property exists and can be set.")
            else:
                raise PSError(f"InvalidOperation: The property '{name}' cannot be found on this object. "
                              f"Verify that the property exists and can be set.")
            return
        if kind == "index":
            obj = self.eval(target[1])
            key = self.eval(target[2])
            if isinstance(obj, list):
                index = int(to_number(key))
                if not -len(obj) <= index < len(obj):
                    raise PSError("IndexOutOfRangeException: Index was outside the bounds of the array.")
                obj[index] = value
            elif isinstance(obj, CIDict):
                obj[key] = value
            else:
                raise PSError("InvalidOperation: Cannot index into a null array." if obj is None
                              else f"InvalidOperation: Unable to index into an object of type {type_of(obj)}.")
            return
        raise PSError("InvalidOperation: The assignment expression is not valid.")

    # pipelines ---------------------------------------------------------------------
    def run_pipeline(self, node) -> list:
        elements, redirects = node[1], node[2]
        errors_before = len(self.errors)
        data: list = []
        for index, element in enumerate(elements):
            if element[0] == "cmd":
                data = self.run_command(element, data if index > 0 else None)
            elif index > 0:
                raise PSError("ParserError: Expressions are only allowed as the first element of a pipeline.")
            else:
                data = enumerate_value(self.eval(element))
            if len(data) > MAX_ITEMS:
                raise PSError("The pipeline produced too many objects for the simulated terminal.")
        for redirect in redirects:
            if redirect[0] == "merge":
                continue
            target = to_string(self.eval(redirect[1])) if redirect[1][0] != "var" or redirect[1][1] != "null" else None
            if redirect[0] in ("2>", "2>>"):
                if target is None or target == "":
                    del self.errors[errors_before:]
                    continue
                raise Unsupported("Saving errors to a file is not supported in the simulated terminal.")
            if target is None:
                data = []
                continue
            self.write_file(target, format_output(data), append=redirect[0] in (">>", "*>>"), command="Out-File")
            data = []
        return data

    def run_command(self, element, input_data):
        name_value = self.eval(element[1])
        if isinstance(name_value, ScriptBlock):
            return self.invoke(name_value, None, args=[self.eval(a[1]) for a in element[2] if a[0] == "arg"])
        name = to_string(name_value)
        lower = name.lower()
        canonical = ALIASES.get(lower, name)
        cmdlet = COMMANDS.get(canonical.lower())
        if cmdlet is None:
            if lower in NATIVE or lower in ("sort", "uniq"):
                return self.run_native(name, element[2], input_data)
            if lower in UNAVAILABLE or lower.endswith(".exe"):
                raise Unsupported(f"{name}: not available in the simulated terminal (no network, processes or "
                                  f"system configuration here).")
            if lower in ("exit", "logout"):
                raise PSError("This is the simulated terminal: there is nothing to exit.")
            raise PSError(f"{name}: The term '{name}' is not recognized as a name of a cmdlet, function, script "
                          f"file, or executable program.\nCheck the spelling of the name, or if a path was included, "
                          f"verify that the path is correct and try again.")
        if cmdlet.name == "Where-Object":
            return self.c_where_object(element[2], input_data)
        bound = self.bind(cmdlet, element[2])
        self.depth += 1
        if self.depth > 50:
            raise PSError("The script failed due to call depth overflow.")
        try:
            return getattr(self, cmdlet.method)(bound, input_data)
        finally:
            self.depth -= 1

    def bind(self, cmdlet: Cmdlet, args) -> dict:
        bound: dict = {}
        positional = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg[0] == "param":
                param = self.find_param(cmdlet, arg[1])
                if param.switch:
                    bound[param.name] = True if arg[2] is None else to_bool(self.eval(arg[2]))
                elif arg[2] is not None:
                    bound[param.name] = self.eval(arg[2])
                elif i + 1 < len(args) and args[i + 1][0] == "arg":
                    bound[param.name] = self.eval(args[i + 1][1])
                    i += 1
                else:
                    raise PSError(f"{cmdlet.name}: Missing an argument for parameter '{param.name}'. "
                                  f"Specify a parameter of type 'System.Object' and try again.")
            else:
                positional.append(self.eval(arg[1]))
            i += 1
        slots = sorted((p for p in cmdlet.params if p.position is not None and p.name not in bound),
                       key=lambda p: p.position)
        while positional:
            if not slots:
                raise PSError(f"{cmdlet.name}: A positional parameter cannot be found that accepts argument "
                              f"'{to_string(positional[0])}'.")
            param = slots.pop(0)
            if param.rest:
                bound[param.name] = positional if len(positional) > 1 else positional[0]
                positional = []
            else:
                bound[param.name] = positional.pop(0)
        return bound

    def find_param(self, cmdlet: Cmdlet, name: str) -> P:
        lower = name.lower()
        common = {"erroraction", "ea", "warningaction", "wa", "verbose", "debug", "outvariable", "ov",
                  "errorvariable", "ev", "informationaction", "pipelinevariable", "outbuffer"}
        exact = [p for p in cmdlet.params if p.name.lower() == lower or lower in (a.lower() for a in p.aliases)]
        if exact:
            return exact[0]
        matches = [p for p in cmdlet.params if p.name.lower().startswith(lower)]
        if len(matches) == 1:
            return matches[0]
        if lower in common:
            return P(name, switch=lower in ("verbose", "debug"))
        if len(matches) > 1:
            raise PSError(f"{cmdlet.name}: Parameter cannot be processed because the parameter name '{name}' is "
                          f"ambiguous. Possible matches include: {' '.join('-' + p.name for p in matches)}.")
        raise PSError(f"{cmdlet.name}: A parameter cannot be found that matches parameter name '{name}'.")

    def run_native(self, name: str, args, input_data):
        """grep, wc... as native Linux programs: text in, lines of text out."""
        from .bash import BashShell, Cmd

        if self._bash is None:
            self._bash = BashShell(self.fs)
        self._bash.cwd = self.cwd
        words = [name]
        for arg in args:
            if arg[0] == "param":
                words.append("-" + arg[1])
                if arg[2] is not None:
                    words.append(to_string(self.eval(arg[2])))
            else:
                value = self.eval(arg[1])
                words += [to_string(v) for v in value] if isinstance(value, list) else [to_string(value)]
        stdin = None
        if input_data is not None:
            stdin = "".join(line + "\n" for line in self.as_text_lines(input_data))
        expanded = []
        for word in words:
            if any(ch in word for ch in "*?[") and not word.startswith("-"):
                from .bash import Word
                expanded += self._bash.expand_glob(Word(word, True))
            else:
                expanded.append(word)
        cmd = Cmd(self._bash, expanded, stdin, tty=False)
        try:
            output, _ = self._bash.call(cmd)
        except ShellError as exc:
            cmd.error(str(exc))
            output = ""
        self.errors += cmd.err
        return output.split("\n")[:-1] if output.endswith("\n") else ([output] if output else [])

    def as_text_lines(self, values: list) -> list[str]:
        lines = []
        for value in values:
            if isinstance(value, str):
                lines.append(value)
            else:
                text = format_output([value])
                lines += text.rstrip("\n").split("\n")
        return lines

    # expressions -------------------------------------------------------------------------
    def eval(self, node):
        kind = node[0]
        if kind == "const":
            return node[1]
        if kind == "var":
            return self.variable(node[1])
        if kind == "xstr":
            return "".join(p if isinstance(p, str) else to_string(self.eval(p)) for p in node[1])
        if kind == "paren":
            return self.statement_value(node[1])
        if kind == "subexpr":
            return unwrap(self.run_script(node[1]))
        if kind == "arraysub":
            return self.run_script(node[1])
        if kind == "array":
            return [self.eval(item) for item in node[1]]
        if kind == "hash":
            table = CIDict()
            for key_node, value_node in node[1]:
                table[self.eval(key_node)] = self.statement_value(value_node)
            return table
        if kind == "scriptblock":
            return ScriptBlock(node[1], node[2])
        if kind == "type":
            return TypeLiteral(node[1])
        if kind == "cast":
            return convert(node[1], self.eval(node[2]))
        if kind == "member":
            obj = self.eval(node[1])
            name = self.member_name(node[2])
            if node[3]:
                return self.static_member(obj, name)
            value = self.get_member(obj, name)
            return None if value is MISSING else value
        if kind == "call":
            obj = self.eval(node[1])
            name = self.member_name(node[2])
            args = [self.eval(a) for a in node[3]]
            if node[4]:
                return self.static_call(obj, name, args)
            return self.call_method(obj, name, args)
        if kind == "index":
            return self.index(self.eval(node[1]), self.eval(node[2]))
        if kind == "binop":
            return self.binop(node[1], node[2], node[3])
        if kind in ("and", "or", "xor"):
            left = to_bool(self.eval(node[1]))
            if kind == "and":
                return left and to_bool(self.eval(node[2]))
            if kind == "or":
                return left or to_bool(self.eval(node[2]))
            return left != to_bool(self.eval(node[2]))
        if kind == "unary":
            op = node[1]
            value = self.eval(node[2])
            if op == "not":
                return not to_bool(value)
            if op == "neg":
                return -to_number(value)
            if op == "pos":
                return to_number(value)
            if op == "split":
                return flatten([to_string(v).split() for v in enumerate_value(value)])
            if op == "join":
                return "".join(to_string(v) for v in enumerate_value(value))
            if op == "bnot":
                return ~int(to_number(value))
        if kind == "range":
            start, end = int(to_number(self.eval(node[1]))), int(to_number(self.eval(node[2])))
            if abs(end - start) > MAX_ITEMS:
                raise PSError("The range is too large for the simulated terminal.")
            return list(range(start, end + 1)) if start <= end else list(range(start, end - 1, -1))
        if kind in ("postinc", "preinc"):
            target = node[2]
            old = self.eval(target)
            new = to_number(old) + (1 if node[1] == "++" else -1)
            self.store(target, new)
            return old if kind == "postinc" else new
        if kind == "assign":
            return self.assign(node)
        if kind in ("pipeline", "if", "foreach", "for", "while"):
            return self.statement_value(node)
        if kind == "cmd":
            return unwrap(self.run_command(node, None))
        raise PSError(f"The simulated terminal cannot evaluate '{kind}'.")

    def member_name(self, node) -> str:
        return to_string(self.eval(node)) if isinstance(node, tuple) else str(node)

    def variable(self, name: str):
        if name in ("_", "psitem"):
            return self.item_stack[-1] if self.item_stack else None
        if name.startswith("env:"):
            return self.env.get(name[4:])
        if name == "home":
            return HOME
        if name == "pwd":
            return PSObject({"Path": self.cwd}, "System.Management.Automation.PathInfo", text=self.cwd, view="path")
        if name == "psversiontable":
            return CIDict({"PSVersion": VERSION, "PSEdition": "Core", "GitCommitId": VERSION, "OS": "Linux (simulated)",
                           "Platform": "Unix", "PSCompatibleVersions": "1.0, 2.0, 3.0, 4.0, 5.0, 5.1, 6.0, 7.0",
                           "PSRemotingProtocolVersion": "2.3", "SerializationVersion": "1.1.0.1",
                           "WSManStackVersion": "3.0"})
        if name in ("islinux", "ismacos", "iswindows", "iscoreclr"):
            return name in ("islinux", "iscoreclr")
        if name == "host":
            return PSObject({"Name": "ConsoleHost", "Version": VERSION}, "System.Management.Automation.Internal.Host")
        if name == "error":
            return list(reversed(self.errors))
        if name == "ofs":
            return " "
        return self.variables.get(name)

    # members -----------------------------------------------------------------------------
    def get_member(self, obj, name: str):
        lower = name.lower()
        if obj is None or obj is MISSING:
            return MISSING
        if isinstance(obj, list):
            if lower in ("count", "length", "longlength"):
                return len(obj)
            if lower == "rank":
                return 1
            values = [v for v in (self.get_member(item, name) for item in obj) if v is not MISSING]
            values = flatten(values)
            return MISSING if not values and not obj else unwrap(values) if len(values) != 1 else values[0]
        if lower == "psobject":
            props = self.property_list(obj)
            return PSObject({"Properties": [PSObject({"Name": n, "Value": v, "MemberType": "NoteProperty",
                                                      "TypeNameOfValue": type_of(v)}) for n, v in props],
                             "TypeNames": [type_of(obj), "System.Object"]})
        if isinstance(obj, str):
            if lower in ("length",):
                return len(obj)
            if lower == "count":
                return 1
            return MISSING
        if isinstance(obj, CIDict):
            if name in obj:
                return obj[name]
            if lower == "count":
                return len(obj)
            if lower == "keys":
                return list(obj.keys())
            if lower == "values":
                return list(obj.values())
            return MISSING
        if isinstance(obj, PSObject):
            if name in obj.props:
                return obj.props[name]
            if lower == "count":
                return 1
            return MISSING
        if isinstance(obj, XmlNode):
            value = obj.member(name)
            if value is MISSING and lower == "count":
                return 1
            return value
        if isinstance(obj, datetime):
            values = {"year": obj.year, "month": obj.month, "day": obj.day, "hour": obj.hour, "minute": obj.minute,
                      "second": obj.second, "millisecond": obj.microsecond // 1000, "dayofweek": obj.strftime("%A"),
                      "dayofyear": obj.timetuple().tm_yday, "date": obj.replace(hour=0, minute=0, second=0, microsecond=0),
                      "timeofday": TimeSpan(obj.hour * 3600 + obj.minute * 60 + obj.second + obj.microsecond / 1e6),
                      "kind": "Utc", "ticks": int((obj - datetime(1, 1, 1)).total_seconds() * 1e7)}
            return values.get(lower, 1 if lower == "count" else MISSING)
        if isinstance(obj, TimeSpan):
            return obj.member(name)
        if isinstance(obj, (int, float, bool)):
            return 1 if lower == "count" else MISSING
        if isinstance(obj, TypeLiteral):
            values = {"name": TYPE_NAMES.get(obj.name.lower(), obj.name).split(".")[-1],
                      "fullname": TYPE_NAMES.get(obj.name.lower(), obj.name)}
            return values.get(lower, MISSING)
        if isinstance(obj, ScriptBlock):
            return obj.text if lower == "ast" else MISSING
        return MISSING

    def property_list(self, obj) -> list[tuple[str, object]]:
        if isinstance(obj, PSObject):
            return list(obj.props.items())
        if isinstance(obj, CIDict):
            return [("Count", len(obj)), ("Keys", list(obj.keys())), ("Values", list(obj.values()))]
        if isinstance(obj, XmlNode):
            return [(n, obj.member(n)) for n in obj.property_names()]
        if isinstance(obj, str):
            return [("Length", len(obj))]
        if isinstance(obj, datetime):
            return [(n, self.get_member(obj, n)) for n in ("Date", "Day", "DayOfWeek", "DayOfYear", "Hour", "Kind",
                                                            "Millisecond", "Minute", "Month", "Second", "Ticks",
                                                            "TimeOfDay", "Year")]
        if isinstance(obj, TimeSpan):
            return [(n, obj.member(n)) for n in properties(obj)]
        return []

    def index(self, obj, key):
        if obj is None:
            raise PSError("InvalidOperation: Cannot index into a null array.")
        if isinstance(key, list):
            return [v for v in (self.index(obj, k) for k in key) if v is not None]
        if isinstance(obj, CIDict):
            return obj.get(key)
        if isinstance(obj, (list, str)):
            i = int(to_number(key))
            return obj[i] if -len(obj) <= i < len(obj) else None
        if isinstance(obj, XmlNode):
            value = obj.member(to_string(key)) if isinstance(key, str) else (obj if to_number(key) == 0 else None)
            return None if value is MISSING else value
        if isinstance(obj, PSObject):
            if isinstance(key, str):
                return obj.props.get(key)
            return obj if to_number(key) == 0 else None
        if is_number(key):
            return obj if key == 0 else None
        raise PSError(f"InvalidOperation: Unable to index into an object of type {type_of(obj)}.")

    def call_method(self, obj, name: str, args: list):
        lower = name.lower()
        if obj is None or obj is MISSING:
            raise PSError("InvalidOperation: You cannot call a method on a null-valued expression.")
        if lower == "gettype":
            full = type_of(obj)
            base = {"System.String": "System.Object", "System.Int32": "System.ValueType",
                    "System.Object[]": "System.Array"}.get(full, "System.Object")
            return PSObject({"IsPublic": True, "IsSerial": True, "Name": full.split(".")[-1], "BaseType": base,
                             "FullName": full}, "System.RuntimeType", text=full, view="type")
        if lower == "tostring" and not args and not isinstance(obj, (datetime, int, float)):
            return to_string(obj)
        if lower == "equals" and args:
            return equals(obj, args[0])
        if isinstance(obj, list):
            if lower == "contains":
                return any(equals(v, args[0]) for v in obj)
            if lower == "indexof":
                return next((i for i, v in enumerate(obj) if equals(v, args[0])), -1)
            if lower in ("where", "foreach"):
                if not args or not isinstance(args[0], ScriptBlock):
                    raise PSError(f"InvalidOperation: .{name}() needs a script block, e.g. .{name}({{ $_ }})")
                out = []
                for item in obj:
                    result = self.invoke(args[0], item)
                    if lower == "where":
                        if to_bool(unwrap(result)):
                            out.append(item)
                    else:
                        out += result
                return out
            values = [self.call_method(item, name, args) for item in obj]
            return values
        if isinstance(obj, str):
            return self.string_method(obj, lower, name, args)
        if isinstance(obj, datetime):
            if lower == "tostring":
                return date_format(obj, to_string(args[0])) if args and args[0] is not None else to_string(obj)
            if lower.startswith("add"):
                unit = lower[3:]
                seconds = {"days": 86400, "hours": 3600, "minutes": 60, "seconds": 1, "milliseconds": 0.001}.get(unit)
                if seconds is None:
                    raise PSError(f"InvalidOperation: Method invocation failed because [System.DateTime] does not "
                                  f"contain a method named '{name}'.")
                return obj + timedelta(seconds=to_number(args[0]) * seconds)
            if lower in ("touniversaltime", "tolocaltime"):
                return obj
            if lower == "toshortdatestring":
                return obj.strftime("%m/%d/%Y")
            if lower == "toshorttimestring":
                return obj.strftime("%H:%M")
            if lower == "tolongdatestring":
                return obj.strftime("%A, %d %B %Y")
            if lower == "subtract":
                return arithmetic("-", obj, args[0])
        if is_number(obj) or isinstance(obj, bool):
            if lower == "tostring":
                return net_format("{0:" + to_string(args[0]) + "}", [obj]) if args else format_number(obj)
            if lower == "compareto":
                return ordering(obj, args[0])
        if isinstance(obj, TimeSpan) and lower == "tostring":
            return str(obj)
        if isinstance(obj, CIDict):
            if lower == "containskey":
                return args[0] in obj
            if lower == "containsvalue":
                return any(equals(v, args[0]) for v in obj.values())
            if lower == "add":
                if args[0] in obj:
                    raise PSError(f"MethodInvocationException: Item has already been added. Key in dictionary: "
                                  f"'{to_string(args[0])}'")
                obj[args[0]] = args[1] if len(args) > 1 else None
                return None
            if lower == "remove":
                obj.pop(args[0], None)
                return None
            if lower == "clear":
                obj.clear()
                return None
        if isinstance(obj, PSObject) and lower in obj.methods:
            return obj.methods[lower](*args)
        if isinstance(obj, XmlNode):
            if lower == "getattribute":
                return obj.element.get(to_string(args[0]), "")
            if lower == "hasattribute":
                return to_string(args[0]) in obj.element.attrib
            if lower in ("selectnodes", "selectsinglenode"):
                raise Unsupported("XPath (SelectNodes) is not supported in the simulated terminal; "
                                  "use dots and Where-Object, e.g. $log.Events.Event | Where-Object {...}")
        if isinstance(obj, ScriptBlock) and lower in ("invoke", "invokereturnasis"):
            return unwrap(self.invoke(obj, None, args=args))
        raise PSError(f"InvalidOperation: Method invocation failed because [{type_of(obj)}] does not contain a "
                      f"method named '{name}'.")

    def string_method(self, text: str, lower: str, name: str, args: list):
        a = [to_string(x) if not is_number(x) else x for x in args]
        if lower == "toupper" or lower == "toupperinvariant":
            return text.upper()
        if lower == "tolower" or lower == "tolowerinvariant":
            return text.lower()
        if lower == "trim":
            return text.strip(a[0]) if a else text.strip()
        if lower == "trimstart":
            return text.lstrip(a[0]) if a else text.lstrip()
        if lower == "trimend":
            return text.rstrip(a[0]) if a else text.rstrip()
        if lower == "split":
            if not args:
                return text.split()
            separators = flatten([to_string(x) for x in enumerate_value(args[0])]) if isinstance(args[0], list) else [to_string(args[0])]
            if len(separators) == 1 and len(separators[0]) > 1 and not (len(args) > 1):
                separators = list(separators[0])  # .NET picks the char[] overload for a string of several characters
            pattern = "|".join(re.escape(s) for s in separators if s)
            return re.split(pattern, text) if pattern else [text]
        if lower == "replace":
            return text.replace(to_string(args[0]), to_string(args[1]) if len(args) > 1 else "")
        if lower == "contains":
            return to_string(args[0]) in text
        if lower == "startswith":
            return text.startswith(to_string(args[0]))
        if lower == "endswith":
            return text.endswith(to_string(args[0]))
        if lower == "substring":
            start = int(to_number(args[0]))
            if start > len(text):
                raise PSError('MethodInvocationException: Exception calling "Substring" with "1" argument(s): '
                              '"startIndex cannot be larger than length of string."')
            if len(args) > 1:
                length = int(to_number(args[1]))
                if start + length > len(text):
                    raise PSError('MethodInvocationException: Exception calling "Substring" with "2" argument(s): '
                                  '"Index and length must refer to a location within the string."')
                return text[start:start + length]
            return text[start:]
        if lower == "indexof":
            return text.find(to_string(args[0]))
        if lower == "lastindexof":
            return text.rfind(to_string(args[0]))
        if lower == "padleft":
            return text.rjust(int(to_number(args[0])), to_string(args[1]) if len(args) > 1 else " ")
        if lower == "padright":
            return text.ljust(int(to_number(args[0])), to_string(args[1]) if len(args) > 1 else " ")
        if lower == "tostring":
            return text
        if lower == "tochararray":
            return list(text)
        if lower == "insert":
            index = int(to_number(args[0]))
            return text[:index] + to_string(args[1]) + text[index:]
        if lower == "remove":
            start = int(to_number(args[0]))
            count = int(to_number(args[1])) if len(args) > 1 else len(text)
            return text[:start] + text[start + count:]
        if lower == "compareto":
            return ordering(text, args[0])
        if lower == "normalize":
            return text
        raise PSError(f"InvalidOperation: Method invocation failed because [System.String] does not contain a method "
                      f"named '{name}'.")

    def static_member(self, type_value, name: str):
        type_name = to_string(type_value).lower().replace("system.", "") if isinstance(type_value, TypeLiteral) else ""
        lower = name.lower()
        if type_name == "datetime":
            if lower in ("now", "utcnow"):
                return utc_now()
            if lower == "today":
                return utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
            if lower in ("minvalue", "maxvalue"):
                return datetime.min if lower == "minvalue" else datetime.max
        if type_name == "math":
            if lower == "pi":
                return math.pi
            if lower == "e":
                return math.e
        if type_name == "string" and lower == "empty":
            return ""
        if type_name in ("int", "int32") and lower in ("maxvalue", "minvalue"):
            return 2 ** 31 - 1 if lower == "maxvalue" else -2 ** 31
        if type_name in ("environment",) and lower in ("newline", "machinename", "username", "osversion"):
            return {"newline": "\n", "machinename": HOST, "username": USER, "osversion": "Unix 6.6 (simulated)"}[lower]
        raise PSError(f"InvalidOperation: The static member '{name}' of [{to_string(type_value)}] is not "
                      f"supported in the simulated terminal.")

    def static_call(self, type_value, name: str, args: list):
        type_name = to_string(type_value).lower().replace("system.", "") if isinstance(type_value, TypeLiteral) else ""
        lower = name.lower()
        a = args
        if type_name == "math":
            numbers = [to_number(x) for x in a]
            functions = {"floor": lambda x: math.floor(x), "ceiling": lambda x: math.ceil(x), "abs": abs,
                         "sqrt": math.sqrt, "pow": math.pow, "max": max, "min": min, "log10": math.log10,
                         "truncate": math.trunc, "exp": math.exp}
            if lower == "round":
                digits = int(numbers[1]) if len(numbers) > 1 else 0
                value = round(numbers[0], digits)
                return float(value) if digits or isinstance(numbers[0], float) else value
            if lower == "log":
                return math.log(numbers[0]) if len(numbers) == 1 else math.log(numbers[0], numbers[1])
            if lower in functions:
                return functions[lower](*numbers)
        if type_name == "datetime":
            if lower == "parse":
                return parse_date(to_string(a[0]))
            if lower == "parseexact":
                fmt = to_string(a[1])
                python = date_to_strptime(fmt)
                try:
                    return datetime.strptime(to_string(a[0]), python)
                except ValueError:
                    raise PSError(f'MethodInvocationException: Exception calling "ParseExact": "String '
                                  f'\'{to_string(a[0])}\' was not recognized as a valid DateTime."') from None
        if type_name == "string":
            if lower == "join":
                values = flatten(a[1:]) if len(a) > 2 else enumerate_value(a[1])
                return to_string(a[0]).join(to_string(v) for v in values)
            if lower == "isnullorempty":
                return a[0] is None or to_string(a[0]) == ""
            if lower == "isnullorwhitespace":
                return a[0] is None or to_string(a[0]).strip() == ""
            if lower == "format":
                return net_format(to_string(a[0]), flatten(a[1:]))
            if lower == "concat":
                return "".join(to_string(v) for v in flatten(a))
        if type_name in ("int", "int32", "long", "double") and lower in ("parse", "tryparse"):
            return convert(type_name, a[0])
        if type_name in ("regex", "text.regularexpressions.regex"):
            if lower == "escape":
                return re.escape(to_string(a[0]))
            pattern = net_regex(to_string(a[1]))
            text = to_string(a[0])
            if lower == "ismatch":
                return bool(pattern.search(text))
            if lower == "replace":
                return pattern.sub(net_replacement(to_string(a[2])), text)
            if lower in ("match", "matches"):
                found = [regex_match(m) for m in pattern.finditer(text)]
                if lower == "match":
                    return found[0] if found else regex_match(None)
                return found
            if lower == "split":
                return pattern.split(text)
        if type_name in ("io.path",):
            path = to_string(a[0]) if a else ""
            if lower == "getfilename":
                return posixpath.basename(path)
            if lower == "getextension":
                return posixpath.splitext(path)[1]
            if lower == "getfilenamewithoutextension":
                return posixpath.splitext(posixpath.basename(path))[0]
            if lower == "getdirectoryname":
                return posixpath.dirname(path)
            if lower == "combine":
                return posixpath.join(*[to_string(x) for x in a])
        if type_name == "convert":
            if lower == "toint32":
                return int(to_string(a[0]), int(to_number(a[1])) if len(a) > 1 else 10)
            if lower == "tostring" and len(a) > 1:
                base = int(to_number(a[1]))
                number = int(to_number(a[0]))
                return {2: format(number, "b"), 8: format(number, "o"), 16: format(number, "x")}.get(base, str(number))
        if type_name == "timespan" and lower.startswith("from"):
            unit = {"fromdays": 86400, "fromhours": 3600, "fromminutes": 60, "fromseconds": 1,
                    "frommilliseconds": 0.001}.get(lower)
            if unit:
                return TimeSpan(to_number(a[0]) * unit)
        if type_name == "ipaddress" and lower == "parse":
            return convert("ipaddress", a[0])
        raise PSError(f"InvalidOperation: Method invocation failed because [{to_string(type_value)}] does not "
                      f"contain a method named '{name}' (or it is not supported in the simulated terminal).")

    # operators ---------------------------------------------------------------------------
    def binop(self, op: str, left_node, right_node):
        left = self.eval(left_node)
        right = self.eval(right_node)
        if op in ("+", "-", "*", "/", "%"):
            return arithmetic(op, left, right)
        if op == "f":
            return net_format(to_string(left), enumerate_value(right) if isinstance(right, list) else [right])
        if op in ("band", "bor", "bxor"):
            a, b = int(to_number(left)), int(to_number(right))
            return {"band": a & b, "bor": a | b, "bxor": a ^ b}[op]
        case_sensitive = op.startswith("c") and op not in ("contains",)
        base = op[1:] if op[0] in "ic" and op[1:] in ("eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match",
                                                      "notmatch", "contains", "notcontains", "in", "notin",
                                                      "replace", "split") else op
        if base in ("is", "isnot"):
            type_name = right.name if isinstance(right, TypeLiteral) else to_string(right)
            result = is_type(left, type_name)
            return result if base == "is" else not result
        if base == "as":
            try:
                return convert(right.name if isinstance(right, TypeLiteral) else to_string(right), left)
            except PSError:
                return None
        if base in ("contains", "notcontains"):
            found = any(equals(item, right, case_sensitive) for item in enumerate_value(left))
            return found if base == "contains" else not found
        if base in ("in", "notin"):
            found = any(equals(item, left, case_sensitive) for item in enumerate_value(right))
            return found if base == "in" else not found
        if base == "replace":
            pattern_text, replacement = (right + [""])[:2] if isinstance(right, list) else (right, "")
            pattern = net_regex(to_string(pattern_text), case_sensitive)
            repl = net_replacement(to_string(replacement))
            if isinstance(left, list):
                return [pattern.sub(repl, to_string(v)) for v in left]
            return pattern.sub(repl, to_string(left))
        if base == "split":
            pattern_text, limit = (right + [0])[:2] if isinstance(right, list) else (right, 0)
            pattern = net_regex(to_string(pattern_text), case_sensitive)
            limit = int(to_number(limit))
            return flatten([pattern.split(to_string(v), maxsplit=max(limit - 1, 0)) for v in enumerate_value(left)])
        if base == "join":
            return to_string(right).join(to_string(v) for v in enumerate_value(left))
        if base in ("eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch"):
            if isinstance(left, list):
                return [item for item in left if compare_scalar(base, item, right, case_sensitive)]
            found: list = []
            result = compare_scalar(base, left, right, case_sensitive, found)
            if base == "match" and found:
                self.variables["matches"] = match_table(found[0])
            return result
        raise PSError(f"ParserError: Unexpected token '-{op}' in expression or statement.")

    # script blocks -----------------------------------------------------------------------
    def invoke(self, block: ScriptBlock, item, args=None) -> list:
        self.item_stack.append(item)
        saved_args = self.variables.get("args")
        self.variables["args"] = list(args or [])
        self.depth += 1
        if self.depth > 100:
            raise PSError("The script failed due to call depth overflow.")
        try:
            return self.run_script(block.body)
        except ReturnFlow as flow:
            return flow.values
        finally:
            self.depth -= 1
            self.item_stack.pop()
            self.variables["args"] = saved_args

    def property_value(self, obj, prop):
        """A property given as a name (wildcards allowed), a script block or a calculated-property hashtable."""
        if isinstance(prop, ScriptBlock):
            return unwrap(self.invoke(prop, obj))
        if isinstance(prop, CIDict):
            expression = next((prop[k] for k in prop if k.lower() in ("expression", "e")), None)
            return self.property_value(obj, expression) if expression is not None else None
        value = self.get_member(obj, to_string(prop))
        return None if value is MISSING else value

    # files -------------------------------------------------------------------------------
    def resolve(self, path: str) -> str:
        path = path.replace("\\", "/")
        if path == "~" or path.startswith("~/"):
            path = HOME + path[1:]
        return posixpath.normpath(posixpath.join(self.cwd, path)) if path else self.cwd

    def relative(self, path: str) -> str:
        prefix = self.cwd.rstrip("/") + "/"
        return path[len(prefix):] if path.startswith(prefix) else path

    def expand_paths(self, command: str, patterns, must_exist: bool = True) -> list[str]:
        out = []
        for pattern in enumerate_value(patterns):
            text = to_string(pattern)
            path = self.resolve(text)
            if any(ch in posixpath.basename(path) for ch in "*?["):
                regex = wildcard_regex(posixpath.basename(path))
                matches = [posixpath.join(posixpath.dirname(path), n) for n in self.fs.listdir(posixpath.dirname(path))
                           if regex.match(n)] if self.fs.is_dir(posixpath.dirname(path)) else []
                if not matches and must_exist:
                    continue
                out += matches
            elif self.fs.exists(path) or not must_exist:
                out.append(path)
            else:
                self.errors.append(f"{command}: Cannot find path '{path}' because it does not exist.")
        return out

    def write_file(self, target: str, text: str, append: bool, command: str):
        path = self.resolve(target)
        try:
            self.fs.write(path, text.encode("utf-8"), append=append)
        except PermissionError:
            raise PSError(f"{command}: Access to the path '{path}' is denied.") from None
        except FileNotFoundError:
            raise PSError(f"{command}: Could not find a part of the path '{path}'.") from None
        except IsADirectoryError:
            raise PSError(f"{command}: Access to the path '{path}' is denied.") from None

    def file_object(self, path: str) -> PSObject:
        is_dir = self.fs.is_dir(path)
        name = posixpath.basename(path) or "/"
        in_logs = path.startswith(LOGS + "/") or path == LOGS
        owner = "root" if in_logs or not path.startswith(HOME) else USER
        mode = ("drwx------" if path == HOME else "drwxr-xr-x") if is_dir else "-rw-r--r--"
        modified = datetime(2026, 10, 27, 9, 0, 0)
        props = {"Name": name, "FullName": path, "DirectoryName": posixpath.dirname(path),
                 "Directory": posixpath.dirname(path), "Extension": posixpath.splitext(name)[1] if not is_dir else "",
                 "BaseName": posixpath.splitext(name)[0] if not is_dir else name,
                 "Length": None if is_dir else self.fs.size(path), "Size": 4096 if is_dir else self.fs.size(path),
                 "LastWriteTime": modified, "CreationTime": modified, "UnixMode": mode, "User": owner, "Group": owner,
                 "PSIsContainer": is_dir, "Mode": "d----" if is_dir else "-----",
                 "Exists": True, "IsReadOnly": in_logs}
        if is_dir:
            props.pop("Length")
        return PSObject(props, "System.IO.DirectoryInfo" if is_dir else "System.IO.FileInfo", text=path, view="file")

    def read_file(self, command: str, path: str) -> str | None:
        if self.fs.is_dir(path):
            self.errors.append(f"{command}: Unable to get content because it is a directory: '{path}'. "
                               f"Please use 'Get-ChildItem' instead.")
            return None
        return self.fs.read_text(path)

    # =====================================================================================
    # Cmdlets
    # =====================================================================================
    def c_get_childitem(self, p, input_data):
        targets = p.get("Path") or ["."]
        out = []
        for path in self.expand_paths("Get-ChildItem", targets):
            if self.fs.is_file(path):
                out.append(path)
                continue
            queue = [path]
            while queue:
                folder = queue.pop(0)
                entries = [posixpath.join(folder, e) for e in self.fs.listdir(folder)]
                dirs = [e for e in entries if self.fs.is_dir(e)]
                files = [e for e in entries if self.fs.is_file(e)]
                out += dirs + files
                if p.get("Recurse"):
                    queue = dirs + queue
        if p.get("Filter"):
            regex = wildcard_regex(to_string(p["Filter"]))
            out = [o for o in out if regex.match(posixpath.basename(o))]
        if p.get("Include"):
            patterns = [wildcard_regex(to_string(x)) for x in enumerate_value(p["Include"])]
            out = [o for o in out if any(r.match(posixpath.basename(o)) for r in patterns)]
        if p.get("Exclude"):
            patterns = [wildcard_regex(to_string(x)) for x in enumerate_value(p["Exclude"])]
            out = [o for o in out if not any(r.match(posixpath.basename(o)) for r in patterns)]
        if p.get("File"):
            out = [o for o in out if self.fs.is_file(o)]
        if p.get("Directory"):
            out = [o for o in out if self.fs.is_dir(o)]
        if p.get("Name"):
            base = self.resolve(to_string(enumerate_value(targets)[0]))
            return [o[len(base.rstrip("/")) + 1:] if o.startswith(base.rstrip("/") + "/") else posixpath.basename(o)
                    for o in out]
        return [self.file_object(o) for o in out]

    def c_get_item(self, p, input_data):
        return [self.file_object(path) for path in self.expand_paths("Get-Item", p.get("Path") or ".")]

    def c_set_location(self, p, input_data):
        target = to_string(p.get("Path") or HOME)
        path = self.resolve(target)
        if not self.fs.is_dir(path):
            raise PSError(f"Set-Location: Cannot find path '{path}' because it does not exist.")
        self.cwd = path
        return []

    def c_get_location(self, p, input_data):
        return [self.variable("pwd")]

    def c_get_content(self, p, input_data):
        out = []
        for path in self.expand_paths("Get-Content", p.get("Path") or []):
            text = self.read_file("Get-Content", path)
            if text is None:
                continue
            if p.get("Raw"):
                out.append(text)
                continue
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            if p.get("TotalCount") is not None:
                lines = lines[:int(to_number(p["TotalCount"]))]
            if p.get("Tail") is not None:
                count = int(to_number(p["Tail"]))
                lines = lines[-count:] if count else []
            out += lines
        if "Path" not in p:
            raise PSError("Get-Content: Cannot bind argument to parameter 'Path' because it is null.")
        return out

    def _csv_objects(self, text: str, delimiter: str, header) -> list:
        rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
        rows = [r for r in rows if r]
        if not rows:
            return []
        if header:
            names = [to_string(h) for h in enumerate_value(header)]
        else:
            if rows[0] and rows[0][0].startswith("#TYPE"):
                rows = rows[1:]
            names, rows = rows[0], rows[1:]
        objects = []
        for row in rows:
            values = row + [None] * (len(names) - len(row))
            objects.append(PSObject(dict(zip(names, values))))
        return objects

    def c_import_csv(self, p, input_data):
        delimiter = to_string(p.get("Delimiter") or ",")
        out = []
        for path in self.expand_paths("Import-Csv", p.get("Path") or []):
            text = self.read_file("Import-Csv", path)
            if text is not None:
                out += self._csv_objects(text, delimiter, p.get("Header"))
        return out

    def c_convertfrom_csv(self, p, input_data):
        lines = [to_string(v) for v in (enumerate_value(p["InputObject"]) if "InputObject" in p else input_data or [])]
        return self._csv_objects("\n".join(lines), to_string(p.get("Delimiter") or ","), p.get("Header"))

    def _csv_lines(self, objects: list, delimiter: str) -> list[str]:
        if not objects:
            return []
        names = [n for n, _ in self.property_list(objects[0])]
        quote = lambda v: '"' + to_string(v).replace('"', '""') + '"'  # noqa: E731
        lines = [delimiter.join(quote(n) for n in names)]
        for obj in objects:
            values = dict(self.property_list(obj))
            lines.append(delimiter.join(quote(values.get(n)) for n in names))
        return lines

    def c_convertto_csv(self, p, input_data):
        objects = enumerate_value(p["InputObject"]) if "InputObject" in p else input_data or []
        return self._csv_lines(objects, to_string(p.get("Delimiter") or ","))

    def c_export_csv(self, p, input_data):
        objects = enumerate_value(p["InputObject"]) if "InputObject" in p else input_data or []
        lines = self._csv_lines(objects, to_string(p.get("Delimiter") or ","))
        if p.get("Append") and lines:
            lines = lines[1:]
        self.write_file(to_string(p.get("Path")), "".join(l + "\n" for l in lines), bool(p.get("Append")), "Export-Csv")
        return []

    def json_to_ps(self, value, as_hashtable: bool):
        if isinstance(value, dict):
            if as_hashtable:
                return CIDict({k: self.json_to_ps(v, True) for k, v in value.items()})
            return PSObject({k: self.json_to_ps(v, False) for k, v in value.items()})
        if isinstance(value, list):
            return [self.json_to_ps(v, as_hashtable) for v in value]
        if isinstance(value, str) and ISO_DATE.match(value):
            return parse_date(value)
        return value

    def c_convertfrom_json(self, p, input_data):
        text = to_string(p["InputObject"]) if "InputObject" in p else "\n".join(
            to_string(v) for v in input_data or [])
        if not text.strip():
            return []
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PSError(f"ConvertFrom-Json: Conversion from JSON failed with error: {exc}") from None
        result = self.json_to_ps(value, bool(p.get("AsHashtable")))
        if isinstance(result, list) and not p.get("NoEnumerate"):
            return result
        return [result]

    def ps_to_json(self, value, depth: int, max_depth: int):
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        if isinstance(value, list):
            return [self.ps_to_json(v, depth + 1, max_depth) for v in value]
        if isinstance(value, (PSObject, CIDict, XmlNode)):
            if depth >= max_depth:
                return to_string(value)
            items = self.property_list(value) if not isinstance(value, CIDict) else list(value.items())
            return {to_string(k): self.ps_to_json(v, depth + 1, max_depth) for k, v in items}
        return to_string(value)

    def c_convertto_json(self, p, input_data):
        objects = enumerate_value(p["InputObject"]) if "InputObject" in p else input_data or []
        depth = int(to_number(p.get("Depth", 2)))
        data = [self.ps_to_json(o, 0, depth) for o in objects]
        value = data if len(data) != 1 or p.get("AsArray") else data[0]
        if p.get("Compress"):
            return [json.dumps(value, ensure_ascii=False, separators=(",", ":"))]
        return [json.dumps(value, ensure_ascii=False, indent=2)]

    def c_where_object(self, args, input_data):
        script = None
        prop = None
        operator = None
        value = None
        has_value = False
        positional = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg[0] == "param":
                name = arg[1].lower()
                matches = [k for k in WHERE_OPERATORS if k == name] or [k for k in WHERE_OPERATORS if k.startswith(name)]
                if not matches:
                    raise PSError(f"Where-Object: A parameter cannot be found that matches parameter name '{arg[1]}'.")
                key = WHERE_OPERATORS[matches[0]]
                given = self.eval(arg[2]) if arg[2] is not None else None
                if key in ("property", "value", "filterscript"):
                    if given is None and i + 1 < len(args) and args[i + 1][0] == "arg":
                        given = self.eval(args[i + 1][1])
                        i += 1
                    if key == "property":
                        prop = given
                    elif key == "value":
                        value, has_value = given, True
                    else:
                        script = given
                else:
                    operator = key
                    if arg[2] is not None:
                        value, has_value = given, True
            else:
                positional.append(self.eval(arg[1]))
            i += 1
        for item in positional:
            if isinstance(item, ScriptBlock) and script is None and prop is None:
                script = item
            elif prop is None and script is None:
                prop = item
            elif not has_value:
                value, has_value = item, True
            else:
                raise PSError(f"Where-Object: A positional parameter cannot be found that accepts argument "
                              f"'{to_string(item)}'.")
        out = []
        for obj in input_data or []:
            if script is not None:
                if not isinstance(script, ScriptBlock):
                    raise PSError("Where-Object: Cannot bind parameter 'FilterScript'. Use a script block: "
                                  "Where-Object { $_.Name -eq 'x' }")
                if to_bool(unwrap(self.invoke(script, obj))):
                    out.append(obj)
                continue
            if prop is None:
                raise PSError("Where-Object: The property name is missing. Example: Where-Object Name -eq 'x'")
            actual = self.property_value(obj, prop)
            if operator is None or operator == "not":
                keep = to_bool(actual) if operator is None else not to_bool(actual)
            else:
                case = operator.startswith("c") and operator[1:] in WHERE_OPERATORS
                base = operator[1:] if case else operator
                if base in ("contains", "notcontains"):
                    found = any(equals(v, value, case) for v in enumerate_value(actual))
                    keep = found if base == "contains" else not found
                elif base in ("in", "notin"):
                    found = any(equals(v, actual, case) for v in enumerate_value(value))
                    keep = found if base == "in" else not found
                elif base in ("is", "isnot"):
                    result = is_type(actual, value.name if isinstance(value, TypeLiteral) else to_string(value))
                    keep = result if base == "is" else not result
                elif isinstance(actual, list):
                    keep = bool([v for v in actual if compare_scalar(base, v, value, case)])
                else:
                    keep = compare_scalar(base, actual, value, case)
            if keep:
                out.append(obj)
        return out

    def c_select_object(self, p, input_data):
        items = list(input_data or [])
        if p.get("Skip") is not None:
            items = items[int(to_number(p["Skip"])):]
        if p.get("Index") is not None:
            items = [items[int(to_number(i))] for i in enumerate_value(p["Index"]) if int(to_number(i)) < len(items)]
        first = p.get("First")
        last = p.get("Last")
        if first is not None or last is not None:
            chosen = items[:int(to_number(first))] if first is not None else []
            if last is not None:
                count = int(to_number(last))
                tail = items[-count:] if count else []
                chosen += [t for t in tail if t not in chosen] if first is not None else tail
            items = chosen
        props = enumerate_value(p.get("Property"))
        if p.get("ExpandProperty") is not None:
            name = to_string(p["ExpandProperty"])
            out = []
            for item in items:
                value = self.get_member(item, name)
                if value is MISSING:
                    self.errors.append(f"Select-Object: Property \"{name}\" cannot be found.")
                    continue
                out += enumerate_value(value) if isinstance(value, list) else [value]
            return self.unique(out) if p.get("Unique") else out
        if not props:
            selected = [PSObject(item.props, "Selected." + item.type_name, item.display, None, item.text, item.view)
                        if isinstance(item, PSObject) and item.type_name.endswith("PSCustomObject")
                        and not item.type_name.startswith("Selected.") else item for item in items]
            return self.unique(selected) if p.get("Unique") else selected
        out = []
        for item in items:
            values = {}
            for prop in props:
                if isinstance(prop, CIDict):
                    label = next((to_string(prop[k]) for k in prop if k.lower() in ("name", "n", "label", "l")), None)
                    values[label or "Expression"] = self.property_value(item, prop)
                elif isinstance(prop, ScriptBlock):
                    values[prop.text.strip()] = self.property_value(item, prop)
                else:
                    name = to_string(prop)
                    if any(ch in name for ch in "*?"):
                        regex = wildcard_regex(name)
                        for key, value in self.property_list(item):
                            if regex.match(key):
                                values[key] = value
                    else:
                        actual = next((k for k, _ in self.property_list(item) if k.lower() == name.lower()), name)
                        value = self.get_member(item, name)
                        values[actual] = None if value is MISSING else value
            exclude = [to_string(x).lower() for x in enumerate_value(p.get("ExcludeProperty"))]
            values = {k: v for k, v in values.items() if k.lower() not in exclude}
            base_type = item.type_name if isinstance(item, PSObject) else type_of(item)
            type_name = base_type if base_type.startswith("Selected.") else "Selected." + base_type
            out.append(PSObject(values, type_name))
        return self.unique(out) if p.get("Unique") else out

    @staticmethod
    def unique(items: list) -> list:
        """Select-Object -Unique: equal objects (same text, or same property values) appear once."""
        out, seen = [], set()
        for item in items:
            key = (tuple((k, to_string(v)) for k, v in item.props.items()) if isinstance(item, PSObject)
                   else to_string(item))
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    def sort_key_values(self, item, props):
        if not props:
            return [item]
        return [self.property_value(item, prop) for prop in props]

    def c_sort_object(self, p, input_data):
        items = list(input_data or [])
        props = enumerate_value(p.get("Property"))
        descending_all = bool(p.get("Descending"))
        case = bool(p.get("CaseSensitive"))
        directions = []
        for prop in props:
            if isinstance(prop, CIDict):
                if any(k.lower() == "descending" for k in prop):
                    directions.append(to_bool(next(prop[k] for k in prop if k.lower() == "descending")))
                elif any(k.lower() == "ascending" for k in prop):
                    directions.append(not to_bool(next(prop[k] for k in prop if k.lower() == "ascending")))
                else:
                    directions.append(descending_all)
            else:
                directions.append(descending_all)
        if not props:
            directions = [descending_all]
        keyed = [(self.sort_key_values(item, props), index, item) for index, item in enumerate(items)]

        def compare(a, b):
            for i, (x, y) in enumerate(zip(a[0], b[0])):
                result = sort_compare(x, y, case)
                if result:
                    return -result if directions[i] else result
            return 0

        import functools
        keyed.sort(key=functools.cmp_to_key(lambda a, b: compare(a, b) or (a[1] - b[1])))
        result = [item for _, _, item in keyed]
        if p.get("Unique"):
            unique = []
            for entry in keyed:
                if not unique or compare(unique[-1], entry) != 0:
                    unique.append(entry)
            result = [item for _, _, item in unique]
        if p.get("Top") is not None:
            result = result[:int(to_number(p["Top"]))]
        if p.get("Bottom") is not None:
            count = int(to_number(p["Bottom"]))
            result = result[-count:] if count else []
        return result

    def c_group_object(self, p, input_data):
        props = enumerate_value(p.get("Property"))
        case = bool(p.get("CaseSensitive"))
        groups: dict = {}
        order = []
        for item in input_data or []:
            values = self.sort_key_values(item, props) if props else [item]
            name = ", ".join(to_string(v) for v in values)
            key = name if case else name.casefold()
            if key not in groups:
                groups[key] = {"name": name, "values": values, "items": []}
                order.append(key)
            groups[key]["items"].append(item)
        entries = [groups[k] for k in order]
        import functools
        entries.sort(key=functools.cmp_to_key(
            lambda a, b: next((r for r in (sort_compare(x, y, case) for x, y in zip(a["values"], b["values"])) if r), 0)))
        if p.get("AsHashTable"):
            table = CIDict()
            for entry in entries:
                key = entry["name"] if p.get("AsString") or len(entry["values"]) != 1 else entry["values"][0]
                table[key] = entry["items"]
            return [table]
        out = []
        for entry in entries:
            props_out = {"Count": len(entry["items"]), "Name": entry["name"]}
            if not p.get("NoElement"):
                props_out["Group"] = entry["items"]
            props_out["Values"] = entry["values"]
            out.append(PSObject(props_out, "Microsoft.PowerShell.Commands.GroupInfo",
                                display=["Count", "Name"] + ([] if p.get("NoElement") else ["Group"]), view="group"))
        return out

    def c_measure_object(self, p, input_data):
        items = list(input_data or [])
        if p.get("Line") or p.get("Word") or p.get("Character"):
            texts = [to_string(i) for i in items]
            props = {}
            if p.get("Line"):
                props["Lines"] = sum(t.count("\n") + 1 for t in texts)
            if p.get("Word"):
                props["Words"] = sum(len(t.split()) for t in texts)
            if p.get("Character"):
                props["Characters"] = sum(len(t) for t in texts)
            props["Property"] = None
            return [PSObject(props, "Microsoft.PowerShell.Commands.TextMeasureInfo")]
        props_wanted = enumerate_value(p.get("Property"))
        out = []
        for prop in props_wanted or [None]:
            values = [self.property_value(i, prop) if prop is not None else i for i in items]
            stats = {"Count": len(values), "Average": None, "Sum": None, "Maximum": None, "Minimum": None,
                     "StandardDeviation": None, "Property": to_string(prop) if prop is not None else None}
            wants = {k: p.get(k) or p.get("AllStats") for k in ("Sum", "Average", "Maximum", "Minimum", "StandardDeviation")}
            if any(wants.values()):
                numbers = []
                for v in values:
                    if v is None:
                        continue
                    try:
                        numbers.append(to_number(v))
                    except PSError:
                        raise PSError(f'Measure-Object: Input object "{to_string(v)}" is not numeric.') from None
                stats["Count"] = len(numbers)
                if wants["Sum"]:
                    stats["Sum"] = sum(numbers)
                if wants["Average"]:
                    stats["Average"] = float(sum(numbers)) / len(numbers) if numbers else None
                if wants["Maximum"]:
                    stats["Maximum"] = max(numbers) if numbers else None
                if wants["Minimum"]:
                    stats["Minimum"] = min(numbers) if numbers else None
                if wants["StandardDeviation"] and len(numbers) > 1:
                    stats["StandardDeviation"] = statistics.stdev(numbers)
                for key in ("Sum", "Maximum", "Minimum"):
                    if stats[key] is not None:
                        stats[key] = float(stats[key]) if key == "Sum" and any(isinstance(n, float) for n in numbers) else stats[key]
            out.append(PSObject(stats, "Microsoft.PowerShell.Commands.GenericMeasureInfo", view="measure"))
        return out

    def c_foreach_object(self, p, input_data):
        out = []
        if p.get("MemberName") is not None or (isinstance(p.get("Process"), str)):
            name = to_string(p.get("MemberName") or p.get("Process"))
            arguments = enumerate_value(p.get("ArgumentList"))
            for item in input_data or []:
                value = self.get_member(item, name)
                if value is not MISSING and not arguments:
                    out += enumerate_value(value) if isinstance(value, list) else [value]
                else:
                    out += enumerate_value(self.call_method(item, name, arguments))
            return out
        blocks = enumerate_value(p.get("Process"))
        begin, end = p.get("Begin"), p.get("End")
        if len(blocks) == 3 and begin is None and end is None:
            begin, blocks, end = blocks[0], [blocks[1]], blocks[2]
        if begin is not None:
            out += self.invoke(begin, None)
        for item in input_data or []:
            for block in blocks:
                if not isinstance(block, ScriptBlock):
                    raise PSError("ForEach-Object: Cannot bind parameter 'Process'. Use a script block: "
                                  "ForEach-Object { $_.Name }")
                out += self.invoke(block, item)
        if end is not None:
            out += self.invoke(end, None)
        return out

    def c_get_member(self, p, input_data):
        seen = []
        out = []
        for item in input_data or []:
            full = type_of(item)
            key = full if not isinstance(item, PSObject) or not item.custom() else (full, tuple(item.props))
            if key in seen:
                continue
            seen.append(key)
            out += [m for m in members_of(item, self) if self.member_matches(m, p)]
        if not input_data:
            raise PSError("Get-Member: You must specify an object for the Get-Member cmdlet.")
        return out

    @staticmethod
    def member_matches(member: PSObject, p) -> bool:
        if p.get("MemberType") is not None:
            wanted = [to_string(v).lower() for v in enumerate_value(p["MemberType"])]
            kind = member.props["MemberType"].lower()
            if not any(kind == w or (w == "properties" and "property" in kind) or (w == "methods" and "method" in kind)
                       for w in wanted):
                return False
        if p.get("Name") is not None:
            patterns = [wildcard_regex(to_string(n)) for n in enumerate_value(p["Name"])]
            if not any(r.match(member.props["Name"]) for r in patterns):
                return False
        return True

    def table_getter(self, obj, column):
        if isinstance(column, (ScriptBlock, CIDict)):
            return self.property_value(obj, column)
        value = self.get_member(obj, to_string(column))
        if value is MISSING and isinstance(obj, (PSObject, XmlNode)):
            return value_of(obj, to_string(column))
        return None if value is MISSING else value

    def _columns(self, p, objects):
        props = enumerate_value(p.get("Property"))
        if not props:
            return None
        names = []
        for prop in props:
            if isinstance(prop, CIDict):
                names.append(prop)
            elif isinstance(prop, ScriptBlock):
                names.append(prop)
            elif any(ch in to_string(prop) for ch in "*?"):
                regex = wildcard_regex(to_string(prop))
                names += [n for n, _ in self.property_list(objects[0]) if regex.match(n)] if objects else []
            else:
                names.append(to_string(prop))
        return names

    def _labels(self, columns):
        labels = []
        for column in columns:
            if isinstance(column, CIDict):
                labels.append(next((to_string(column[k]) for k in column if k.lower() in ("name", "n", "label", "l")),
                                   "Expression"))
            elif isinstance(column, ScriptBlock):
                labels.append(column.text.strip())
            else:
                labels.append(column)
        return labels

    def c_format_table(self, p, input_data):
        objects = list(input_data or [])
        columns = self._columns(p, objects)
        if columns is None:
            text = format_output(objects)
            if objects and all(isinstance(o, PSObject) and not o.view for o in objects):
                names = properties(objects[0])
                text = format_table(objects, names, self.table_getter)
            return [FormattedText(text)]
        labels = self._labels(columns)
        rows = [PSObject({label: self.table_getter(o, c) for label, c in zip(labels, columns)}) for o in objects]
        text = format_table(rows, labels, lambda o, n: o.props.get(n))
        if p.get("HideTableHeaders"):
            lines = text.split("\n")
            text = "\n".join(lines[:1] + lines[3:])
        return [FormattedText(text)]

    def c_format_list(self, p, input_data):
        objects = list(input_data or [])
        columns = self._columns(p, objects)
        if columns is None:
            names_for = lambda o: [n for n, _ in self.property_list(o)] or None  # noqa: E731
            lines = []
            for obj in objects:
                names = names_for(obj)
                if not names:
                    lines.append(format_output([obj]).rstrip("\n"))
                    continue
                lines.append(format_list([obj], names, self.table_getter).rstrip("\n"))
            return [FormattedText("\n".join(lines) + "\n\n")]
        labels = self._labels(columns)
        rows = [PSObject({label: self.table_getter(o, c) for label, c in zip(labels, columns)}) for o in objects]
        return [FormattedText(format_list(rows, labels, lambda o, n: o.props.get(n)))]

    def c_out_string(self, p, input_data):
        text = format_output(list(input_data or []))
        if p.get("Stream"):
            return text.rstrip("\n").split("\n")
        return [text]

    def c_out_host(self, p, input_data):
        return [FormattedText(format_output(list(input_data or [])))]

    def c_out_null(self, p, input_data):
        return []

    def c_out_file(self, p, input_data):
        text = format_output(list(input_data or []))
        self.write_file(to_string(p.get("FilePath")), text, bool(p.get("Append")), "Out-File")
        return []

    def _content_text(self, p, input_data) -> str:
        values = enumerate_value(p["Value"]) if "Value" in p else list(input_data or [])
        return "".join(to_string(v) + "\n" for v in values)

    def c_set_content(self, p, input_data):
        self.write_file(to_string(p.get("Path")), self._content_text(p, input_data), False, "Set-Content")
        return []

    def c_add_content(self, p, input_data):
        self.write_file(to_string(p.get("Path")), self._content_text(p, input_data), True, "Add-Content")
        return []

    def c_select_string(self, p, input_data):
        if p.get("Pattern") is None:
            raise PSError("Select-String: Cannot bind argument to parameter 'Pattern' because it is null.")
        patterns = [to_string(x) for x in enumerate_value(p["Pattern"])]
        case = bool(p.get("CaseSensitive"))
        if p.get("SimpleMatch"):
            regexes = [re.compile(re.escape(x), 0 if case else re.IGNORECASE) for x in patterns]
        else:
            regexes = [net_regex(x, case) for x in patterns]
        sources = []
        if p.get("Path") is not None:
            for path in self.expand_paths("Select-String", p["Path"]):
                text = self.read_file("Select-String", path)
                if text is not None:
                    lines = text.split("\n")
                    if lines and lines[-1] == "":
                        lines.pop()
                    sources.append((path, lines))
        else:
            values = enumerate_value(p["InputObject"]) if "InputObject" in p else input_data or []
            sources.append((None, [to_string(v) for v in values]))
        out = []
        for path, lines in sources:
            for number, line in enumerate(lines, 1):
                found = [m for r in regexes for m in (r.finditer(line) if p.get("AllMatches") else [r.search(line)]) if m]
                hit = bool(found) != bool(p.get("NotMatch"))
                if not hit:
                    continue
                if p.get("Quiet"):
                    return [True]
                if p.get("Raw"):
                    out.append(line)
                    continue
                shown = self.relative(path) if path else None
                text = f"{shown}:{number}:{line}" if path else line
                out.append(PSObject({"IgnoreCase": not case, "LineNumber": number, "Line": line,
                                     "Filename": posixpath.basename(path) if path else "InputStream",
                                     "Path": path or "InputStream", "Pattern": patterns[0],
                                     "Matches": [regex_match(m) for m in found]},
                                    "Microsoft.PowerShell.Commands.MatchInfo", text=text, view="match"))
                if p.get("List"):
                    break
        if p.get("Quiet"):
            return [False]
        return out

    # Get-WinEvent ------------------------------------------------------------------------
    LIVE_LOGS = ("This lab's Get-WinEvent reads .evtx files only, for example: "
                 "Get-WinEvent -Path ~/logs/windows_security.evtx. Live logs such as 'Security' exist only on Windows.")

    def evtx_records(self, path: str) -> list[PSObject]:
        if path in self._evtx_cache:
            return self._evtx_cache[path]
        if posixpath.splitext(path)[1].lower() != ".evtx":
            raise PSError(f"Get-WinEvent: Get-WinEvent reads .evtx event log files, and '{path}' is not one. "
                          f"For an exported XML file use: [xml](Get-Content '{path}' -Raw)")
        try:
            content = evtx.read_evtx(self.fs.read_bytes(path))
        except evtx.EvtxError as exc:
            raise PSError(f"Get-WinEvent: Get-WinEvent could not read '{path}': {exc}") from None
        records = [event_record(text) for text in content.records]
        records.reverse()  # newest first, as on Windows
        self._evtx_cache[path] = records
        return records

    def c_get_winevent(self, p, input_data):
        if p.get("LogName") is not None or p.get("ListLog") is not None or p.get("ComputerName") is not None:
            raise PSError("Get-WinEvent: " + self.LIVE_LOGS)
        if p.get("FilterXPath") is not None:
            raise Unsupported("Get-WinEvent: -FilterXPath is not supported in the simulated terminal; "
                              "use -FilterHashtable.")
        if p.get("FilterHashtable") is not None:
            queries = [q for q in enumerate_value(p["FilterHashtable"])]
            if not all(isinstance(q, CIDict) for q in queries):
                raise PSError("Get-WinEvent: Cannot bind parameter 'FilterHashtable'. Use @{ Path = '...'; Id = 4625 }")
        elif p.get("Path") is not None:
            queries = [CIDict({"Path": p["Path"]})]
        else:
            raise PSError("Get-WinEvent: " + self.LIVE_LOGS)
        found = []
        seen = set()
        for query in queries:
            paths = query.get("Path")
            if paths is None:
                raise PSError("Get-WinEvent: " + self.LIVE_LOGS)
            for path in self.expand_paths("Get-WinEvent", paths):
                records = self.evtx_records(path)
                if p.get("Oldest"):
                    records = list(reversed(records))
                for record in records:
                    key = (path, record.props["RecordId"])
                    if key not in seen and self.event_matches(record, query):
                        seen.add(key)
                        found.append(record)
        if not found:
            if self.errors and self.errors[-1].startswith("Get-WinEvent: Cannot find path"):
                return []
            self.errors.append("Get-WinEvent: No events were found that match the specified selection criteria.")
            return []
        if p.get("MaxEvents") is not None:
            found = found[:int(to_number(p["MaxEvents"]))]
        return found

    @staticmethod
    def event_matches(record: PSObject, query: CIDict) -> bool:
        data = record.event_data
        for key in query:
            wanted = enumerate_value(query[key])
            lower = key.lower()
            if lower == "path":
                continue
            if lower == "logname":
                ok = any(equals(record.props["LogName"], w) for w in wanted)
            elif lower == "id":
                ok = any(equals(record.props["Id"], w) for w in wanted)
            elif lower == "providername":
                ok = any(equals(record.props["ProviderName"], w) for w in wanted)
            elif lower == "level":
                ok = any(equals(record.props["Level"], w) for w in wanted)
            elif lower == "keywords":
                ok = bool(record.props["Keywords"] & int(to_number(wanted[0])))
            elif lower == "starttime":
                ok = record.props["TimeCreated"] >= convert("datetime", wanted[0])
            elif lower == "endtime":
                ok = record.props["TimeCreated"] <= convert("datetime", wanted[0])
            elif lower == "data":
                ok = any(equals(v, w) for v in data.values() for w in wanted)
            elif lower in ("userid", "suppresshashfilter"):
                raise Unsupported(f"Get-WinEvent: the '{key}' filter is not supported in the simulated terminal.")
            else:
                ok = key in data and any(equals(data[key], w) for w in wanted)
            if not ok:
                return False
        return True

    # small cmdlets ---------------------------------------------------------------------------
    def c_write_output(self, p, input_data):
        value = p.get("InputObject")
        if p.get("NoEnumerate"):
            return [value]
        return enumerate_value(value) if "InputObject" in p else []

    def c_write_host(self, p, input_data):
        separator = to_string(p.get("Separator", " "))
        values = enumerate_value(p.get("Object")) if "Object" in p else []
        text = separator.join(to_string(v) for v in values)
        return [FormattedText(text + ("" if p.get("NoNewline") else "\n"))]

    def c_write_error(self, p, input_data):
        self.errors.append(f"Write-Error: {to_string(p.get('Message'))}")
        return []

    def c_get_date(self, p, input_data):
        value = convert("datetime", p["Date"]) if p.get("Date") is not None else utc_now()
        for part, attr in (("Year", "year"), ("Month", "month"), ("Day", "day")):
            if p.get(part) is not None:
                value = value.replace(**{attr: int(to_number(p[part]))})
        if p.get("Format") is not None:
            return [date_format(value, to_string(p["Format"]))]
        if p.get("UFormat") is not None:
            return [value.strftime(to_string(p["UFormat"]))]
        return [value]

    def c_new_timespan(self, p, input_data):
        if p.get("Start") is not None or p.get("End") is not None:
            start = convert("datetime", p["Start"]) if p.get("Start") is not None else utc_now()
            end = convert("datetime", p["End"]) if p.get("End") is not None else utc_now()
            return [TimeSpan((end - start).total_seconds())]
        seconds = sum(to_number(p.get(k, 0)) * f for k, f in (("Days", 86400), ("Hours", 3600), ("Minutes", 60),
                                                              ("Seconds", 1)))
        return [TimeSpan(seconds)]

    def c_clear_host(self, p, input_data):
        self.cleared = True
        return []

    def c_get_help(self, p, input_data):
        name = to_string(p.get("Name") or "")
        if not name:
            lines = ["Simulated PowerShell 7: the commands below work here. Aliases (ls, cat, where, select, sort,",
                     "group, measure, %, ?) work as on Windows. Linux tools (grep, wc, head...) work too.", ""]
            width = max(len(c.name) for c in CMDLETS)
            lines += [f"  {c.name:<{width}}  {c.synopsis}" for c in CMDLETS]
            lines += ["", "Type 'Get-Help NAME' for the parameters of a command."]
            return [FormattedText("\n".join(lines) + "\n")]
        canonical = ALIASES.get(name.lower(), name)
        cmdlet = COMMANDS.get(canonical.lower())
        if cmdlet is None:
            raise PSError(f"Get-Help: Get-Help could not find {name} in a help file in this session.")
        params = " ".join(f"[-{x.name}]" if x.switch else f"[-{x.name} <value>]" for x in cmdlet.params)
        aliases = ", ".join(a for a, c in ALIASES.items() if c == cmdlet.name)
        text = (f"\nNAME\n    {cmdlet.name}\n\nSYNOPSIS\n    {cmdlet.synopsis}\n\nSYNTAX\n    {cmdlet.name} {params}\n"
                + (f"\nALIASES\n    {aliases}\n" if aliases else "")
                + EXAMPLES.get(cmdlet.name, "") + "\n")
        return [FormattedText(text)]

    def c_get_command(self, p, input_data):
        names = [c.name for c in CMDLETS]
        if p.get("Name") is not None:
            regexes = [wildcard_regex(to_string(n)) for n in enumerate_value(p["Name"])]
            names = [n for n in names if any(r.match(n) for r in regexes)] + [
                a for a in ALIASES if any(r.match(a) for r in regexes)]
            if not names:
                raise PSError(f"Get-Command: The term '{to_string(p['Name'])}' is not recognized as a name of a cmdlet, "
                              f"function, script file, or executable program.")
        if p.get("Verb") is not None:
            names = [n for n in names if n.lower().startswith(to_string(p["Verb"]).lower() + "-")]
        if p.get("Noun") is not None:
            regex = wildcard_regex(to_string(p["Noun"]))
            names = [n for n in names if "-" in n and regex.match(n.split("-", 1)[1])]
        out = []
        for name in names:
            if name in ALIASES:
                out.append(PSObject({"CommandType": "Alias", "Name": f"{name} -> {ALIASES[name]}", "Version": "",
                                     "Source": ""}, "System.Management.Automation.AliasInfo", view="command"))
            else:
                out.append(PSObject({"CommandType": "Cmdlet", "Name": name, "Version": VERSION,
                                     "Source": "Microsoft.PowerShell (simulated)"},
                                    "System.Management.Automation.CmdletInfo", view="command"))
        return out

    def c_get_history(self, p, input_data):
        entries = [PSObject({"Id": i, "CommandLine": line}, "Microsoft.PowerShell.Commands.HistoryInfo", view="history")
                   for i, line in enumerate(self.history[:-1], 1)]
        if p.get("Count") is not None:
            entries = entries[-int(to_number(p["Count"])):]
        return entries

    def c_test_path(self, p, input_data):
        out = []
        for path in enumerate_value(p.get("Path")):
            resolved = self.resolve(to_string(path))
            kind = to_string(p.get("PathType") or "Any").lower()
            exists = (self.fs.exists(resolved) if kind == "any" else self.fs.is_file(resolved) if kind == "leaf"
                      else self.fs.is_dir(resolved))
            out.append(exists)
        return out

    def c_get_unique(self, p, input_data):
        out = []
        for item in input_data or []:
            if not out or to_string(out[-1]) != to_string(item):
                out.append(item)
        return out

    def c_join_path(self, p, input_data):
        children = [to_string(c) for c in enumerate_value(p.get("ChildPath"))]
        return [posixpath.join(to_string(p.get("Path")), *children)]

    def c_split_path(self, p, input_data):
        path = to_string(p.get("Path"))
        if p.get("Leaf"):
            return [posixpath.basename(path)]
        if p.get("Extension"):
            return [posixpath.splitext(path)[1]]
        if p.get("LeafBase"):
            return [posixpath.splitext(posixpath.basename(path))[0]]
        return [posixpath.dirname(path)]

    def c_resolve_path(self, p, input_data):
        return [PSObject({"Path": path}, "System.Management.Automation.PathInfo", text=path, view="path")
                for path in self.expand_paths("Resolve-Path", p.get("Path"))]

    def c_start_sleep(self, p, input_data):
        return []

    def c_get_alias(self, p, input_data):
        names = sorted(ALIASES)
        if p.get("Name") is not None:
            regex = wildcard_regex(to_string(p["Name"]))
            names = [n for n in names if regex.match(n)]
        return [PSObject({"CommandType": "Alias", "Name": f"{n} -> {ALIASES[n]}", "Version": "", "Source": ""},
                         "System.Management.Automation.AliasInfo", view="command") for n in names]

    def c_get_variable(self, p, input_data):
        items = [(k, v) for k, v in self.variables.items() if k.lower() not in ("args",)]
        if p.get("Name") is not None:
            regex = wildcard_regex(to_string(p["Name"]))
            items = [(k, v) for k, v in items if regex.match(k)]
        if p.get("ValueOnly"):
            return [v for _, v in items]
        return [PSObject({"Name": k, "Value": v}, "System.Management.Automation.PSVariable") for k, v in items]

    def c_remove_item(self, p, input_data):
        for path in self.expand_paths("Remove-Item", p.get("Path")):
            if not self.fs.writable(path):
                self.errors.append(f"Remove-Item: Access to the path '{path}' is denied.")
            elif self.fs.is_dir(path):
                self.errors.append(f"Remove-Item: '{path}' is a folder; only files can be removed here.")
            else:
                self.fs.remove(path)
        return []

    def c_new_item(self, p, input_data):
        path = self.resolve(to_string(p.get("Path")))
        if to_string(p.get("ItemType") or "File").lower() == "directory":
            if not self.fs.writable(path):
                raise PSError(f"New-Item: Access to the path '{path}' is denied.")
            self.fs.dirs.add(path)
            self.fs._add_parents(path)
        else:
            if self.fs.exists(path) and not p.get("Force"):
                raise PSError(f"New-Item: The file '{path}' already exists.")
            self.write_file(path, to_string(p.get("Value") or ""), False, "New-Item")
        return [self.file_object(path)]

    def c_compare_object(self, p, input_data):
        reference = enumerate_value(p.get("ReferenceObject"))
        difference = enumerate_value(p.get("DifferenceObject"))
        props = enumerate_value(p.get("Property"))
        key = (lambda o: tuple(to_string(self.property_value(o, x)).casefold() for x in props)) if props else (
            lambda o: to_string(o).casefold())
        ref_keys = [key(o) for o in reference]
        dif_keys = [key(o) for o in difference]
        out = []

        def entry(obj, indicator):
            values = {to_string(x): self.property_value(obj, x) for x in props} if props else {"InputObject": obj}
            values["SideIndicator"] = indicator
            return PSObject(values)

        if p.get("IncludeEqual"):
            out += [entry(o, "==") for o, k in zip(reference, ref_keys) if k in dif_keys]
        if not p.get("ExcludeDifferent"):
            out += [entry(o, "=>") for o, k in zip(difference, dif_keys) if k not in ref_keys]
            out += [entry(o, "<=") for o, k in zip(reference, ref_keys) if k not in dif_keys]
        return out

    def c_get_random(self, p, input_data):
        items = enumerate_value(p.get("InputObject")) or list(input_data or [])
        if items:
            return [items[0]]
        return [int(to_number(p.get("Minimum", 0)))]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def sort_compare(x, y, case: bool = False) -> int:
    if x is None and y is None:
        return 0
    if x is None:
        return -1
    if y is None:
        return 1
    if is_number(x) and is_number(y):
        return (x > y) - (x < y)
    if isinstance(x, datetime) and isinstance(y, datetime):
        return (x > y) - (x < y)
    if isinstance(x, bool) and isinstance(y, bool):
        return (x > y) - (x < y)
    return ordering(to_string(x), to_string(y), case)


def net_replacement(text: str) -> str:
    """.NET replacement syntax ($1, ${name}, $0) -> Python's."""
    text = text.replace("\\", "\\\\")
    text = re.sub(r"\$\{(\w+)\}", r"\\g<\1>", text)
    text = re.sub(r"\$(\d+)", r"\\g<\1>", text)
    return text.replace("$$", "$")


def match_table(match: re.Match) -> CIDict:
    table = CIDict()
    table[0] = match.group(0)
    for index, group in enumerate(match.groups(), 1):
        if group is not None:
            table[index] = group
    for name, group in match.groupdict().items():
        if group is not None:
            table[name] = group
    return table


def regex_match(match) -> PSObject:
    if match is None:
        return PSObject({"Success": False, "Value": "", "Index": 0, "Length": 0},
                        "System.Text.RegularExpressions.Match", text="")
    groups = [PSObject({"Name": str(i), "Value": g or "", "Success": g is not None}) for i, g in
              enumerate([match.group(0), *match.groups()])]
    return PSObject({"Groups": groups, "Success": True, "Name": "0", "Captures": [match.group(0)],
                     "Index": match.start(), "Length": match.end() - match.start(), "Value": match.group(0)},
                    "System.Text.RegularExpressions.Match", display=["Groups", "Success", "Name", "Captures", "Index",
                                                                     "Length", "Value"], text=match.group(0))


def date_to_strptime(fmt: str) -> str:
    replacements = [("yyyy", "%Y"), ("MM", "%m"), ("dd", "%d"), ("HH", "%H"), ("mm", "%M"), ("ss", "%S"),
                    ("yy", "%y"), ("MMM", "%b")]
    for token, value in replacements:
        fmt = fmt.replace(token, value)
    return fmt


def event_record(xml_text: str) -> PSObject:
    root = ET.fromstring(xml_text)

    def find(path):
        node = root
        for part in path.split("/"):
            node = next((c for c in node if local_name(c.tag) == part), None)
            if node is None:
                return None
        return node

    def text(path, default=""):
        node = find(path)
        return node.text if node is not None and node.text is not None else default

    data = CIDict()
    values = []
    event_data = find("EventData")
    if event_data is not None:
        for item in event_data:
            if local_name(item.tag) == "Data":
                values.append(item.text or "")
                if item.get("Name"):
                    data[item.get("Name")] = item.text or ""
    event_id = int(text("System/EventID", "0") or 0)
    level = int(text("System/Level", "0") or 0)
    keywords_text = text("System/Keywords", "0x0")
    keywords = int(keywords_text, 16) if keywords_text.startswith("0x") else int(keywords_text or 0)
    if keywords >= 2 ** 63:
        keywords -= 2 ** 64
    created = find("System/TimeCreated")
    when = parse_date(created.get("SystemTime")[:19]) if created is not None and created.get("SystemTime") else None
    provider = find("System/Provider")
    description = EVENT_DESCRIPTIONS.get(event_id, f"Event {event_id}.")
    message = "\n".join([description, ""] + [f"  {k}:\t{v}" for k, v in data.items()])
    props = {"Id": event_id, "Version": int(text("System/Version", "0") or 0), "Level": level,
             "LevelDisplayName": LEVEL_NAMES.get(level, ""), "Task": int(text("System/Task", "0") or 0),
             "Keywords": keywords, "RecordId": int(text("System/EventRecordID", "0") or 0),
             "ProviderName": provider.get("Name") if provider is not None else "",
             "LogName": text("System/Channel"), "MachineName": text("System/Computer"), "TimeCreated": when,
             "Message": message, "Properties": [PSObject({"Value": v}) for v in values]}
    record = PSObject(props, "System.Diagnostics.Eventing.Reader.EventLogRecord",
                      display=["TimeCreated", "Id", "LevelDisplayName", "Message"], view="event",
                      methods={"ToXml": lambda: xml_text})
    record.event_data = data  # named event data, for -FilterHashtable @{ TargetUserName = ... }
    return record


def members_of(item, shell) -> list[PSObject]:
    full = type_of(item)
    if isinstance(item, PSObject) and item.custom():
        type_name = full if not full.startswith("Selected.") else full
        type_name = type_name if type_name != "System.Management.Automation.PSCustomObject" else full
    else:
        type_name = full

    def member(name, kind, definition):
        return PSObject({"TypeName": type_name, "Name": name, "MemberType": kind, "Definition": definition},
                        "Microsoft.PowerShell.Commands.MemberDefinition", view="member")

    base = [member("Equals", "Method", "bool Equals(System.Object obj)"),
            member("GetHashCode", "Method", "int GetHashCode()"),
            member("GetType", "Method", "type GetType()"), member("ToString", "Method", "string ToString()")]
    if isinstance(item, PSObject) and item.custom():
        notes = sorted(item.props.items(), key=lambda kv: kv[0].lower())
        return base + [member(k, "NoteProperty", f"{short_type(v)} {k}={to_string(v)}") for k, v in notes]
    if isinstance(item, str):
        methods = [("Contains", "bool Contains(string value)"), ("EndsWith", "bool EndsWith(string value)"),
                   ("IndexOf", "int IndexOf(string value)"), ("PadLeft", "string PadLeft(int totalWidth)"),
                   ("Replace", "string Replace(string oldValue, string newValue)"),
                   ("Split", "string[] Split(string separator)"), ("StartsWith", "bool StartsWith(string value)"),
                   ("Substring", "string Substring(int startIndex, int length)"), ("ToLower", "string ToLower()"),
                   ("ToUpper", "string ToUpper()"), ("Trim", "string Trim()")]
        out = [member(n, "Method", d) for n, d in methods] + base
        out.sort(key=lambda m: m.props["Name"].lower())
        return out + [member("Length", "Property", "int Length {get;}")]
    if isinstance(item, datetime):
        methods = [("AddDays", "datetime AddDays(double value)"), ("AddHours", "datetime AddHours(double value)"),
                   ("AddMinutes", "datetime AddMinutes(double value)"), ("ToString", "string ToString(string format)"),
                   ("ToUniversalTime", "datetime ToUniversalTime()")]
        props = ["Date", "Day", "DayOfWeek", "DayOfYear", "Hour", "Minute", "Month", "Second", "TimeOfDay", "Year"]
        return ([member(n, "Method", d) for n, d in methods] +
                [member(n, "Property", f"{short_type(shell.get_member(item, n))} {n} {{get;}}") for n in props])
    if isinstance(item, PSObject):
        props = list(item.props.items())
        methods = [member(k, "Method", f"string {k}()") for k in item.methods] if item.methods else []
        return base + methods + [member(k, "Property", f"{short_type(v)} {k} {{get;}}") for k, v in props]
    if isinstance(item, XmlNode):
        props = [member(n, "Property", f"{short_type(item.member(n))} {n} {{get;set;}}") for n in item.property_names()]
        methods = [member("GetAttribute", "Method", "string GetAttribute(string name)"),
                   member("SelectNodes", "Method", "System.Xml.XmlNodeList SelectNodes(string xpath)")]
        return methods + base + props
    if isinstance(item, CIDict):
        return base + [member("Add", "Method", "void Add(System.Object key, System.Object value)"),
                       member("ContainsKey", "Method", "bool ContainsKey(System.Object key)"),
                       member("Count", "Property", "int Count {get;}"),
                       member("Keys", "Property", "System.Collections.ICollection Keys {get;}"),
                       member("Values", "Property", "System.Collections.ICollection Values {get;}")]
    if is_number(item):
        return base + [member("CompareTo", "Method", "int CompareTo(System.Object value)"),
                       member("ToString", "Method", "string ToString(string format)")]
    return base


def short_type(value) -> str:
    names = {"System.String": "string", "System.Int32": "int", "System.Int64": "long", "System.Double": "double",
             "System.Boolean": "bool", "System.DateTime": "datetime", "System.Object[]": "Object[]",
             "null": "object"}
    full = type_of(value)
    if isinstance(value, PSObject) and value.custom():
        return "System.Management.Automation.PSCustomObject"
    return names.get(full, full)


EXAMPLES = {
    "Where-Object": "\nEXAMPLES\n    Import-Csv logs/sample_auth_logs.csv | Where-Object event_code -eq 4625\n"
                    "    Import-Csv logs/sample_auth_logs.csv | Where-Object { $_.result -eq 'FAILURE' -and $_.source_ip -notlike '10.*' }\n",
    "Select-Object": "\nEXAMPLES\n    Import-Csv logs/sample_auth_logs.csv | Select-Object -First 3\n"
                     "    Import-Csv logs/sample_auth_logs.csv | Select-Object username, source_ip -First 5\n"
                     "    ... | Select-Object -ExpandProperty username\n",
    "Group-Object": "\nEXAMPLES\n    Import-Csv logs/sample_auth_logs.csv | Group-Object event_code\n"
                    "    ... | Group-Object username | Sort-Object Count -Descending | Select-Object -First 5\n",
    "Get-WinEvent": "\nEXAMPLES\n    Get-WinEvent -Path ~/logs/windows_security.evtx -MaxEvents 5\n"
                    "    Get-WinEvent -FilterHashtable @{ Path = \"$HOME/logs/windows_security.evtx\"; Id = 4625 }\n"
                    "\nNOTES\n    Lab version: reads .evtx files only. On Windows, @{ LogName = 'Security'; Id = 4625 }\n"
                    "    reads the live log.\n",
    "Import-Csv": "\nEXAMPLES\n    Import-Csv logs/sample_auth_logs.csv | Select-Object -First 2\n"
                  "    (Import-Csv logs/sample_auth_logs.csv).Count\n",
    "ConvertFrom-Json": "\nEXAMPLES\n    $signins = (Get-Content logs/entra_signins.json -Raw | ConvertFrom-Json).value\n"
                        "    $signins | Where-Object { $_.status.errorCode -ne 0 }\n",
    "Get-Content": "\nEXAMPLES\n    Get-Content logs/linux_auth.log -TotalCount 5\n"
                   "    $log = [xml](Get-Content logs/windows_security.xml -Raw)\n",
    "Select-String": "\nEXAMPLES\n    Select-String -Path logs/linux_auth.log -Pattern 'Failed password'\n"
                     "    (Select-String -Path logs/linux_auth.log -Pattern 'Failed password').Count\n",
    "Sort-Object": "\nEXAMPLES\n    ... | Sort-Object Count -Descending\n    ... | Sort-Object timestamp\n",
    "Measure-Object": "\nEXAMPLES\n    Import-Csv logs/sample_auth_logs.csv | Measure-Object\n",
    "ForEach-Object": "\nEXAMPLES\n    ... | ForEach-Object { $_.username.ToUpper() }\n",
}
