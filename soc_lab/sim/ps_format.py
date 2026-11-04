"""How the simulated PowerShell prints objects (Out-Default): tables, lists and the special views.

Objects with up to four properties print as a table, others as a list, as in PowerShell. Files,
groups, Get-Member, events and Select-String results have their own views, close to PowerShell 7.
"""

from __future__ import annotations

from datetime import datetime

from .ps_values import (FormattedText, PSObject, TimeSpan, TIMESPAN_PROPS, XmlNode, CIDict, MISSING, format_number,
                        is_number, long_date, to_string)

WIDTH = 120  # characters per line of the simulated console


def cell(value) -> str:
    """A value inside a table or list."""
    if value is None or value is MISSING:
        return ""
    if isinstance(value, list):
        inner = ", ".join(cell(v) for v in value[:4])
        return "{" + inner + (", …" if len(value) > 4 else "") + "}"
    if isinstance(value, XmlNode):
        return value.name if len(value.element) or value.element.attrib else (value.element.text or "")
    if isinstance(value, CIDict):
        return "System.Collections.Hashtable"
    return to_string(value).replace("\r", "")


def first_line(text: str) -> str:
    if "\n" in text:
        return text.split("\n", 1)[0] + "…"
    return text


def truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[:max(width - 1, 0)] + "…"


def properties(obj) -> list[str]:
    if isinstance(obj, PSObject):
        return list(obj.display) if obj.display else list(obj.props)
    if isinstance(obj, XmlNode):
        return obj.property_names()
    if isinstance(obj, CIDict):
        return ["Name", "Value"]
    if isinstance(obj, TimeSpan):
        return TIMESPAN_PROPS
    return []


def value_of(obj, name: str):
    if isinstance(obj, PSObject):
        return obj.props.get(name)
    if isinstance(obj, XmlNode):
        return obj.display_value(name)
    if isinstance(obj, TimeSpan):
        return obj.member(name)
    return None


def table(rows: list, columns: list[str], right: set[str] | None = None, fixed: dict | None = None) -> list[str]:
    """Rows of values -> aligned lines (header, dashes, rows). Numbers are right-aligned."""
    texts = [[first_line(cell(value_of(r, c) if not isinstance(r, list) else r[i])) for i, c in enumerate(columns)]
             for r in rows]
    raw = [[value_of(r, c) if not isinstance(r, list) else r[i] for i, c in enumerate(columns)] for r in rows]
    right = set(right or set())
    for i, c in enumerate(columns):
        if raw and all(is_number(v[i]) for v in raw if v[i] not in (None, "")) and any(is_number(v[i]) for v in raw):
            right.add(c)
    widths = []
    for i, c in enumerate(columns):
        widths.append((fixed or {}).get(c) or max([len(c)] + [len(t[i]) for t in texts]))
    total = sum(widths) + len(widths) - 1
    if total > WIDTH and widths:
        widths[-1] = max(len(columns[-1]), widths[-1] - (total - WIDTH))
        while sum(widths) + len(widths) - 1 > WIDTH and len(widths) > 1:
            biggest = max(range(len(widths) - 1), key=lambda k: widths[k])
            widths[biggest] -= 1

    def line(values, dashes=False):
        parts = []
        for i, (c, text) in enumerate(zip(columns, values)):
            text = truncate(text, widths[i])
            last_column = i == len(columns) - 1
            if c in right:
                parts.append(text.rjust(widths[i]))
            else:
                parts.append(text if last_column else text.ljust(widths[i]))
        return " ".join(parts).rstrip()

    header = line(columns)
    dashes = line(["-" * len(c) for c in columns])
    return [header, dashes] + [line(t) for t in texts]


def list_view(objects: list, names_of=properties, getter=value_of) -> list[str]:
    out = []
    for obj in objects:
        names = names_of(obj)
        if not names:
            continue
        width = max(len(n) for n in names)
        out.append("")
        for name in names:
            value = getter(obj, name)
            text = cell(value)
            lines = text.split("\n")
            out.append(f"{name.ljust(width)} : {lines[0]}".rstrip() if lines[0] else f"{name.ljust(width)} :")
            for extra in lines[1:]:
                out.append(" " * (width + 3) + extra)
    return out


def scalar_text(value) -> str:
    if isinstance(value, datetime):
        return long_date(value)
    if isinstance(value, bool) or is_number(value):
        return format_number(value)
    return to_string(value)


def shape(obj):
    if isinstance(obj, PSObject):
        if obj.view:
            return ("view", obj.view)
        return ("object", obj.type_name, tuple(properties(obj)))
    if isinstance(obj, XmlNode):
        return ("xml", tuple(obj.property_names()))
    if isinstance(obj, CIDict):
        return ("hashtable",)
    if isinstance(obj, TimeSpan):
        return ("timespan",)
    if isinstance(obj, FormattedText):
        return ("text",)
    return ("scalar",)


def format_output(objects: list) -> str:
    """The text PowerShell prints for these objects at the end of a pipeline."""
    lines: list[str] = []
    i = 0
    while i < len(objects):
        kind = shape(objects[i])
        j = i
        while j < len(objects) and shape(objects[j]) == kind and kind[0] != "text":
            j += 1
        group = objects[i:max(j, i + 1)]
        i = max(j, i + 1)
        if kind[0] == "scalar":
            for value in group:
                if value is None:
                    continue
                lines += scalar_text(value).split("\n")
        elif kind[0] == "text":
            text = group[0].text
            lines += text[:-1].split("\n") if text.endswith("\n") else text.split("\n") if text else []
        elif kind[0] == "hashtable":
            rows = [[k, v] for h in group for k, v in h.items()]
            lines += [""] + table(rows, ["Name", "Value"]) + [""]
        elif kind[0] == "view":
            lines += VIEWS[kind[1]](group)
        else:
            names = properties(group[0])
            if not names:
                lines += [scalar_text(to_string(g)) for g in group]
            elif len(names) <= 4:
                lines += [""] + table(group, names) + [""]
            else:
                lines += list_view(group) + [""]
    text = "\n".join(lines)
    return text + "\n" if lines else ""


# ---------------------------------------------------------------------------
# Special views
# ---------------------------------------------------------------------------
def files_view(group: list) -> list[str]:
    out = []
    directory = None
    batch: list = []

    def flush():
        if not batch:
            return
        out.extend(["", f"    Directory: {directory}", ""])
        rows = [[o.props["UnixMode"], o.props["User"], o.props["Group"],
                 o.props["LastWriteTime"].strftime("%m/%d/%Y %H:%M"),
                 "" if o.props["PSIsContainer"] else str(o.props["Size"]), o.props["Name"]] for o in batch]
        out.extend(table(rows, ["UnixMode", "User", "Group", "LastWriteTime", "Size", "Name"],
                         right={"User", "LastWriteTime", "Size"}))
        batch.clear()

    for obj in group:
        if obj.props["DirectoryName"] != directory:
            flush()
            directory = obj.props["DirectoryName"]
        batch.append(obj)
    flush()
    return out + [""]


def group_view(group: list) -> list[str]:
    rows = [[g.props["Count"], g.props["Name"], g.props.get("Group")] for g in group]
    has_group = any(g.props.get("Group") is not None for g in group)
    columns = ["Count", "Name", "Group"] if has_group else ["Count", "Name"]
    rows = [r[:len(columns)] for r in rows]
    name_width = max([25] + [len(cell(r[1])) for r in rows]) if not has_group else 25
    return [""] + table(rows, columns, right={"Count"}, fixed={"Count": 5, "Name": name_width}) + [""]


def member_view(group: list) -> list[str]:
    out = []
    current = None
    batch: list = []

    def flush():
        if batch:
            out.extend(["", f"   TypeName: {current}", ""])
            out.extend(table([[m.props["Name"], m.props["MemberType"], m.props["Definition"]] for m in batch],
                             ["Name", "MemberType", "Definition"]))
            batch.clear()

    for member in group:
        if member.props["TypeName"] != current:
            flush()
            current = member.props["TypeName"]
        batch.append(member)
    flush()
    return out + [""]


def event_view(group: list) -> list[str]:
    rows = [[e.props["TimeCreated"], e.props["Id"], e.props["LevelDisplayName"], e.props["Message"]] for e in group]
    return [""] + table(rows, ["TimeCreated", "Id", "LevelDisplayName", "Message"]) + [""]


def match_view(group: list) -> list[str]:
    return [""] + [to_string(m) for m in group] + [""]


def history_view(group: list) -> list[str]:
    rows = [[h.props["Id"], h.props["CommandLine"]] for h in group]
    return [""] + table(rows, ["Id", "CommandLine"], right={"Id"}) + [""]


def command_view(group: list) -> list[str]:
    rows = [[c.props["CommandType"], c.props["Name"], c.props["Version"], c.props["Source"]] for c in group]
    return [""] + table(rows, ["CommandType", "Name", "Version", "Source"]) + [""]


def type_view(group: list) -> list[str]:
    rows = [[t.props["IsPublic"], t.props["IsSerial"], t.props["Name"], t.props["BaseType"]] for t in group]
    return [""] + table(rows, ["IsPublic", "IsSerial", "Name", "BaseType"]) + [""]


def measure_view(group: list) -> list[str]:
    return list_view(group) + [""]


def path_view(group: list) -> list[str]:
    return [""] + table([[p.props["Path"]] for p in group], ["Path"]) + [""]


VIEWS = {"file": files_view, "group": group_view, "member": member_view, "event": event_view,
         "match": match_view, "history": history_view, "command": command_view, "type": type_view,
         "measure": measure_view, "path": path_view}


def format_table(objects: list, columns: list | None, getter) -> str:
    if not objects:
        return ""
    names = columns or properties(objects[0])
    if not names:
        return "\n".join(scalar_text(o) for o in objects) + "\n"
    rows = [[getter(o, n) for n in names] for o in objects]
    return "\n".join([""] + table(rows, [n if isinstance(n, str) else n for n in names]) + [""]) + "\n"


def format_list(objects: list, columns: list | None, getter) -> str:
    if not objects:
        return ""
    lines = list_view(objects, (lambda o: columns or properties(o) or ["Value"]),
                      (lambda o, n: getter(o, n) if (columns or properties(o)) else o))
    return "\n".join(lines + ["", ""])
