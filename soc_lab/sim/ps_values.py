"""Values of the simulated PowerShell: objects, XML, hashtables, dates, conversions and operators.

Python values stand for .NET ones: None is $null, str, bool, int, float, list (arrays), datetime,
TimeSpan, CIDict (hashtables), PSObject (custom objects, files, events, groups) and XmlNode ([xml]).
Comparisons and conversions follow PowerShell: the left operand decides the type, strings compare
without case, and an array on the left filters instead of answering True or False.
"""

from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET
from collections.abc import MutableMapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .core import ShellError


class PSError(ShellError):
    """A terminating error, printed in PowerShell's concise style ("Category: message")."""


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------
class CIDict(MutableMapping):
    """Ordered dictionary with case-insensitive string keys, like a PowerShell hashtable."""

    def __init__(self, items=None):
        self._data: dict = {}
        for key, value in (items.items() if isinstance(items, (dict, CIDict)) else items or []):
            self[key] = value

    @staticmethod
    def _key(key):
        return key.lower() if isinstance(key, str) else key

    def __getitem__(self, key):
        return self._data[self._key(key)][1]

    def __setitem__(self, key, value):
        k = self._key(key)
        original = self._data[k][0] if k in self._data else key
        self._data[k] = (original, value)

    def __delitem__(self, key):
        del self._data[self._key(key)]

    def __iter__(self):
        return (original for original, _ in self._data.values())

    def __len__(self):
        return len(self._data)

    def __contains__(self, key):
        return self._key(key) in self._data

    def get(self, key, default=None):
        k = self._key(key)
        return self._data[k][1] if k in self._data else default


class PSObject:
    """A .NET-style object: ordered properties, an optional default view and optional methods."""

    def __init__(self, props=None, type_name: str = "System.Management.Automation.PSCustomObject",
                 display: list[str] | None = None, methods: dict | None = None, text=None, view: str = ""):
        self.props = CIDict(props or {})
        self.type_name = type_name
        self.display = display
        self.methods = {k.lower(): v for k, v in (methods or {}).items()}
        self.text = text
        self.view = view  # a special format: "file", "group", "member", "event", "match", ...

    def __repr__(self):
        return f"PSObject({self.type_name}, {dict(self.props)})"

    def custom(self) -> bool:
        return self.type_name.endswith("PSCustomObject") or self.type_name.startswith("Selected.")


@dataclass
class ScriptBlock:
    body: tuple
    text: str

    def __str__(self):
        return self.text


@dataclass(frozen=True)
class TypeLiteral:
    name: str

    def __str__(self):
        return self.name


@dataclass
class FormattedText:
    """Already formatted output (Format-Table, Write-Host, a native command): printed as it is."""

    text: str


class XmlNode:
    """An element of an [xml] document, with PowerShell's adapter: children and attributes become properties."""

    def __init__(self, element: ET.Element, document: bool = False, parent_ns: str = ""):
        self.element = element
        self.document = document
        self.parent_ns = parent_ns  # an element shows "xmlns" only where its namespace is declared

    @property
    def namespace(self) -> str:
        return self.element.tag[1:].split("}")[0] if self.element.tag.startswith("{") else ""

    @property
    def name(self) -> str:
        return "#document" if self.document else local_name(self.element.tag)

    def children(self, name: str | None = None) -> list[ET.Element]:
        if self.document:
            return [self.element] if name is None or local_name(self.element.tag).lower() == name.lower() else []
        return [c for c in self.element if isinstance(c.tag, str)
                and (name is None or local_name(c.tag).lower() == name.lower())]

    def member(self, name: str):
        lower = name.lower()
        if lower == "#text":
            return self.element.text if not self.document else None
        if lower in ("innertext", "#cdata-section"):
            return "".join(self.element.itertext())
        if lower == "outerxml":
            return ET.tostring(self.element, encoding="unicode") if not self.document else xml_text(self.element)
        if lower == "innerxml":
            return "".join(ET.tostring(c, encoding="unicode") for c in self.element) if not self.document else xml_text(self.element)
        if lower in ("localname", "name"):
            matches = self.children(name)
            if not matches and not any(local_name(k).lower() == lower for k in self.element.attrib):
                return self.name
        if lower == "childnodes":
            return [XmlNode(c, parent_ns=self.namespace) for c in self.children()]
        if lower == "documentelement" and self.document:
            return XmlNode(self.element)
        if not self.document:
            for key, value in self.element.attrib.items():
                if local_name(key).lower() == lower:
                    return value
        matches = self.children(name)
        if not matches:
            return MISSING
        values = [element_value(m, "" if self.document else self.namespace) for m in matches]
        return values[0] if len(values) == 1 else values

    def property_names(self) -> list[str]:
        if self.document:
            return ["xml", local_name(self.element.tag)]
        names = (["xmlns"] if self.namespace and self.namespace != self.parent_ns else []) + [
            local_name(k) for k in self.element.attrib]
        for child in self.children():
            name = local_name(child.tag)
            if name not in names:
                names.append(name)
        if not self.children() and (self.element.text or "").strip():
            names.append("#text")
        return names

    def display_value(self, name: str):
        if name == "xmlns":
            return self.element.tag[1:].split("}")[0]
        if name == "xml" and self.document:
            return 'version="1.0" encoding="utf-8"'
        value = self.member(name)
        if isinstance(value, XmlNode):
            return value.name
        if isinstance(value, list):
            return "{" + ", ".join(v.name if isinstance(v, XmlNode) else to_string(v) for v in value) + "}"
        return value


class _Missing:
    def __repr__(self):
        return "MISSING"


MISSING = _Missing()  # a member that does not exist (PowerShell returns $null without an error)


def local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def xml_text(element: ET.Element) -> str:
    return ET.tostring(element, encoding="unicode")


def element_value(element: ET.Element, parent_ns: str = ""):
    """A child element as PowerShell shows it: text for a simple element, else the node."""
    if not element.attrib and not len(element):
        return element.text if element.text is not None else ""
    return XmlNode(element, parent_ns=parent_ns)


@dataclass(frozen=True)
class TimeSpan:
    seconds: float

    @property
    def parts(self):
        total = abs(self.seconds)
        days, rest = divmod(total, 86400)
        hours, rest = divmod(rest, 3600)
        minutes, secs = divmod(rest, 60)
        return int(days), int(hours), int(minutes), int(secs), int(round((secs - int(secs)) * 1000))

    def __str__(self):
        days, hours, minutes, secs, ms = self.parts
        sign = "-" if self.seconds < 0 else ""
        text = f"{sign}{days}.{hours:02d}:{minutes:02d}:{secs:02d}" if days else f"{sign}{hours:02d}:{minutes:02d}:{secs:02d}"
        frac = abs(self.seconds) - math.floor(abs(self.seconds))
        if frac > 1e-9:
            text += f".{int(round(frac * 1e7)):07d}"
        return text

    def member(self, name: str):
        days, hours, minutes, secs, ms = self.parts
        sign = -1 if self.seconds < 0 else 1
        values = {"days": sign * days, "hours": sign * hours, "minutes": sign * minutes, "seconds": sign * secs,
                  "milliseconds": sign * ms, "ticks": int(self.seconds * 1e7),
                  "totaldays": self.seconds / 86400, "totalhours": self.seconds / 3600,
                  "totalminutes": self.seconds / 60, "totalseconds": float(self.seconds),
                  "totalmilliseconds": self.seconds * 1000}
        return values.get(name.lower(), MISSING)


TIMESPAN_PROPS = ["Days", "Hours", "Minutes", "Seconds", "Milliseconds", "Ticks", "TotalDays", "TotalHours",
                  "TotalMinutes", "TotalSeconds", "TotalMilliseconds"]


# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------
INT_TEXT = re.compile(r"^\s*[-+]?\d+\s*$")
FLOAT_TEXT = re.compile(r"^\s*[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?\s*$")
HEX_TEXT = re.compile(r"^\s*0x[0-9a-fA-F]+\s*$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$")


def format_number(value) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    text = "%.15g" % value  # PowerShell shows doubles with 15 significant digits
    if "e" in text:
        mantissa, exponent = text.split("e")
        text = f"{mantissa}E{int(exponent):+03d}"
    return text


def format_date(value: datetime) -> str:
    return value.strftime("%m/%d/%Y %H:%M:%S")


def long_date(value: datetime) -> str:
    return value.strftime("%A, %d %B %Y %H:%M:%S")


def to_string(value) -> str:
    """How PowerShell turns a value into text ("$value", [string]$value)."""
    if value is None or value is MISSING:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return format_number(value)
    if isinstance(value, datetime):
        return format_date(value)
    if isinstance(value, (list, tuple)):
        return " ".join(to_string(v) for v in value)
    if isinstance(value, PSObject):
        if value.text is not None:
            return value.text(value) if callable(value.text) else value.text
        if value.custom():
            return "@{" + "; ".join(f"{k}={to_string(v)}" for k, v in value.props.items()) + "}"
        return value.type_name
    if isinstance(value, XmlNode):
        return "#document" if value.document else ("System.Xml.XmlElement" if len(value.element) or value.element.attrib
                                                     else value.element.text or "")
    if isinstance(value, CIDict):
        return "System.Collections.Hashtable"
    if isinstance(value, ScriptBlock):
        return value.text
    if isinstance(value, TimeSpan):
        return str(value)
    if isinstance(value, TypeLiteral):
        return TYPE_NAMES.get(value.name.lower(), value.name)
    if isinstance(value, FormattedText):
        return value.text
    return str(value)


def to_bool(value) -> bool:
    if value is None or value is MISSING:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value != ""
    if isinstance(value, (list, tuple)):
        if len(value) == 0:
            return False
        if len(value) == 1:
            return to_bool(value[0])
        return True
    return True


def to_number(value, target: str = "number"):
    """[int]/[double] conversion: strings are parsed, failures raise PowerShell's message."""
    if value is None or value is MISSING:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return 0
        if INT_TEXT.match(text):
            return int(text)
        if HEX_TEXT.match(text):
            return int(text, 16)
        if FLOAT_TEXT.match(text):
            return float(text)
    if isinstance(value, list) and len(value) == 1:
        return to_number(value[0], target)
    type_name = {"number": "System.Int32", "int": "System.Int32", "double": "System.Double"}.get(target, target)
    raise PSError(f'InvalidArgument: Cannot convert value "{to_string(value)}" to type "{type_name}". '
                  f'Error: "The input string \'{to_string(value)}\' was not in a correct format."')


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def parse_date(text: str) -> datetime:
    text = text.strip()
    if ISO_DATE.match(text) or re.match(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$", text):
        value = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
        return value.replace(tzinfo=None) if value.tzinfo else value
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y", "%d %B %Y", "%B %d, %Y", "%H:%M:%S", "%H:%M"):
        try:
            value = datetime.strptime(text, fmt)
            if fmt.startswith("%H"):
                today = utc_now()
                value = value.replace(year=today.year, month=today.month, day=today.day)
            return value
        except ValueError:
            continue
    raise PSError(f'InvalidArgument: Cannot convert value "{text}" to type "System.DateTime". '
                  f'Error: "String \'{text}\' was not recognized as a valid DateTime."')


def utc_now() -> datetime:
    """The simulated computer's clock is UTC, like the Docker terminal."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def round_half_even(value: float) -> int:
    return int(round(value))


TYPE_NAMES = {
    "int": "System.Int32", "int32": "System.Int32", "long": "System.Int64", "int64": "System.Int64",
    "double": "System.Double", "float": "System.Single", "single": "System.Single", "decimal": "System.Decimal",
    "string": "System.String", "bool": "System.Boolean", "boolean": "System.Boolean", "datetime": "System.DateTime",
    "xml": "System.Xml.XmlDocument", "array": "System.Array", "object[]": "System.Object[]",
    "hashtable": "System.Collections.Hashtable", "pscustomobject": "System.Management.Automation.PSObject",
    "char": "System.Char", "timespan": "System.TimeSpan", "regex": "System.Text.RegularExpressions.Regex",
    "math": "System.Math", "byte": "System.Byte", "object": "System.Object", "ordered": "ordered",
    "string[]": "System.String[]", "int[]": "System.Int32[]", "ipaddress": "System.Net.IPAddress",
}


def convert(type_name: str, value):
    """[type]value."""
    name = type_name.lower()
    for prefix in ("system.", "system.xml."):
        if name.startswith(prefix) and name[len(prefix):] in TYPE_NAMES:
            name = name[len(prefix):]
    if name.endswith("[]"):
        items = value if isinstance(value, list) else [] if value is None else [value]
        return [convert(name[:-2], item) for item in items]
    if name in ("int", "int32", "long", "int64", "byte"):
        number = to_number(value, "int")
        return round_half_even(number) if isinstance(number, float) else int(number)
    if name in ("double", "float", "single", "decimal"):
        return float(to_number(value, "double"))
    if name == "string":
        return None if value is None else to_string(value)
    if name in ("bool", "boolean"):
        return to_bool(value)
    if name == "datetime":
        if isinstance(value, datetime):
            return value
        return parse_date(to_string(value))
    if name in ("xml", "xmldocument"):
        text = to_string(value) if not isinstance(value, list) else "\n".join(to_string(v) for v in value)
        try:
            root = ET.fromstring(text.lstrip("﻿"))
        except ET.ParseError as exc:
            raise PSError(f'InvalidArgument: Cannot convert value "{text[:40]}..." to type "System.Xml.XmlDocument". '
                          f'Error: "{exc}"') from None
        return XmlNode(root, document=True)
    if name in ("array", "object[]"):
        return value if isinstance(value, list) else [] if value is None else [value]
    if name in ("hashtable", "ordered"):
        if isinstance(value, CIDict):
            return value
        raise PSError(f'InvalidArgument: Cannot convert value to type "System.Collections.Hashtable".')
    if name in ("pscustomobject", "psobject"):
        if isinstance(value, CIDict):
            return PSObject(dict(value.items()))
        return value
    if name == "char":
        if isinstance(value, int):
            return chr(value)
        text = to_string(value)
        if len(text) != 1:
            raise PSError(f'InvalidArgument: Cannot convert value "{text}" to type "System.Char".')
        return text
    if name == "timespan":
        if isinstance(value, TimeSpan):
            return value
        match = re.fullmatch(r"(?:(\d+)\.)?(\d+):(\d+)(?::(\d+))?", to_string(value).strip())
        if not match:
            raise PSError(f'InvalidArgument: Cannot convert value "{to_string(value)}" to type "System.TimeSpan".')
        d, h, m, s = (int(g or 0) for g in match.groups())
        return TimeSpan(d * 86400 + h * 3600 + m * 60 + s)
    if name in ("object", "psobject"):
        return value
    if name == "regex":
        return to_string(value)
    if name == "ipaddress":
        text = to_string(value)
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text) or any(int(p) > 255 for p in text.split(".")):
            raise PSError(f'InvalidArgument: Cannot convert value "{text}" to type "System.Net.IPAddress".')
        return text
    raise PSError(f"InvalidOperation: Unable to find type [{type_name}].")


def type_of(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "System.Boolean"
    if isinstance(value, int):
        return "System.Int32" if -2 ** 31 <= value < 2 ** 31 else "System.Int64"
    if isinstance(value, float):
        return "System.Double"
    if isinstance(value, str):
        return "System.String"
    if isinstance(value, datetime):
        return "System.DateTime"
    if isinstance(value, list):
        return "System.Object[]"
    if isinstance(value, CIDict):
        return "System.Collections.Hashtable"
    if isinstance(value, PSObject):
        return value.type_name
    if isinstance(value, XmlNode):
        return "System.Xml.XmlDocument" if value.document else "System.Xml.XmlElement"
    if isinstance(value, TimeSpan):
        return "System.TimeSpan"
    if isinstance(value, ScriptBlock):
        return "System.Management.Automation.ScriptBlock"
    if isinstance(value, TypeLiteral):
        return "System.RuntimeType"
    return "System.Object"


def is_type(value, type_name: str) -> bool:
    name = type_name.lower()
    actual = type_of(value).lower()
    full = TYPE_NAMES.get(name, name).lower()
    if full in ("system.object", "object"):
        return value is not None
    if name in ("array", "object[]"):
        return isinstance(value, list)
    if name in ("pscustomobject", "psobject"):
        return isinstance(value, PSObject)
    if is_number(value) and name in ("valuetype",):
        return True
    return actual == full or actual.split(".")[-1].lower() == name


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------
def wildcard_regex(pattern: str, case_sensitive: bool = False) -> re.Pattern:
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                out.append(re.escape(ch))
            else:
                out.append("[" + pattern[i + 1:end].replace("\\", "\\\\") + "]")
                i = end
        elif ch == "`" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 1
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$", 0 if case_sensitive else re.IGNORECASE | re.DOTALL)


def net_regex(pattern: str, case_sensitive: bool = False) -> re.Pattern:
    """.NET regular expressions are close to Python's; named groups (?<name>) need a P."""
    python = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", pattern)
    try:
        return re.compile(python, 0 if case_sensitive else re.IGNORECASE)
    except re.error as exc:
        raise PSError(f'InvalidOperation: The regular expression pattern {pattern} is not valid: {exc}') from None


def coerce_pair(left, right):
    """Convert the right operand to the type of the left one, as PowerShell does."""
    if isinstance(left, bool):
        return left, to_bool(right)
    if is_number(left):
        if is_number(right):
            return left, right
        try:
            return left, to_number(right)
        except PSError:
            return to_string(left), to_string(right)
    if isinstance(left, datetime):
        if isinstance(right, datetime):
            return left, right
        try:
            return left, parse_date(to_string(right))
        except PSError:
            return to_string(left), to_string(right)
    if isinstance(left, str) or left is None:
        if left is None:
            return left, right
        return left, to_string(right)
    return left, right


def equals(left, right, case_sensitive: bool = False) -> bool:
    if left is None or left is MISSING:
        return right is None or right is MISSING
    if right is None or right is MISSING:
        return False
    a, b = coerce_pair(left, right)
    if isinstance(a, str) and isinstance(b, str):
        return a == b if case_sensitive else a.casefold() == b.casefold()
    if isinstance(a, PSObject) or isinstance(b, PSObject):
        return a is b
    return a == b


def ordering(left, right, case_sensitive: bool = False) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return -1
    if right is None:
        return 1
    a, b = coerce_pair(left, right)
    if isinstance(a, str) and isinstance(b, str):
        if not case_sensitive:
            a, b = a.casefold(), b.casefold()
        return (a > b) - (a < b)
    if is_number(a) and is_number(b) or isinstance(a, datetime) and isinstance(b, datetime):
        return (a > b) - (a < b)
    a, b = to_string(a), to_string(b)
    return (a.casefold() > b.casefold()) - (a.casefold() < b.casefold())


def compare_scalar(op: str, left, right, case_sensitive: bool, matches_out: list | None = None) -> bool:
    if op == "eq":
        return equals(left, right, case_sensitive)
    if op == "ne":
        return not equals(left, right, case_sensitive)
    if op in ("gt", "ge", "lt", "le"):
        result = ordering(left, right, case_sensitive)
        return {"gt": result > 0, "ge": result >= 0, "lt": result < 0, "le": result <= 0}[op]
    if op in ("like", "notlike"):
        found = bool(wildcard_regex(to_string(right), case_sensitive).match(to_string(left)))
        return found if op == "like" else not found
    if op in ("match", "notmatch"):
        found = net_regex(to_string(right), case_sensitive).search(to_string(left))
        if found and matches_out is not None:
            matches_out.append(found)
        return bool(found) if op == "match" else not found
    raise PSError(f"InvalidOperation: unknown operator -{op}")


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def unwrap(values: list):
    """Pipeline output used as a value: nothing -> $null, one item -> the item, more -> an array."""
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return list(values)


def net_format(fmt: str, args: list) -> str:
    """The -f operator: {0}, {1,10}, {0:N2}, {0:yyyy-MM-dd}."""
    def replace(match):
        index = int(match.group(1))
        width = match.group(2)
        spec = match.group(3)
        value = args[index] if index < len(args) else None
        text = format_with_spec(value, spec) if spec else to_string(value)
        if width:
            w = int(width)
            text = text.rjust(w) if w > 0 else text.ljust(-w)
        return text

    try:
        text = re.sub(r"\{(\d+)(?:,\s*(-?\d+))?(?::([^}]*))?\}", replace, fmt)
    except IndexError:
        raise PSError("Error formatting a string: Index (zero based) must be greater than or equal to zero "
                      "and less than the size of the argument list.") from None
    return text.replace("{{", "{").replace("}}", "}")


def format_with_spec(value, spec: str) -> str:
    if isinstance(value, datetime):
        return date_format(value, spec)
    if isinstance(value, str) and not spec:
        return value
    match = re.fullmatch(r"([NnFfDdPpXxCcEeGg])(\d*)", spec or "")
    if match and (is_number(value) or isinstance(value, str)):
        kind, digits = match.group(1), match.group(2)
        number = to_number(value) if isinstance(value, str) else value
        if kind in "Nn":
            return f"{number:,.{int(digits or 2)}f}"
        if kind in "Ff":
            return f"{number:.{int(digits or 2)}f}"
        if kind in "Dd":
            return f"{int(number):0{int(digits or 1)}d}"
        if kind in "Pp":
            return f"{number * 100:,.{int(digits or 2)}f} %"
        if kind in "Xx":
            text = f"{int(number):0{int(digits or 1)}x}"
            return text.upper() if kind == "X" else text
        if kind in "Ee":
            return f"{number:.{int(digits or 6)}{kind}}"
        return format_number(number)
    if is_number(value) and spec and re.fullmatch(r"[#0,.]+", spec):
        decimals = len(spec.split(".")[1]) if "." in spec else 0
        text = f"{value:,.{decimals}f}" if "," in spec else f"{value:.{decimals}f}"
        return text
    return to_string(value)


DATE_TOKENS = [
    ("yyyy", "%Y"), ("yy", "%y"), ("MMMM", "%B"), ("MMM", "%b"), ("MM", "%m"), ("M", "{M}"),
    ("dddd", "%A"), ("ddd", "%a"), ("dd", "%d"), ("d", "{d}"), ("HH", "%H"), ("H", "{H}"), ("hh", "%I"),
    ("h", "{h}"), ("mm", "%M"), ("m", "{m}"), ("ss", "%S"), ("s", "{s}"), ("fff", "{fff}"), ("tt", "%p"),
    ("zzz", "+00:00"), ("K", "Z"),
]


def date_format(value: datetime, fmt: str) -> str:
    standard = {"d": "%m/%d/%Y", "D": "%A, %d %B %Y", "t": "%H:%M", "T": "%H:%M:%S", "g": "%m/%d/%Y %H:%M",
                "G": "%m/%d/%Y %H:%M:%S", "s": "%Y-%m-%dT%H:%M:%S", "u": "%Y-%m-%d %H:%M:%SZ",
                "o": "%Y-%m-%dT%H:%M:%S.{fffffff}Z", "O": "%Y-%m-%dT%H:%M:%S.{fffffff}Z", "f": "%A, %d %B %Y %H:%M",
                "F": "%A, %d %B %Y %H:%M:%S"}
    if fmt in standard:
        return value.strftime(standard[fmt]).replace("{fffffff}", f"{value.microsecond * 10:07d}")
    out = []
    i = 0
    while i < len(fmt):
        if fmt[i] in "'\"":
            end = fmt.find(fmt[i], i + 1)
            end = len(fmt) if end == -1 else end
            out.append(fmt[i + 1:end].replace("%", "%%"))
            i = end + 1
            continue
        if fmt[i] == "\\" and i + 1 < len(fmt):
            out.append(fmt[i + 1])
            i += 2
            continue
        for token, replacement in DATE_TOKENS:
            if fmt.startswith(token, i):
                out.append(replacement)
                i += len(token)
                break
        else:
            out.append(fmt[i].replace("%", "%%"))
            i += 1
    text = value.strftime("".join(out))
    return (text.replace("{M}", str(value.month)).replace("{d}", str(value.day)).replace("{H}", str(value.hour))
            .replace("{h}", str(value.hour % 12 or 12)).replace("{m}", str(value.minute))
            .replace("{s}", str(value.second)).replace("{fff}", f"{value.microsecond // 1000:03d}"))


def add(left, right):
    if left is None:
        return right if not isinstance(right, list) else list(right)
    if isinstance(left, list):
        return left + (right if isinstance(right, list) else [right])
    if isinstance(left, str):
        return left + to_string(right)
    if isinstance(left, CIDict):
        if not isinstance(right, CIDict):
            raise PSError("InvalidOperation: A hash table can only be added to another hash table.")
        for key in right:
            if key in left:
                raise PSError(f"InvalidOperation: Item has already been added. Key in dictionary: '{key}'")
        merged = CIDict(left)
        merged.update(right)
        return merged
    if isinstance(left, datetime):
        if isinstance(right, TimeSpan):
            return left + timedelta(seconds=right.seconds)
        raise PSError('InvalidOperation: Method invocation failed because [System.DateTime] does not contain '
                      'a method named "op_Addition".')
    if isinstance(left, TimeSpan) and isinstance(right, TimeSpan):
        return TimeSpan(left.seconds + right.seconds)
    if is_number(left) or isinstance(left, bool):
        result = to_number(left) + to_number(right)
        return result
    raise PSError(f'InvalidOperation: Method invocation failed because [{type_of(left)}] does not contain '
                  f'a method named "op_Addition".')


def arithmetic(op: str, left, right):
    if op == "+":
        return add(left, right)
    if op == "-":
        if isinstance(left, datetime) and isinstance(right, datetime):
            return TimeSpan((left - right).total_seconds())
        if isinstance(left, datetime) and isinstance(right, TimeSpan):
            return left - timedelta(seconds=right.seconds)
        if isinstance(left, TimeSpan) and isinstance(right, TimeSpan):
            return TimeSpan(left.seconds - right.seconds)
        return to_number(left) - to_number(right)
    if op == "*":
        if isinstance(left, str):
            return left * int(to_number(right))
        if isinstance(left, list):
            return left * int(to_number(right))
        return to_number(left) * to_number(right)
    if op in "/%":
        a, b = to_number(left), to_number(right)
        if b == 0:
            raise PSError("RuntimeException: Attempted to divide by zero.")
        if op == "%":
            return a % b if isinstance(a, int) and isinstance(b, int) else math.fmod(a, b)
        result = a / b
        return int(result) if isinstance(a, int) and isinstance(b, int) and result == int(result) else result
    raise PSError(f"InvalidOperation: unknown operator {op}")
