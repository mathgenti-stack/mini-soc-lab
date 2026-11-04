"""Read binary Windows event log files (.evtx) with the Python standard library only.

An .evtx file is a 4 KiB file header followed by 64 KiB chunks. Each chunk holds event records, and each
record holds the event as "binary XML" (BinXML): a token stream that refers to element names and reusable
templates stored elsewhere in the same chunk, plus an array of typed values that fill the template's
placeholders. This module turns every record back into the same <Event> XML text that Event Viewer
would export, so the existing Windows XML conversion (parsers.py) is reused unchanged.

Only what the lab needs is implemented: it reads the records that are in the file, it does not recover
deleted records or records from the unused part of a chunk, and it does not verify checksums
(a damaged checksum does not stop a readable record from being read).
Anything that cannot be decoded is counted, never guessed: a damaged record or chunk does not stop the rest.

Format reference: Joachim Metz, "Windows XML Event Log (EVTX) format" (libyal/libevtx documentation).
"""

from __future__ import annotations

import re
import struct
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape, quoteattr

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"**\x00\x00"
FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
RECORD_HEADER_SIZE = 24  # signature, size, record id, written time
MAX_DEPTH = 32  # nested elements / templates; real events need far fewer
MAX_SUBSTITUTIONS = 4096

# BinXML tokens. 0x40 is a flag ("has attributes" / "more follows") on some of them.
T_EOF, T_OPEN, T_CLOSE_START, T_CLOSE_EMPTY, T_END = 0x00, 0x01, 0x02, 0x03, 0x04
T_VALUE, T_ATTRIBUTE, T_CDATA, T_CHARREF, T_ENTITYREF = 0x05, 0x06, 0x07, 0x08, 0x09
T_PI_TARGET, T_PI_DATA, T_TEMPLATE, T_SUB, T_OPTIONAL_SUB, T_FRAGMENT = 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
_VALUE_TOKENS = {T_VALUE, T_SUB, T_OPTIONAL_SUB, T_CHARREF, T_ENTITYREF}

# Value types used in substitution arrays.
V_NULL, V_STRING, V_ANSI, V_BINXML = 0x00, 0x01, 0x02, 0x21
_FIXED = {0x03: "<b", 0x04: "<B", 0x05: "<h", 0x06: "<H", 0x07: "<i", 0x08: "<I", 0x09: "<q", 0x0A: "<Q",
          0x0B: "<f", 0x0C: "<d"}
_XML_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-:]*$")  # event schemas use ASCII names only


class EvtxError(ValueError):
    """The data is not an .evtx file, or one record cannot be decoded."""


@dataclass
class EvtxContent:
    records: list[str] = field(default_factory=list)  # one <Event> XML document per readable record
    bad_records: int = 0  # records that are present but cannot be decoded
    bad_chunks: int = 0  # chunks with a damaged header; their records cannot be reached at all


def is_evtx(data: bytes) -> bool:
    return data[:8] == FILE_MAGIC


def read_evtx(data: bytes) -> EvtxContent:
    """Decode every record of an .evtx file into XML text."""
    if not is_evtx(data):
        raise EvtxError("not an .evtx file (the 'ElfFile' signature is missing)")
    if len(data) < FILE_HEADER_SIZE:
        raise EvtxError("the file is shorter than the 4 KiB .evtx header")
    content = EvtxContent()
    for start in range(FILE_HEADER_SIZE, len(data), CHUNK_SIZE):
        chunk = data[start:start + CHUNK_SIZE]
        if chunk[:8] != CHUNK_MAGIC or len(chunk) < CHUNK_HEADER_SIZE:
            if chunk.strip(b"\x00"):  # all zeros is unused, preallocated space - not damage
                content.bad_chunks += 1
            continue
        _Chunk(chunk).read_records(content)
    return content


# ---------------------------------------------------------------------------
# Decoded BinXML is held as a small tree of tuples before rendering:
#   ("text", str)                       literal character data
#   ("raw", str)                        XML that is already rendered (char/entity references)
#   ("sub", index, optional)            placeholder filled from the substitution array
#   ("elem", name, attributes, children, has_content)
#   ("xml", str)                        a template instance, already rendered
# attributes is a list of (name, [value nodes]).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Value:
    text: str | None  # None = no value (NULL)
    is_xml: bool = False  # nested BinXML, rendered as XML rather than escaped text
    items: tuple[str, ...] | None = None  # array values: an element holding one is repeated per item


class _Chunk:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.templates: dict[int, list] = {}  # definition offset -> node tree (templates are per chunk)

    # -- low-level readers (all offsets are relative to the start of the chunk) --
    def _u8(self, pos: int) -> int:
        self._need(pos, 1)
        return self.data[pos]

    def _u16(self, pos: int) -> int:
        self._need(pos, 2)
        return struct.unpack_from("<H", self.data, pos)[0]

    def _u32(self, pos: int) -> int:
        self._need(pos, 4)
        return struct.unpack_from("<I", self.data, pos)[0]

    def _need(self, pos: int, size: int) -> None:
        if pos < 0 or pos + size > len(self.data):
            raise EvtxError(f"offset {pos} is outside the chunk")

    def _utf16(self, pos: int, chars: int) -> str:
        self._need(pos, 2 * chars)
        return self.data[pos:pos + 2 * chars].decode("utf-16-le")

    # -- records --
    def read_records(self, content: EvtxContent) -> None:
        free = self._u32(48)  # "free space offset": where unused space starts
        end = free if CHUNK_HEADER_SIZE <= free <= len(self.data) else len(self.data)
        pos = CHUNK_HEADER_SIZE
        while pos < end:
            size = self._u32(pos + 4) if pos + 8 <= end else 0
            if (self.data[pos:pos + 4] != RECORD_MAGIC or size < RECORD_HEADER_SIZE + 4 or pos + size > end
                    or self._u32(pos + size - 4) != size):
                if self.data[pos:end].strip(b"\x00"):
                    content.bad_records += 1  # without a valid size the rest of the chunk cannot be walked
                break
            try:
                record = self.render_fragment(pos + RECORD_HEADER_SIZE, pos + size - 4)
                ET.fromstring(record)  # guarantee: every record returned is well-formed XML
                content.records.append(record)
            except (EvtxError, ET.ParseError, struct.error, IndexError, UnicodeDecodeError, ValueError,
                    OverflowError):
                content.bad_records += 1
            pos += size
        if free > len(self.data) and pos >= end:
            content.bad_records += 1  # the chunk was cut short (truncated file): its last records are lost

    def render_fragment(self, pos: int, end: int, depth: int = 0) -> str:
        nodes, _ = self._parse_fragment(pos, end, depth)
        return _render(nodes, [])

    # -- BinXML parsing --
    def _parse_fragment(self, pos: int, end: int, depth: int) -> tuple[list, int]:
        if depth > MAX_DEPTH:
            raise EvtxError("BinXML is nested too deeply")
        nodes: list = []
        while pos < end:
            token = self._u8(pos)
            kind = token & 0x0F if token & 0x40 else token
            if kind == T_EOF:
                return nodes, pos + 1
            if kind == T_FRAGMENT:
                pos += 4  # token, major version, minor version, flags
            elif kind == T_OPEN:
                node, pos = self._parse_element(pos, depth + 1)
                nodes.append(node)
            elif kind == T_TEMPLATE:
                node, pos = self._parse_template_instance(pos, depth + 1)
                nodes.append(node)
            else:
                raise EvtxError(f"unexpected BinXML token 0x{token:02x} at offset {pos}")
        return nodes, pos

    def _name(self, pos: int) -> tuple[str, int]:
        """Read a 4-byte name offset at `pos`. If the name is stored right there (first use), skip over it."""
        offset = self._u32(pos)
        pos += 4
        chars = self._u16(offset + 6)
        name = self._utf16(offset + 8, chars)
        if not _XML_NAME.match(name):
            raise EvtxError(f"invalid element or attribute name {name!r}")
        if offset == pos:  # defined inline: next-offset (4), hash (2), length (2), UTF-16 text, NUL (2)
            pos = offset + 8 + 2 * chars + 2
        return name, pos

    def _parse_element(self, pos: int, depth: int) -> tuple[tuple, int]:
        if depth > MAX_DEPTH:
            raise EvtxError("BinXML is nested too deeply")
        has_attributes = bool(self._u8(pos) & 0x40)
        pos += 1 + 2 + 4  # token, dependency id, data size
        name, pos = self._name(pos)
        attributes = []
        if has_attributes:
            pos += 4  # attribute list size
            while True:
                token = self._u8(pos)
                if token & 0x0F != T_ATTRIBUTE:
                    raise EvtxError(f"expected an attribute at offset {pos}")
                attribute, pos = self._name(pos + 1)
                values, pos = self._parse_values(pos)
                attributes.append((attribute, values))
                if not token & 0x40:  # 0x46 = another attribute follows
                    break
        token = self._u8(pos)
        if token == T_CLOSE_EMPTY:
            return ("elem", name, attributes, [], False), pos + 1
        if token != T_CLOSE_START:
            raise EvtxError(f"expected the end of a start tag at offset {pos}")
        pos += 1
        children: list = []
        while True:
            token = self._u8(pos)
            kind = token & 0x0F if token & 0x40 else token
            if kind == T_END:
                return ("elem", name, attributes, children, True), pos + 1
            if kind == T_OPEN:
                child, pos = self._parse_element(pos, depth + 1)
                children.append(child)
            elif kind == T_TEMPLATE:
                child, pos = self._parse_template_instance(pos, depth + 1)
                children.append(child)
            elif kind == T_CDATA:
                chars = self._u16(pos + 1)
                children.append(("text", self._utf16(pos + 3, chars)))
                pos += 3 + 2 * chars
            elif kind in (T_PI_TARGET, T_PI_DATA):
                pos = self._skip_processing_instruction(pos)
            elif kind in _VALUE_TOKENS:
                values, pos = self._parse_values(pos)
                children.extend(values)
            else:
                raise EvtxError(f"unexpected BinXML token 0x{token:02x} at offset {pos}")

    def _parse_values(self, pos: int) -> tuple[list, int]:
        """Read consecutive value tokens (literal text, substitutions, character or entity references)."""
        nodes: list = []
        while True:
            token = self._u8(pos)
            kind = token & 0x0F if token & 0x40 else token
            if kind == T_VALUE:
                value_type = self._u8(pos + 1)
                if value_type != V_STRING:
                    raise EvtxError(f"unsupported literal value type 0x{value_type:02x}")
                chars = self._u16(pos + 2)
                nodes.append(("text", self._utf16(pos + 4, chars)))
                pos += 4 + 2 * chars
            elif kind in (T_SUB, T_OPTIONAL_SUB):
                nodes.append(("sub", self._u16(pos + 1), kind == T_OPTIONAL_SUB))
                pos += 4  # token, index (2), value type (1)
            elif kind == T_CHARREF:
                nodes.append(("raw", f"&#{self._u16(pos + 1)};"))
                pos += 3
            elif kind == T_ENTITYREF:
                entity, pos = self._name(pos + 1)
                nodes.append(("raw", f"&{entity};"))
            else:
                return nodes, pos

    def _skip_processing_instruction(self, pos: int) -> int:
        if self._u8(pos) == T_PI_TARGET:
            _, pos = self._name(pos + 1)
            return pos
        return pos + 3 + 2 * self._u16(pos + 1)

    def _parse_template_instance(self, pos: int, depth: int) -> tuple[tuple, int]:
        # token (1), unknown (1), template id (4), definition offset (4)
        definition = self._u32(pos + 6)
        pos += 10
        definition_size = self._u32(definition + 20)  # next-definition offset (4), GUID (16), data size (4)
        if definition == pos:  # defined inline on first use: skip over the definition
            pos = definition + 24 + definition_size
        template = self._template(definition, definition_size, depth)

        count = self._u32(pos)
        if count > MAX_SUBSTITUTIONS:
            raise EvtxError(f"implausible number of substitution values ({count})")
        pos += 4
        descriptors = [(self._u16(pos + 4 * i), self._u8(pos + 4 * i + 2)) for i in range(count)]
        pos += 4 * count
        values = []
        for size, value_type in descriptors:
            self._need(pos, size)
            values.append(self._value(value_type, pos, size, depth))
            pos += size
        return ("xml", _render(template, values)), pos

    def _template(self, definition: int, size: int, depth: int) -> list:
        if definition not in self.templates:
            nodes, _ = self._parse_fragment(definition + 24, definition + 24 + size, depth)
            self.templates[definition] = nodes
        return self.templates[definition]

    def _value(self, value_type: int, pos: int, size: int, depth: int) -> _Value:
        raw = self.data[pos:pos + size]
        if value_type == V_NULL or (size == 0 and value_type != V_BINXML):
            return _Value(None)
        if value_type == V_BINXML:
            return _Value(self.render_fragment(pos, pos + size, depth + 1), is_xml=True)
        if value_type & 0x80:  # array of the base type
            items = tuple(_array(value_type & 0x7F, raw))
            return _Value(", ".join(items), items=items)
        return _Value(_format_value(value_type, raw))


def _format_value(value_type: int, raw: bytes) -> str:
    if value_type in (V_STRING, V_ANSI):  # a string ends at its first NUL, as Windows renders it
        return raw.decode("utf-16-le" if value_type == V_STRING else "latin-1").split("\x00", 1)[0]
    if value_type in _FIXED:
        number = struct.unpack(_FIXED[value_type], raw[:struct.calcsize(_FIXED[value_type])])[0]
        return repr(number) if isinstance(number, float) else str(number)
    if value_type == 0x0D:  # Boolean (32-bit)
        return "true" if int.from_bytes(raw, "little") else "false"
    if value_type == 0x0E:  # Binary
        return raw.hex().upper()
    if value_type == 0x0F:  # GUID
        return "{" + str(uuid.UUID(bytes_le=raw[:16])).upper() + "}"
    if value_type in (0x10, 0x14, 0x15):  # SizeT, HexInt32, HexInt64
        return hex(int.from_bytes(raw, "little"))
    if value_type == 0x11:
        return _filetime(int.from_bytes(raw[:8], "little"))
    if value_type == 0x12:
        return _systemtime(raw)
    if value_type == 0x13:
        return _sid(raw)
    return raw.hex().upper()  # types the lab never reads (handles, EvtXml): kept visible, not guessed


def _array(value_type: int, raw: bytes) -> list[str]:
    if value_type in (V_STRING, V_ANSI):  # NUL-terminated strings; empty items are kept, as Windows does
        text = raw.decode("utf-16-le" if value_type == V_STRING else "latin-1")
        return (text[:-1] if text.endswith("\x00") else text).split("\x00")
    width = {0x0D: 4, 0x0F: 16, 0x10: 8 if len(raw) % 8 == 0 else 4, 0x11: 8, 0x12: 16, 0x14: 4, 0x15: 8}.get(
        value_type, struct.calcsize(_FIXED[value_type]) if value_type in _FIXED else 0)
    if not width or len(raw) % width:
        return [raw.hex().upper()]
    return [_format_value(value_type, raw[i:i + width]) for i in range(0, len(raw), width)]


def _filetime(ticks: int) -> str:
    """FILETIME (100 ns ticks since 1601-01-01 UTC) in the form Event Viewer uses: 2026-10-21T08:01:12.0000001Z."""
    moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=ticks // 10_000_000)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{ticks % 10_000_000:07d}Z"


def _systemtime(raw: bytes) -> str:
    year, month, _weekday, day, hour, minute, second, millis = struct.unpack("<8H", raw[:16])
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.{millis:03d}0000Z"


def _sid(raw: bytes) -> str:
    revision, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    parts = struct.unpack(f"<{count}I", raw[8:8 + 4 * count])
    return "-".join(["S", str(revision), str(authority), *map(str, parts)])


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
_INVALID_XML_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")


def _text(value: str) -> str:
    """Escape text for XML, dropping control characters that XML 1.0 cannot hold."""
    return escape(_INVALID_XML_CHARS.sub("", value))


def _render(nodes: list, values: list[_Value]) -> str:
    return "".join(_render_node(node, values) for node in nodes)


def _render_node(node: tuple, values: list[_Value]) -> str:
    kind = node[0]
    if kind == "text":
        return _text(node[1])
    if kind in ("raw", "xml"):
        return node[1]
    if kind == "sub":
        value = values[node[1]] if node[1] < len(values) else _Value(None)
        if value.text is None:
            return ""
        return value.text if value.is_xml else _text(value.text)
    _, name, attributes, children, _has_content = node
    if children and all(part[0] == "sub" and part[2] and _is_null(part, values) for part in children):
        return ""  # content is only optional substitutions with no value: Windows leaves the element out
    array = values[children[0][1]].items if (len(children) == 1 and children[0][0] == "sub"
                                             and children[0][1] < len(values)) else None
    if array is not None:  # an array value fills one element per item
        return "".join(_render_node(("elem", name, attributes, [("text", item)] if item else [], True), values)
                       for item in array)
    rendered_attributes = ""
    for attribute, parts in attributes:
        if all(part[0] == "sub" and _is_null(part, values) for part in parts) and any(p[2] for p in parts):
            continue  # an optional substitution with no value: Windows leaves the attribute out
        text = _INVALID_XML_CHARS.sub("", "".join(_attribute_text(part, values) for part in parts))
        rendered_attributes += f" {attribute}={quoteattr(text)}"
    inner = _render(children, values)
    return f"<{name}{rendered_attributes}>{inner}</{name}>" if inner else f"<{name}{rendered_attributes}/>"


def _is_null(part: tuple, values: list[_Value]) -> bool:
    return part[1] >= len(values) or values[part[1]].text is None


def _attribute_text(part: tuple, values: list[_Value]) -> str:
    if part[0] == "sub":
        return "" if _is_null(part, values) else values[part[1]].text
    if part[0] == "raw":  # character reference inside an attribute: resolve it to the character
        match = re.fullmatch(r"&#(\d+);", part[1])
        return chr(int(match[1])) if match else part[1]
    return part[1]
