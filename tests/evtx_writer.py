"""A minimal .evtx writer, used only to build test files and data/examples/windows_security.evtx.

It turns <Event> XML (as Event Viewer exports it) into a binary event log the way Windows stores one:
each event becomes a BinXML template instance. The template holds the element structure and the fixed
text; the event's own values (time, record id, user name, ...) go into a typed substitution array.
Names and templates are written in full on first use in a chunk and referenced by offset afterwards,
so both paths of the reader are exercised.

Regenerate the example file with:
    python tests/evtx_writer.py data/examples/windows_security.xml data/examples/windows_security.evtx
"""

from __future__ import annotations

import struct
import sys
import uuid
import xml.etree.ElementTree as ET
import zlib
from datetime import datetime, timezone
from pathlib import Path

FILE_HEADER_SIZE, CHUNK_SIZE, CHUNK_HEADER_SIZE = 4096, 65536, 512

# Value types (see soc_lab/evtx.py).
STRING, UINT8, UINT16, UINT32, UINT64, GUID, FILETIME, SID, HEX32, HEX64 = (
    0x01, 0x04, 0x06, 0x08, 0x0A, 0x0F, 0x11, 0x13, 0x14, 0x15)

# Which values are typed (not plain strings), keyed by element name or "Element@attribute".
SYSTEM_TYPES = {"EventID": UINT16, "Version": UINT8, "Level": UINT8, "Task": UINT16, "Opcode": UINT8,
                "Keywords": HEX64, "TimeCreated@SystemTime": FILETIME, "EventRecordID": UINT64,
                "Provider@Guid": GUID, "Execution@ProcessID": UINT32, "Execution@ThreadID": UINT32,
                "Security@UserID": SID}
DATA_TYPES = {"SubjectUserSid": SID, "TargetUserSid": SID, "Status": HEX32, "SubStatus": HEX32, "LogonType": UINT32}
# Text kept in the template itself (the same for every event), as Windows does for these.
LITERAL = {"Channel", "Provider@Name", "Data@Name"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _encode(value_type: int, text: str) -> bytes:
    if value_type == STRING:
        return text.encode("utf-16-le")
    if value_type in (UINT8, UINT16, UINT32, UINT64):
        return struct.pack({UINT8: "<B", UINT16: "<H", UINT32: "<I", UINT64: "<Q"}[value_type], int(text))
    if value_type in (HEX32, HEX64):
        return struct.pack("<I" if value_type == HEX32 else "<Q", int(text, 16))
    if value_type == GUID:
        return uuid.UUID(text.strip("{}")).bytes_le
    if value_type == FILETIME:
        whole, _, fraction = text.rstrip("Z").partition(".")
        moment = datetime.fromisoformat(whole).replace(tzinfo=timezone.utc)
        seconds = int((moment - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds())
        return struct.pack("<Q", seconds * 10_000_000 + int((fraction + "0000000")[:7]))
    if value_type == SID:
        parts = text.split("-")
        revision, authority, subs = int(parts[1]), int(parts[2]), [int(p) for p in parts[3:]]
        return bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)
    raise ValueError(value_type)


class _ChunkWriter:
    def __init__(self) -> None:
        self.buf = bytearray(CHUNK_HEADER_SIZE)
        self.names: dict[str, int] = {}
        self.templates: dict[tuple, int] = {}
        self.records: list[int] = []  # record ids
        self.last_record_offset = 0

    def fits(self, size_hint: int) -> bool:
        return len(self.buf) + size_hint < CHUNK_SIZE

    def _w(self, data: bytes) -> None:
        self.buf += data

    def _name(self, name: str) -> None:
        if name in self.names:
            self._w(struct.pack("<I", self.names[name]))
            return
        offset = len(self.buf) + 4
        self.names[name] = offset
        self._w(struct.pack("<I", offset))
        self._w(struct.pack("<IHH", 0, zlib.crc32(name.encode()) & 0xFFFF, len(name)))
        self._w(name.encode("utf-16-le") + b"\x00\x00")

    # -- template structure --
    def _template_shape(self, element: ET.Element, values: list, path: str = "") -> tuple:
        """Describe the element tree; values that vary per event are appended to `values`."""
        name = _local(element.tag)
        in_data = name == "Data"
        attributes = []
        if path == "":  # the Event element carries the namespace as a plain attribute
            namespace = element.tag[1:].split("}")[0] if element.tag.startswith("{") else ""
            if namespace:
                attributes.append(("xmlns", ("lit", namespace)))
        for attribute, text in element.attrib.items():
            key = f"{name}@{attribute}"
            if key in LITERAL:
                attributes.append((attribute, ("lit", text)))
            else:
                values.append((SYSTEM_TYPES.get(key, STRING), text))
                attributes.append((attribute, ("sub", len(values) - 1, False)))
        children = [self._template_shape(child, values, f"{path}/{name}") for child in element]
        text = (element.text or "").strip()
        content = None
        if name in LITERAL and text:
            content = ("lit", text)
        elif not children and (text or in_data):
            value_type = DATA_TYPES.get(element.get("Name", ""), STRING) if in_data else SYSTEM_TYPES.get(name, STRING)
            values.append((value_type if text else 0x00, text))
            content = ("sub", len(values) - 1, in_data)  # Data values are optional substitutions
        return (name, tuple(attributes), content, tuple(children))

    def _element(self, shape: tuple) -> None:
        name, attributes, content, children = shape
        self._w(bytes([0x41 if attributes else 0x01]) + struct.pack("<hI", -1, 0))  # dependency id, data size
        self._name(name)
        if attributes:
            self._w(struct.pack("<I", 0))  # attribute list size (not used by the reader)
            for index, (attribute, value) in enumerate(attributes):
                self._w(bytes([0x46 if index < len(attributes) - 1 else 0x06]))
                self._name(attribute)
                self._value_token(value)
        if content is None and not children:
            self._w(b"\x03")
            return
        self._w(b"\x02")
        if content is not None:
            self._value_token(content)
        for child in children:
            self._element(child)
        self._w(b"\x04")

    def _value_token(self, value: tuple) -> None:
        if value[0] == "lit":
            self._w(b"\x05\x01" + struct.pack("<H", len(value[1])) + value[1].encode("utf-16-le"))
        else:
            _, index, optional = value
            self._w(bytes([0x0E if optional else 0x0D]) + struct.pack("<HB", index, 0))

    # -- records --
    def add(self, element: ET.Element, record_id: int, written: int) -> None:
        start = len(self.buf)
        self._w(b"**\x00\x00" + struct.pack("<IQQ", 0, record_id, written))
        self._w(b"\x0f\x01\x01\x00")  # fragment header
        values: list = []
        shape = self._template_shape(element, values)
        self._w(b"\x0c\x01" + struct.pack("<I", zlib.crc32(repr(shape).encode())))
        if shape in self.templates:
            self._w(struct.pack("<I", self.templates[shape]))
        else:
            definition = len(self.buf) + 4
            self.templates[shape] = definition
            self._w(struct.pack("<I", definition))
            self._w(struct.pack("<I", 0) + uuid.uuid5(uuid.NAMESPACE_OID, repr(shape)).bytes_le)
            size_at = len(self.buf)
            self._w(struct.pack("<I", 0))
            self._w(b"\x0f\x01\x01\x00")
            self._element(shape)
            self._w(b"\x00")  # end of fragment
            struct.pack_into("<I", self.buf, size_at, len(self.buf) - size_at - 4)
        encoded = [b"" if value_type == 0x00 else _encode(value_type, text) for value_type, text in values]
        self._w(struct.pack("<I", len(values)))
        for (value_type, _), data in zip(values, encoded):
            self._w(struct.pack("<HBB", len(data), value_type, 0))
        for data in encoded:
            self._w(data)
        size = len(self.buf) - start + 4
        self._w(struct.pack("<I", size))
        struct.pack_into("<I", self.buf, start + 4, size)
        self.records.append(record_id)
        self.last_record_offset = start

    def finish(self) -> bytes:
        first, last = (self.records[0], self.records[-1]) if self.records else (0, 0)
        # signature, first/last record number, first/last record id, header size, last record offset,
        # free space offset, records checksum; then the header checksum over bytes 0-120 and 128-512.
        struct.pack_into("<8sQQQQIIII", self.buf, 0, b"ElfChnk\x00", first, last, first, last, 128,
                         self.last_record_offset, len(self.buf), zlib.crc32(bytes(self.buf[CHUNK_HEADER_SIZE:])))
        struct.pack_into("<I", self.buf, 124, zlib.crc32(bytes(self.buf[:120]) + bytes(self.buf[128:512])))
        return bytes(self.buf) + b"\x00" * (CHUNK_SIZE - len(self.buf))


def build_evtx(events: list[ET.Element], records_per_chunk: int = 1000) -> bytes:
    """Write <Event> elements as a binary .evtx file."""
    chunks: list[bytes] = []
    writer = _ChunkWriter()
    next_record = 1
    for element in events:
        record_id = next(int(e.text) for e in element.iter() if _local(e.tag) == "EventRecordID")
        if len(writer.records) >= records_per_chunk or not writer.fits(8192):
            chunks.append(writer.finish())
            writer = _ChunkWriter()
        writer.add(element, record_id, 0)
        next_record = record_id + 1
    if writer.records:
        chunks.append(writer.finish())
    header = bytearray(FILE_HEADER_SIZE)
    struct.pack_into("<8sQQQIHHHH", header, 0, b"ElfFile\x00", 0, max(len(chunks) - 1, 0), next_record,
                     128, 1, 3, FILE_HEADER_SIZE, len(chunks))
    struct.pack_into("<I", header, 124, zlib.crc32(bytes(header[:120])))
    return bytes(header) + b"".join(chunks)


def events_from_xml(text: str) -> list[ET.Element]:
    root = ET.fromstring(text.split("?>", 1)[-1] if text.lstrip().startswith("<?xml") else text)
    return [element for element in root.iter() if _local(element.tag) == "Event"]


if __name__ == "__main__":
    source, target = Path(sys.argv[1]), Path(sys.argv[2])
    target.write_bytes(build_evtx(events_from_xml(source.read_text(encoding="utf-8"))))
    print(f"Wrote {target}")
