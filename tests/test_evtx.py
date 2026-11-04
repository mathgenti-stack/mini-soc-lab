"""Binary Windows event logs (.evtx): decoding, conversion, and damaged input."""

import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evtx_writer import CHUNK_HEADER_SIZE, CHUNK_SIZE, FILE_HEADER_SIZE, build_evtx, events_from_xml
from soc_lab.cli import main
from soc_lab.evtx import EvtxError, _filetime, _sid, is_evtx, read_evtx
from soc_lab.parsers import ConversionError, convert

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "data" / "examples"
XML_EXAMPLE = EXAMPLES / "windows_security.xml"
EVTX_EXAMPLE = EXAMPLES / "windows_security.evtx"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def xml_events():
    return events_from_xml(XML_EXAMPLE.read_text(encoding="utf-8"))


def canonical(element):
    """Element tree as plain data, ignoring namespace prefixes and GUID letter case."""
    tag = element.tag.rsplit("}", 1)[-1]
    attributes = sorted((k, v.lower()) for k, v in element.attrib.items())
    return tag, attributes, (element.text or "").strip(), [canonical(child) for child in element]


def test_example_file_matches_the_xml_example():
    """The committed .evtx holds the same events as the XML example, so it converts to identical lab events."""
    from_xml = convert(XML_EXAMPLE.read_bytes(), "auto", XML_EXAMPLE.name)
    from_evtx = convert(EVTX_EXAMPLE.read_bytes(), "auto", EVTX_EXAMPLE.name)
    assert from_evtx.fmt == "windows_evtx"
    assert from_evtx.events.equals(from_xml.events)
    assert (from_evtx.records_read, dict(from_evtx.skipped)) == (from_xml.records_read, dict(from_xml.skipped))


def test_example_file_is_up_to_date():
    assert EVTX_EXAMPLE.read_bytes() == build_evtx(xml_events()), \
        "regenerate with: python tests/evtx_writer.py data/examples/windows_security.xml data/examples/windows_security.evtx"


def test_every_record_renders_back_to_the_original_xml():
    content = read_evtx(build_evtx(xml_events()))
    assert (content.bad_records, content.bad_chunks) == (0, 0)
    assert [canonical(ET.fromstring(r)) for r in content.records] == [canonical(e) for e in xml_events()]


def test_records_spread_over_several_chunks():
    """Names and templates are stored per chunk; every chunk must be decoded on its own."""
    data = build_evtx(xml_events(), records_per_chunk=4)
    assert len(data) == FILE_HEADER_SIZE + 5 * CHUNK_SIZE  # 17 events, 4 per chunk
    content = read_evtx(data)
    assert len(content.records) == 17 and content.bad_records == 0
    assert convert(data, "windows_evtx").events.equals(convert(EVTX_EXAMPLE.read_bytes()).events)


def test_value_formatting():
    assert _filetime(0) == "1601-01-01T00:00:00.0000000Z"
    unix_epoch = 116_444_736_000_000_000  # 1970-01-01 in FILETIME ticks
    moment = datetime(2026, 10, 21, 8, 1, 12, tzinfo=timezone.utc)
    assert _filetime(unix_epoch + int(moment.timestamp()) * 10_000_000 + 1) == "2026-10-21T08:01:12.0000001Z"
    sid = bytes([1, 2]) + (5).to_bytes(6, "big") + struct.pack("<2I", 32, 544)
    assert _sid(sid) == "S-1-5-32-544"


def test_detection_by_signature_and_name():
    data = EVTX_EXAMPLE.read_bytes()
    assert is_evtx(data) and not is_evtx(XML_EXAMPLE.read_bytes())
    assert convert(data).fmt == "windows_evtx"  # from the contents alone
    with pytest.raises(ConversionError):  # named .evtx but not one
        convert(b"<Events/>", "auto", "renamed.evtx")


def test_not_an_evtx_file():
    with pytest.raises(EvtxError):
        read_evtx(b"hello")
    with pytest.raises(EvtxError):
        read_evtx(b"ElfFile\x00" + b"\x00" * 100)  # shorter than the header


def test_damaged_chunk_is_counted_and_the_rest_is_read():
    data = bytearray(build_evtx(xml_events(), records_per_chunk=9))  # two chunks: 9 + 8 events
    data[FILE_HEADER_SIZE:FILE_HEADER_SIZE + 8] = b"XXXXXXXX"  # break the first chunk's signature
    result = convert(bytes(data), "windows_evtx")
    assert result.skipped["damaged_chunk"] == 1
    assert read_evtx(bytes(data)).records and len(read_evtx(bytes(data)).records) == 8


def test_damaged_record_is_counted_and_others_survive():
    data = bytearray(build_evtx(xml_events()))
    first = FILE_HEADER_SIZE + CHUNK_HEADER_SIZE
    second = first + struct.unpack_from("<I", data, first + 4)[0]
    # Point the second record's template outside the chunk; its size fields stay valid, so the chunk can
    # still be walked. Offset: record header (24) + fragment header (4) + template token, unknown, id (6).
    struct.pack_into("<I", data, second + 24 + 4 + 6, 0xFFFFFF00)
    content = read_evtx(bytes(data))
    assert content.bad_records == 1 and len(content.records) == 16
    result = convert(bytes(data), "windows_evtx")
    assert result.skipped["invalid_record"] == 1 and result.records_read == 17


def test_truncated_file_does_not_crash():
    data = build_evtx(xml_events())
    for cut in (FILE_HEADER_SIZE + 100, FILE_HEADER_SIZE + CHUNK_HEADER_SIZE + 300, len(data) - 60000):
        content = read_evtx(data[:cut])
        assert len(content.records) < 17 and content.bad_records + content.bad_chunks >= 1


def test_random_corruption_never_raises():
    """Fuzzing: flipped bytes may lose records, but must never crash the reader."""
    import random
    original = build_evtx(xml_events())
    rng = random.Random(7)
    for _ in range(200):
        data = bytearray(original)
        for _ in range(rng.randint(1, 20)):
            data[rng.randrange(FILE_HEADER_SIZE, FILE_HEADER_SIZE + 6000)] = rng.randrange(256)
        content = read_evtx(bytes(data))
        for record in content.records:
            ET.fromstring(record)  # whatever is returned is well-formed XML


def test_names_that_are_not_xml_are_refused():
    """A crafted name must not be able to inject markup (for example a DOCTYPE) into the rendered XML."""
    events = [ET.fromstring(f'<Event xmlns="{NS}"><System><EventID>4624</EventID>'
                            f'<EventRecordID>1</EventRecordID></System></Event>')]
    data = bytearray(build_evtx(events))
    name = "EventID".encode("utf-16-le")
    at = data.index(name)
    data[at:at + len(name)] = "Ev<!DOC".encode("utf-16-le")
    content = read_evtx(bytes(data))
    assert content.records == [] and content.bad_records == 1


def test_cli_analyses_an_evtx_file(capsys):
    assert main(["analyse", "--input", str(EVTX_EXAMPLE)]) == 0
    output = capsys.readouterr().out
    assert "Converted from windows_evtx: 17 records read, 14 events, 3 skipped" in output
    assert "R005" in output
