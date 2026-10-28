import pandas as pd
import pytest

from factories import at, event
from soc_lab.log_loader import LogFileError, load_events, validate_events
from soc_lab.models import ALL_COLUMNS

HEADER = ",".join(ALL_COLUMNS)


def _csv(tmp_path, text, name="logs.csv"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _raw(rows):
    return pd.DataFrame([dict(r, event_id=r.get("event_id", f"E{n}")) for n, r in enumerate(rows)]).astype(str)


def test_missing_file_raises_clear_error(tmp_path):
    with pytest.raises(LogFileError, match="not found"):
        load_events(tmp_path / "does_not_exist.csv")


def test_directory_instead_of_file_raises(tmp_path):
    with pytest.raises(LogFileError, match="directory"):
        load_events(tmp_path)


def test_empty_file_returns_no_events_with_warning(tmp_path):
    result = load_events(_csv(tmp_path, ""))
    assert result.events.empty
    assert list(result.events.columns) == list(ALL_COLUMNS)
    assert any("empty" in w for w in result.quality.warnings)


def test_header_only_file_returns_no_events(tmp_path):
    result = load_events(_csv(tmp_path, HEADER + "\n"))
    assert result.events.empty
    assert result.quality.rows_read == 0


def test_empty_bytes_upload_returns_no_events():
    assert load_events(b"   ").events.empty


def test_missing_required_column_raises(tmp_path):
    path = _csv(tmp_path, "event_id,timestamp,username\nE1,2026-10-07T10:00:00Z,a.user\n")
    with pytest.raises(LogFileError, match="source_ip"):
        load_events(path)


def test_optional_columns_may_be_absent():
    raw = pd.DataFrame([{"event_id": "E1", "timestamp": "2026-10-07T10:00:00Z", "username": "a.user",
                         "source_ip": "10.0.0.1", "event_type": "LOGON", "result": "SUCCESS"}])
    events, quality = validate_events(raw)
    assert len(events) == 1
    assert events.loc[0, "hostname"] == ""
    assert any("hostname" in w for w in quality.warnings)


def test_invalid_timestamps_are_rejected_and_reported():
    rows = [event(at(0)), dict(event(at(1)), timestamp="not-a-date"), dict(event(at(2)), timestamp="2026-13-45T25:00:00Z")]
    events, quality = validate_events(_raw(rows))
    assert len(events) == 1
    assert quality.rows_rejected == 2
    assert set(quality.rejected_rows["rejection_reason"]) == {"invalid timestamp"}


def test_incomplete_records_are_rejected_with_field_name():
    rows = [event(at(0)), dict(event(at(1)), username=""), dict(event(at(2)), source_ip="  ")]
    events, quality = validate_events(_raw(rows))
    assert len(events) == 1
    assert sorted(quality.rejected_rows["rejection_reason"]) == [
        "missing required field: source_ip", "missing required field: username"]


def test_unknown_event_type_and_result_are_rejected():
    rows = [dict(event(at(0)), event_type="LOGIN_ATTEMPT"), dict(event(at(1)), result="MAYBE")]
    events, quality = validate_events(_raw(rows))
    assert events.empty
    assert sorted(quality.rejected_rows["rejection_reason"]) == ["unknown event_type", "unknown result"]


def test_exact_duplicate_rows_are_removed_once():
    row = dict(event(at(0)), event_id="E1")
    events, quality = validate_events(_raw([row, row, row]))
    assert len(events) == 1
    assert quality.exact_duplicates_removed == 2


def test_conflicting_duplicate_event_ids_keep_first():
    rows = [dict(event(at(0), username="first"), event_id="E1"), dict(event(at(1), username="second"), event_id="E1")]
    events, quality = validate_events(_raw(rows))
    assert events["username"].tolist() == ["first"]
    assert quality.duplicate_event_ids_removed == 1
    assert "duplicate event_id" in quality.rejected_rows["rejection_reason"].iloc[0]


def test_values_are_normalised_and_sorted_by_time():
    rows = [dict(event(at(5)), username=" A.User ", event_type="logon", result="failure"), event(at(0))]
    events, _ = validate_events(_raw(rows))
    assert events["username"].tolist() == ["a.user", "a.user"]
    assert events["event_type"].unique().tolist() == ["LOGON"]
    assert events["timestamp"].is_monotonic_increasing
    assert str(events["timestamp"].dt.tz) == "UTC"


def test_load_from_csv_file_round_trip(tmp_path):
    rows = [dict(event(at(n)), event_id=f"E{n}") for n in range(3)]
    path = tmp_path / "logs.csv"
    pd.DataFrame(rows)[list(ALL_COLUMNS)].to_csv(path, index=False)
    result = load_events(path)
    assert result.quality.rows_read == 3
    assert result.quality.rows_accepted == 3
