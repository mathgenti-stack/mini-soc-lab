"""Read authentication logs from CSV and validate them before analysis.

Bad input is never silently "fixed": rows that cannot be trusted are rejected,
counted and kept aside with a reason, so the analyst can see what was excluded.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from .i18n import Msg
from .models import ALL_COLUMNS, OPTIONAL_COLUMNS, REQUIRED_COLUMNS, VALID_EVENT_TYPES, VALID_RESULTS

# Rejection reasons are stored in the data as fixed English codes; these keys translate them for display.
MISSING_FIELD_PREFIX = "missing required field: "
REJECTION_REASON_KEYS = {
    "invalid timestamp": "rejection.invalid_timestamp",
    "unknown event_type": "rejection.unknown_event_type",
    "unknown result": "rejection.unknown_result",
    "duplicate event_id with different content": "rejection.duplicate_event_id",
}


class LogFileError(Exception):
    """Raised when a log source cannot be read at all (missing file, wrong format, missing columns)."""


@dataclass
class DataQualityReport:
    source: str
    rows_read: int = 0
    rows_accepted: int = 0
    exact_duplicates_removed: int = 0
    duplicate_event_ids_removed: int = 0
    rejected_rows: pd.DataFrame = field(default_factory=pd.DataFrame)
    warnings: list[str] = field(default_factory=list)

    @property
    def rows_rejected(self) -> int:
        return len(self.rejected_rows)

    def rejection_summary(self) -> pd.DataFrame:
        if self.rejected_rows.empty:
            return pd.DataFrame(columns=["rejection_reason", "rows"])
        counts = self.rejected_rows["rejection_reason"].value_counts()
        return counts.rename_axis("rejection_reason").reset_index(name="rows")


def rejection_reason_msg(reason: str):
    """Translatable form of a stored rejection reason (unknown reasons are returned unchanged)."""
    if reason.startswith(MISSING_FIELD_PREFIX):
        return Msg("rejection.missing_field", column=reason[len(MISSING_FIELD_PREFIX):])
    return Msg(REJECTION_REASON_KEYS[reason]) if reason in REJECTION_REASON_KEYS else reason


@dataclass
class LoadResult:
    events: pd.DataFrame
    quality: DataQualityReport


def empty_events_frame() -> pd.DataFrame:
    """An empty DataFrame with the expected schema and dtypes."""
    frame = pd.DataFrame({column: pd.Series(dtype="str") for column in ALL_COLUMNS})
    frame["timestamp"] = pd.Series(dtype="datetime64[ns, UTC]")
    return frame


def load_events(source: str | Path | io.IOBase | bytes, source_name: str | None = None) -> LoadResult:
    """Load and validate events from a CSV path, raw bytes, or a file-like object."""
    if isinstance(source, (str, Path)):
        path = Path(source)
        name = source_name or str(path)
        if not path.exists():
            raise LogFileError(Msg("error.log_not_found", path=str(path)))
        if path.is_dir():
            raise LogFileError(Msg("error.log_is_directory", path=str(path)))
        if path.stat().st_size == 0:
            return _empty_result(name, Msg("warning.log_file_empty"))
        reader_input = path
    elif isinstance(source, bytes):
        name = source_name or "uploaded data"
        if not source.strip():
            return _empty_result(name, Msg("warning.upload_empty"))
        reader_input = io.BytesIO(source)
    else:
        name = source_name or "uploaded data"
        reader_input = source

    try:
        raw = pd.read_csv(reader_input, dtype=str, keep_default_na=False)
    except pd.errors.EmptyDataError:
        return _empty_result(name, Msg("warning.source_no_data"))
    except (pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise LogFileError(Msg("error.csv_parse", name=name, detail=str(exc))) from exc

    events, quality = validate_events(raw, name)
    return LoadResult(events, quality)


def _empty_result(name: str, message: Msg) -> LoadResult:
    return LoadResult(empty_events_frame(), DataQualityReport(source=name, warnings=[message]))


def validate_events(raw: pd.DataFrame, source_name: str = "data") -> tuple[pd.DataFrame, DataQualityReport]:
    """Normalise and validate raw string data. Returns (clean events, quality report)."""
    quality = DataQualityReport(source=source_name, rows_read=len(raw))
    frame = raw.copy()
    frame.columns = [str(column).strip().lower() for column in frame.columns]

    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise LogFileError(Msg("error.missing_columns", name=source_name, columns=", ".join(missing)))
    for column in OPTIONAL_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
            quality.warnings.append(Msg("warning.optional_column_missing", column=column))
    frame = frame[list(ALL_COLUMNS)].fillna("").astype(str)

    if frame.empty:
        quality.warnings.append(Msg("warning.header_only"))
        return empty_events_frame(), quality

    for column in ALL_COLUMNS:
        frame[column] = frame[column].str.strip()
    frame["username"] = frame["username"].str.lower()
    frame["event_type"] = frame["event_type"].str.upper()
    frame["result"] = frame["result"].str.upper()

    # 1. Exact duplicate rows (e.g. the same event forwarded twice by a collector).
    duplicated = frame.duplicated(keep="first")
    quality.exact_duplicates_removed = int(duplicated.sum())
    frame = frame[~duplicated]

    # 2. Row-level validation. Each row gets the first problem found.
    reasons = pd.Series("", index=frame.index, dtype="str")

    missing_fields = frame[list(REQUIRED_COLUMNS)].eq("")
    for column in REQUIRED_COLUMNS:
        reasons = reasons.mask((reasons == "") & missing_fields[column], f"{MISSING_FIELD_PREFIX}{column}")

    parsed = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce", format="ISO8601")
    reasons = reasons.mask((reasons == "") & parsed.isna(), "invalid timestamp")
    reasons = reasons.mask((reasons == "") & ~frame["event_type"].isin(VALID_EVENT_TYPES), "unknown event_type")
    reasons = reasons.mask((reasons == "") & ~frame["result"].isin(VALID_RESULTS), "unknown result")

    rejected_mask = reasons != ""
    rejected = raw.loc[frame.index[rejected_mask]].copy()
    rejected["rejection_reason"] = reasons[rejected_mask].values

    clean = frame[~rejected_mask].copy()
    clean["timestamp"] = parsed[~rejected_mask]

    # 3. Different rows sharing the same event_id: keep the first, report the rest.
    id_conflicts = clean.duplicated(subset="event_id", keep="first")
    if id_conflicts.any():
        conflicting = raw.loc[clean.index[id_conflicts]].copy()
        conflicting["rejection_reason"] = "duplicate event_id with different content"
        rejected = pd.concat([rejected, conflicting])
        quality.duplicate_event_ids_removed = int(id_conflicts.sum())
        clean = clean[~id_conflicts]

    clean = clean.sort_values(["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    quality.rejected_rows = rejected.reset_index(drop=True)
    quality.rows_accepted = len(clean)
    if quality.exact_duplicates_removed:
        quality.warnings.append(Msg("warning.duplicates_removed", count=quality.exact_duplicates_removed))
    if quality.rows_rejected:
        quality.warnings.append(Msg("warning.rows_rejected", count=quality.rows_rejected))
    return clean, quality
