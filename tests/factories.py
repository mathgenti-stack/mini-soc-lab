"""Helpers for building small, hand-crafted event sets in tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from soc_lab.log_loader import validate_events

BASE_TIME = datetime(2026, 10, 7, 10, 0, 0, tzinfo=timezone.utc)  # a Wednesday, business hours


def at(minutes: float = 0, base: datetime = BASE_TIME) -> datetime:
    return base + timedelta(minutes=minutes)


def event(ts: datetime, username: str = "a.user", source_ip: str = "10.10.1.50", result: str = "FAILURE",
          event_type: str = "LOGON", hostname: str = "LON-WS-001", failure_reason: str | None = None,
          logon_type: str = "INTERACTIVE") -> dict:
    if failure_reason is None:
        failure_reason = "BAD_PASSWORD" if result == "FAILURE" else ""
    return {"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "username": username, "source_ip": source_ip,
            "hostname": hostname, "event_type": event_type, "event_code": "", "result": result,
            "failure_reason": failure_reason, "logon_type": logon_type}


def failures(count: int, start: float = 0, every_minutes: float = 1, **kwargs) -> list[dict]:
    return [event(at(start + n * every_minutes), result="FAILURE", **kwargs) for n in range(count)]


def make_events(rows: list[dict]) -> pd.DataFrame:
    """Turn event dicts into a validated events DataFrame, assigning event IDs."""
    raw = pd.DataFrame([dict(row, event_id=row.get("event_id", f"T-{n:05d}")) for n, row in enumerate(rows, 1)])
    events, _quality = validate_events(raw.astype(str))
    return events
