"""Filtering used by the dashboard, kept out of the UI code so it can be unit tested."""

from __future__ import annotations

from datetime import date

import pandas as pd

from .models import Alert


def filter_events(events: pd.DataFrame, start: date | None = None, end: date | None = None,
                  usernames: list[str] | None = None, source_ips: list[str] | None = None,
                  event_types: list[str] | None = None, search: str = "") -> pd.DataFrame:
    """Filter events. Empty filter lists mean 'no filter'. Dates are inclusive (UTC)."""
    mask = pd.Series(True, index=events.index)
    days = events["timestamp"].dt.date
    if start:
        mask &= days >= start
    if end:
        mask &= days <= end
    if usernames:
        mask &= events["username"].isin(usernames)
    if source_ips:
        mask &= events["source_ip"].isin(source_ips)
    if event_types:
        mask &= events["event_type"].isin(event_types)
    if search.strip():
        term = search.strip().lower()
        text = events.drop(columns="timestamp").astype(str).agg(" ".join, axis=1).str.lower()
        mask &= text.str.contains(term, regex=False)
    return events[mask]


def filter_alerts(alerts: list[Alert], start: date | None = None, end: date | None = None,
                  usernames: list[str] | None = None, source_ips: list[str] | None = None,
                  severities: list[str] | None = None) -> list[Alert]:
    """Keep alerts that overlap the date range and involve any selected user / IP / severity."""
    selected = []
    for alert in alerts:
        if start and alert.last_seen.date() < start:
            continue
        if end and alert.first_seen.date() > end:
            continue
        if usernames and not set(usernames) & set(alert.usernames):
            continue
        if source_ips and not set(source_ips) & set(alert.source_ips):
            continue
        if severities and alert.severity.value not in severities:
            continue
        selected.append(alert)
    return selected
