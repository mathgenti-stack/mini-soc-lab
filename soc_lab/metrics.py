"""Dashboard indicators, calculated from the processed events and alerts (pure functions)."""

from __future__ import annotations

import pandas as pd

from .models import SEVERITY_ORDER, Alert, EventType, Result


def compute_kpis(events: pd.DataFrame, alerts: list[Alert]) -> dict:
    logons = events[events["event_type"] == EventType.LOGON]
    successful = int((logons["result"] == Result.SUCCESS).sum())
    failed = int((logons["result"] == Result.FAILURE).sum())
    return {
        "total_events": len(events),
        "successful_logins": successful,
        "failed_logins": failed,
        "account_lockouts": int((events["event_type"] == EventType.ACCOUNT_LOCKOUT).sum()),
        "failure_rate": failed / (successful + failed) if successful + failed else 0.0,
        "unique_users": int(events["username"].nunique()),
        "unique_source_ips": int(events["source_ip"].nunique()),
        "total_alerts": len(alerts),
        "alerts_by_severity": severity_breakdown(alerts),
    }


def severity_breakdown(alerts: list[Alert]) -> dict[str, int]:
    """Alert counts per severity, highest first, including severities with zero alerts."""
    counts = {severity.value: 0 for severity in reversed(SEVERITY_ORDER)}
    for alert in alerts:
        counts[alert.severity.value] += 1
    return counts


def alerts_to_frame(alerts: list[Alert]) -> pd.DataFrame:
    columns = ["alert_id", "severity", "rule_id", "rule_name", "title", "entity_type", "entity", "first_seen",
               "last_seen", "event_count", "usernames", "source_ips", "hostnames", "mitre_attack", "trigger_reason"]
    return pd.DataFrame([alert.to_record() for alert in alerts], columns=columns)


def logon_timeline(events: pd.DataFrame, freq: str = "1h") -> pd.DataFrame:
    """Successful and failed logons per time bucket - the basis of the activity timeline."""
    logons = events[events["event_type"] == EventType.LOGON]
    if logons.empty:
        return pd.DataFrame(columns=["bucket", "result", "count"])
    return (logons.assign(bucket=logons["timestamp"].dt.floor(freq))
            .groupby(["bucket", "result"]).size().reset_index(name="count"))


def top_failure_sources(events: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    failures = events[(events["event_type"] == EventType.LOGON) & (events["result"] == Result.FAILURE)]
    if failures.empty:
        return pd.DataFrame(columns=["source_ip", "failed_logins", "distinct_accounts"])
    grouped = failures.groupby("source_ip").agg(failed_logins=("event_id", "count"),
                                                distinct_accounts=("username", "nunique"))
    return grouped.sort_values("failed_logins", ascending=False).head(limit).reset_index()
