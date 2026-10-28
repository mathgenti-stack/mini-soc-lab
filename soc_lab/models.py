"""Core data structures and constants shared across the Mini SOC Lab."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import pandas as pd

# ---------------------------------------------------------------------------
# Log schema
# ---------------------------------------------------------------------------
REQUIRED_COLUMNS = ("event_id", "timestamp", "username", "source_ip", "event_type", "result")
OPTIONAL_COLUMNS = ("hostname", "event_code", "failure_reason", "logon_type")
ALL_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS


class EventType:
    LOGON = "LOGON"
    LOGOFF = "LOGOFF"
    ACCOUNT_LOCKOUT = "ACCOUNT_LOCKOUT"
    ACCOUNT_UNLOCK = "ACCOUNT_UNLOCK"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"


class Result:
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    INFO = "INFO"


VALID_EVENT_TYPES = {
    EventType.LOGON,
    EventType.LOGOFF,
    EventType.ACCOUNT_LOCKOUT,
    EventType.ACCOUNT_UNLOCK,
    EventType.PASSWORD_CHANGE,
}
VALID_RESULTS = {Result.SUCCESS, Result.FAILURE, Result.INFO}

# Event codes modelled on the equivalent Windows Security log event IDs,
# so the synthetic data feels familiar to anyone who has used a SIEM.
EVENT_CODES = {
    (EventType.LOGON, Result.SUCCESS): "4624",
    (EventType.LOGON, Result.FAILURE): "4625",
    (EventType.LOGOFF, Result.INFO): "4634",
    (EventType.PASSWORD_CHANGE, Result.SUCCESS): "4723",
    (EventType.ACCOUNT_LOCKOUT, Result.INFO): "4740",
    (EventType.ACCOUNT_UNLOCK, Result.INFO): "4767",
}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)

    def escalate(self, steps: int = 1) -> "Severity":
        """Return the severity `steps` levels higher, capped at Critical."""
        return SEVERITY_ORDER[min(self.rank + steps, len(SEVERITY_ORDER) - 1)]


SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

INCIDENT_STATUSES = [
    "New",
    "In Progress",
    "Escalated",
    "Closed - True Positive",
    "Closed - Benign True Positive",
    "Closed - False Positive",
]


@dataclass
class Alert:
    """A detection produced by a rule. An alert is a lead to investigate, not proof of an attack."""

    rule_id: str
    rule_name: str
    title: str
    severity: Severity
    entity_type: str  # "user" or "source_ip"
    entity: str
    first_seen: pd.Timestamp
    last_seen: pd.Timestamp
    evidence_event_ids: list[str]
    usernames: list[str]
    source_ips: list[str]
    hostnames: list[str]
    trigger_reason: str
    observed_facts: list[str]
    hypotheses: list[str]
    pattern: str = ""
    mitre_attack: str = ""
    alert_id: str = ""  # assigned by the detection engine
    severity_reason: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def event_count(self) -> int:
        return len(self.evidence_event_ids)

    @property
    def playbook_key(self) -> str:
        return f"{self.rule_id}:{self.pattern}" if self.pattern else self.rule_id

    def to_record(self) -> dict:
        """Flatten the alert into a dict suitable for a DataFrame or CSV row."""
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "title": self.title,
            "entity_type": self.entity_type,
            "entity": self.entity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "usernames": ", ".join(self.usernames),
            "source_ips": ", ".join(self.source_ips),
            "hostnames": ", ".join(self.hostnames),
            "mitre_attack": self.mitre_attack,
            "trigger_reason": self.trigger_reason,
        }


def format_timestamp(ts: pd.Timestamp) -> str:
    """Human-readable UTC timestamp used in alerts and reports."""
    return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
