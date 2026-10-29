"""Group related alerts into cases.

Several rules often fire on the same activity: a brute force raises R001 for the account and R003
for the address. An analyst should triage that once, not twice. Two alerts are linked when they
share an account or a source address AND their time spans overlap or are at most `window_minutes`
apart. Links are transitive (A-B and B-C put A, B and C in one case).

A case is a grouping aid, not a verdict: its severity is simply the highest severity among its
alerts, and every link records which shared account or address caused it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .i18n import Msg
from .models import Alert, Severity

DEFAULT_WINDOW_MINUTES = 120
MAX_LISTED_VALUES = 5


@dataclass(frozen=True)
class Link:
    """Why two alerts are in the same case."""

    alert_a: str
    alert_b: str
    usernames: tuple[str, ...]
    source_ips: tuple[str, ...]

    @property
    def reason(self) -> Msg:
        parts = []
        if self.source_ips:
            parts.append(Msg("case.shared.ips", values=_listed(self.source_ips)))
        if self.usernames:
            parts.append(Msg("case.shared.users", values=_listed(self.usernames)))
        return Msg("case.link", a=self.alert_a, b=self.alert_b, shared=Msg.join(parts, "; "))


@dataclass
class Case:
    case_id: str
    alerts: list[Alert]
    links: list[Link] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return max((alert.severity for alert in self.alerts), key=lambda s: s.rank)

    @property
    def alert_ids(self) -> list[str]:
        return [alert.alert_id for alert in self.alerts]

    @property
    def first_seen(self) -> pd.Timestamp:
        return min(alert.first_seen for alert in self.alerts)

    @property
    def last_seen(self) -> pd.Timestamp:
        return max(alert.last_seen for alert in self.alerts)

    @property
    def rule_ids(self) -> list[str]:
        return sorted({alert.rule_id for alert in self.alerts})

    @property
    def entities(self) -> list[str]:
        """The main entity of each alert (account or address), in alert order, without repeats."""
        return list(dict.fromkeys(alert.entity for alert in self.alerts))

    @property
    def usernames(self) -> list[str]:
        return sorted({name for alert in self.alerts for name in alert.usernames})

    @property
    def source_ips(self) -> list[str]:
        return sorted({ip for alert in self.alerts for ip in alert.source_ips})

    @property
    def mitre_attack(self) -> list[str]:
        return list(dict.fromkeys(alert.mitre_attack for alert in self.alerts if alert.mitre_attack))

    @property
    def event_ids(self) -> list[str]:
        return list(dict.fromkeys(event_id for alert in self.alerts for event_id in alert.evidence_event_ids))

    @property
    def title(self) -> Msg:
        if len(self.alerts) == 1:
            return Msg("case.title.single", entities=", ".join(self.entities))
        return Msg("case.title", count=len(self.alerts), entities=_listed(self.entities))

    def to_record(self) -> dict:
        """A flat row for tables and CSV (plain English strings, like Alert.to_record)."""
        return {
            "case_id": self.case_id,
            "severity": self.severity.value,
            "alert_count": len(self.alerts),
            "alert_ids": ", ".join(self.alert_ids),
            "rule_ids": ", ".join(self.rule_ids),
            "title": str(self.title),
            "entities": ", ".join(self.entities),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": len(self.event_ids),
            "usernames": ", ".join(self.usernames),
            "source_ips": ", ".join(self.source_ips),
            "mitre_attack": " | ".join(self.mitre_attack),
        }


def correlation_window(config: dict) -> float:
    return config.get("correlation", {}).get("window_minutes", DEFAULT_WINDOW_MINUTES)


def correlate_alerts(alerts: list[Alert], window_minutes: float = DEFAULT_WINDOW_MINUTES) -> list[Case]:
    """Group alerts into cases, ordered by first activity and numbered CASE-0001, CASE-0002, ..."""
    window = pd.Timedelta(minutes=window_minutes)
    ordered = sorted(alerts, key=lambda a: (a.first_seen, a.alert_id))
    parent = list(range(len(ordered)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    links: list[tuple[int, Link]] = []
    for i, first in enumerate(ordered):
        for j in range(i + 1, len(ordered)):
            second = ordered[j]
            if second.first_seen - first.last_seen > window:
                break  # sorted by start time: every later alert starts even further away
            users = tuple(sorted(set(first.usernames) & set(second.usernames)))
            ips = tuple(sorted(set(first.source_ips) & set(second.source_ips)))
            if users or ips:
                parent[root(j)] = root(i)
                links.append((i, Link(first.alert_id, second.alert_id, users, ips)))

    groups: dict[int, list[int]] = {}
    for i in range(len(ordered)):
        groups.setdefault(root(i), []).append(i)
    cases = []
    for number, members in enumerate(sorted(groups.values(), key=lambda m: m[0]), start=1):
        member_set = set(members)
        cases.append(Case(case_id=f"CASE-{number:04d}", alerts=[ordered[i] for i in members],
                          links=[link for i, link in links if i in member_set]))
    return cases


def case_for_alert(cases: list[Case], alert_id: str) -> Case | None:
    return next((case for case in cases if alert_id in case.alert_ids), None)


def cases_to_frame(cases: list[Case]) -> pd.DataFrame:
    columns = ["case_id", "severity", "alert_count", "alert_ids", "rule_ids", "title", "entities", "first_seen",
               "last_seen", "event_count", "usernames", "source_ips", "mitre_attack"]
    return pd.DataFrame([case.to_record() for case in cases], columns=columns)


def cases_to_csv(cases: list[Case]) -> str:
    frame = cases_to_frame(cases)
    if not frame.empty:
        for column in ("first_seen", "last_seen"):
            frame[column] = pd.to_datetime(frame[column], utc=True).dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return frame.to_csv(index=False)


def _listed(values) -> str:
    values = list(values)
    shown = ", ".join(values[:MAX_LISTED_VALUES])
    return shown if len(values) <= MAX_LISTED_VALUES else f"{shown} (+{len(values) - MAX_LISTED_VALUES})"
