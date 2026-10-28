"""Runs the enabled detection rules and assigns stable alert IDs."""

from __future__ import annotations

from typing import Callable

import pandas as pd

from ..models import Alert
from .context import DetectionContext
from .rules import (
    detect_high_failure_rate,
    detect_multiple_failed_logins,
    detect_single_ip_many_accounts,
    detect_success_after_failures,
    detect_suspicious_patterns,
)

RuleFunction = Callable[[pd.DataFrame, dict, DetectionContext], list[Alert]]

RULE_REGISTRY: dict[str, tuple[str, RuleFunction]] = {
    "R001": ("Multiple failed logon attempts", detect_multiple_failed_logins),
    "R002": ("Successful logon after repeated failures", detect_success_after_failures),
    "R003": ("High authentication failure rate", detect_high_failure_rate),
    "R004": ("Repeated failures from a single IP across many accounts", detect_single_ip_many_accounts),
    "R005": ("Suspicious authentication pattern", detect_suspicious_patterns),
}


def run_detection(events: pd.DataFrame, config: dict) -> list[Alert]:
    """Run every enabled rule over validated events and return alerts sorted by time."""
    if events.empty:
        return []
    context = DetectionContext.from_config(config)
    alerts: list[Alert] = []
    for rule_id, (_name, rule) in RULE_REGISTRY.items():
        params = config["rules"].get(rule_id, {})
        if params.get("enabled", True):
            alerts.extend(rule(events, params, context))

    # Drop exact repeats (same rule, pattern, entity and time span).
    unique: dict[tuple, Alert] = {}
    for alert in alerts:
        key = (alert.rule_id, alert.pattern, alert.entity, alert.first_seen, alert.last_seen)
        unique.setdefault(key, alert)

    ordered = sorted(unique.values(), key=lambda a: (a.first_seen, a.rule_id, a.pattern, a.entity))
    for number, alert in enumerate(ordered, start=1):
        alert.alert_id = f"ALR-{number:04d}"
    return ordered
