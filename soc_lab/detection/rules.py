"""Detection rules.

Each rule is a pure function: (events DataFrame, rule parameters, context) -> list[Alert].
Rules only describe what the data shows. The wording deliberately separates
observed facts ("12 failed logons were recorded") from hypotheses
("this may indicate password guessing"), because a pattern is not proof of intent.
"""

from __future__ import annotations

from collections import Counter, defaultdict

import pandas as pd

from ..i18n import Msg
from ..models import Alert, EventType, Result, Severity, format_timestamp
from .context import DetectionContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def find_bursts(times: list[pd.Timestamp], window: pd.Timedelta, threshold: int,
                keys: list[str] | None = None) -> list[tuple[int, int, int]]:
    """Find bursts of activity in a sorted list of timestamps.

    Events are first grouped into clusters where each event is no more than `window`
    after the previous one. Within each cluster a sliding window of length `window`
    measures the peak: the number of events (or of distinct `keys`, if given).
    Clusters whose peak reaches `threshold` are returned as (start, end, peak),
    where start/end are positions in the input list.
    """
    bursts = []
    start, total = 0, len(times)
    while start < total:
        end = start
        while end + 1 < total and times[end + 1] - times[end] <= window:
            end += 1
        cluster_keys = keys[start:end + 1] if keys is not None else None
        peak = _peak_in_window(times[start:end + 1], window, cluster_keys)
        if peak >= threshold:
            bursts.append((start, end, peak))
        start = end + 1
    return bursts


def _peak_in_window(times, window, keys=None) -> int:
    best, left, counter = 0, 0, Counter()
    for right in range(len(times)):
        if keys is not None:
            counter[keys[right]] += 1
        while times[right] - times[left] > window:
            if keys is not None:
                counter[keys[left]] -= 1
                if counter[keys[left]] == 0:
                    del counter[keys[left]]
            left += 1
        best = max(best, len(counter) if keys is not None else right - left + 1)
    return best


def _logons(events: pd.DataFrame, result: str | None = None) -> pd.DataFrame:
    mask = events["event_type"] == EventType.LOGON
    if result:
        mask &= events["result"] == result
    return events[mask]


def _unique(values) -> list[str]:
    return sorted({str(v) for v in values if str(v)})


def _describe_ips(ips, ctx: DetectionContext) -> Msg:
    return Msg.join([Msg("common.ip_with_kind", ip=ip, kind=ctx.classify_ip(ip)) for ip in _unique(ips)], ", ")


def _or_not_recorded(value: str):
    return value or Msg("common.not_recorded")


def _reason_counts(frame: pd.DataFrame) -> str:
    counts = frame["failure_reason"].replace("", "NOT_RECORDED").value_counts()
    return ", ".join(f"{reason} x{count}" for reason, count in counts.items())


def _duration(first: pd.Timestamp, last: pd.Timestamp) -> str:
    seconds = int((last - first).total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"


def _alert_from(evidence: pd.DataFrame, **fields) -> Alert:
    evidence = evidence.sort_values("timestamp", kind="stable")
    return Alert(
        first_seen=evidence["timestamp"].iloc[0],
        last_seen=evidence["timestamp"].iloc[-1],
        evidence_event_ids=evidence["event_id"].tolist(),
        usernames=_unique(evidence["username"]),
        source_ips=_unique(evidence["source_ip"]),
        hostnames=_unique(evidence["hostname"]),
        **fields,
    )


# ---------------------------------------------------------------------------
# R001 - Multiple failed logon attempts for one account
# ---------------------------------------------------------------------------
def detect_multiple_failed_logins(events: pd.DataFrame, params: dict, ctx: DetectionContext) -> list[Alert]:
    window = pd.Timedelta(minutes=params["window_minutes"])
    threshold = int(params["failure_threshold"])
    alerts = []
    for username, group in _logons(events, Result.FAILURE).groupby("username", sort=True):
        group = group.sort_values("timestamp", kind="stable")
        for start, end, peak in find_bursts(group["timestamp"].tolist(), window, threshold):
            burst = group.iloc[start:end + 1]
            external = [ip for ip in burst["source_ip"].unique() if not ctx.is_internal(ip)]
            severity, severity_reason = Severity.MEDIUM, Msg("rule.severity.base")
            if peak >= params["high_severity_threshold"] or external:
                severity = Severity.HIGH
                severity_reason = (Msg("r001.severity.external") if external else
                                   Msg("r001.severity.peak", peak=peak, threshold=params["high_severity_threshold"]))
            first, last = burst["timestamp"].iloc[0], burst["timestamp"].iloc[-1]
            facts = [
                Msg("r001.fact.burst", count=len(burst), user=username, first=format_timestamp(first),
                    last=format_timestamp(last), duration=_duration(first, last)),
                Msg("r001.fact.peak", window=params["window_minutes"], peak=peak),
                Msg("common.fact.sources", ips=_describe_ips(burst["source_ip"], ctx)),
                Msg("common.fact.target_hosts", hosts=_or_not_recorded(", ".join(_unique(burst["hostname"])))),
                Msg("common.fact.failure_reasons", reasons=_reason_counts(burst)),
            ]
            lockouts = events[(events["event_type"] == EventType.ACCOUNT_LOCKOUT) & (events["username"] == username)
                              & events["timestamp"].between(first, last + window)]
            if not lockouts.empty:
                facts.append(Msg("r001.fact.lockout", time=format_timestamp(lockouts["timestamp"].iloc[0])))
            alerts.append(_alert_from(
                burst,
                rule_id="R001",
                rule_name=Msg("rule.R001.name"),
                title=Msg("r001.title", user=username),
                severity=severity,
                severity_reason=severity_reason,
                entity_type="user",
                entity=username,
                trigger_reason=Msg("r001.trigger", threshold=threshold, window=params["window_minutes"], peak=peak),
                observed_facts=facts,
                hypotheses=[Msg("r001.hypothesis.1"), Msg("r001.hypothesis.2")],
                mitre_attack="T1110.001 Brute Force: Password Guessing",
            ))
    return alerts


# ---------------------------------------------------------------------------
# R002 - Successful logon shortly after repeated failures
# ---------------------------------------------------------------------------
def detect_success_after_failures(events: pd.DataFrame, params: dict, ctx: DetectionContext) -> list[Alert]:
    lookback = pd.Timedelta(minutes=params["lookback_minutes"])
    min_failures = int(params["min_failures"])
    alerts = []
    for username, group in _logons(events).groupby("username", sort=True):
        pending: list[int] = []  # positional indices of failures since the last success
        group = group.sort_values("timestamp", kind="stable").reset_index(drop=True)
        for position, row in group.iterrows():
            if row["result"] == Result.FAILURE:
                pending.append(position)
                continue
            if row["result"] != Result.SUCCESS:
                continue
            recent = [p for p in pending if row["timestamp"] - group.at[p, "timestamp"] <= lookback]
            pending = []
            if len(recent) < min_failures:
                continue
            failures = group.loc[recent]
            evidence = pd.concat([failures, group.loc[[position]]])
            success_ip = row["source_ip"]
            same_ip_failures = int((failures["source_ip"] == success_ip).sum())

            severity, severity_reason = Severity.MEDIUM, Msg("rule.severity.base")
            if not ctx.is_internal(success_ip):
                severity, severity_reason = Severity.HIGH, Msg("r002.severity.external")
                if same_ip_failures >= params["critical_failure_threshold"]:
                    severity = Severity.CRITICAL
                    severity_reason = Msg("r002.severity.critical", count=same_ip_failures,
                                          threshold=params["critical_failure_threshold"])
            alerts.append(_alert_from(
                evidence,
                rule_id="R002",
                rule_name=Msg("rule.R002.name"),
                title=Msg("r002.title", count=len(failures), user=username),
                severity=severity,
                severity_reason=severity_reason,
                entity_type="user",
                entity=username,
                trigger_reason=Msg("r002.trigger", min_failures=min_failures, window=params["lookback_minutes"],
                                   count=len(failures)),
                observed_facts=[
                    Msg("r002.fact.failures", count=len(failures), user=username, window=params["lookback_minutes"],
                        time=format_timestamp(row["timestamp"])),
                    Msg("r002.fact.success", ip=success_ip, kind=ctx.classify_ip(success_ip),
                        host=_or_not_recorded(row["hostname"]), logon_type=_or_not_recorded(row["logon_type"])),
                    Msg("r002.fact.same_ip", same=same_ip_failures, count=len(failures)),
                    Msg("r002.fact.time_to_success", duration=_duration(failures["timestamp"].iloc[0], row["timestamp"])),
                    Msg("common.fact.failure_reasons", reasons=_reason_counts(failures)),
                ],
                hypotheses=[Msg("r002.hypothesis.1"), Msg("r002.hypothesis.2")],
                mitre_attack="T1110 Brute Force / T1078 Valid Accounts",
            ))
    return alerts


# ---------------------------------------------------------------------------
# R003 - High authentication failure rate (per source IP or per account, per day)
# ---------------------------------------------------------------------------
def detect_high_failure_rate(events: pd.DataFrame, params: dict, ctx: DetectionContext) -> list[Alert]:
    logons = _logons(events)
    if logons.empty:
        return []
    logons = logons.assign(day=logons["timestamp"].dt.strftime("%Y-%m-%d"))
    min_attempts = int(params["min_attempts"])
    threshold = float(params["failure_rate_threshold"])
    alerts = []
    for field in params["entity_fields"]:
        label = Msg("r003.label.source_ip") if field == "source_ip" else Msg("r003.label.username")
        for (entity, day), group in logons.groupby([field, "day"], sort=True):
            attempts = len(group)
            failures = int((group["result"] == Result.FAILURE).sum())
            rate = failures / attempts
            if attempts < min_attempts or rate < threshold:
                continue
            severity, reasons = Severity.LOW, [Msg("rule.severity.base")]
            if rate >= params["high_failure_rate"]:
                severity = Severity.MEDIUM
                reasons = [Msg("r003.severity.medium", rate=params["high_failure_rate"])]
            external = [ip for ip in group["source_ip"].unique() if not ctx.is_internal(ip)]
            if external:
                severity = severity.escalate()
                reasons.append(Msg("r003.severity.external"))
            alerts.append(_alert_from(
                group,
                rule_id="R003",
                rule_name=Msg("rule.R003.name"),
                title=Msg("r003.title", label=label, entity=entity, day=day),
                severity=severity,
                severity_reason=Msg.join(reasons),
                entity_type="source_ip" if field == "source_ip" else "user",
                entity=entity,
                trigger_reason=Msg("r003.trigger", threshold=threshold, min_attempts=min_attempts, label=label,
                                   rate=rate, attempts=attempts),
                observed_facts=[
                    Msg("r003.fact.rate", day=day, label=label, entity=entity, attempts=attempts, failures=failures,
                        rate=rate),
                    Msg("r003.fact.distinct", accounts=group["username"].nunique(), ips=group["source_ip"].nunique()),
                    Msg("common.fact.sources", ips=_describe_ips(group["source_ip"], ctx)),
                    Msg("common.fact.failure_reasons", reasons=_reason_counts(group[group["result"] == Result.FAILURE])),
                ],
                hypotheses=[Msg("r003.hypothesis.1"), Msg("r003.hypothesis.2")],
                mitre_attack="T1110 Brute Force",
                extra={"failure_rate": round(rate, 3), "attempts": attempts, "day": day, "entity_field": field},
            ))
    return alerts


# ---------------------------------------------------------------------------
# R004 - One source IP failing against many different accounts
# ---------------------------------------------------------------------------
def detect_single_ip_many_accounts(events: pd.DataFrame, params: dict, ctx: DetectionContext) -> list[Alert]:
    window = pd.Timedelta(minutes=params["window_minutes"])
    min_accounts = int(params["min_distinct_accounts"])
    successes = _logons(events, Result.SUCCESS)
    alerts = []
    for source_ip, group in _logons(events, Result.FAILURE).groupby("source_ip", sort=True):
        group = group.sort_values("timestamp", kind="stable")
        bursts = find_bursts(group["timestamp"].tolist(), window, min_accounts, keys=group["username"].tolist())
        for start, end, peak in bursts:
            burst = group.iloc[start:end + 1]
            first, last = burst["timestamp"].iloc[0], burst["timestamp"].iloc[-1]
            targeted = set(burst["username"])
            # Any successful logon from the same address during the activity - including accounts
            # that succeeded at the first attempt and so never appear among the failures.
            related_success = successes[(successes["source_ip"] == source_ip)
                                        & successes["timestamp"].between(first, last + window)]
            unknown = int((burst["failure_reason"] == "UNKNOWN_USER").sum())
            external = not ctx.is_internal(source_ip)

            severity, reasons = Severity.MEDIUM, [Msg("rule.severity.base")]
            if external or peak >= params["high_distinct_accounts"]:
                severity = Severity.HIGH
                reasons = [Msg("r004.severity.external") if external else Msg("r004.severity.peak", peak=peak)]
            if not related_success.empty:
                severity = Severity.CRITICAL
                reasons.append(Msg("r004.severity.critical"))
            facts = [
                Msg("r004.fact.burst", count=len(burst), ip=source_ip, kind=ctx.classify_ip(source_ip),
                    accounts=len(targeted), first=format_timestamp(first), last=format_timestamp(last)),
                Msg("r004.fact.peak", window=params["window_minutes"], peak=peak),
                Msg("r004.fact.unknown", unknown=unknown),
                Msg("r004.fact.accounts", accounts=", ".join(sorted(targeted))),
                Msg("common.fact.target_hosts", hosts=_or_not_recorded(", ".join(_unique(burst["hostname"])))),
            ]
            if related_success.empty:
                facts.append(Msg("r004.fact.no_success"))
            else:
                for _, success in related_success.iterrows():
                    prior = (Msg("r004.prior.also_failed") if success["username"] in targeted
                             else Msg("r004.prior.no_failures"))
                    facts.append(Msg("r004.fact.success", user=success["username"],
                                     time=format_timestamp(success["timestamp"]), prior=prior))
            alerts.append(_alert_from(
                pd.concat([burst, related_success]),
                rule_id="R004",
                rule_name=Msg("rule.R004.name"),
                title=Msg("r004.title", count=len(targeted), ip=source_ip),
                severity=severity,
                severity_reason=Msg.join(reasons),
                entity_type="source_ip",
                entity=source_ip,
                trigger_reason=Msg("r004.trigger", min_accounts=min_accounts, window=params["window_minutes"],
                                   peak=peak),
                observed_facts=facts,
                hypotheses=[Msg("r004.hypothesis.1"), Msg("r004.hypothesis.2")],
                mitre_attack="T1110.003 Brute Force: Password Spraying",
            ))
    return alerts


# ---------------------------------------------------------------------------
# R005 - Suspicious authentication patterns (combinations of weaker signals)
# ---------------------------------------------------------------------------
def detect_suspicious_patterns(events: pd.DataFrame, params: dict, ctx: DetectionContext) -> list[Alert]:
    return (_lockout_then_success(events, params, ctx)
            + _off_hours_new_source(events, params, ctx)
            + _rapid_source_change(events, params, ctx))


R005_NAME = Msg("rule.R005.name")


def _lockout_then_success(events, params, ctx) -> list[Alert]:
    window = pd.Timedelta(minutes=params["lockout_success_window_minutes"])
    lockouts = events[events["event_type"] == EventType.ACCOUNT_LOCKOUT]
    successes = _logons(events, Result.SUCCESS)
    unlocks = events[events["event_type"] == EventType.ACCOUNT_UNLOCK]
    alerts = []
    for lockout_index, lockout in lockouts.sort_values("timestamp").iterrows():
        user, locked_at = lockout["username"], lockout["timestamp"]
        after = successes[(successes["username"] == user) & (successes["timestamp"] > locked_at)
                          & (successes["timestamp"] <= locked_at + window)]
        if after.empty:
            continue
        success = after.iloc[0]
        unlocked = unlocks[(unlocks["username"] == user)
                           & unlocks["timestamp"].between(locked_at, success["timestamp"])]
        external = not ctx.is_internal(success["source_ip"])
        facts = [
            Msg("r005.lockout.fact.locked", user=user, time=format_timestamp(locked_at)),
            Msg("r005.lockout.fact.success", time=format_timestamp(success["timestamp"]), ip=success["source_ip"],
                kind=ctx.classify_ip(success["source_ip"]), duration=_duration(locked_at, success["timestamp"])),
        ]
        if unlocked.empty:
            facts.append(Msg("r005.lockout.fact.no_unlock"))
        else:
            facts.append(Msg("r005.lockout.fact.unlock", time=format_timestamp(unlocked["timestamp"].iloc[0]),
                             ip=unlocked["source_ip"].iloc[0]))
        alerts.append(_alert_from(
            events.loc[[lockout_index, *unlocked.index, after.index[0]]],
            rule_id="R005", pattern="lockout_then_success", rule_name=R005_NAME,
            title=Msg("r005.lockout.title", user=user),
            severity=Severity.HIGH if external else Severity.MEDIUM,
            severity_reason=(Msg("r005.lockout.severity.external") if external
                             else Msg("r005.lockout.severity.internal")),
            entity_type="user", entity=user,
            trigger_reason=Msg("r005.lockout.trigger", window=params["lockout_success_window_minutes"]),
            observed_facts=facts,
            hypotheses=[Msg("r005.lockout.hypothesis.1"), Msg("r005.lockout.hypothesis.2")],
            mitre_attack="T1110 Brute Force / T1078 Valid Accounts",
        ))
    return alerts


def _off_hours_new_source(events, params, ctx) -> list[Alert]:
    successes = _logons(events, Result.SUCCESS).sort_values("timestamp", kind="stable")
    if successes.empty:
        return []
    learning_end = events["timestamp"].min() + pd.Timedelta(days=params["baseline_learning_days"])
    seen: dict[str, set[str]] = defaultdict(set)
    alerts = []
    for index, row in successes.iterrows():
        user, ip, ts = row["username"], row["source_ip"], row["timestamp"]
        is_new = ip not in seen[user]
        seen[user].add(ip)
        if not is_new or ts < learning_end or ctx.is_business_hours(ts):
            continue
        external = not ctx.is_internal(ip)
        alerts.append(_alert_from(
            successes.loc[[index]],
            rule_id="R005", pattern="off_hours_new_source", rule_name=R005_NAME,
            title=Msg("r005.off_hours.title", user=user),
            severity=Severity.MEDIUM if external else Severity.LOW,
            severity_reason=(Msg("r005.off_hours.severity.external") if external
                             else Msg("r005.off_hours.severity.internal")),
            entity_type="user", entity=user,
            trigger_reason=Msg("r005.off_hours.trigger"),
            observed_facts=[
                Msg("r005.off_hours.fact.logon", user=user, time=format_timestamp(ts),
                    start=ctx.business_start_hour, end=ctx.business_end_hour),
                Msg("r005.off_hours.fact.new_source", ip=ip, kind=ctx.classify_ip(ip)),
                Msg("common.fact.host_logon_type", host=_or_not_recorded(row["hostname"]),
                    logon_type=_or_not_recorded(row["logon_type"])),
            ],
            hypotheses=[Msg("r005.off_hours.hypothesis.1"), Msg("r005.off_hours.hypothesis.2")],
            mitre_attack="T1078 Valid Accounts",
        ))
    return alerts


def _rapid_source_change(events, params, ctx) -> list[Alert]:
    window = pd.Timedelta(minutes=params["rapid_source_change_minutes"])
    successes = _logons(events, Result.SUCCESS)
    if successes.empty:
        return []
    external = successes[~successes["source_ip"].map(ctx.is_internal).astype(bool)]
    alerts = []
    for user, group in external.groupby("username", sort=True):
        group = group.sort_values("timestamp", kind="stable").reset_index(drop=True)
        for i in range(1, len(group)):
            previous, current = group.iloc[i - 1], group.iloc[i]
            gap = current["timestamp"] - previous["timestamp"]
            if previous["source_ip"] == current["source_ip"] or gap > window:
                continue
            alerts.append(_alert_from(
                group.iloc[[i - 1, i]],
                rule_id="R005", pattern="rapid_source_change", rule_name=R005_NAME,
                title=Msg("r005.rapid.title", duration=_duration(previous["timestamp"], current["timestamp"]), user=user),
                severity=Severity.MEDIUM,
                severity_reason=Msg("r005.rapid.severity"),
                entity_type="user", entity=user,
                trigger_reason=Msg("r005.rapid.trigger", window=params["rapid_source_change_minutes"]),
                observed_facts=[
                    Msg("r005.rapid.fact.first", user=user, ip=previous["source_ip"],
                        time=format_timestamp(previous["timestamp"])),
                    Msg("r005.rapid.fact.second", user=user, ip=current["source_ip"],
                        time=format_timestamp(current["timestamp"]),
                        duration=_duration(previous["timestamp"], current["timestamp"])),
                    Msg("r005.rapid.fact.no_geo"),
                ],
                hypotheses=[Msg("r005.rapid.hypothesis.1"), Msg("r005.rapid.hypothesis.2")],
                mitre_attack="T1078 Valid Accounts",
            ))
    return alerts
