"""Detection rules.

Each rule is a pure function: (events DataFrame, rule parameters, context) -> list[Alert].
Rules only describe what the data shows. The wording deliberately separates
observed facts ("12 failed logons were recorded") from hypotheses
("this may indicate password guessing"), because a pattern is not proof of intent.
"""

from __future__ import annotations

from collections import Counter, defaultdict

import pandas as pd

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


def _describe_ips(ips, ctx: DetectionContext) -> str:
    return ", ".join(f"{ip} ({ctx.classify_ip(ip)})" for ip in _unique(ips))


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
            severity, severity_reason = Severity.MEDIUM, "Base severity for this rule."
            if peak >= params["high_severity_threshold"] or external:
                severity = Severity.HIGH
                severity_reason = ("Raised to High: failures came from an external address."
                                   if external else
                                   f"Raised to High: peak of {peak} failures reached the high-severity threshold "
                                   f"({params['high_severity_threshold']}).")
            first, last = burst["timestamp"].iloc[0], burst["timestamp"].iloc[-1]
            facts = [
                f"{len(burst)} failed logon attempts were recorded for account '{username}' between "
                f"{format_timestamp(first)} and {format_timestamp(last)} ({_duration(first, last)}).",
                f"The highest number of failures within any {params['window_minutes']}-minute window was {peak}.",
                f"Source address(es): {_describe_ips(burst['source_ip'], ctx)}.",
                f"Target host(s): {', '.join(_unique(burst['hostname'])) or 'not recorded'}.",
                f"Failure reasons: {_reason_counts(burst)}.",
            ]
            lockouts = events[(events["event_type"] == EventType.ACCOUNT_LOCKOUT) & (events["username"] == username)
                              & events["timestamp"].between(first, last + window)]
            if not lockouts.empty:
                facts.append(f"An account lockout was recorded at {format_timestamp(lockouts['timestamp'].iloc[0])}.")
            alerts.append(_alert_from(
                burst,
                rule_id="R001",
                rule_name="Multiple failed logon attempts",
                title=f"Multiple failed logons for account {username}",
                severity=severity,
                severity_reason=severity_reason,
                entity_type="user",
                entity=username,
                trigger_reason=(f"At least {threshold} failed logons for the same account within "
                                f"{params['window_minutes']} minutes (observed peak: {peak})."),
                observed_facts=facts,
                hypotheses=[
                    "The pattern is consistent with password guessing against a single account "
                    "(MITRE ATT&CK T1110.001), but this has not been confirmed.",
                    "It may also be a user, device or application repeatedly submitting an old or mistyped password.",
                ],
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

            severity, severity_reason = Severity.MEDIUM, "Base severity for this rule."
            if not ctx.is_internal(success_ip):
                severity, severity_reason = Severity.HIGH, "Raised to High: the successful logon came from an external address."
                if same_ip_failures >= params["critical_failure_threshold"]:
                    severity = Severity.CRITICAL
                    severity_reason = (f"Raised to Critical: {same_ip_failures} failures from the same external address "
                                       f"preceded the success (threshold {params['critical_failure_threshold']}).")
            alerts.append(_alert_from(
                evidence,
                rule_id="R002",
                rule_name="Successful logon after repeated failures",
                title=f"Successful logon after {len(failures)} failures for account {username}",
                severity=severity,
                severity_reason=severity_reason,
                entity_type="user",
                entity=username,
                trigger_reason=(f"A successful logon was preceded by at least {min_failures} failed logons for the "
                                f"same account within {params['lookback_minutes']} minutes (observed: {len(failures)})."),
                observed_facts=[
                    f"{len(failures)} failed logons for '{username}' were recorded in the "
                    f"{params['lookback_minutes']} minutes before a successful logon at {format_timestamp(row['timestamp'])}.",
                    f"The successful logon came from {success_ip} ({ctx.classify_ip(success_ip)}) to host "
                    f"'{row['hostname'] or 'not recorded'}' (logon type: {row['logon_type'] or 'not recorded'}).",
                    f"{same_ip_failures} of the {len(failures)} failures came from the same source address as the success.",
                    f"Time from first failure to success: {_duration(failures['timestamp'].iloc[0], row['timestamp'])}.",
                    f"Failure reasons: {_reason_counts(failures)}.",
                ],
                hypotheses=[
                    "If the failures were password guesses, the success may mean the password was guessed and the "
                    "account is now in use by someone else (MITRE ATT&CK T1110 followed by T1078).",
                    "Equally, the legitimate user may have mistyped or forgotten their password and then remembered it.",
                ],
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
        label = "source address" if field == "source_ip" else "account"
        for (entity, day), group in logons.groupby([field, "day"], sort=True):
            attempts = len(group)
            failures = int((group["result"] == Result.FAILURE).sum())
            rate = failures / attempts
            if attempts < min_attempts or rate < threshold:
                continue
            severity, reasons = Severity.LOW, ["Base severity for this rule."]
            if rate >= params["high_failure_rate"]:
                severity = Severity.MEDIUM
                reasons = [f"Raised to Medium: failure rate reached {params['high_failure_rate']:.0%}."]
            external = [ip for ip in group["source_ip"].unique() if not ctx.is_internal(ip)]
            if external:
                severity = severity.escalate()
                reasons.append("Raised one level: activity involved an external address.")
            alerts.append(_alert_from(
                group,
                rule_id="R003",
                rule_name="High authentication failure rate",
                title=f"High logon failure rate for {label} {entity} on {day}",
                severity=severity,
                severity_reason=" ".join(reasons),
                entity_type="source_ip" if field == "source_ip" else "user",
                entity=entity,
                trigger_reason=(f"Failure rate of at least {threshold:.0%} over at least {min_attempts} logon attempts "
                                f"for one {label} in a calendar day (observed: {rate:.0%} of {attempts})."),
                observed_facts=[
                    f"On {day}, {label} '{entity}' had {attempts} logon attempts, of which {failures} failed "
                    f"({rate:.0%}).",
                    f"Distinct accounts involved: {group['username'].nunique()}; distinct source addresses: "
                    f"{group['source_ip'].nunique()}.",
                    f"Source address(es): {_describe_ips(group['source_ip'], ctx)}.",
                    f"Failure reasons: {_reason_counts(group[group['result'] == Result.FAILURE])}.",
                ],
                hypotheses=[
                    "A sustained high failure rate can indicate automated credential attacks.",
                    "It is also typical of misconfigured scripts or services using an expired or wrong password, "
                    "or of authorised security scanning.",
                ],
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

            severity, reasons = Severity.MEDIUM, ["Base severity for this rule."]
            if external or peak >= params["high_distinct_accounts"]:
                severity = Severity.HIGH
                reasons = ["Raised to High: " + ("the source is an external address."
                                                 if external else
                                                 f"{peak} distinct accounts reached the high threshold.")]
            if not related_success.empty:
                severity = Severity.CRITICAL
                reasons.append("Raised to Critical: at least one account logged on successfully from the same "
                               "address during the activity.")
            facts = [
                f"{len(burst)} failed logons from {source_ip} ({ctx.classify_ip(source_ip)}) targeted "
                f"{len(targeted)} distinct accounts between {format_timestamp(first)} and {format_timestamp(last)}.",
                f"The highest number of distinct accounts within any {params['window_minutes']}-minute window was {peak}.",
                f"{unknown} of the attempts were rejected as UNKNOWN_USER (account name not recognised).",
                f"Accounts attempted: {', '.join(sorted(targeted))}.",
                f"Target host(s): {', '.join(_unique(burst['hostname'])) or 'not recorded'}.",
            ]
            if related_success.empty:
                facts.append("No successful logon from this address was recorded during the activity or the "
                             "following window.")
            else:
                for _, success in related_success.iterrows():
                    prior = ("also had failed attempts" if success["username"] in targeted
                             else "had no failed attempts in this burst")
                    facts.append(f"Successful logon for '{success['username']}' from the same address at "
                                 f"{format_timestamp(success['timestamp'])} (this account {prior}).")
            alerts.append(_alert_from(
                pd.concat([burst, related_success]),
                rule_id="R004",
                rule_name="Repeated failures from a single IP across many accounts",
                title=f"Logon failures against {len(targeted)} accounts from {source_ip}",
                severity=severity,
                severity_reason=" ".join(reasons),
                entity_type="source_ip",
                entity=source_ip,
                trigger_reason=(f"At least {min_accounts} distinct accounts failed to log on from one source address "
                                f"within {params['window_minutes']} minutes (observed peak: {peak})."),
                observed_facts=facts,
                hypotheses=[
                    "Few attempts per account across many accounts is consistent with password spraying "
                    "(MITRE ATT&CK T1110.003) or account enumeration, but intent cannot be determined from logs alone.",
                    "Shared egress addresses (VPN, NAT, proxies) and authorised vulnerability scanners produce the "
                    "same shape of activity.",
                ],
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


R005_NAME = "Suspicious authentication pattern"


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
            f"Account '{user}' was locked out at {format_timestamp(locked_at)}.",
            f"A successful logon followed at {format_timestamp(success['timestamp'])} from "
            f"{success['source_ip']} ({ctx.classify_ip(success['source_ip'])}), "
            f"{_duration(locked_at, success['timestamp'])} later.",
        ]
        if unlocked.empty:
            facts.append("No account unlock event was recorded between the lockout and the successful logon.")
        else:
            facts.append(f"An account unlock event was recorded at {format_timestamp(unlocked['timestamp'].iloc[0])} "
                         f"from {unlocked['source_ip'].iloc[0]}.")
        alerts.append(_alert_from(
            events.loc[[lockout_index, *unlocked.index, after.index[0]]],
            rule_id="R005", pattern="lockout_then_success", rule_name=R005_NAME,
            title=f"Successful logon shortly after lockout of account {user}",
            severity=Severity.HIGH if external else Severity.MEDIUM,
            severity_reason=("High: the successful logon came from an external address." if external
                             else "Medium: successful logon from an internal address."),
            entity_type="user", entity=user,
            trigger_reason=(f"An account lockout followed by a successful logon for the same account within "
                            f"{params['lockout_success_window_minutes']} minutes."),
            observed_facts=facts,
            hypotheses=[
                "A success soon after a lockout can mean the guessing continued until it worked once the lockout expired.",
                "It commonly happens when the service desk unlocks a user who forgot their password.",
            ],
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
            title=f"Out-of-hours logon from a new source for account {user}",
            severity=Severity.MEDIUM if external else Severity.LOW,
            severity_reason=("Medium: the new source is an external address." if external
                             else "Low: the new source is an internal address."),
            entity_type="user", entity=user,
            trigger_reason=("A successful logon outside business hours from a source address not previously seen "
                            "for this account (after the baseline learning period)."),
            observed_facts=[
                f"Successful logon for '{user}' at {format_timestamp(ts)}, outside the configured business hours "
                f"({ctx.business_start_hour:02d}:00-{ctx.business_end_hour:02d}:00 UTC, weekdays).",
                f"Source {ip} ({ctx.classify_ip(ip)}) had not been seen in any earlier successful logon for this "
                f"account in the dataset.",
                f"Host: '{row['hostname'] or 'not recorded'}', logon type: {row['logon_type'] or 'not recorded'}.",
            ],
            hypotheses=[
                "Unusual time plus unfamiliar source can be a sign that valid credentials are being used by someone "
                "other than the account owner (MITRE ATT&CK T1078).",
                "On-call work, travel, a new home router or a mobile hotspot explain this pattern just as well.",
            ],
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
                title=f"Logons from two external addresses within {_duration(previous['timestamp'], current['timestamp'])} "
                      f"for account {user}",
                severity=Severity.MEDIUM,
                severity_reason="Medium: concurrent external sessions need verification but are often legitimate.",
                entity_type="user", entity=user,
                trigger_reason=(f"Two successful logons for the same account from different external addresses "
                                f"within {params['rapid_source_change_minutes']} minutes."),
                observed_facts=[
                    f"Successful logon for '{user}' from {previous['source_ip']} at "
                    f"{format_timestamp(previous['timestamp'])}.",
                    f"Successful logon for '{user}' from {current['source_ip']} at "
                    f"{format_timestamp(current['timestamp'])}, {_duration(previous['timestamp'], current['timestamp'])} later.",
                    "No geolocation data is available in this dataset, so physical distance cannot be assessed.",
                ],
                hypotheses=[
                    "Two sources in quick succession may indicate the account is being used from two places at once, "
                    "for example after credential theft (MITRE ATT&CK T1078).",
                    "Switching between home broadband and a mobile hotspot, or a VPN client reconnecting, produces "
                    "the same pattern.",
                ],
                mitre_attack="T1078 Valid Accounts",
            ))
    return alerts
