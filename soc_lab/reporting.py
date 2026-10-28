"""Build investigation reports from alerts and export them as Markdown and CSV.

Every statement in a report is derived from the events in the dataset. Where the data
cannot answer a question, the report says so instead of guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from .detection.context import DetectionContext
from .detection.playbooks import COMMON_LIMITATIONS, Playbook, get_playbook
from .metrics import alerts_to_frame
from .models import INCIDENT_STATUSES, Alert, EventType, Result, format_timestamp

EVIDENCE_COLUMNS = ["timestamp", "event_id", "event_type", "event_code", "result", "username", "source_ip",
                    "hostname", "logon_type", "failure_reason"]
MARKDOWN_EVIDENCE_LIMIT = 40
FOLLOW_UP_WINDOW = pd.Timedelta(hours=1)
PASSWORD_CHANGE_LOOKBACK = pd.Timedelta(days=7)


@dataclass
class InvestigationReport:
    incident_id: str
    alert: Alert
    status: str
    generated_at: pd.Timestamp
    evidence: pd.DataFrame
    context_findings: list[str]
    benign_indicators: list[str]
    conclusion: str
    playbook: Playbook
    limitations: list[str]
    related_alert_ids: list[str] = field(default_factory=list)
    analyst_notes: str = ""


def build_investigation_report(alert: Alert, events: pd.DataFrame, config: dict,
                               all_alerts: list[Alert] | None = None, status: str = "New",
                               analyst_notes: str = "", generated_at: pd.Timestamp | None = None
                               ) -> InvestigationReport:
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Unknown incident status: {status}")
    ctx = DetectionContext.from_config(config)
    evidence = (events[events["event_id"].isin(alert.evidence_event_ids)]
                .sort_values("timestamp", kind="stable")[EVIDENCE_COLUMNS].reset_index(drop=True))
    findings, benign, success_observed = _context_checks(alert, events, ctx)
    related = [other.alert_id for other in (all_alerts or []) if other.alert_id != alert.alert_id and (
        set(other.usernames) & set(alert.usernames) or set(other.source_ips) & set(alert.source_ips))]
    if related:
        findings.append(f"Related alerts sharing an account or source address: {', '.join(related)}.")
    playbook = get_playbook(alert.playbook_key)
    return InvestigationReport(
        incident_id=alert.alert_id.replace("ALR", "INC"),
        alert=alert,
        status=status,
        generated_at=generated_at or pd.Timestamp.now(tz="UTC").floor("s"),
        evidence=evidence,
        context_findings=findings,
        benign_indicators=benign,
        conclusion=_conclusion(alert, ctx, benign, success_observed),
        playbook=playbook,
        limitations=playbook.limitations + COMMON_LIMITATIONS,
        related_alert_ids=related,
        analyst_notes=analyst_notes.strip(),
    )


def _context_checks(alert: Alert, events: pd.DataFrame, ctx: DetectionContext) -> tuple[list[str], list[str], bool]:
    """Look around the alert for facts that make it more or less concerning."""
    findings: list[str] = []
    benign: list[str] = []
    before = events[events["timestamp"] < alert.first_seen]
    successes = events[(events["event_type"] == EventType.LOGON) & (events["result"] == Result.SUCCESS)]

    for ip in alert.source_ips:
        prior = before[(before["source_ip"] == ip) & (before["event_type"] == EventType.LOGON)
                       & (before["result"] == Result.SUCCESS)]
        prior_users = sorted(prior["username"].unique())
        if prior.empty:
            history = "no successful logons from this address before the alert"
        else:
            history = (f"{len(prior)} earlier successful logon(s) from this address, by: "
                       f"{', '.join(prior_users[:5])}{' ...' if len(prior_users) > 5 else ''}")
        findings.append(f"Source {ip} is {ctx.classify_ip(ip)}; dataset shows {history}.")
    if alert.source_ips and all(ctx.is_internal(ip) for ip in alert.source_ips):
        benign.append("all source addresses are internal")

    users = alert.usernames
    follow_up = successes[successes["username"].isin(users) & successes["source_ip"].isin(alert.source_ips)
                          & successes["timestamp"].between(alert.first_seen, alert.last_seen + FOLLOW_UP_WINDOW)]
    success_observed = not follow_up.empty
    if success_observed:
        accounts = ", ".join(sorted(follow_up["username"].unique()))
        findings.append(f"Successful logon(s) from the alert's source address(es) were recorded for: {accounts} "
                        f"(between first activity and one hour after the last).")
    else:
        findings.append("No successful logon from the alert's source address(es) for the affected account(s) was "
                        "recorded between first activity and one hour after the last.")

    never_succeeded = [user for user in users if successes[successes["username"] == user].empty]
    if never_succeeded:
        findings.append(f"Account name(s) with no successful logon anywhere in the dataset: "
                        f"{', '.join(never_succeeded)} (they may not exist in the directory).")

    for user in users:
        if ctx.is_service_account(user):
            findings.append(f"'{user}' matches the service account naming convention.")
            benign.append(f"'{user}' appears to be a service account")
        changes = events[(events["username"] == user) & (events["event_type"] == EventType.PASSWORD_CHANGE)
                         & events["timestamp"].between(alert.first_seen - PASSWORD_CHANGE_LOOKBACK, alert.last_seen)]
        for _, change in changes.iterrows():
            findings.append(f"Password change recorded for '{user}' at {format_timestamp(change['timestamp'])}.")
            benign.append(f"recent password change for '{user}'")
        unlocks = events[(events["username"] == user) & (events["event_type"] == EventType.ACCOUNT_UNLOCK)
                         & events["timestamp"].between(alert.first_seen, alert.last_seen + FOLLOW_UP_WINDOW)]
        for _, unlock in unlocks.iterrows():
            findings.append(f"Account unlock for '{user}' recorded at {format_timestamp(unlock['timestamp'])} from "
                            f"{unlock['source_ip']} ({ctx.classify_ip(unlock['source_ip'])}).")
            benign.append(f"account unlock recorded for '{user}'")
        changes_after = events[(events["username"] == user) & (events["event_type"] == EventType.PASSWORD_CHANGE)
                               & (events["timestamp"] > alert.last_seen)]
        if not changes_after.empty and ctx.is_service_account(user):
            findings.append(f"A later password change for '{user}' was recorded at "
                            f"{format_timestamp(changes_after['timestamp'].iloc[0])}.")
    return findings, sorted(set(benign)), success_observed


def _conclusion(alert: Alert, ctx: DetectionContext, benign: list[str], success_observed: bool) -> str:
    external = any(not ctx.is_internal(ip) for ip in alert.source_ips)
    if success_observed and external:
        text = ("The evidence shows activity matching the detection criteria together with at least one successful "
                "logon from an external source address. This is consistent with possible unauthorised access but "
                "does not confirm it. Escalation to a senior analyst is recommended if the account owner cannot "
                "confirm the activity.")
    elif benign:
        text = ("The evidence shows activity matching the detection criteria. Contextual indicators support a "
                f"possible benign explanation ({'; '.join(benign)}). These indicators must be verified, for example "
                "against service desk tickets or change records, before the alert is closed.")
    elif external:
        text = ("The evidence shows activity from an external source address matching the detection criteria. No "
                "successful logon from that address for the affected account(s) was recorded in this dataset, so "
                "the attempts appear to have been unsuccessful based on the available data.")
    else:
        text = ("The evidence shows activity matching the detection criteria. The available data does not establish "
                "whether it was malicious; further investigation is required to classify this alert.")
    return text + " This conclusion is based only on the authentication events in this dataset."


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "- None recorded."


def _numbered(items: list[str]) -> str:
    return "\n".join(f"{n}. {item}" for n, item in enumerate(items, start=1))


def _markdown_table(frame: pd.DataFrame) -> str:
    def cell(value) -> str:
        if isinstance(value, pd.Timestamp):
            return format_timestamp(value)
        return str(value).replace("|", "\\|") or "-"
    header = "| " + " | ".join(frame.columns) + " |"
    divider = "| " + " | ".join("---" for _ in frame.columns) + " |"
    rows = ["| " + " | ".join(cell(v) for v in row) + " |" for row in frame.itertuples(index=False)]
    return "\n".join([header, divider, *rows])


def render_markdown(report: InvestigationReport) -> str:
    alert = report.alert
    timeline = report.evidence.head(MARKDOWN_EVIDENCE_LIMIT)
    truncated = len(report.evidence) - len(timeline)
    timeline_note = (f"\n\n_{truncated} further event(s) omitted here; see the CSV evidence export for the full list._"
                     if truncated > 0 else "")
    affected = ", ".join(alert.usernames) or "Not applicable"
    return f"""# Incident Investigation Report: {report.incident_id}

**{alert.title}**

| Field | Value |
| --- | --- |
| Incident ID | {report.incident_id} |
| Alert ID | {alert.alert_id} |
| Detection rule | {alert.rule_id} - {alert.rule_name}{f' ({alert.pattern})' if alert.pattern else ''} |
| Severity | {alert.severity.value} |
| Incident status | {report.status} |
| First seen | {format_timestamp(alert.first_seen)} |
| Last seen | {format_timestamp(alert.last_seen)} |
| Affected account(s) | {affected} |
| Source IP address(es) | {', '.join(alert.source_ips) or 'Not recorded'} |
| Host(s) | {', '.join(alert.hostnames) or 'Not recorded'} |
| Supporting events | {alert.event_count} |
| MITRE ATT&CK (possible) | {alert.mitre_attack or 'Not mapped'} |
| Report generated | {format_timestamp(report.generated_at)} |

> This report was generated from synthetic lab data. An alert is a lead for investigation, not proof of malicious activity.

## 1. Why this alert was generated

{alert.trigger_reason}

**Severity rationale:** {alert.severity_reason}

## 2. Observed behaviour (facts from the logs)

{_bullets(alert.observed_facts)}

## 3. Context checks

{_bullets(report.context_findings)}

## 4. Hypotheses (not confirmed)

{_bullets(alert.hypotheses)}

## 5. Potential benign explanations

{_bullets(report.playbook.benign_explanations)}

## 6. False-positive considerations

{_bullets(report.playbook.false_positive_considerations)}

## 7. Event timeline (supporting log events)

{_markdown_table(timeline)}{timeline_note}

## 8. Recommended investigation steps

{_numbered(report.playbook.investigation_steps)}

## 9. Suggested containment actions

Only to be proposed through the organisation's change and incident processes, and only if the investigation supports them.

{_bullets(report.playbook.containment_actions)}

## 10. Evidence-based conclusion

{report.conclusion}

## 11. Analyst notes

{report.analyst_notes or '_No analyst notes recorded._'}

## 12. Limitations of this investigation

{_bullets(report.limitations)}
"""


def evidence_to_csv(report: InvestigationReport) -> str:
    frame = report.evidence.copy()
    frame.insert(0, "incident_id", report.incident_id)
    frame["timestamp"] = frame["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return frame.to_csv(index=False)


def alerts_to_csv(alerts: list[Alert]) -> str:
    frame = alerts_to_frame(alerts)
    for column in ("first_seen", "last_seen"):
        if not frame.empty:
            frame[column] = pd.to_datetime(frame[column], utc=True).dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return frame.to_csv(index=False)


def save_report(report: InvestigationReport, output_dir: str | Path) -> tuple[Path, Path]:
    """Write `<incident>.md` and `<incident>_evidence.csv` into output_dir."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    markdown_path = directory / f"{report.incident_id}.md"
    csv_path = directory / f"{report.incident_id}_evidence.csv"
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    csv_path.write_text(evidence_to_csv(report), encoding="utf-8", newline="")
    return markdown_path, csv_path
