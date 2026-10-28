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
from .i18n import DEFAULT_LANGUAGE, Msg, t, tr
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
        findings.append(Msg("finding.related", ids=", ".join(related)))
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
            history = Msg("finding.history.none")
        else:
            history = Msg("finding.history.prior", count=len(prior),
                          users=f"{', '.join(prior_users[:5])}{' ...' if len(prior_users) > 5 else ''}")
        findings.append(Msg("finding.source", ip=ip, kind=ctx.classify_ip(ip), history=history))
    if alert.source_ips and all(ctx.is_internal(ip) for ip in alert.source_ips):
        benign.append(Msg("benign.all_internal"))

    users = alert.usernames
    follow_up = successes[successes["username"].isin(users) & successes["source_ip"].isin(alert.source_ips)
                          & successes["timestamp"].between(alert.first_seen, alert.last_seen + FOLLOW_UP_WINDOW)]
    success_observed = not follow_up.empty
    if success_observed:
        accounts = ", ".join(sorted(follow_up["username"].unique()))
        findings.append(Msg("finding.success", accounts=accounts))
    else:
        findings.append(Msg("finding.no_success"))

    never_succeeded = [user for user in users if successes[successes["username"] == user].empty]
    if never_succeeded:
        findings.append(Msg("finding.never_succeeded", users=", ".join(never_succeeded)))

    for user in users:
        if ctx.is_service_account(user):
            findings.append(Msg("finding.service_account", user=user))
            benign.append(Msg("benign.service_account", user=user))
        changes = events[(events["username"] == user) & (events["event_type"] == EventType.PASSWORD_CHANGE)
                         & events["timestamp"].between(alert.first_seen - PASSWORD_CHANGE_LOOKBACK, alert.last_seen)]
        for _, change in changes.iterrows():
            findings.append(Msg("finding.password_change", user=user, time=format_timestamp(change["timestamp"])))
            benign.append(Msg("benign.password_change", user=user))
        unlocks = events[(events["username"] == user) & (events["event_type"] == EventType.ACCOUNT_UNLOCK)
                         & events["timestamp"].between(alert.first_seen, alert.last_seen + FOLLOW_UP_WINDOW)]
        for _, unlock in unlocks.iterrows():
            findings.append(Msg("finding.unlock", user=user, time=format_timestamp(unlock["timestamp"]),
                                ip=unlock["source_ip"], kind=ctx.classify_ip(unlock["source_ip"])))
            benign.append(Msg("benign.unlock", user=user))
        changes_after = events[(events["username"] == user) & (events["event_type"] == EventType.PASSWORD_CHANGE)
                               & (events["timestamp"] > alert.last_seen)]
        if not changes_after.empty and ctx.is_service_account(user):
            findings.append(Msg("finding.later_password_change", user=user,
                                time=format_timestamp(changes_after["timestamp"].iloc[0])))
    return findings, sorted(set(benign)), success_observed


def _conclusion(alert: Alert, ctx: DetectionContext, benign: list[str], success_observed: bool) -> Msg:
    external = any(not ctx.is_internal(ip) for ip in alert.source_ips)
    if success_observed and external:
        text = Msg("conclusion.external_success")
    elif benign:
        text = Msg("conclusion.benign", indicators=Msg.join(benign, "; "))
    elif external:
        text = Msg("conclusion.external_no_success")
    else:
        text = Msg("conclusion.undetermined")
    return Msg.join([text, Msg("conclusion.basis")])


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _bullets(items: list[str], lang: str = DEFAULT_LANGUAGE) -> str:
    return "\n".join(f"- {tr(item, lang)}" for item in items) if items else f"- {t('report.none_recorded', lang)}"


def _numbered(items: list[str], lang: str = DEFAULT_LANGUAGE) -> str:
    return "\n".join(f"{n}. {tr(item, lang)}" for n, item in enumerate(items, start=1))


def _markdown_table(frame: pd.DataFrame) -> str:
    def cell(value) -> str:
        if isinstance(value, pd.Timestamp):
            return format_timestamp(value)
        return str(value).replace("|", "\\|") or "-"
    header = "| " + " | ".join(frame.columns) + " |"
    divider = "| " + " | ".join("---" for _ in frame.columns) + " |"
    rows = ["| " + " | ".join(cell(v) for v in row) + " |" for row in frame.itertuples(index=False)]
    return "\n".join([header, divider, *rows])


def render_markdown(report: InvestigationReport, lang: str = DEFAULT_LANGUAGE) -> str:
    """The investigation report as Markdown, in `lang`. Log data (evidence table, IDs) is never translated."""
    def label(key: str, **params) -> str:
        return t(f"report.{key}", lang, **params)

    alert = report.alert
    timeline = report.evidence.head(MARKDOWN_EVIDENCE_LIMIT)
    truncated = len(report.evidence) - len(timeline)
    timeline_note = f"\n\n_{label('truncated', count=truncated)}_" if truncated > 0 else ""
    affected = ", ".join(alert.usernames) or label("not_applicable")
    return f"""# {label('title')}: {report.incident_id}

**{tr(alert.title, lang)}**

| {label('field.field')} | {label('field.value')} |
| --- | --- |
| {label('field.incident_id')} | {report.incident_id} |
| {label('field.alert_id')} | {alert.alert_id} |
| {label('field.rule')} | {alert.rule_id} - {tr(alert.rule_name, lang)}{f' ({alert.pattern})' if alert.pattern else ''} |
| {label('field.severity')} | {t(f'severity.{alert.severity.value}', lang)} |
| {label('field.status')} | {t(f'status.{report.status}', lang)} |
| {label('field.first_seen')} | {format_timestamp(alert.first_seen)} |
| {label('field.last_seen')} | {format_timestamp(alert.last_seen)} |
| {label('field.accounts')} | {affected} |
| {label('field.source_ips')} | {', '.join(alert.source_ips) or label('not_recorded')} |
| {label('field.hosts')} | {', '.join(alert.hostnames) or label('not_recorded')} |
| {label('field.supporting_events')} | {alert.event_count} |
| {label('field.mitre')} | {alert.mitre_attack or label('not_mapped')} |
| {label('field.generated')} | {format_timestamp(report.generated_at)} |

> {label('disclaimer')}

## {label('section.why')}

{tr(alert.trigger_reason, lang)}

**{label('severity_rationale')}:** {tr(alert.severity_reason, lang)}

## {label('section.observed')}

{_bullets(alert.observed_facts, lang)}

## {label('section.context')}

{_bullets(report.context_findings, lang)}

## {label('section.hypotheses')}

{_bullets(alert.hypotheses, lang)}

## {label('section.benign')}

{_bullets(report.playbook.benign_explanations, lang)}

## {label('section.false_positive')}

{_bullets(report.playbook.false_positive_considerations, lang)}

## {label('section.timeline')}

{_markdown_table(timeline)}{timeline_note}

## {label('section.steps')}

{_numbered(report.playbook.investigation_steps, lang)}

## {label('section.containment')}

{label('containment_note')}

{_bullets(report.playbook.containment_actions, lang)}

## {label('section.conclusion')}

{tr(report.conclusion, lang)}

## {label('section.notes')}

{report.analyst_notes or '_' + label('no_notes') + '_'}

## {label('section.limitations')}

{_bullets(report.limitations, lang)}
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
