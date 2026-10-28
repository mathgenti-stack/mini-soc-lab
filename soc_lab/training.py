"""Training mode: a structured triage questionnaire for practising Tier 1 SOC analysis.

The analyst answers a fixed set of questions about an alert *before* seeing the tool's own
analysis, then compares each answer with a reference built from the alert, the investigation
report and (when available) the ground-truth scenario labels.

All texts (questions, hints, ground-truth guides, reference answers) come from the translation
files in soc_lab/locales, so the questionnaire follows the language chosen in the dashboard.
Saved answers are keyed by question id, never by text, so switching language keeps them.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from . import i18n
from .detection.context import DetectionContext
from .i18n import t, tr
from .models import Alert, EventType, Result, format_timestamp
from .reporting import InvestigationReport

LANGUAGES = tuple(i18n.LANGUAGES)
NOT_ATTACK_SCENARIOS = {"normal", "data_quality_test"}


# ---------------------------------------------------------------------------
# Questions (texts: keys `stage.<id>`, `question.<id>.text` / `.hint` in soc_lab/locales)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Stage:
    id: str

    def label(self, lang: str) -> str:
        return t(f"stage.{self.id}", lang)


@dataclass(frozen=True)
class Question:
    id: str
    stage: str

    def text(self, lang: str) -> str:
        return t(f"question.{self.id}.text", lang)

    def hint(self, lang: str, **values) -> str:
        return t(f"question.{self.id}.hint", lang, **values)


STAGES = [Stage(stage_id) for stage_id in ("understand", "facts", "context", "decide", "communicate")]

QUESTIONS = [
    Question("rule", "understand"),
    Question("scope", "understand"),
    Question("counts", "facts"),
    Question("success", "facts"),
    Question("source", "facts"),
    Question("time", "facts"),
    Question("account_events", "facts"),
    Question("account_type", "context"),
    Question("benign", "context"),
    Question("missing", "context"),
    Question("verdict", "decide"),
    Question("severity", "decide"),
    Question("mitre", "decide"),
    Question("action", "decide"),
    Question("summary", "communicate"),
]
QUESTION_IDS = [q.id for q in QUESTIONS]


def questions_for_stage(stage_id: str) -> list[Question]:
    return [q for q in QUESTIONS if q.stage == stage_id]


# ---------------------------------------------------------------------------
# Ground truth ("gabarito") - texts: keys `scenario.<name>.verdict` / `.explanation`
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScenarioGuide:
    scenario: str
    expected_statuses: tuple[str, ...]

    def verdict(self, lang: str) -> str:
        return t(f"scenario.{self.scenario}.verdict", lang)

    def explanation(self, lang: str) -> str:
        return t(f"scenario.{self.scenario}.explanation", lang)


SCENARIO_GUIDES = {name: ScenarioGuide(name, statuses) for name, statuses in [
    ("simulated_brute_force", ("Closed - True Positive", "Escalated")),
    ("simulated_password_spray", ("Escalated",)),
    ("simulated_credential_compromise", ("Escalated",)),
    ("ambiguous_rapid_source_change", ("In Progress", "Escalated")),
    ("benign_forgotten_password", ("Closed - Benign True Positive",)),
    ("benign_authorised_scan", ("Closed - Benign True Positive",)),
    ("benign_on_call_engineer", ("Closed - Benign True Positive",)),
    ("benign_service_account_expired", ("Closed - Benign True Positive",)),
    ("normal", ("Closed - False Positive",)),
]}

EXPLAINED_STATUSES = ["Closed - True Positive", "Closed - Benign True Positive", "Closed - False Positive",
                      "Escalated", "In Progress"]


def status_explanations(lang: str, translate_names: bool = True) -> list[tuple[str, str]]:
    """(status name, what it means) for each closing/working status, in `lang`."""
    return [(t(f"status.{status}", lang) if translate_names else status, t(f"status_help.{status}", lang))
            for status in EXPLAINED_STATUSES]


def load_ground_truth(path: Path) -> dict[str, str]:
    """Read a ground-truth CSV (event_id, scenario) into a dict. Missing file -> empty dict."""
    if not path.exists():
        return {}
    frame = pd.read_csv(path, dtype=str).drop_duplicates("event_id", keep="first")
    return dict(zip(frame["event_id"], frame["scenario"]))


def scenario_for_alert(alert: Alert, truth: dict[str, str]) -> str | None:
    """Most common non-normal scenario among the alert's evidence, 'normal' if all are normal, None if unknown."""
    labels = [truth[eid] for eid in alert.evidence_event_ids if eid in truth]
    if not labels:
        return None
    interesting = Counter(label for label in labels if label not in NOT_ATTACK_SCENARIOS)
    return interesting.most_common(1)[0][0] if interesting else "normal"


# ---------------------------------------------------------------------------
# Reference answers
# ---------------------------------------------------------------------------
def _duration(start: pd.Timestamp, end: pd.Timestamp, lang: str) -> str:
    seconds = int((end - start).total_seconds())
    hours, rest = divmod(seconds, 3600)
    minutes = rest // 60
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min" if minutes else t("ref.under_one_minute", lang)


def _findings(report: InvestigationReport, lang: str, *keys: str) -> list[str]:
    """Context findings of the given kinds (Msg keys), rendered in `lang`."""
    return [tr(f, lang) for f in report.context_findings if getattr(f, "key", None) in keys]


def reference_answers(question_id: str, alert: Alert, report: InvestigationReport, config: dict,
                      lang: str = i18n.DEFAULT_LANGUAGE) -> list[str]:
    """Reference points for one question, built only from the alert, the report and the data."""
    ctx = DetectionContext.from_config(config)
    evidence = report.evidence
    playbook = report.playbook

    def items(values) -> list[str]:
        return [tr(value, lang) for value in values]

    if question_id == "rule":
        rule = f"{alert.rule_id} - {tr(alert.rule_name, lang)}" + (f" ({alert.pattern})" if alert.pattern else "")
        return [rule, tr(alert.trigger_reason, lang)]

    if question_id == "scope":
        none = t("ref.none", lang)
        return [
            t("ref.scope.accounts", lang, values=", ".join(alert.usernames) or none),
            t("ref.scope.source_ips", lang, values=", ".join(alert.source_ips) or none),
            t("ref.scope.hosts", lang, values=", ".join(alert.hostnames) or none),
            t("ref.scope.window", lang, first=format_timestamp(alert.first_seen),
              last=format_timestamp(alert.last_seen), duration=_duration(alert.first_seen, alert.last_seen, lang)),
        ]

    if question_id == "counts":
        failures = evidence[(evidence["event_type"] == EventType.LOGON) & (evidence["result"] == Result.FAILURE)]
        if failures.empty:
            return [t("ref.counts.none", lang)]
        span = _duration(failures["timestamp"].min(), failures["timestamp"].max(), lang)
        accounts = failures["username"].nunique()
        reasons = ", ".join(f"{r} ({n})" for r, n in failures["failure_reason"].value_counts().items() if r)
        line = t("ref.counts.summary", lang, count=len(failures), accounts=accounts, span=span)
        return [line] + ([t("ref.counts.reasons", lang, reasons=reasons)] if reasons else [])

    if question_id == "success":
        lines = _findings(report, lang, "finding.success", "finding.no_success")
        wins = evidence[(evidence["event_type"] == EventType.LOGON) & (evidence["result"] == Result.SUCCESS)]
        for _, row in wins.iterrows():
            lines.append(t("ref.success.in_evidence", lang, user=row["username"], ip=row["source_ip"],
                           time=format_timestamp(row["timestamp"])))
        return lines

    if question_id == "source":
        lines = [f"{ip}: {tr(ctx.classify_ip(ip), lang)}" for ip in alert.source_ips]
        return lines + _findings(report, lang, "finding.source")

    if question_id == "time":
        lines = []
        for label, ts in ((t("ref.time.start", lang), alert.first_seen), (t("ref.time.end", lang), alert.last_seen)):
            inside = ctx.is_business_hours(ts)
            day = t(f"weekday.{ts.weekday()}", lang)
            where = t("ref.time.inside" if inside else "ref.time.outside", lang)
            lines.append(f"{label}: {format_timestamp(ts)} ({day}) - {where}")
        return lines

    if question_id == "account_events":
        counts = evidence["event_type"].value_counts()
        lines = [f"{kind}: {int(counts[kind])}" for kind in
                 (EventType.ACCOUNT_LOCKOUT, EventType.ACCOUNT_UNLOCK, EventType.PASSWORD_CHANGE) if kind in counts]
        lines += _findings(report, lang, "finding.password_change", "finding.unlock", "finding.later_password_change")
        return lines or [t("ref.account_events.none", lang)]

    if question_id == "account_type":
        service = [u for u in alert.usernames if ctx.is_service_account(u)]
        others = [u for u in alert.usernames if not ctx.is_service_account(u)]
        lines = []
        if service:
            lines.append(t("ref.account_type.service", lang, users=", ".join(service)))
        if others:
            lines.append(t("ref.account_type.users", lang, count=len(others), users=", ".join(others)))
        lines += _findings(report, lang, "finding.never_succeeded")
        return lines or [t("ref.account_type.ip_only", lang)]

    if question_id == "benign":
        return (items(playbook.benign_explanations) + items(playbook.false_positive_considerations)
                + [t("ref.benign.indicator", lang, indicator=b) for b in report.benign_indicators])

    if question_id == "missing":
        return items(playbook.investigation_steps)

    if question_id == "verdict":
        return [tr(report.conclusion, lang)]

    if question_id == "severity":
        severity = t(f"severity.{alert.severity.value}", lang)
        return [f"{severity}: {tr(alert.severity_reason, lang)}" if alert.severity_reason else severity]

    if question_id == "mitre":
        return [alert.mitre_attack or t("ref.not_mapped", lang)]

    if question_id == "action":
        return items(playbook.containment_actions)

    if question_id == "summary":
        return [tr(report.conclusion, lang)] + items(alert.observed_facts[:3])

    raise KeyError(f"Unknown question: {question_id}")


# ---------------------------------------------------------------------------
# Saving answers and exporting them
# ---------------------------------------------------------------------------
def dataset_token(source_name: str) -> str:
    """Filesystem- and widget-key-safe identifier for a dataset."""
    return re.sub(r"[^A-Za-z0-9]+", "_", source_name).strip("_").lower() or "dataset"


def answers_path(base_dir: Path, source_name: str, alert_id: str) -> Path:
    return base_dir / f"{dataset_token(source_name)}__{alert_id}.json"


def load_progress(path: Path) -> dict:
    """Saved answers, status and reveal flag for one alert. Unreadable or missing file -> empty progress."""
    empty = {"answers": {}, "status": None, "revealed": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    answers = data.get("answers") if isinstance(data.get("answers"), dict) else {}
    return {"answers": {k: str(v) for k, v in answers.items() if k in QUESTION_IDS},
            "status": data.get("status"), "revealed": bool(data.get("revealed", False))}


def save_progress(path: Path, answers: dict[str, str], status: str | None, revealed: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"answers": {k: v for k, v in answers.items() if k in QUESTION_IDS and v.strip()},
               "status": status, "revealed": revealed,
               "updated": pd.Timestamp.now(tz="UTC").floor("s").isoformat()}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def answered_count(answers: dict[str, str]) -> int:
    return sum(1 for qid in QUESTION_IDS if answers.get(qid, "").strip())


def answers_to_markdown(answers: dict[str, str], lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    """Analyst triage answers formatted for the 'Analyst notes' section of the report."""
    blocks = []
    for stage in STAGES:
        stage_lines = []
        for question in questions_for_stage(stage.id):
            answer = answers.get(question.id, "").strip()
            if answer:
                stage_lines.append(f"**{question.text(lang)}**\n\n{answer}")
        if stage_lines:
            blocks.append(f"### {stage.label(lang)}\n\n" + "\n\n".join(stage_lines))
    return "\n\n".join(blocks)
