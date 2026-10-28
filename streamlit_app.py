"""Mini SOC Lab dashboard.  Run with:  streamlit run streamlit_app.py"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from soc_lab.config import DEFAULT_CONFIG_PATH, ConfigError, load_config, with_overrides
from soc_lab.detection import run_detection
from soc_lab.filters import filter_alerts, filter_events
from soc_lab import training
from soc_lab.log_generator import GeneratorSettings, generate_csv_text, generate_events
from soc_lab.log_loader import LogFileError, load_events
from soc_lab.metrics import alerts_to_frame, compute_kpis, logon_timeline, top_failure_sources
from soc_lab.models import INCIDENT_STATUSES, SEVERITY_ORDER, format_timestamp
from soc_lab.reporting import alerts_to_csv, build_investigation_report, evidence_to_csv, render_markdown

SAMPLE_LOG_PATH = Path(__file__).parent / "data" / "sample_auth_logs.csv"
GROUND_TRUTH_PATH = Path(__file__).parent / "data" / "sample_auth_logs_ground_truth.csv"
ANSWERS_DIR = Path(os.environ.get("SOC_LAB_ANSWERS_DIR", Path(__file__).parent / "training_answers"))
SEVERITY_NAMES = [s.value for s in reversed(SEVERITY_ORDER)]  # Critical first
SEVERITY_COLOURS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#2a78d6"}
RESULT_COLOURS = {"SUCCESS": "#2a78d6", "FAILURE": "#eb6834", "INFO": "#8a8984"}

st.set_page_config(page_title="Mini SOC Lab", page_icon=":shield:", layout="wide")


@st.cache_data(show_spinner="Analysing events...")
def run_pipeline(csv_bytes: bytes, source_name: str, config_json: str):
    result = load_events(csv_bytes, source_name)
    alerts = run_detection(result.events, json.loads(config_json))
    return result, alerts


@st.cache_data(show_spinner="Generating synthetic events...")
def generate_dataset(seed: int, days: int) -> bytes:
    return generate_csv_text(GeneratorSettings(seed=seed, days=days)).encode("utf-8")


@st.cache_data
def sample_ground_truth() -> dict[str, str]:
    return training.load_ground_truth(GROUND_TRUTH_PATH)


@st.cache_data(show_spinner=False)
def generated_ground_truth(seed: int, days: int) -> dict[str, str]:
    frame = generate_events(GeneratorSettings(seed=seed, days=days)).drop_duplicates("event_id", keep="first")
    return dict(zip(frame["event_id"], frame["scenario"]))


def severity_scale() -> alt.Scale:
    return alt.Scale(domain=SEVERITY_NAMES, range=[SEVERITY_COLOURS[s] for s in SEVERITY_NAMES])


def result_scale(domain: list[str]) -> alt.Scale:
    return alt.Scale(domain=domain, range=[RESULT_COLOURS[r] for r in domain])


# ---------------------------------------------------------------------------
# Sidebar: data source and detection tuning
# ---------------------------------------------------------------------------
st.sidebar.title("Mini SOC Lab")
st.sidebar.caption("Authentication log triage on synthetic data")

source_choice = st.sidebar.radio(
    "Data source", ["Sample dataset", "Generate new synthetic dataset", "Upload CSV"],
    help="All bundled and generated data is fictional.",
)
if source_choice == "Sample dataset":
    if not SAMPLE_LOG_PATH.exists():
        st.error("Sample dataset not found. Create it with: `python -m soc_lab.cli generate`")
        st.stop()
    csv_bytes, source_name = SAMPLE_LOG_PATH.read_bytes(), SAMPLE_LOG_PATH.name
    ground_truth = sample_ground_truth()
elif source_choice == "Generate new synthetic dataset":
    seed = st.sidebar.number_input("Random seed", min_value=0, max_value=1_000_000, value=7, step=1)
    days = st.sidebar.slider("Days of activity", min_value=7, max_value=28, value=14)
    csv_bytes, source_name = generate_dataset(int(seed), int(days)), f"generated (seed {seed}, {days} days)"
    ground_truth = generated_ground_truth(int(seed), int(days))
    st.sidebar.download_button("Download generated CSV", csv_bytes, file_name=f"auth_logs_seed{seed}.csv",
                               mime="text/csv")
else:
    upload = st.sidebar.file_uploader("Authentication log CSV", type=["csv"],
                                      help="Must follow the schema in docs/log_format.md.")
    if upload is None:
        st.info("Upload a CSV file using the sidebar to begin.")
        st.stop()
    csv_bytes, source_name = upload.getvalue(), upload.name
    ground_truth = {}

try:
    base_config = load_config(DEFAULT_CONFIG_PATH)
except ConfigError as exc:
    st.error(f"Detection configuration error: {exc}")
    st.stop()

with st.sidebar.expander("Detection thresholds"):
    st.caption("Defaults come from config/detection_rules.json. Changes apply to this session only.")
    rules = base_config["rules"]
    overrides = {
        "R001": {"enabled": st.checkbox("R001 Multiple failed logons", rules["R001"]["enabled"]),
                 "failure_threshold": st.number_input("R001 failures", 1, 100, rules["R001"]["failure_threshold"]),
                 "window_minutes": st.number_input("R001 window (minutes)", 1, 1440, rules["R001"]["window_minutes"])},
        "R002": {"enabled": st.checkbox("R002 Success after failures", rules["R002"]["enabled"]),
                 "min_failures": st.number_input("R002 minimum prior failures", 1, 100, rules["R002"]["min_failures"])},
        "R003": {"enabled": st.checkbox("R003 High failure rate", rules["R003"]["enabled"]),
                 "min_attempts": st.number_input("R003 minimum attempts per day", 1, 1000, rules["R003"]["min_attempts"]),
                 "failure_rate_threshold": st.slider("R003 failure rate", 0.05, 1.0,
                                                     float(rules["R003"]["failure_rate_threshold"]), 0.05)},
        "R004": {"enabled": st.checkbox("R004 One IP, many accounts", rules["R004"]["enabled"]),
                 "min_distinct_accounts": st.number_input("R004 distinct accounts", 2, 100,
                                                          rules["R004"]["min_distinct_accounts"])},
        "R005": {"enabled": st.checkbox("R005 Suspicious patterns", rules["R005"]["enabled"])},
    }
try:
    config = with_overrides(base_config, overrides)
except ConfigError as exc:
    st.sidebar.error(str(exc))
    config = base_config

try:
    load_result, alerts = run_pipeline(csv_bytes, source_name, json.dumps(config))
except LogFileError as exc:
    st.error(f"Could not load the log data: {exc}")
    st.stop()

events, quality = load_result.events, load_result.quality

st.title("Mini SOC Lab - Authentication Monitoring")
st.caption(f"Source: **{source_name}** - {quality.rows_accepted} events accepted, {quality.rows_rejected} rejected, "
           f"{quality.exact_duplicates_removed} duplicates removed. All data is synthetic.")

if events.empty:
    for warning in quality.warnings:
        st.warning(warning)
    st.info("There are no valid events to analyse.")
    st.stop()

# ---------------------------------------------------------------------------
# Filters (shared across tabs)
# ---------------------------------------------------------------------------
first_day, last_day = events["timestamp"].min().date(), events["timestamp"].max().date()
with st.container(border=True):
    col_date, col_user, col_ip, col_type, col_sev = st.columns([1.3, 1, 1, 1, 1])
    date_range = col_date.date_input("Date range (UTC)", (first_day, last_day), min_value=first_day,
                                     max_value=last_day)
    selected_users = col_user.multiselect("Username", sorted(events["username"].unique()))
    selected_ips = col_ip.multiselect("Source IP", sorted(events["source_ip"].unique()))
    selected_types = col_type.multiselect("Event type", sorted(events["event_type"].unique()))
    selected_severities = col_sev.multiselect("Alert severity", SEVERITY_NAMES)

start_day, end_day = (date_range if isinstance(date_range, tuple) and len(date_range) == 2
                      else (first_day, last_day))
view_events = filter_events(events, start_day, end_day, selected_users, selected_ips, selected_types)
view_alerts = filter_alerts(alerts, start_day, end_day, selected_users, selected_ips, selected_severities)
kpis = compute_kpis(view_events, view_alerts)

tab_overview, tab_alerts, tab_events, tab_investigate, tab_quality, tab_about = st.tabs(
    ["Overview", "Alerts", "Event Explorer", "Investigation", "Data Quality", "About"])

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
with tab_overview:
    m = st.columns(6)
    m[0].metric("Events analysed", f"{kpis['total_events']:,}")
    m[1].metric("Successful logons", f"{kpis['successful_logins']:,}")
    m[2].metric("Failed logons", f"{kpis['failed_logins']:,}", help="LOGON events with result FAILURE.")
    m[3].metric("Failure rate", f"{kpis['failure_rate']:.1%}")
    m[4].metric("Account lockouts", kpis["account_lockouts"])
    m[5].metric("Alerts generated", kpis["total_alerts"])

    left, right = st.columns([1, 2])
    with left:
        st.subheader("Alerts by severity")
        severity_frame = pd.DataFrame({"severity": list(kpis["alerts_by_severity"]),
                                       "alerts": list(kpis["alerts_by_severity"].values())})
        bars = alt.Chart(severity_frame).mark_bar(cornerRadiusEnd=4, size=26).encode(
            y=alt.Y("severity:N", sort=SEVERITY_NAMES, title=None),
            x=alt.X("alerts:Q", title="Alerts", axis=alt.Axis(tickMinStep=1)),
            color=alt.Color("severity:N", scale=severity_scale(), legend=None),
            tooltip=["severity", "alerts"],
        )
        labels = bars.mark_text(align="left", dx=4).encode(text="alerts:Q", color=alt.value("#52514e"))
        st.altair_chart(bars + labels, width="stretch")
    with right:
        st.subheader("Timeline of authentication activity and alerts")
        timeline = logon_timeline(view_events)
        failures = timeline[timeline["result"] == "FAILURE"]
        base = alt.Chart(failures).mark_bar(color=RESULT_COLOURS["FAILURE"], width=3).encode(
            x=alt.X("bucket:T", title="Time (UTC, hourly)"),
            y=alt.Y("count:Q", title="Failed logons per hour"),
            tooltip=[alt.Tooltip("bucket:T", title="Hour", format="%Y-%m-%d %H:00"),
                     alt.Tooltip("count:Q", title="Failed logons")],
        )
        alert_points = alerts_to_frame(view_alerts)
        layers = base
        if not alert_points.empty:
            dots = alt.Chart(alert_points).mark_point(filled=True, size=110, stroke="white", strokeWidth=2).encode(
                x="first_seen:T",
                y=alt.value(8),
                color=alt.Color("severity:N", scale=severity_scale(), title="Alert severity"),
                shape=alt.Shape("severity:N", sort=SEVERITY_NAMES, legend=None),
                tooltip=["alert_id", "severity", "title", alt.Tooltip("first_seen:T", format="%Y-%m-%d %H:%M")],
            )
            layers = base + dots
        st.altair_chart(layers.properties(height=280), width="stretch")
        st.caption("Bars: failed logons per hour. Markers along the top: alerts at their first-seen time "
                   "(hover for details).")

    st.subheader("Top sources of failed logons")
    st.dataframe(top_failure_sources(view_events), hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
with tab_alerts:
    st.subheader(f"Alert queue ({len(view_alerts)})")
    if not view_alerts:
        st.info("No alerts match the current filters.")
    else:
        frame = alerts_to_frame(view_alerts)
        st.dataframe(
            frame[["alert_id", "severity", "rule_id", "title", "entity", "first_seen", "last_seen", "event_count",
                   "source_ips", "mitre_attack"]],
            hide_index=True, width="stretch",
            column_config={"first_seen": st.column_config.DatetimeColumn("First seen", format="YYYY-MM-DD HH:mm"),
                           "last_seen": st.column_config.DatetimeColumn("Last seen", format="YYYY-MM-DD HH:mm"),
                           "event_count": st.column_config.NumberColumn("Events")},
        )
        st.download_button("Export alert list (CSV)", alerts_to_csv(view_alerts), "alerts.csv", "text/csv")
        st.caption("Open the Investigation tab to review the evidence behind any alert.")

# ---------------------------------------------------------------------------
# Event explorer
# ---------------------------------------------------------------------------
with tab_events:
    search = st.text_input("Search events", placeholder="e.g. 203.0.113, BAD_PASSWORD, LON-VPN-01, EVT-000123")
    shown = filter_events(view_events, search=search)
    st.caption(f"{len(shown):,} of {len(events):,} events shown")
    st.dataframe(shown, hide_index=True, width="stretch",
                 column_config={"timestamp": st.column_config.DatetimeColumn("timestamp",
                                                                             format="YYYY-MM-DD HH:mm:ss")})
    export = shown.assign(timestamp=shown["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
    st.download_button("Export filtered events (CSV)", export.to_csv(index=False), "filtered_events.csv", "text/csv")

# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------
def render_alert_summary(alert, status: str, show_mitre: bool) -> None:
    info = st.columns(4)
    info[0].metric("Severity", alert.severity.value)
    info[1].metric("Rule", alert.rule_id)
    info[2].metric("Supporting events", alert.event_count)
    info[3].metric("Status", status)
    lines = [
        f"**Detection rule:** {alert.rule_name}{f' ({alert.pattern})' if alert.pattern else ''}",
        f"**First seen:** {format_timestamp(alert.first_seen)} - **Last seen:** {format_timestamp(alert.last_seen)}",
        f"**Affected account(s):** {', '.join(alert.usernames) or 'n/a'}",
        f"**Source IP(s):** {', '.join(alert.source_ips)} - **Host(s):** {', '.join(alert.hostnames) or 'n/a'}",
    ]
    if show_mitre:
        lines.append(f"**MITRE ATT&CK (possible):** {alert.mitre_attack}")
    st.markdown("  \n".join(lines))


def render_evidence(report) -> None:
    evidence = report.evidence
    result_domain = [r for r in RESULT_COLOURS if r in set(evidence["result"])]
    evidence_chart = alt.Chart(evidence).mark_point(filled=True, size=90, stroke="white", strokeWidth=1.5).encode(
        x=alt.X("timestamp:T", title="Time (UTC)"),
        y=alt.Y("event_type:N", title=None),
        color=alt.Color("result:N", scale=result_scale(result_domain), title="Result"),
        shape=alt.Shape("result:N", legend=None),
        tooltip=["event_id", alt.Tooltip("timestamp:T", format="%Y-%m-%d %H:%M:%S"), "username", "source_ip",
                 "hostname", "result", "failure_reason"],
    ).properties(height=170)
    st.altair_chart(evidence_chart, width="stretch")
    st.dataframe(evidence, hide_index=True, width="stretch",
                 column_config={"timestamp": st.column_config.DatetimeColumn("timestamp",
                                                                             format="YYYY-MM-DD HH:mm:ss")})


def render_tool_analysis(alert, report) -> None:
    with st.container(border=True):
        st.markdown("**Why this alert was generated**")
        st.write(alert.trigger_reason)
        st.caption(f"Severity rationale: {alert.severity_reason}")

    facts_col, hypo_col = st.columns(2)
    with facts_col:
        st.markdown("#### Observed facts")
        st.markdown("\n".join(f"- {fact}" for fact in alert.observed_facts))
        st.markdown("#### Context checks")
        st.markdown("\n".join(f"- {finding}" for finding in report.context_findings))
    with hypo_col:
        st.markdown("#### Hypotheses (not confirmed)")
        st.markdown("\n".join(f"- {h}" for h in alert.hypotheses))
        st.markdown("#### Potential benign explanations")
        st.markdown("\n".join(f"- {b}" for b in report.playbook.benign_explanations))
        st.markdown("#### False-positive considerations")
        st.markdown("\n".join(f"- {c}" for c in report.playbook.false_positive_considerations))

    steps_col, contain_col = st.columns(2)
    with steps_col:
        st.markdown("#### Recommended investigation steps")
        st.markdown("\n".join(f"{n}. {s}" for n, s in enumerate(report.playbook.investigation_steps, 1)))
    with contain_col:
        st.markdown("#### Suggested containment actions")
        st.caption("Proposals only - to be raised through the organisation's processes if justified.")
        st.markdown("\n".join(f"- {c}" for c in report.playbook.containment_actions))

    st.markdown("#### Evidence-based conclusion")
    st.info(report.conclusion)
    with st.expander("Limitations of this investigation"):
        st.markdown("\n".join(f"- {item}" for item in report.limitations))


def render_exports(report) -> None:
    dl1, dl2, _ = st.columns([1, 1, 2])
    dl1.download_button("Export report (Markdown)", render_markdown(report), f"{report.incident_id}.md",
                        "text/markdown", type="primary")
    dl2.download_button("Export evidence (CSV)", evidence_to_csv(report), f"{report.incident_id}_evidence.csv",
                        "text/csv")


def render_training(alert, base_report, saved: dict, token: str, lang: str) -> None:
    """Questionnaire first, tool analysis and ground truth only after the analyst chooses to reveal them."""
    pt = lang == "pt"
    key = f"{token}_{alert.alert_id}"
    status_key, reveal_key = f"status_{key}", f"reveal_{key}"
    if status_key not in st.session_state:
        st.session_state[status_key] = saved["status"] if saved["status"] in INCIDENT_STATUSES else "New"
    if reveal_key not in st.session_state:
        st.session_state[reveal_key] = saved["revealed"]

    st.info(
        "**Como treinar:** responda as perguntas abaixo usando a tabela de evidências e a aba **Event Explorer**. "
        "A análise da ferramenta fica escondida. Quando terminar, ligue **Mostrar resposta** no final da página e "
        "compare. Suas respostas são salvas automaticamente." if pt else
        "**How to practise:** answer the questions below using the evidence table and the **Event Explorer** tab. "
        "The tool's analysis is hidden. When you finish, switch on **Show answer** at the bottom and compare. "
        "Your answers are saved automatically.")

    render_alert_summary(alert, st.session_state[status_key], show_mitre=False)
    st.markdown("#### " + ("Evidências do alerta (dados brutos)" if pt else "Alert evidence (raw data)"))
    render_evidence(base_report)

    hours = base_config["environment"]["business_hours"]
    answers: dict[str, str] = {}
    for stage in training.STAGES:
        with st.container(border=True):
            st.markdown(f"#### {stage.pt if pt else stage.en}")
            for question in training.questions_for_stage(stage.id):
                answer_key = f"ans_{key}_{question.id}"
                if answer_key not in st.session_state:
                    st.session_state[answer_key] = saved["answers"].get(question.id, "")
                st.markdown(f"**{question.text(lang)}**")
                st.caption("💡 " + question.hint(lang, start=int(hours["start_hour"]), end=int(hours["end_hour"])))
                answers[question.id] = st.text_area(question.text(lang), key=answer_key, height=90,
                                                    label_visibility="collapsed")
            if stage.id == "decide":
                st.selectbox("Status do incidente (a sua decisão)" if pt else "Incident status (your decision)",
                             INCIDENT_STATUSES, key=status_key)
                with st.expander("O que significa cada status?" if pt else "What does each status mean?"):
                    st.markdown("\n".join(f"- **{name}:** {meaning}"
                                          for name, meaning in training.STATUS_EXPLANATIONS[lang]))
    status = st.session_state[status_key]

    total = len(training.QUESTIONS)
    done = training.answered_count(answers)
    st.progress(done / total, text=(f"{done} de {total} perguntas respondidas" if pt
                                    else f"{done} of {total} questions answered"))
    can_reveal = bool(answers.get("verdict", "").strip())
    st.toggle("Mostrar resposta (análise da ferramenta e gabarito)" if pt
              else "Show answer (tool analysis and ground truth)",
              key=reveal_key, disabled=not can_reveal and not st.session_state[reveal_key])
    if not can_reveal and not st.session_state[reveal_key]:
        st.caption("Responda pelo menos a pergunta do veredito para liberar a resposta." if pt
                   else "Answer at least the verdict question to unlock the answer.")
    revealed = st.session_state[reveal_key]

    changed = ({k: v for k, v in answers.items() if v.strip()} != saved["answers"]
               or (status != (saved["status"] or "New")) or revealed != saved["revealed"])
    if changed:
        try:
            training.save_progress(training.answers_path(ANSWERS_DIR, source_name, alert.alert_id),
                                   answers, status, revealed)
        except OSError as exc:
            st.warning(f"Could not save your answers: {exc}")
        else:
            if revealed != saved["revealed"]:
                st.rerun()  # refresh the progress counter and the ✅ marks in the alert list

    report = replace(base_report, status=status, analyst_notes=training.answers_to_markdown(answers, lang))
    if revealed:
        st.divider()
        scenario = training.scenario_for_alert(alert, ground_truth)
        guide = training.SCENARIO_GUIDES.get(scenario) if scenario else None
        with st.container(border=True):
            st.markdown("### " + ("Gabarito" if pt else "Ground truth"))
            if guide is None:
                st.write("Este dataset não tem gabarito (ex.: CSV enviado por upload). Compare com a análise abaixo."
                         if pt else "This dataset has no ground truth (e.g. an uploaded CSV). Compare with the "
                                    "analysis below.")
            else:
                st.markdown(f"**{guide.verdict_pt if pt else guide.verdict_en}**")
                st.write(guide.explanation_pt if pt else guide.explanation_en)
                expected = " / ".join(guide.expected_statuses)
                if status in guide.expected_statuses:
                    st.success(f"{'Seu status' if pt else 'Your status'}: {status} ✅")
                else:
                    st.warning(f"{'Seu status' if pt else 'Your status'}: {status} - "
                               f"{'esperado' if pt else 'expected'}: {expected}")
                st.caption(("Cenário no arquivo de gabarito: " if pt else "Scenario in the ground-truth file: ")
                           + f"`{scenario}`")

        st.markdown("### " + ("Compare as suas respostas" if pt else "Compare your answers"))
        for stage in training.STAGES:
            st.markdown(f"**{stage.pt if pt else stage.en}**")
            for question in training.questions_for_stage(stage.id):
                answered = bool(answers[question.id].strip())
                with st.expander(("✍️ " if answered else "⬜ ") + question.text(lang)):
                    mine, ref = st.columns(2)
                    mine.markdown("**" + ("Sua resposta" if pt else "Your answer") + "**")
                    mine.write(answers[question.id] if answered else ("_Sem resposta._" if pt else "_No answer._"))
                    ref.markdown("**" + ("Referência" if pt else "Reference") + "**")
                    points = training.reference_answers(question.id, alert, base_report, config, lang)
                    ref.markdown("\n".join(f"- {point}" for point in points) or "-")

        st.markdown("### " + ("Análise completa da ferramenta" if pt else "Full tool analysis"))
        st.markdown(f"**MITRE ATT&CK (possible):** {alert.mitre_attack}")
        render_tool_analysis(alert, report)

    st.divider()
    st.caption("O relatório exportado inclui as suas respostas na seção 'Analyst notes'." if pt
               else "The exported report includes your answers in the 'Analyst notes' section.")
    render_exports(report)


with tab_investigate:
    if not view_alerts:
        st.info("No alerts match the current filters.")
    else:
        token = training.dataset_token(source_name)
        progress = {a.alert_id: training.load_progress(training.answers_path(ANSWERS_DIR, source_name, a.alert_id))
                    for a in view_alerts}

        mode_col, lang_col = st.columns([2, 1])
        training_mode = mode_col.toggle("Modo treino / Training mode", value=True, key="training_mode",
                                        help="Hides the tool's analysis until you have answered the triage questions.")
        lang = "pt" if lang_col.radio("Idioma / Language", ["Português", "English"], horizontal=True,
                                      key="training_lang") == "Português" else "en"

        trained = sum(1 for p in progress.values() if p["revealed"])
        if training_mode:
            st.caption((f"Casos treinados: {trained} de {len(view_alerts)} (✅ = já comparado com a resposta)"
                        if lang == "pt" else
                        f"Cases practised: {trained} of {len(view_alerts)} (✅ = already compared with the answer)"))
        labels = {a.alert_id: f"{'✅ ' if training_mode and progress[a.alert_id]['revealed'] else ''}"
                              f"{a.alert_id} | {a.severity.value} | {a.title}" for a in view_alerts}
        alert_id = st.selectbox("Select an alert to investigate", list(labels), format_func=labels.get,
                                key=f"investigate_alert_{token}")
        alert = next(a for a in view_alerts if a.alert_id == alert_id)

        if training_mode:
            st.markdown(f"### {alert.alert_id.replace('ALR', 'INC')} - {alert.title}")
            base_report = build_investigation_report(alert, events, config, all_alerts=alerts)
            render_training(alert, base_report, progress[alert_id], token, lang)
        else:
            col_status, col_notes = st.columns([1, 2])
            status = col_status.selectbox("Incident status", INCIDENT_STATUSES, key=f"status_free_{token}_{alert_id}")
            notes = col_notes.text_area("Analyst notes (included in the export)",
                                        key=f"notes_{token}_{alert_id}", height=80)
            report = build_investigation_report(alert, events, config, all_alerts=alerts, status=status,
                                                analyst_notes=notes)
            st.markdown(f"### {report.incident_id} - {alert.title}")
            render_alert_summary(alert, status, show_mitre=True)
            render_tool_analysis(alert, report)
            st.markdown("#### Event timeline (supporting evidence)")
            render_evidence(report)
            render_exports(report)

# ---------------------------------------------------------------------------
# Data quality
# ---------------------------------------------------------------------------
with tab_quality:
    q = st.columns(4)
    q[0].metric("Rows read", quality.rows_read)
    q[1].metric("Rows accepted", quality.rows_accepted)
    q[2].metric("Rows rejected", quality.rows_rejected)
    q[3].metric("Exact duplicates removed", quality.exact_duplicates_removed)
    for warning in quality.warnings:
        st.warning(warning)
    if quality.rows_rejected:
        st.markdown("#### Rejection reasons")
        st.dataframe(quality.rejection_summary(), hide_index=True)
        st.markdown("#### Rejected rows (excluded from analysis)")
        st.dataframe(quality.rejected_rows, hide_index=True, width="stretch")
    else:
        st.success("All rows passed validation.")

# ---------------------------------------------------------------------------
# About
# ---------------------------------------------------------------------------
with tab_about:
    st.markdown("""
**Mini SOC Lab** is a learning and portfolio project that simulates first-line SOC triage of authentication logs.

- **Data:** synthetic events for a fictional London organisation. Public-looking IPs are from the RFC 5737
  documentation ranges. No real systems, people or credentials are involved.
- **Detection:** five configurable rules (R001-R005) - see `docs/detection_rules.md`.
- **Alerts are leads, not verdicts.** Each alert separates observed facts from hypotheses and lists benign
  explanations, so the analyst decides the outcome.
- **No automated response.** Suggested containment actions are proposals only.

Documentation lives in the `docs/` folder of the repository.
""")
