"""Mini SOC Lab dashboard.  Run with:  streamlit run streamlit_app.py"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from soc_lab.case_store import CaseStore, alert_fingerprint, dataset_key, default_db_path
from soc_lab.config import DEFAULT_CONFIG_PATH, ConfigError, load_config, with_overrides
from soc_lab.correlation import case_for_alert, cases_to_csv, cases_to_frame, correlate_alerts, correlation_window
from soc_lab.detection import run_detection
from soc_lab.enrichment import display_rows, load_enrichment
from soc_lab.detection.export import CODE_LANGUAGES, FIELD_MAPPING, FORMAT_NAMES, FORMATS, export_rules, export_zip
from soc_lab.filters import filter_alerts, filter_events
from soc_lab import scoring, training
from soc_lab.i18n import DEFAULT_LANGUAGE, LANGUAGES, t, tr
from soc_lab.log_generator import GeneratorSettings, generate_csv_text, generate_events
from soc_lab.log_loader import LogFileError, load_events, rejection_reason_msg
from soc_lab.parsers import FORMATS as LOG_FORMATS, ConversionError, convert
from soc_lab.metrics import alerts_to_frame, compute_kpis, logon_timeline, top_failure_sources
from soc_lab.models import INCIDENT_STATUSES, SEVERITY_ORDER, format_timestamp
from soc_lab.reporting import alerts_to_csv, build_investigation_report, evidence_to_csv, render_markdown

SAMPLE_LOG_PATH = Path(__file__).parent / "data" / "sample_auth_logs.csv"
GROUND_TRUTH_PATH = Path(__file__).parent / "data" / "sample_auth_logs_ground_truth.csv"
ANSWERS_DIR = Path(os.environ.get("SOC_LAB_ANSWERS_DIR", Path(__file__).parent / "training_answers"))
SEVERITY_NAMES = [s.value for s in reversed(SEVERITY_ORDER)]  # Critical first
SEVERITY_COLOURS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#2a78d6"}
RESULT_COLOURS = {"SUCCESS": "#2a78d6", "FAILURE": "#eb6834", "INFO": "#8a8984"}
DATA_SOURCES = ["sample", "generate", "examples", "upload"]
EXAMPLES_DIR = Path(__file__).parent / "data" / "examples"
EXAMPLE_FILES = ["linux_auth.log", "windows_security.xml", "entra_signins.json"]
EXAMPLE_YEAR = 2026  # the classic syslog lines in linux_auth.log have no year
TAB_IDS = ["overview", "alerts", "cases", "events", "investigation", "quality", "export", "about"]

st.set_page_config(page_title="Mini SOC Lab", page_icon=":shield:", layout="wide")

# ---------------------------------------------------------------------------
# Language. Every widget below has a fixed key, so switching language only changes
# the text on screen - selections, answers and progress stay where they are.
# ---------------------------------------------------------------------------
# The language can come from the link (?lang=pt-BR), and the link follows the selector, so a shared URL
# opens in the same language. The default is read once per session so the widget never resets.
if "initial_lang" not in st.session_state:
    st.session_state["initial_lang"] = st.query_params.get("lang") if st.query_params.get("lang") in LANGUAGES         else DEFAULT_LANGUAGE
lang = st.sidebar.segmented_control(t("ui.language_selector"), list(LANGUAGES), format_func=LANGUAGES.get,
                                    default=st.session_state["initial_lang"], required=True, key="lang")
if st.query_params.get("lang") != lang:
    st.query_params["lang"] = lang


def T(key: str, **params) -> str:
    """Interface text in the selected language."""
    return t(key, lang, **params)


def L(value):
    """A text produced by the analysis (alert, playbook, report) in the selected language."""
    return tr(value, lang)


def severity_label(value: str) -> str:
    return T(f"severity.{value}")


def status_label(value: str) -> str:
    return T(f"status.{value}")


def error_text(exc: Exception) -> str:
    return L(exc.args[0]) if exc.args else str(exc)


@st.cache_data(show_spinner=False)
def run_pipeline(csv_bytes: bytes, source_name: str, config_json: str):
    result = load_events(csv_bytes, source_name)
    alerts = run_detection(result.events, json.loads(config_json))
    return result, alerts


@st.cache_resource
def triage_store(path: str) -> CaseStore:
    return CaseStore(path)


@st.cache_data(show_spinner=False)
def convert_log(data: bytes, fmt: str, filename: str, year: int):
    return convert(data, fmt, filename, year)


@st.cache_data(show_spinner=False)
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
    return alt.Scale(domain=[severity_label(s) for s in SEVERITY_NAMES],
                     range=[SEVERITY_COLOURS[s] for s in SEVERITY_NAMES])


def result_scale(domain: list[str]) -> alt.Scale:
    return alt.Scale(domain=domain, range=[RESULT_COLOURS[r] for r in domain])


# ---------------------------------------------------------------------------
# Sidebar: data source and detection tuning
# ---------------------------------------------------------------------------
st.sidebar.title("Mini SOC Lab")
st.sidebar.caption(T("ui.sidebar.caption"))

source_choice = st.sidebar.radio(
    T("ui.source.label"), DATA_SOURCES, format_func=lambda key: T(f"ui.source.{key}"),
    help=T("ui.source.help"), key="data_source",
)
if source_choice == "sample":
    if not SAMPLE_LOG_PATH.exists():
        st.error(T("ui.error.sample_missing"))
        st.stop()
    csv_bytes, source_name = SAMPLE_LOG_PATH.read_bytes(), SAMPLE_LOG_PATH.name
    ground_truth = sample_ground_truth()
elif source_choice == "generate":
    seed = st.sidebar.number_input(T("ui.source.seed"), min_value=0, max_value=1_000_000, value=7, step=1,
                                   key="gen_seed")
    days = st.sidebar.slider(T("ui.source.days"), min_value=7, max_value=28, value=14, key="gen_days")
    with st.spinner(T("ui.spinner.generating")):
        csv_bytes = generate_dataset(int(seed), int(days))
        ground_truth = generated_ground_truth(int(seed), int(days))
    source_name = f"generated (seed {seed}, {days} days)"
    st.sidebar.download_button(T("ui.source.download"), csv_bytes, file_name=f"auth_logs_seed{seed}.csv",
                               mime="text/csv", key="download_generated")
elif source_choice == "examples":
    example = st.sidebar.selectbox(T("ui.source.example_label"), EXAMPLE_FILES, key="example_file",
                                   format_func=lambda name: T(f"ui.source.example.{Path(name).stem}"))
    raw_bytes, source_name, log_format, log_year = (EXAMPLES_DIR / example).read_bytes(), example, "auto", EXAMPLE_YEAR
    ground_truth = {}
else:
    upload = st.sidebar.file_uploader(T("ui.source.upload_label"), type=["csv", "log", "txt", "xml", "json"],
                                      help=T("ui.source.upload_help"), key="upload_csv")
    log_format = st.sidebar.selectbox(T("ui.source.format"), ["auto", *LOG_FORMATS], key="upload_format",
                                      format_func=lambda fmt: T(f"ui.format.{fmt}"))
    log_year = st.sidebar.number_input(T("ui.source.year"), 1990, 2100, datetime.now(timezone.utc).year,
                                       help=T("ui.source.year_help"), key="syslog_year")
    if upload is None:
        st.info(T("ui.source.upload_prompt"))
        st.stop()
    raw_bytes, source_name = upload.getvalue(), upload.name
    ground_truth = {}

# Real-world formats are converted to the lab schema first; the CSV then goes through the normal validation.
conversion = None
if source_choice in ("examples", "upload"):
    try:
        conversion = convert_log(raw_bytes, log_format, source_name, int(log_year))
    except ConversionError as exc:
        st.error(T("ui.error.conversion", detail=error_text(exc)))
        st.stop()
    if conversion.fmt == "lab_csv":
        csv_bytes, conversion = raw_bytes, None
    else:
        csv_bytes = conversion.to_csv_bytes()
        st.sidebar.caption(T("ui.source.converted", format=T(f"ui.format.{conversion.fmt}"),
                             read=conversion.records_read, events=len(conversion.events),
                             skipped=conversion.records_skipped))
        st.sidebar.download_button(T("ui.source.download_converted"), csv_bytes, key="download_converted",
                                   file_name=f"{Path(source_name).stem}_converted.csv", mime="text/csv")

try:
    base_config = load_config(DEFAULT_CONFIG_PATH)
except ConfigError as exc:
    st.error(T("ui.error.config", detail=error_text(exc)))
    st.stop()

with st.sidebar.expander(T("ui.thresholds.title")):
    st.caption(T("ui.thresholds.caption"))
    rules = base_config["rules"]

    def threshold(widget, rule_id: str, param: str, *args):
        return widget(T(f"ui.thresholds.{rule_id}.{param}"), *args, key=f"thr_{rule_id}_{param}")

    overrides = {
        "R001": {"enabled": threshold(st.checkbox, "R001", "enabled", rules["R001"]["enabled"]),
                 "failure_threshold": threshold(st.number_input, "R001", "failure_threshold", 1, 100,
                                                rules["R001"]["failure_threshold"]),
                 "window_minutes": threshold(st.number_input, "R001", "window_minutes", 1, 1440,
                                             rules["R001"]["window_minutes"])},
        "R002": {"enabled": threshold(st.checkbox, "R002", "enabled", rules["R002"]["enabled"]),
                 "min_failures": threshold(st.number_input, "R002", "min_failures", 1, 100,
                                           rules["R002"]["min_failures"])},
        "R003": {"enabled": threshold(st.checkbox, "R003", "enabled", rules["R003"]["enabled"]),
                 "min_attempts": threshold(st.number_input, "R003", "min_attempts", 1, 1000,
                                           rules["R003"]["min_attempts"]),
                 "failure_rate_threshold": threshold(st.slider, "R003", "failure_rate_threshold", 0.05, 1.0,
                                                     float(rules["R003"]["failure_rate_threshold"]), 0.05)},
        "R004": {"enabled": threshold(st.checkbox, "R004", "enabled", rules["R004"]["enabled"]),
                 "min_distinct_accounts": threshold(st.number_input, "R004", "min_distinct_accounts", 2, 100,
                                                    rules["R004"]["min_distinct_accounts"])},
        "R005": {"enabled": threshold(st.checkbox, "R005", "enabled", rules["R005"]["enabled"])},
    }
    case_window = st.number_input(T("ui.thresholds.correlation_window"), 0, 1440,
                                  int(correlation_window(base_config)), key="thr_correlation_window")
use_enrichment = st.sidebar.toggle(T("ui.enrichment.toggle"), value=True, key="use_enrichment",
                                   help=T("ui.enrichment.toggle_help"))
enrichment = load_enrichment() if use_enrichment else None
for warning in enrichment.warnings if enrichment else []:
    st.sidebar.warning(L(warning))

try:
    config = with_overrides(base_config, overrides)
except ConfigError as exc:
    st.sidebar.error(error_text(exc))
    config = base_config

try:
    with st.spinner(T("ui.spinner.analysing")):
        load_result, alerts = run_pipeline(csv_bytes, source_name, json.dumps(config))
except LogFileError as exc:
    st.error(T("ui.error.load", detail=error_text(exc)))
    st.stop()

events, quality = load_result.events, load_result.quality

# Triage status and notes of the free investigation mode live in SQLite (soc_lab/case_store.py).
store = triage_store(str(default_db_path()))
dataset = dataset_key(source_name, csv_bytes)
triage = store.all_for(dataset)


def triage_status(alert) -> str:
    record = triage.get(alert_fingerprint(alert))
    return record.status if record else "New"


def save_triage(alert, status_key: str, notes_key: str) -> None:
    store.save(dataset, alert, st.session_state[status_key], st.session_state[notes_key])


st.sidebar.caption(T("ui.store.saved", path=store.path.name) if store.persistent else T("ui.store.memory"))

st.title(T("ui.title"))
st.caption(T("ui.source_caption", source=source_name, accepted=quality.rows_accepted, rejected=quality.rows_rejected,
             duplicates=quality.exact_duplicates_removed))

if events.empty:
    for warning in quality.warnings:
        st.warning(L(warning))
    st.info(T("ui.no_valid_events"))
    st.stop()

# ---------------------------------------------------------------------------
# Filters (shared across tabs)
# ---------------------------------------------------------------------------
first_day, last_day = events["timestamp"].min().date(), events["timestamp"].max().date()
with st.container(border=True):
    col_date, col_user, col_ip, col_type, col_sev = st.columns([1.3, 1, 1, 1, 1])
    date_range = col_date.date_input(T("ui.filter.dates"), (first_day, last_day), min_value=first_day,
                                     max_value=last_day, key="filter_dates")
    selected_users = col_user.multiselect(T("ui.filter.users"), sorted(events["username"].unique()),
                                          key="filter_users")
    selected_ips = col_ip.multiselect(T("ui.filter.ips"), sorted(events["source_ip"].unique()), key="filter_ips")
    selected_types = col_type.multiselect(T("ui.filter.event_types"), sorted(events["event_type"].unique()),
                                          key="filter_event_types")
    selected_severities = col_sev.multiselect(T("ui.filter.severity"), SEVERITY_NAMES, format_func=severity_label,
                                              key="filter_severity")

start_day, end_day = (date_range if isinstance(date_range, tuple) and len(date_range) == 2
                      else (first_day, last_day))
view_events = filter_events(events, start_day, end_day, selected_users, selected_ips, selected_types)
view_alerts = filter_alerts(alerts, start_day, end_day, selected_users, selected_ips, selected_severities)
kpis = compute_kpis(view_events, view_alerts)

# Cases are built from every alert, then shown when at least one of their alerts passes the filters,
# so a filter never splits a case in two.
cases = correlate_alerts(alerts, case_window)
view_alert_ids = {a.alert_id for a in view_alerts}
view_cases = [case for case in cases if view_alert_ids & set(case.alert_ids)]
token = training.dataset_token(source_name)

# Tab labels change with the language, so the open tab is remembered by id ("active_tab") and the
# tab widget gets one key per language; a language switch reopens the same tab under its new name.
tab_labels = [T(f"ui.tab.{tab}") for tab in TAB_IDS]
tab_key = f"main_tabs_{lang}"
active_tab = st.session_state.get("active_tab", TAB_IDS[0])
tab_overview, tab_alerts, tab_cases, tab_events, tab_investigate, tab_quality, tab_export, tab_about = st.tabs(
    tab_labels, key=tab_key, default=tab_labels[TAB_IDS.index(active_tab)], on_change="rerun")
chosen_tab = st.session_state.get(tab_key)
st.session_state["active_tab"] = TAB_IDS[tab_labels.index(chosen_tab)] if chosen_tab in tab_labels else active_tab

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
with tab_overview:
    m = st.columns(7)
    m[0].metric(T("ui.kpi.events"), f"{kpis['total_events']:,}")
    m[1].metric(T("ui.kpi.successful"), f"{kpis['successful_logins']:,}")
    m[2].metric(T("ui.kpi.failed"), f"{kpis['failed_logins']:,}", help=T("ui.kpi.failed_help"))
    m[3].metric(T("ui.kpi.failure_rate"), f"{kpis['failure_rate']:.1%}")
    m[4].metric(T("ui.kpi.lockouts"), kpis["account_lockouts"])
    m[5].metric(T("ui.kpi.alerts"), kpis["total_alerts"])
    m[6].metric(T("ui.kpi.cases"), len(view_cases), help=T("ui.kpi.cases_help"))

    left, right = st.columns([1, 2])
    with left:
        st.subheader(T("ui.overview.by_severity"))
        severity_frame = pd.DataFrame({"severity": [severity_label(s) for s in kpis["alerts_by_severity"]],
                                       "alerts": list(kpis["alerts_by_severity"].values())})
        bars = alt.Chart(severity_frame).mark_bar(cornerRadiusEnd=4, size=26).encode(
            y=alt.Y("severity:N", sort=[severity_label(s) for s in SEVERITY_NAMES], title=None),
            x=alt.X("alerts:Q", title=T("ui.chart.alerts"), axis=alt.Axis(tickMinStep=1)),
            color=alt.Color("severity:N", scale=severity_scale(), legend=None),
            tooltip=[alt.Tooltip("severity:N", title=T("ui.chart.severity")),
                     alt.Tooltip("alerts:Q", title=T("ui.chart.alerts"))],
        )
        labels = bars.mark_text(align="left", dx=4).encode(text="alerts:Q", color=alt.value("#52514e"))
        st.altair_chart(bars + labels, width="stretch")
    with right:
        st.subheader(T("ui.overview.timeline"))
        timeline = logon_timeline(view_events)
        failures = timeline[timeline["result"] == "FAILURE"]
        base = alt.Chart(failures).mark_bar(color=RESULT_COLOURS["FAILURE"], width=3).encode(
            x=alt.X("bucket:T", title=T("ui.chart.time_hourly")),
            y=alt.Y("count:Q", title=T("ui.chart.failed_per_hour")),
            tooltip=[alt.Tooltip("bucket:T", title=T("ui.chart.hour"), format="%Y-%m-%d %H:00"),
                     alt.Tooltip("count:Q", title=T("ui.kpi.failed"))],
        )
        alert_points = alerts_to_frame(view_alerts)
        layers = base
        if not alert_points.empty:
            alert_points = alert_points.assign(severity=alert_points["severity"].map(severity_label),
                                               title=[L(a.title) for a in view_alerts])
            dots = alt.Chart(alert_points).mark_point(filled=True, size=110, stroke="white", strokeWidth=2).encode(
                x="first_seen:T",
                y=alt.value(8),
                color=alt.Color("severity:N", scale=severity_scale(), title=T("ui.filter.severity")),
                shape=alt.Shape("severity:N", sort=[severity_label(s) for s in SEVERITY_NAMES], legend=None),
                tooltip=[alt.Tooltip("alert_id:N", title=T("ui.col.alert_id")),
                         alt.Tooltip("severity:N", title=T("ui.chart.severity")),
                         alt.Tooltip("title:N", title=T("ui.col.title")),
                         alt.Tooltip("first_seen:T", title=T("ui.col.first_seen"), format="%Y-%m-%d %H:%M")],
            )
            layers = base + dots
        st.altair_chart(layers.properties(height=280), width="stretch")
        st.caption(T("ui.overview.timeline_caption"))

    st.subheader(T("ui.overview.top_sources"))
    st.dataframe(top_failure_sources(view_events), hide_index=True, width="stretch",
                 column_config={"failed_logins": st.column_config.NumberColumn(T("ui.kpi.failed")),
                                "distinct_accounts": st.column_config.NumberColumn(T("ui.col.distinct_accounts"))})

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
with tab_alerts:
    st.subheader(T("ui.alerts.queue", count=len(view_alerts)))
    if not view_alerts:
        st.info(T("ui.alerts.none"))
    else:
        frame = alerts_to_frame(view_alerts).assign(
            severity=lambda f: f["severity"].map(severity_label), title=[L(a.title) for a in view_alerts],
            status=[status_label(triage_status(a)) for a in view_alerts])
        st.dataframe(
            frame[["alert_id", "severity", "status", "rule_id", "title", "entity", "first_seen", "last_seen",
                   "event_count", "source_ips", "mitre_attack"]],
            hide_index=True, width="stretch",
            column_config={"alert_id": T("ui.col.alert_id"), "severity": T("ui.chart.severity"),
                           "status": T("ui.inv.status"),
                           "rule_id": T("ui.col.rule"), "title": T("ui.col.title"), "entity": T("ui.col.entity"),
                           "first_seen": st.column_config.DatetimeColumn(T("ui.col.first_seen"),
                                                                         format="YYYY-MM-DD HH:mm"),
                           "last_seen": st.column_config.DatetimeColumn(T("ui.col.last_seen"),
                                                                        format="YYYY-MM-DD HH:mm"),
                           "event_count": st.column_config.NumberColumn(T("ui.col.events")),
                           "source_ips": T("ui.col.source_ips"), "mitre_attack": "MITRE ATT&CK"},
        )
        export_alerts, export_triage = st.columns(2)
        export_alerts.download_button(T("ui.alerts.export"), alerts_to_csv(view_alerts), "alerts.csv", "text/csv",
                                      key="export_alerts")
        export_triage.download_button(T("ui.store.export"), store.to_csv(dataset, view_alerts), "triage.csv",
                                      "text/csv", key="export_triage")
        st.caption(T("ui.alerts.caption"))

# ---------------------------------------------------------------------------
# Cases (related alerts grouped by soc_lab/correlation.py)
# ---------------------------------------------------------------------------
with tab_cases:
    st.subheader(T("ui.cases.header", count=len(view_cases)))
    st.caption(T("ui.cases.caption", window=case_window))
    if not view_cases:
        st.info(T("ui.cases.none"))
    else:
        case_frame = cases_to_frame(view_cases).assign(
            severity=lambda f: f["severity"].map(severity_label), title=[L(c.title) for c in view_cases])
        st.dataframe(
            case_frame[["case_id", "severity", "alert_count", "alert_ids", "rule_ids", "title", "first_seen",
                        "last_seen", "event_count"]],
            hide_index=True, width="stretch",
            column_config={"case_id": T("ui.cases.col.case"), "severity": T("ui.chart.severity"),
                           "alert_count": st.column_config.NumberColumn(T("ui.cases.col.alert_count")),
                           "alert_ids": T("ui.cases.col.alert_ids"), "rule_ids": T("ui.cases.col.rules"),
                           "title": T("ui.col.title"),
                           "first_seen": st.column_config.DatetimeColumn(T("ui.col.first_seen"),
                                                                         format="YYYY-MM-DD HH:mm"),
                           "last_seen": st.column_config.DatetimeColumn(T("ui.col.last_seen"),
                                                                        format="YYYY-MM-DD HH:mm"),
                           "event_count": st.column_config.NumberColumn(T("ui.col.events"))},
        )
        st.download_button(T("ui.cases.export"), cases_to_csv(view_cases), "cases.csv", "text/csv",
                           key="export_cases")

        case_labels = {c.case_id: f"{c.case_id} | {severity_label(c.severity.value)} | {L(c.title)}"
                       for c in view_cases}
        case_id = st.selectbox(T("ui.cases.select"), list(case_labels), format_func=case_labels.get,
                               key=f"case_select_{token}")
        case = next(c for c in view_cases if c.case_id == case_id)

        info = st.columns(4)
        info[0].metric(T("ui.inv.severity"), severity_label(case.severity.value))
        info[1].metric(T("ui.cases.col.alert_count"), len(case.alerts))
        info[2].metric(T("ui.inv.supporting_events"), len(case.event_ids))
        info[3].metric(T("ui.cases.col.rules"), ", ".join(case.rule_ids))

        st.markdown(f"#### {T('ui.cases.alerts')}")
        members = alerts_to_frame(case.alerts).assign(
            severity=lambda f: f["severity"].map(severity_label), title=[L(a.title) for a in case.alerts],
            status=[status_label(triage_status(a)) for a in case.alerts])
        st.dataframe(members[["alert_id", "severity", "status", "rule_id", "title", "entity", "first_seen",
                              "last_seen"]],
                     hide_index=True, width="stretch",
                     column_config={"alert_id": T("ui.col.alert_id"), "severity": T("ui.chart.severity"),
                                    "status": T("ui.inv.status"),
                                    "rule_id": T("ui.col.rule"), "title": T("ui.col.title"),
                                    "entity": T("ui.col.entity"),
                                    "first_seen": st.column_config.DatetimeColumn(T("ui.col.first_seen"),
                                                                                  format="YYYY-MM-DD HH:mm"),
                                    "last_seen": st.column_config.DatetimeColumn(T("ui.col.last_seen"),
                                                                                 format="YYYY-MM-DD HH:mm")})

        st.markdown(f"#### {T('ui.cases.why')}")
        if case.links:
            st.markdown("\n".join(f"- {L(link.reason)}" for link in case.links))
        else:
            st.caption(T("ui.cases.single"))
        if case.mitre_attack:
            st.markdown(f"**MITRE ATT&CK:** {' | '.join(case.mitre_attack)}")

        st.markdown(f"#### {T('ui.cases.timeline')}")
        alerts_for_event: dict[str, list[str]] = {}
        for member in case.alerts:
            for event_id in member.evidence_event_ids:
                alerts_for_event.setdefault(event_id, []).append(member.alert_id)
        case_events = events[events["event_id"].isin(case.event_ids)].sort_values("timestamp", kind="stable")
        case_events = case_events.assign(alerts=case_events["event_id"].map(lambda e: ", ".join(alerts_for_event[e])))
        st.dataframe(case_events[["timestamp", "event_id", "alerts", "username", "source_ip", "event_type", "result",
                                  "failure_reason", "hostname"]],
                     hide_index=True, width="stretch",
                     column_config={"timestamp": st.column_config.DatetimeColumn("timestamp",
                                                                                 format="YYYY-MM-DD HH:mm:ss"),
                                    "alerts": T("ui.cases.col.alerts_for_event")})
        st.caption(T("ui.cases.severity_note"))

# ---------------------------------------------------------------------------
# IP enrichment tables (used by the Event Explorer and the Investigation tab)
# ---------------------------------------------------------------------------
ENRICHMENT_COLUMNS =["ip", "location", "asn", "as_org", "network_type", "threat_intel"]


def render_enrichment_table(infos) -> None:
    rows = display_rows(infos, lang)
    if not rows:
        st.caption(T("ui.enrichment.none"))
        return
    st.dataframe(pd.DataFrame(rows, columns=ENRICHMENT_COLUMNS), hide_index=True, width="stretch",
                 column_config={column: T(f"ui.enrichment.col.{column}") for column in ENRICHMENT_COLUMNS})
    st.caption(T("ui.enrichment.caption"))


# ---------------------------------------------------------------------------
# Event explorer (raw log data: column names and values are kept as recorded)
# ---------------------------------------------------------------------------
with tab_events:
    search = st.text_input(T("ui.events.search"), placeholder=T("ui.events.placeholder"), key="event_search")
    shown = filter_events(view_events, search=search)
    st.caption(T("ui.events.shown", shown=f"{len(shown):,}", total=f"{len(events):,}"))
    st.dataframe(shown, hide_index=True, width="stretch",
                 column_config={"timestamp": st.column_config.DatetimeColumn("timestamp",
                                                                             format="YYYY-MM-DD HH:mm:ss")})
    export = shown.assign(timestamp=shown["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
    st.download_button(T("ui.events.export"), export.to_csv(index=False), "filtered_events.csv", "text/csv",
                       key="export_events")
    if enrichment is not None:
        with st.expander(T("ui.enrichment.events_title")):
            internal = config["environment"]["internal_networks"]
            render_enrichment_table([enrichment.lookup(ip, internal) for ip in sorted(shown["source_ip"].unique())])

# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------
def bullet_list(items) -> str:
    return "\n".join(f"- {L(item)}" for item in items)


def render_alert_summary(alert, status: str, show_mitre: bool) -> None:
    info = st.columns(4)
    info[0].metric(T("ui.inv.severity"), severity_label(alert.severity.value))
    info[1].metric(T("ui.inv.rule"), alert.rule_id)
    info[2].metric(T("ui.inv.supporting_events"), alert.event_count)
    info[3].metric(T("ui.inv.status"), status_label(status))
    not_available = T("ui.inv.not_available")
    lines = [
        f"**{T('ui.inv.detection_rule')}:** {L(alert.rule_name)}{f' ({alert.pattern})' if alert.pattern else ''}",
        f"**{T('ui.col.first_seen')}:** {format_timestamp(alert.first_seen)} - "
        f"**{T('ui.col.last_seen')}:** {format_timestamp(alert.last_seen)}",
        f"**{T('ui.inv.accounts')}:** {', '.join(alert.usernames) or not_available}",
        f"**{T('ui.inv.source_ips')}:** {', '.join(alert.source_ips)} - "
        f"**{T('ui.inv.hosts')}:** {', '.join(alert.hostnames) or not_available}",
    ]
    if show_mitre:
        lines.append(f"**{T('ui.inv.mitre')}:** {alert.mitre_attack}")
    st.markdown("  \n".join(lines))


def render_enrichment(report) -> None:
    """Lookup data for the alert's addresses: raw context, shown in training mode too (an analyst would look it up)."""
    if enrichment is None:
        return
    st.markdown(f"#### {T('ui.enrichment.title')}")
    render_enrichment_table(report.ip_enrichment)


def render_evidence(report) -> None:
    evidence = report.evidence
    result_domain = [r for r in RESULT_COLOURS if r in set(evidence["result"])]
    evidence_chart = alt.Chart(evidence).mark_point(filled=True, size=90, stroke="white", strokeWidth=1.5).encode(
        x=alt.X("timestamp:T", title=T("ui.chart.time")),
        y=alt.Y("event_type:N", title=None),
        color=alt.Color("result:N", scale=result_scale(result_domain), title=T("ui.chart.result")),
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
        st.markdown(f"**{T('ui.inv.why')}**")
        st.write(L(alert.trigger_reason))
        st.caption(T("ui.inv.severity_rationale", reason=L(alert.severity_reason)))

    facts_col, hypo_col = st.columns(2)
    with facts_col:
        st.markdown(f"#### {T('ui.inv.observed_facts')}")
        st.markdown(bullet_list(alert.observed_facts))
        st.markdown(f"#### {T('ui.inv.context_checks')}")
        st.markdown(bullet_list(report.context_findings))
    with hypo_col:
        st.markdown(f"#### {T('ui.inv.hypotheses')}")
        st.markdown(bullet_list(alert.hypotheses))
        st.markdown(f"#### {T('ui.inv.benign')}")
        st.markdown(bullet_list(report.playbook.benign_explanations))
        st.markdown(f"#### {T('ui.inv.false_positive')}")
        st.markdown(bullet_list(report.playbook.false_positive_considerations))

    steps_col, contain_col = st.columns(2)
    with steps_col:
        st.markdown(f"#### {T('ui.inv.steps')}")
        st.markdown("\n".join(f"{n}. {L(s)}" for n, s in enumerate(report.playbook.investigation_steps, 1)))
    with contain_col:
        st.markdown(f"#### {T('ui.inv.containment')}")
        st.caption(T("ui.inv.containment_caption"))
        st.markdown(bullet_list(report.playbook.containment_actions))

    st.markdown(f"#### {T('ui.inv.conclusion')}")
    st.info(L(report.conclusion))
    with st.expander(T("ui.inv.limitations")):
        st.markdown(bullet_list(report.limitations))


def render_exports(report) -> None:
    dl1, dl2, _ = st.columns([1, 1, 2])
    dl1.download_button(T("ui.inv.export_report"), render_markdown(report, lang), f"{report.incident_id}.md",
                        "text/markdown", type="primary", key=f"export_report_{report.incident_id}")
    dl2.download_button(T("ui.inv.export_evidence"), evidence_to_csv(report), f"{report.incident_id}_evidence.csv",
                        "text/csv", key=f"export_evidence_{report.incident_id}")


def training_score(alert, report, answers: dict, status: str | None):
    scenario = training.scenario_for_alert(alert, ground_truth)
    return scoring.score_answers(answers, alert, report, config, scenario, status)


def render_score(card) -> None:
    with st.container(border=True):
        st.markdown(f"### {T('ui.score.title')}: {card.percent}%")
        st.progress(card.percent / 100, text=T("ui.score.value", earned=card.earned, total=card.total,
                                                 percent=card.percent))
        st.caption(T("ui.score.caption"))


def render_training(alert, base_report, saved: dict, token: str) -> None:
    """Questionnaire first, tool analysis and ground truth only after the analyst chooses to reveal them."""
    key = f"{token}_{alert.alert_id}"
    status_key, reveal_key = f"status_{key}", f"reveal_{key}"
    if status_key not in st.session_state:
        st.session_state[status_key] = saved["status"] if saved["status"] in INCIDENT_STATUSES else "New"
    if reveal_key not in st.session_state:
        st.session_state[reveal_key] = saved["revealed"]

    st.info(T("ui.training.how_to"))

    render_alert_summary(alert, st.session_state[status_key], show_mitre=False)
    st.markdown(f"#### {T('ui.training.evidence')}")
    render_evidence(base_report)
    render_enrichment(base_report)

    hours = base_config["environment"]["business_hours"]
    answers: dict[str, str] = {}
    for stage in training.STAGES:
        with st.container(border=True):
            st.markdown(f"#### {stage.label(lang)}")
            for question in training.questions_for_stage(stage.id):
                answer_key = f"ans_{key}_{question.id}"
                if answer_key not in st.session_state:
                    st.session_state[answer_key] = saved["answers"].get(question.id, "")
                st.markdown(f"**{question.text(lang)}**")
                st.caption("💡 " + question.hint(lang, start=int(hours["start_hour"]), end=int(hours["end_hour"])))
                answers[question.id] = st.text_area(question.text(lang), key=answer_key, height=90,
                                                    label_visibility="collapsed")
            if stage.id == "decide":
                st.selectbox(T("ui.training.status"), INCIDENT_STATUSES, format_func=status_label, key=status_key)
                with st.expander(T("ui.training.status_meaning")):
                    st.markdown("\n".join(f"- **{name}:** {meaning}"
                                          for name, meaning in training.status_explanations(lang)))
    status = st.session_state[status_key]

    total = len(training.QUESTIONS)
    done = training.answered_count(answers)
    st.progress(done / total, text=T("ui.training.progress", done=done, total=total))
    can_reveal = bool(answers.get("verdict", "").strip())
    st.toggle(T("ui.training.reveal"), key=reveal_key, disabled=not can_reveal and not st.session_state[reveal_key])
    if not can_reveal and not st.session_state[reveal_key]:
        st.caption(T("ui.training.reveal_locked"))
    revealed = st.session_state[reveal_key]

    changed = ({k: v for k, v in answers.items() if v.strip()} != saved["answers"]
               or (status != (saved["status"] or "New")) or revealed != saved["revealed"])
    if changed:
        try:
            training.save_progress(training.answers_path(ANSWERS_DIR, source_name, alert.alert_id),
                                   answers, status, revealed)
        except OSError as exc:
            st.warning(T("ui.training.save_failed", error=exc))
        else:
            if revealed != saved["revealed"]:
                st.rerun()  # refresh the progress counter and the ✅ marks in the alert list

    report = replace(base_report, status=status, analyst_notes=training.answers_to_markdown(answers, lang))
    if revealed:
        st.divider()
        scenario = training.scenario_for_alert(alert, ground_truth)
        guide = training.SCENARIO_GUIDES.get(scenario) if scenario else None
        with st.container(border=True):
            st.markdown(f"### {T('ui.training.ground_truth')}")
            if guide is None:
                st.write(T("ui.training.no_ground_truth"))
            else:
                st.markdown(f"**{guide.verdict(lang)}**")
                st.write(guide.explanation(lang))
                if status in guide.expected_statuses:
                    st.success(T("ui.training.status_ok", status=status_label(status)))
                else:
                    expected = " / ".join(status_label(s) for s in guide.expected_statuses)
                    st.warning(T("ui.training.status_expected", status=status_label(status), expected=expected))
                st.caption(T("ui.training.scenario", scenario=scenario))

        card = training_score(alert, base_report, answers, status)
        render_score(card)

        st.markdown(f"### {T('ui.training.compare')}")
        for stage in training.STAGES:
            st.markdown(f"**{stage.label(lang)}**")
            for question in training.questions_for_stage(stage.id):
                answered = bool(answers[question.id].strip())
                with st.expander(("✍️ " if answered else "⬜ ") + question.text(lang)):
                    mine, ref = st.columns(2)
                    mine.markdown(f"**{T('ui.training.your_answer')}**")
                    mine.write(answers[question.id] if answered else f"_{T('ui.training.no_answer')}_")
                    ref.markdown(f"**{T('ui.training.reference')}**")
                    points = training.reference_answers(question.id, alert, base_report, config, lang)
                    ref.markdown("\n".join(f"- {point}" for point in points) or "-")
                    checks = card.for_question(question.id)
                    if checks:
                        st.markdown(f"**{T('ui.score.checklist')}**\n\n" + "\n".join(
                            f"- {'✅' if c.passed else '❌'} {L(c.label)}" for c in checks))

        st.markdown(f"### {T('ui.training.full_analysis')}")
        st.markdown(f"**{T('ui.inv.mitre')}:** {alert.mitre_attack}")
        render_tool_analysis(alert, report)

    st.divider()
    st.caption(T("ui.training.export_note"))
    render_exports(report)


with tab_investigate:
    if not view_alerts:
        st.info(T("ui.alerts.none"))
    else:
        progress = {a.alert_id: training.load_progress(training.answers_path(ANSWERS_DIR, source_name, a.alert_id))
                    for a in view_alerts}

        training_mode = st.toggle(T("ui.training.mode"), value=True, key="training_mode",
                                  help=T("ui.training.mode_help"))

        trained = sum(1 for p in progress.values() if p["revealed"])
        if training_mode:
            st.caption(T("ui.training.cases", done=trained, total=len(view_alerts)))
            revealed_alerts = [a for a in view_alerts if progress[a.alert_id]["revealed"]]
            if revealed_alerts:
                scores = [training_score(a, build_investigation_report(a, events, config, all_alerts=alerts),
                                         progress[a.alert_id]["answers"], progress[a.alert_id]["status"]).percent
                          for a in revealed_alerts]
                st.caption(T("ui.score.average", count=len(scores), percent=round(sum(scores) / len(scores))))
        labels = {a.alert_id: f"{'✅ ' if training_mode and progress[a.alert_id]['revealed'] else ''}"
                              f"{a.alert_id} | {severity_label(a.severity.value)} | {L(a.title)}" for a in view_alerts}
        alert_id = st.selectbox(T("ui.inv.select_alert"), list(labels), format_func=labels.get,
                                key=f"investigate_alert_{token}")
        alert = next(a for a in view_alerts if a.alert_id == alert_id)

        if training_mode:
            st.markdown(f"### {alert.alert_id.replace('ALR', 'INC')} - {L(alert.title)}")
            base_report = build_investigation_report(alert, events, config, all_alerts=alerts,
                                                     enrichment=enrichment)
            render_training(alert, base_report, progress[alert_id], token)
        else:
            # Keys use the alert fingerprint, so a threshold change that renumbers alerts never mixes up notes.
            fingerprint = alert_fingerprint(alert)
            status_key, notes_key = f"status_free_{fingerprint}", f"notes_{fingerprint}"
            saved_triage = triage.get(fingerprint)
            if status_key not in st.session_state:
                st.session_state[status_key] = saved_triage.status if saved_triage else "New"
                st.session_state[notes_key] = saved_triage.notes if saved_triage else ""
            col_status, col_notes = st.columns([1, 2])
            # Saved in on_change callbacks, which run before the page is redrawn, so the alert queue
            # and the cases already show the new status.
            save_args = (alert, status_key, notes_key)
            status = col_status.selectbox(T("ui.inv.status_free"), INCIDENT_STATUSES, format_func=status_label,
                                          key=status_key, on_change=save_triage, args=save_args)
            notes = col_notes.text_area(T("ui.inv.notes"), key=notes_key, height=80, on_change=save_triage,
                                        args=save_args)
            if saved_triage:
                col_status.caption(T("ui.store.last_saved", time=saved_triage.updated_at))
            report = build_investigation_report(alert, events, config, all_alerts=alerts, status=status,
                                                analyst_notes=notes, enrichment=enrichment)
            st.markdown(f"### {report.incident_id} - {L(alert.title)}")
            alert_case = case_for_alert(cases, alert.alert_id)
            if alert_case:
                others = [other for other in alert_case.alert_ids if other != alert.alert_id]
                st.info(T("ui.inv.case", case=alert_case.case_id, others=", ".join(others)) if others
                        else T("ui.inv.case_alone", case=alert_case.case_id))
            render_alert_summary(alert, status, show_mitre=True)
            render_tool_analysis(alert, report)
            st.markdown(f"#### {T('ui.inv.timeline')}")
            render_evidence(report)
            render_enrichment(report)
            render_exports(report)
            history = store.history(dataset, alert)
            if history:
                with st.expander(T("ui.store.history", count=len(history))):
                    history_frame = pd.DataFrame(history).assign(
                        status=lambda f: f["status"].map(status_label))
                    st.dataframe(history_frame, hide_index=True, width="stretch",
                                 column_config={"changed_at": T("ui.store.changed_at"),
                                                "alert_id": T("ui.col.alert_id"), "status": T("ui.inv.status"),
                                                "notes": T("ui.store.notes")})

# ---------------------------------------------------------------------------
# Data quality
# ---------------------------------------------------------------------------
with tab_quality:
    if conversion is not None:
        st.markdown(f"#### {T('ui.quality.conversion', format=T(f'ui.format.{conversion.fmt}'))}")
        c = st.columns(3)
        c[0].metric(T("ui.quality.records_read"), conversion.records_read)
        c[1].metric(T("ui.quality.events_converted"), len(conversion.events))
        c[2].metric(T("ui.quality.records_skipped"), conversion.records_skipped)
        if conversion.skipped:
            st.dataframe(pd.DataFrame([{"reason": T(f"conversion.skip.{reason}"), "records": count}
                                       for reason, count in conversion.skipped.most_common()]),
                         hide_index=True, column_config={"reason": T("ui.quality.reason"),
                                                         "records": T("ui.quality.rows")})
        st.caption(T("ui.quality.conversion_caption"))
    q = st.columns(4)
    q[0].metric(T("ui.quality.read"), quality.rows_read)
    q[1].metric(T("ui.quality.accepted"), quality.rows_accepted)
    q[2].metric(T("ui.quality.rejected"), quality.rows_rejected)
    q[3].metric(T("ui.quality.duplicates"), quality.exact_duplicates_removed)
    for warning in quality.warnings:
        st.warning(L(warning))
    if quality.rows_rejected:
        def translate_reasons(frame: pd.DataFrame) -> pd.DataFrame:
            return frame.assign(rejection_reason=frame["rejection_reason"].map(lambda r: L(rejection_reason_msg(r))))

        reason_column = {"rejection_reason": T("ui.quality.reason")}
        st.markdown(f"#### {T('ui.quality.reasons')}")
        st.dataframe(translate_reasons(quality.rejection_summary()), hide_index=True,
                     column_config={**reason_column, "rows": T("ui.quality.rows")})
        st.markdown(f"#### {T('ui.quality.rejected_rows')}")
        st.dataframe(translate_reasons(quality.rejected_rows), hide_index=True, width="stretch",
                     column_config=reason_column)
    else:
        st.success(T("ui.quality.all_passed"))

# ---------------------------------------------------------------------------
# Rule export (detection as code). Built from the same config as the alerts, so the sidebar
# thresholds apply. The exported files are always in English, like the CSV exports.
# ---------------------------------------------------------------------------
with tab_export:
    st.markdown(T("ui.export.intro"))
    exported = export_rules(config)
    if not exported:
        st.info(T("ui.export.none_enabled"))
    else:
        detections = list(dict.fromkeys(rule.detection for rule in exported))
        col_rule, col_format = st.columns([2, 1])
        slug = col_rule.selectbox(T("ui.export.rule"), [d.slug for d in detections], key="export_rule",
                                  format_func=lambda s: next(f"{d.rule_id} - {d.title}" for d in detections
                                                             if d.slug == s))
        fmt = col_format.radio(T("ui.export.format"), list(FORMATS), format_func=FORMAT_NAMES.get, horizontal=True,
                               key="export_format")
        rule = next(r for r in exported if r.detection.slug == slug and r.fmt == fmt)
        if not rule.supported:
            st.warning(T("ui.export.not_expressible"))
        st.code(rule.text, language=CODE_LANGUAGES[fmt])
        col_one, col_all = st.columns(2)
        col_one.download_button(T("ui.export.download", file=rule.filename), rule.text, rule.filename, "text/plain",
                                key="export_download")
        col_all.download_button(T("ui.export.download_all"), export_zip(exported), "mini_soc_lab_rules.zip",
                                "application/zip", key="export_download_all")
        st.markdown(f"#### {T('ui.export.mapping')}")
        st.dataframe(pd.DataFrame(FIELD_MAPPING, columns=["lab", "sentinel", "splunk"]), hide_index=True,
                     column_config={"lab": T("ui.export.col_lab"), "sentinel": T("ui.export.col_sentinel"),
                                    "splunk": T("ui.export.col_splunk")})
        st.caption(T("ui.export.caption"))

# ---------------------------------------------------------------------------
# About
# ---------------------------------------------------------------------------
with tab_about:
    st.markdown(T("ui.about"))
