"""Export the detection rules as Sigma, Splunk SPL and Microsoft Sentinel KQL ("detection as code").

The lab's events mirror the Windows Security log (event codes 4624, 4625, 4740, 4767), so the
exported rules target that log. Every query is built from the current configuration: changing a
threshold in config/detection_rules.json or in the dashboard sidebar changes the exported rule.

The queries reproduce the lab's logic (same clusters, windows, thresholds and severity steps)
where the target language allows it; every difference is written in the rule's own header.
They follow each language's documented syntax but have not been run on a live SIEM.
The exported files are technical artefacts, so - like the CSV exports - they are always in English.
"""

from __future__ import annotations

import io
import json
import re
import uuid
import zipfile
from dataclasses import dataclass

FORMATS = {"sigma": "yml", "spl": "spl", "kql": "kql"}
FORMAT_NAMES = {"sigma": "Sigma", "spl": "Splunk SPL", "kql": "Microsoft Sentinel KQL"}
CODE_LANGUAGES = {"sigma": "yaml", "spl": "splunk-spl", "kql": "kusto"}

# Lab field -> field in Sigma / Sentinel (SecurityEvent table) -> field in Splunk (XmlWinEventLog:Security).
FIELD_MAPPING = [
    ("timestamp", "TimeGenerated", "_time"),
    ("username", "TargetUserName", "TargetUserName"),
    ("source_ip", "IpAddress", "IpAddress"),
    ("event_code", "EventID", "EventCode"),
    ("hostname", "Computer", "host"),
]

SPL_SOURCE = 'index=wineventlog sourcetype="XmlWinEventLog:Security"'
KQL_TABLE = "SecurityEvent"
SIGMA_DATE = "2026-10-29"
SIGMA_LOGSOURCE = {"product": "windows", "service": "security"}
_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/mathgenti-stack/mini-soc-lab")
_UNTESTED = "Syntax follows the official documentation but was not run on a live SIEM: test before production use."


@dataclass(frozen=True)
class Detection:
    """One exported detection. R005 has three patterns, so it becomes three detections."""

    slug: str
    rule_id: str
    title: str
    description: str
    level: str
    tags: tuple[str, ...]
    falsepositives: tuple[str, ...]
    params: tuple[str, ...]
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExportedRule:
    detection: Detection
    fmt: str
    text: str
    supported: bool = True  # False when the language cannot express the rule (the file explains why)

    @property
    def filename(self) -> str:
        return f"{self.detection.slug}.{FORMATS[self.fmt]}"

    @property
    def path(self) -> str:
        return f"{self.fmt}/{self.filename}"


DETECTIONS = [
    Detection(
        "R001_multiple_failed_logons", "R001", "Multiple failed logon attempts for one account",
        "At least failure_threshold failed logons for the same account within any window_minutes sliding window.",
        "medium", ("attack.credential-access", "attack.t1110.001"),
        ("Forgotten or recently changed passwords", "Devices that still hold old credentials"),
        ("window_minutes", "failure_threshold", "high_severity_threshold"),
        ("Severity is raised to high when a source is external or the peak reaches high_severity_threshold.",),
    ),
    Detection(
        "R002_success_after_failures", "R002", "Successful logon after repeated failures",
        "A successful logon preceded by at least min_failures failures for the same account within "
        "lookback_minutes. The failure count restarts after every success.",
        "medium", ("attack.credential-access", "attack.initial-access", "attack.t1110", "attack.t1078"),
        ("Users who mistype their password and then get it right",),
        ("lookback_minutes", "min_failures", "critical_failure_threshold"),
        ("Severity: high when the success came from an external address; critical when, in addition, at least "
         "critical_failure_threshold of the failures came from that same address.",),
    ),
    Detection(
        "R003_high_failure_rate", "R003", "High authentication failure rate",
        "Per source address and per account, per UTC day: at least min_attempts logon attempts and a failure "
        "rate of at least failure_rate_threshold.",
        "low", ("attack.credential-access", "attack.t1110"),
        ("Service accounts with expired passwords", "Scanners", "Misconfigured applications"),
        ("entity_fields", "min_attempts", "failure_rate_threshold", "high_failure_rate"),
        ("Severity: medium when the rate reaches high_failure_rate; raised one more level when external "
         "addresses are involved.",
         "Days are calendar days in UTC: in Splunk, run the search with the user time zone set to UTC."),
    ),
    Detection(
        "R004_single_ip_many_accounts", "R004", "Repeated failures from a single IP across many accounts",
        "At least min_distinct_accounts distinct accounts with failed logons from the same source address within "
        "any window_minutes sliding window (the shape of password spraying).",
        "medium", ("attack.credential-access", "attack.t1110.003"),
        ("Authorised vulnerability scans", "Many users behind one gateway after a password policy change"),
        ("window_minutes", "min_distinct_accounts", "high_distinct_accounts"),
        ("Severity: high when the source is external or high_distinct_accounts is reached; critical when any "
         "account logged on successfully from that address during the activity or within one window after it.",),
    ),
    Detection(
        "R005_lockout_then_success", "R005", "Successful logon after an account lockout",
        "An account lockout (4740) followed by a successful logon for the same account within "
        "lockout_success_window_minutes.",
        "medium", ("attack.credential-access", "attack.initial-access", "attack.t1110", "attack.t1078"),
        ("The service desk unlocked the account and the user logged on again",),
        ("lockout_success_window_minutes",),
        ("Severity: high when the success came from an external address. The result records whether an "
         "unlock (4767) happened in between, a strong benign indicator.",),
    ),
    Detection(
        "R005_off_hours_new_source", "R005", "Out-of-hours logon from a new source",
        "A successful logon outside business hours from an address never seen in an earlier successful logon "
        "for that account. Nothing is alerted during the first baseline_learning_days of the data.",
        "low", ("attack.initial-access", "attack.t1078"),
        ("On-call staff", "Travel", "A new home router or mobile network"),
        ("baseline_learning_days",),
        ("Severity: medium for an external source.",
         "The baseline is the history inside the search time range: search a long enough period.",
         "Business hours are evaluated in UTC: in Splunk, run the search with the user time zone set to UTC."),
    ),
    Detection(
        "R005_rapid_source_change", "R005", "Logons from two external addresses in a short time",
        "Two consecutive successful logons for the same account from different external addresses within "
        "rapid_source_change_minutes (a simplified impossible-travel check, without geolocation).",
        "medium", ("attack.initial-access", "attack.t1078"),
        ("VPN reconnections", "Switching between home broadband and a mobile network"),
        ("rapid_source_change_minutes",),
        ("The Sigma version counts distinct external addresses per account within the window, which also fires when the two logons are not consecutive.",),
    ),
]


def export_rules(config: dict, formats: list[str] | None = None) -> list[ExportedRule]:
    """Every enabled detection in every requested format, built from `config`."""
    env, rules = config["environment"], config["rules"]
    exported = []
    for detection in DETECTIONS:
        params = rules[detection.rule_id]
        if not params.get("enabled", True):
            continue
        for fmt in formats or list(FORMATS):
            text, supported = _BUILDERS[fmt][detection.slug](detection, params, env)
            exported.append(ExportedRule(detection, fmt, text, supported))
    return exported


def export_zip(exported: list[ExportedRule]) -> bytes:
    """All exported files in one zip (fixed timestamps, so the same rules give the same bytes)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in [("README.txt", _zip_readme()), *((rule.path, rule.text) for rule in exported)]:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text)
    return buffer.getvalue()


def _zip_readme() -> str:
    mapping = "\n".join(f"  {lab:<12} -> {sentinel:<15} (Splunk: {splunk})" for lab, sentinel, splunk in FIELD_MAPPING)
    return (f"Mini SOC Lab - exported detection rules\n\n"
            f"sigma/  Sigma rules (with Sigma correlation rules)\n"
            f"spl/    Splunk SPL searches ({SPL_SOURCE})\n"
            f"kql/    Microsoft Sentinel KQL queries ({KQL_TABLE} table)\n\n"
            f"Field mapping (lab -> SIEM):\n{mapping}\n\n{_UNTESTED}\n")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _num(value) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def _seconds(minutes) -> str:
    return _num(float(minutes) * 60)


def _header_lines(detection: Detection, params: dict, fmt: str) -> list[str]:
    values = ", ".join(f"{name}={_num(params[name]) if name != 'entity_fields' else '/'.join(params[name])}"
                       for name in detection.params)
    techniques = ", ".join(tag.split(".", 1)[1].upper() for tag in detection.tags if re.match(r"attack\.t\d", tag))
    lines = [f"Mini SOC Lab {detection.rule_id} - {detection.title} ({FORMAT_NAMES[fmt]})",
             f"Logic: {detection.description}",
             f"Parameters: {values}",
             f"MITRE ATT&CK: {techniques}"]
    lines += [f"Note: {note}" for note in detection.notes]
    lines.append(_UNTESTED)
    return lines


def _spl(detection: Detection, params: dict, body: list[str]) -> tuple[str, bool]:
    header = "\n".join(_header_lines(detection, params, "spl")).replace("```", "'''")
    return f"```\n{header}\n```\n" + "\n".join(body) + "\n", True


def _kql(detection: Detection, params: dict, body: list[str]) -> tuple[str, bool]:
    header = "\n".join(f"// {line}" for line in _header_lines(detection, params, "kql"))
    return header + "\n" + "\n".join(body) + "\n", True


def _spl_is_external(env: dict) -> str:
    checks = " OR ".join(f'cidrmatch("{net}", IpAddress)' for net in env["internal_networks"])
    return f"if({checks}, 0, 1)"


def _kql_internal(env: dict) -> str:
    return f"let internal_networks = dynamic({json.dumps(list(env['internal_networks']))});"


# ---------------------------------------------------------------------------
# Sigma (YAML written by hand: the project has no YAML dependency)
# ---------------------------------------------------------------------------
_PLAIN_SCALAR = re.compile(r"[A-Za-z][A-Za-z0-9_.\-/|]*")
_YAML_RESERVED = {"y", "n", "yes", "no", "on", "off", "true", "false", "null"}


def _yaml_scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _num(value)
    text = str(value)
    if _PLAIN_SCALAR.fullmatch(text) and text.lower() not in _YAML_RESERVED:
        return text
    return json.dumps(text)  # a JSON string is a valid YAML double-quoted scalar


def to_yaml(value, indent: int = 0) -> str:
    """The small YAML subset Sigma rules need: nested mappings, lists and scalars."""
    pad = " " * indent
    lines = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:")
                lines.append(to_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(item)}")
    else:
        for item in value:
            if isinstance(item, dict):
                nested = to_yaml(item, indent + 2).splitlines()
                lines.append(f"{pad}- {nested[0].lstrip()}")
                lines.extend(nested[1:])
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
    return "\n".join(lines)


def _rule_id(detection: Detection, part: str) -> str:
    return str(uuid.uuid5(_ID_NAMESPACE, f"{detection.slug}/{part}"))


def _rule_name(detection: Detection, part: str) -> str:
    return f"mini_soc_lab_{detection.slug.lower()}_{part}"


def _sigma_base(detection: Detection, part: str, title: str, selection: dict, filters: dict | None = None) -> dict:
    condition = "selection" + "".join(f" and not {name}" for name in filters or {})
    return {
        "title": title,
        "id": _rule_id(detection, part),
        "name": _rule_name(detection, part),
        "status": "experimental",
        "description": f"Base rule used by the {detection.rule_id} correlation rule below.",
        "author": "Mini SOC Lab",
        "date": SIGMA_DATE,
        "logsource": SIGMA_LOGSOURCE,
        "detection": {"selection": selection, **(filters or {}), "condition": condition},
        "level": "informational",
    }


def _sigma_correlation(detection: Detection, part: str, correlation: dict, final: bool = True) -> dict:
    rule = {
        "title": detection.title if final else f"{detection.title} - {part.replace('_', ' ')}",
        "id": _rule_id(detection, part),
        "name": _rule_name(detection, part),
        "status": "experimental",
        "description": detection.description,
        "author": "Mini SOC Lab",
        "date": SIGMA_DATE,
        "correlation": correlation,
    }
    if final:
        rule.update(tags=list(detection.tags), falsepositives=list(detection.falsepositives))
    rule["level"] = detection.level
    return rule


def _sigma(detection: Detection, params: dict, documents: list[dict]) -> tuple[str, bool]:
    header = "\n".join(f"# {line}" for line in _header_lines(detection, params, "sigma"))
    return header + "\n" + "\n---\n".join(to_yaml(doc) for doc in documents) + "\n", True


def _sigma_unsupported(detection: Detection, params: dict, reason: str) -> tuple[str, bool]:
    lines = _header_lines(detection, params, "sigma")
    lines[1:1] = [f"Not expressible in Sigma: {reason}",
                  f"Use {detection.slug}.spl or {detection.slug}.kql instead."]
    return "\n".join(f"# {line}" for line in lines) + "\n", False


def _sigma_r001(d, p, env):
    window = f"{_num(p['window_minutes'])}m"
    return _sigma(d, p, [
        _sigma_base(d, "failed_logon", "Failed logon", {"EventID": 4625}),
        _sigma_correlation(d, "correlation", {"type": "event_count", "rules": [_rule_name(d, "failed_logon")],
                                              "group-by": ["TargetUserName"], "timespan": window,
                                              "condition": {"gte": int(p["failure_threshold"])}}),
    ])


def _sigma_r002(d, p, env):
    window = f"{_num(p['lookback_minutes'])}m"
    return _sigma(d, p, [
        _sigma_base(d, "failed_logon", "Failed logon", {"EventID": 4625}),
        _sigma_base(d, "successful_logon", "Successful logon", {"EventID": 4624}),
        _sigma_correlation(d, "repeated_failures", {"type": "event_count", "rules": [_rule_name(d, "failed_logon")],
                                                    "group-by": ["TargetUserName"], "timespan": window,
                                                    "condition": {"gte": int(p["min_failures"])}}, final=False),
        _sigma_correlation(d, "correlation", {"type": "temporal_ordered",
                                              "rules": [_rule_name(d, "repeated_failures"),
                                                        _rule_name(d, "successful_logon")],
                                              "group-by": ["TargetUserName"], "timespan": window}),
    ])


def _sigma_r003(d, p, env):
    return _sigma_unsupported(d, p, "Sigma correlations count events or distinct values but cannot divide "
                                    "failures by attempts to get a failure rate.")


def _sigma_r004(d, p, env):
    window = f"{_num(p['window_minutes'])}m"
    return _sigma(d, p, [
        _sigma_base(d, "failed_logon", "Failed logon", {"EventID": 4625}),
        _sigma_correlation(d, "correlation", {"type": "value_count", "rules": [_rule_name(d, "failed_logon")],
                                              "group-by": ["IpAddress"], "timespan": window,
                                              "condition": {"gte": int(p["min_distinct_accounts"]),
                                                            "field": "TargetUserName"}}),
    ])


def _sigma_r005_lockout(d, p, env):
    window = f"{_num(p['lockout_success_window_minutes'])}m"
    return _sigma(d, p, [
        _sigma_base(d, "lockout", "Account locked out", {"EventID": 4740}),
        _sigma_base(d, "successful_logon", "Successful logon", {"EventID": 4624}),
        _sigma_correlation(d, "correlation", {"type": "temporal_ordered",
                                              "rules": [_rule_name(d, "lockout"), _rule_name(d, "successful_logon")],
                                              "group-by": ["TargetUserName"], "timespan": window}),
    ])


def _sigma_r005_off_hours(d, p, env):
    return _sigma_unsupported(d, p, "the rule needs each account's history of source addresses (a baseline), "
                                    "and Sigma has no notion of a value never seen before.")


def _sigma_r005_rapid(d, p, env):
    window = f"{_num(p['rapid_source_change_minutes'])}m"
    internal = {"filter_internal": {"IpAddress|cidr": list(env["internal_networks"])}}
    return _sigma(d, p, [
        _sigma_base(d, "external_logon", "Successful logon from an external address", {"EventID": 4624}, internal),
        _sigma_correlation(d, "correlation", {"type": "value_count", "rules": [_rule_name(d, "external_logon")],
                                              "group-by": ["TargetUserName"], "timespan": window,
                                              "condition": {"gte": 2, "field": "IpAddress"}}),
    ])


# ---------------------------------------------------------------------------
# Splunk SPL
# ---------------------------------------------------------------------------
def _spl_clusters(group_by: str, window_seconds: str) -> list[str]:
    """Group events into clusters where each one is at most one window after the previous one."""
    return [
        "| sort 0 _time",
        f"| streamstats current=f window=1 last(_time) AS previous_time BY {group_by}",
        f"| eval new_cluster=if(isnull(previous_time) OR _time - previous_time > {window_seconds}, 1, 0)",
        f"| streamstats sum(new_cluster) AS cluster_id BY {group_by}",
    ]


def _spl_r001(d, p, env):
    window = _num(p["window_minutes"])
    return _spl(d, p, [
        f"{SPL_SOURCE} EventCode=4625",
        f"| eval is_external={_spl_is_external(env)}",
        *_spl_clusters("TargetUserName", _seconds(window)),
        f"| streamstats time_window={window}m count AS failures_in_window BY TargetUserName",
        "| stats min(_time) AS first_seen max(_time) AS last_seen count AS failures "
        "max(failures_in_window) AS peak_failures max(is_external) AS any_external values(IpAddress) AS source_ips "
        "BY TargetUserName cluster_id",
        f"| where peak_failures >= {int(p['failure_threshold'])}",
        f"| eval severity=if(any_external=1 OR peak_failures >= {int(p['high_severity_threshold'])}, \"High\", \"Medium\")",
        "| convert ctime(first_seen) ctime(last_seen)",
        "| table first_seen last_seen TargetUserName failures peak_failures source_ips severity",
    ])


def _spl_r002(d, p, env):
    window = _num(p["lookback_minutes"])
    return _spl(d, p, [
        f"{SPL_SOURCE} (EventCode=4624 OR EventCode=4625)",
        "| eval is_failure=if(EventCode=4625, 1, 0), is_success=1 - is_failure",
        "| sort 0 _time",
        "``` Failures belong to the group that ends at the next success, so the count restarts after each success ```",
        "| streamstats sum(is_success) AS successes_so_far BY TargetUserName",
        "| eval attempt_group=if(is_success=1, successes_so_far - 1, successes_so_far)",
        f"| streamstats current=f time_window={window}m sum(is_failure) AS recent_failures "
        "BY TargetUserName attempt_group",
        f"| streamstats current=f time_window={window}m sum(is_failure) AS same_ip_failures "
        "BY TargetUserName attempt_group IpAddress",
        f"| where is_success=1 AND recent_failures >= {int(p['min_failures'])}",
        f"| eval is_external={_spl_is_external(env)}, same_ip_failures=coalesce(same_ip_failures, 0)",
        f"| eval severity=case(is_external=1 AND same_ip_failures >= {int(p['critical_failure_threshold'])}, "
        "\"Critical\", is_external=1, \"High\", true(), \"Medium\")",
        "| table _time TargetUserName IpAddress recent_failures same_ip_failures severity",
    ])


def _spl_r003(d, p, env):
    labels = {"source_ip": '"source_ip=" . IpAddress', "username": '"username=" . TargetUserName'}
    high = _num(p["high_failure_rate"])
    return _spl(d, p, [
        f"{SPL_SOURCE} (EventCode=4624 OR EventCode=4625)",
        f"| eval day=strftime(_time, \"%Y-%m-%d\"), is_failure=if(EventCode=4625, 1, 0), "
        f"is_external={_spl_is_external(env)}",
        f"| eval entity=mvappend({', '.join(labels[field] for field in p['entity_fields'])})",
        "| mvexpand entity",
        "| stats count AS attempts sum(is_failure) AS failures max(is_external) AS any_external BY entity day",
        "| eval failure_rate=failures / attempts",
        f"| where attempts >= {int(p['min_attempts'])} AND failure_rate >= {_num(p['failure_rate_threshold'])}",
        f"| eval severity=case(failure_rate >= {high} AND any_external=1, \"High\", "
        f"failure_rate >= {high} OR any_external=1, \"Medium\", true(), \"Low\")",
        "| eval failure_rate=round(failure_rate, 3)",
        "| table day entity attempts failures failure_rate severity",
    ])


def _spl_r004(d, p, env):
    window = _num(p["window_minutes"])
    return _spl(d, p, [
        f"{SPL_SOURCE} EventCode=4625",
        *_spl_clusters("IpAddress", _seconds(window)),
        f"| streamstats time_window={window}m dc(TargetUserName) AS accounts_in_window BY IpAddress",
        "| stats min(_time) AS first_seen max(_time) AS last_seen max(accounts_in_window) AS peak_distinct_accounts "
        "values(TargetUserName) AS targeted_accounts BY IpAddress cluster_id",
        f"| where peak_distinct_accounts >= {int(p['min_distinct_accounts'])}",
        "``` Any successful logon from the same address during the activity or within one window after it ```",
        "| join type=left max=0 IpAddress",
        f"    [ search {SPL_SOURCE} EventCode=4624",
        "      | eval success_time=_time | rename TargetUserName AS success_account",
        "      | fields IpAddress success_time success_account ]",
        f"| eval related_success=if(success_time >= first_seen AND success_time <= last_seen + {_seconds(window)}, "
        "success_account, null())",
        "| stats values(related_success) AS successful_accounts values(targeted_accounts) AS targeted_accounts "
        "BY IpAddress cluster_id first_seen last_seen peak_distinct_accounts",
        f"| eval is_external={_spl_is_external(env)}",
        f"| eval severity=case(isnotnull(successful_accounts), \"Critical\", is_external=1 OR "
        f"peak_distinct_accounts >= {int(p['high_distinct_accounts'])}, \"High\", true(), \"Medium\")",
        "| convert ctime(first_seen) ctime(last_seen)",
        "| table first_seen last_seen IpAddress peak_distinct_accounts targeted_accounts successful_accounts severity",
    ])


def _spl_r005_lockout(d, p, env):
    return _spl(d, p, [
        f"{SPL_SOURCE} (EventCode=4740 OR EventCode=4767 OR EventCode=4624)",
        "| eval lockout_time=if(EventCode=4740, _time, null()), unlock_time=if(EventCode=4767, _time, null())",
        "| sort 0 _time",
        "| streamstats current=f last(lockout_time) AS last_lockout last(unlock_time) AS last_unlock BY TargetUserName",
        f"| where EventCode=4624 AND _time > last_lockout AND _time - last_lockout <= "
        f"{_seconds(p['lockout_success_window_minutes'])}",
        "``` Keep the first successful logon after each lockout ```",
        "| dedup TargetUserName last_lockout sortby +_time",
        "| eval unlocked_in_between=if(isnotnull(last_unlock) AND last_unlock >= last_lockout, \"yes\", \"no\")",
        f"| eval is_external={_spl_is_external(env)}, severity=if(is_external=1, \"High\", \"Medium\")",
        "| convert ctime(last_lockout)",
        "| table _time TargetUserName IpAddress last_lockout unlocked_in_between severity",
    ])


def _spl_r005_off_hours(d, p, env):
    hours = env["business_hours"]
    weekdays = " OR ".join(f"weekday={day}" for day in hours.get("weekdays", [0, 1, 2, 3, 4])) or "1=0"
    return _spl(d, p, [
        f"{SPL_SOURCE} EventCode=4624",
        "| sort 0 _time",
        "| eventstats min(_time) AS data_start",
        "``` times_seen=1 marks the first successful logon of this account from this address ```",
        "| streamstats count AS times_seen BY TargetUserName IpAddress",
        "``` weekday: Monday=0 ... Sunday=6, as in the lab configuration ```",
        "| eval weekday=(tonumber(strftime(_time, \"%w\")) + 6) % 7, hour=tonumber(strftime(_time, \"%H\"))",
        f"| eval business_hours=if(({weekdays}) AND hour >= {int(hours['start_hour'])} AND "
        f"hour < {int(hours['end_hour'])}, 1, 0)",
        f"| where times_seen=1 AND business_hours=0 AND _time >= data_start + "
        f"{_num(float(p['baseline_learning_days']) * 86400)}",
        f"| eval is_external={_spl_is_external(env)}, severity=if(is_external=1, \"Medium\", \"Low\")",
        "| table _time TargetUserName IpAddress severity",
    ])


def _spl_r005_rapid(d, p, env):
    return _spl(d, p, [
        f"{SPL_SOURCE} EventCode=4624",
        f"| eval is_external={_spl_is_external(env)}",
        "| where is_external=1",
        "| sort 0 _time",
        "| streamstats current=f window=1 last(IpAddress) AS previous_ip last(_time) AS previous_time BY TargetUserName",
        f"| where isnotnull(previous_ip) AND IpAddress != previous_ip AND _time - previous_time <= "
        f"{_seconds(p['rapid_source_change_minutes'])}",
        "| eval severity=\"Medium\"",
        "| convert ctime(previous_time)",
        "| table previous_time previous_ip _time IpAddress TargetUserName severity",
    ])


# ---------------------------------------------------------------------------
# Microsoft Sentinel KQL
# ---------------------------------------------------------------------------
def _kql_clusters(name: str, event_id: int, group_by: str) -> list[str]:
    """Clusters as in SPL; row_id identifies each event for the sliding-window self-join."""
    return [
        f"let {name} = materialize({KQL_TABLE}",
        f"    | where EventID == {event_id}",
        "    | project TimeGenerated, TargetUserName, IpAddress",
        f"    | sort by {group_by} asc, TimeGenerated asc",
        f"    | extend new_cluster = iff({group_by} != prev({group_by}) or TimeGenerated - prev(TimeGenerated) > window, 1, 0)",
        "    | extend cluster_id = row_cumsum(new_cluster), row_id = row_number());",
    ]


def _kql_window_join(name: str, other_column: str) -> list[str]:
    return [
        f"    | join kind=inner ({name} | project cluster_id, OtherTime = TimeGenerated, {other_column}) on cluster_id",
        "    | where OtherTime between ((TimeGenerated - window) .. TimeGenerated)",
    ]


def _kql_r001(d, p, env):
    return _kql(d, p, [
        f"let window = {_num(p['window_minutes'])}m;",
        f"let failure_threshold = {int(p['failure_threshold'])};",
        f"let high_severity_threshold = {int(p['high_severity_threshold'])};",
        _kql_internal(env),
        *_kql_clusters("failures", 4625, "TargetUserName"),
        "let peaks = failures",
        *_kql_window_join("failures", "OtherAccount = TargetUserName"),
        "    | summarize failures_in_window = count() by cluster_id, row_id",
        "    | summarize peak_failures = max(failures_in_window) by cluster_id;",
        "failures",
        "| extend is_external = toint(not(ipv4_is_in_any_range(IpAddress, internal_networks)))",
        "| summarize first_seen = min(TimeGenerated), last_seen = max(TimeGenerated), failures = count(),",
        "    any_external = max(is_external), source_ips = make_set(IpAddress) by cluster_id, TargetUserName",
        "| join kind=inner peaks on cluster_id",
        "| where peak_failures >= failure_threshold",
        "| extend severity = iff(any_external == 1 or peak_failures >= high_severity_threshold, \"High\", \"Medium\")",
        "| project first_seen, last_seen, TargetUserName, failures, peak_failures, source_ips, severity",
    ])


def _kql_r002(d, p, env):
    return _kql(d, p, [
        f"let lookback = {_num(p['lookback_minutes'])}m;",
        f"let min_failures = {int(p['min_failures'])};",
        f"let critical_failure_threshold = {int(p['critical_failure_threshold'])};",
        _kql_internal(env),
        "// Failures belong to the group that ends at the next success, so the count restarts after each success.",
        f"let logons = materialize({KQL_TABLE}",
        "    | where EventID in (4624, 4625)",
        "    | project TimeGenerated, TargetUserName, IpAddress, EventID",
        "    | sort by TargetUserName asc, TimeGenerated asc",
        "    | extend successes_so_far = row_cumsum(toint(EventID == 4624), TargetUserName != prev(TargetUserName))",
        "    | extend attempt_group = iff(EventID == 4624, successes_so_far - 1, successes_so_far));",
        "logons",
        "| where EventID == 4624",
        "| join kind=inner (logons | where EventID == 4625",
        "    | project TargetUserName, attempt_group, FailureTime = TimeGenerated, FailureIp = IpAddress)",
        "    on TargetUserName, attempt_group",
        "| where TimeGenerated - FailureTime between (0s .. lookback)",
        "| summarize recent_failures = count(), same_ip_failures = countif(FailureIp == IpAddress)",
        "    by SuccessTime = TimeGenerated, TargetUserName, IpAddress",
        "| where recent_failures >= min_failures",
        "| extend is_external = not(ipv4_is_in_any_range(IpAddress, internal_networks))",
        "| extend severity = case(is_external and same_ip_failures >= critical_failure_threshold, \"Critical\",",
        "    is_external, \"High\", \"Medium\")",
    ])


def _kql_r003(d, p, env):
    labels = {"source_ip": 'strcat("source_ip=", IpAddress)', "username": 'strcat("username=", TargetUserName)'}
    return _kql(d, p, [
        f"let min_attempts = {int(p['min_attempts'])};",
        f"let failure_rate_threshold = {_num(p['failure_rate_threshold'])};",
        f"let high_failure_rate = {_num(p['high_failure_rate'])};",
        _kql_internal(env),
        KQL_TABLE,
        "| where EventID in (4624, 4625)",
        "| extend day = startofday(TimeGenerated), is_failure = toint(EventID == 4625),",
        "    is_external = toint(not(ipv4_is_in_any_range(IpAddress, internal_networks)))",
        f"| extend entity = pack_array({', '.join(labels[field] for field in p['entity_fields'])})",
        "| mv-expand entity to typeof(string)",
        "| summarize attempts = count(), failures = sum(is_failure), any_external = max(is_external) by entity, day",
        "| extend failure_rate = todouble(failures) / attempts",
        "| where attempts >= min_attempts and failure_rate >= failure_rate_threshold",
        "| extend severity = case(failure_rate >= high_failure_rate and any_external == 1, \"High\",",
        "    failure_rate >= high_failure_rate or any_external == 1, \"Medium\", \"Low\")",
        "| extend failure_rate = round(failure_rate, 3)",
    ])


def _kql_r004(d, p, env):
    return _kql(d, p, [
        f"let window = {_num(p['window_minutes'])}m;",
        f"let min_distinct_accounts = {int(p['min_distinct_accounts'])};",
        f"let high_distinct_accounts = {int(p['high_distinct_accounts'])};",
        _kql_internal(env),
        *_kql_clusters("failures", 4625, "IpAddress"),
        "let peaks = failures",
        *_kql_window_join("failures", "OtherAccount = TargetUserName"),
        "    | summarize accounts_in_window = dcount(OtherAccount, 4) by cluster_id, row_id",
        "    | summarize peak_distinct_accounts = max(accounts_in_window) by cluster_id;",
        f"let successes = {KQL_TABLE}",
        "    | where EventID == 4624",
        "    | project SuccessTime = TimeGenerated, IpAddress, SuccessAccount = TargetUserName;",
        "failures",
        "| summarize first_seen = min(TimeGenerated), last_seen = max(TimeGenerated),",
        "    targeted_accounts = make_set(TargetUserName) by cluster_id, IpAddress",
        "| join kind=inner peaks on cluster_id",
        "| where peak_distinct_accounts >= min_distinct_accounts",
        "// Any successful logon from the same address during the activity or within one window after it.",
        "| join kind=leftouter successes on IpAddress",
        "| summarize successful_accounts = make_set_if(SuccessAccount, SuccessTime between (first_seen .. (last_seen + window))),",
        "    targeted_accounts = take_any(targeted_accounts)",
        "    by cluster_id, IpAddress, first_seen, last_seen, peak_distinct_accounts",
        "| extend is_external = not(ipv4_is_in_any_range(IpAddress, internal_networks))",
        "| extend severity = case(array_length(successful_accounts) > 0, \"Critical\",",
        "    is_external or peak_distinct_accounts >= high_distinct_accounts, \"High\", \"Medium\")",
        "| project first_seen, last_seen, IpAddress, peak_distinct_accounts, targeted_accounts, successful_accounts, severity",
    ])


def _kql_r005_lockout(d, p, env):
    return _kql(d, p, [
        f"let window = {_num(p['lockout_success_window_minutes'])}m;",
        _kql_internal(env),
        f"let lockouts = {KQL_TABLE} | where EventID == 4740 | project LockoutTime = TimeGenerated, TargetUserName;",
        f"let unlocks = {KQL_TABLE} | where EventID == 4767 | project UnlockTime = TimeGenerated, TargetUserName;",
        f"let successes = {KQL_TABLE} | where EventID == 4624 "
        "| project SuccessTime = TimeGenerated, TargetUserName, IpAddress;",
        "lockouts",
        "| join kind=inner successes on TargetUserName",
        "| where SuccessTime > LockoutTime and SuccessTime <= LockoutTime + window",
        "// Keep the first successful logon after each lockout.",
        "| summarize arg_min(SuccessTime, IpAddress) by TargetUserName, LockoutTime",
        "| join kind=leftouter unlocks on TargetUserName",
        "| summarize unlocks_in_between = countif(UnlockTime between (LockoutTime .. SuccessTime))",
        "    by TargetUserName, LockoutTime, SuccessTime, IpAddress",
        "| extend unlocked_in_between = unlocks_in_between > 0",
        "| extend is_external = not(ipv4_is_in_any_range(IpAddress, internal_networks))",
        "| extend severity = iff(is_external, \"High\", \"Medium\")",
    ])


def _kql_r005_off_hours(d, p, env):
    hours = env["business_hours"]
    return _kql(d, p, [
        f"let baseline_learning = {_num(p['baseline_learning_days'])}d;",
        f"let business_weekdays = dynamic({json.dumps(list(hours.get('weekdays', [0, 1, 2, 3, 4])))});"
        "  // Monday=0 ... Sunday=6",
        _kql_internal(env),
        f"let successes = materialize({KQL_TABLE} | where EventID == 4624 "
        "| project TimeGenerated, TargetUserName, IpAddress);",
        "let learning_end = toscalar(successes | summarize min(TimeGenerated)) + baseline_learning;",
        "successes",
        "| sort by TargetUserName asc, IpAddress asc, TimeGenerated asc",
        "// The first row of each account/address pair is the first logon from that address.",
        "| extend new_source = TargetUserName != prev(TargetUserName) or IpAddress != prev(IpAddress)",
        "| where new_source and TimeGenerated >= learning_end",
        "| extend weekday = (toint(dayofweek(TimeGenerated) / 1d) + 6) % 7, hour = hourofday(TimeGenerated)",
        f"| where not(set_has_element(business_weekdays, weekday) and hour >= {int(hours['start_hour'])} "
        f"and hour < {int(hours['end_hour'])})",
        "| extend is_external = not(ipv4_is_in_any_range(IpAddress, internal_networks))",
        "| extend severity = iff(is_external, \"Medium\", \"Low\")",
        "| project TimeGenerated, TargetUserName, IpAddress, severity",
    ])


def _kql_r005_rapid(d, p, env):
    return _kql(d, p, [
        f"let window = {_num(p['rapid_source_change_minutes'])}m;",
        _kql_internal(env),
        KQL_TABLE,
        "| where EventID == 4624",
        "| where not(ipv4_is_in_any_range(IpAddress, internal_networks))",
        "| project TimeGenerated, TargetUserName, IpAddress",
        "| sort by TargetUserName asc, TimeGenerated asc",
        "| extend previous_user = prev(TargetUserName), previous_ip = prev(IpAddress), previous_time = prev(TimeGenerated)",
        "| where TargetUserName == previous_user and IpAddress != previous_ip and TimeGenerated - previous_time <= window",
        "| extend severity = \"Medium\"",
        "| project previous_time, previous_ip, TimeGenerated, IpAddress, TargetUserName, severity",
    ])


_BUILDERS = {
    "sigma": {"R001_multiple_failed_logons": _sigma_r001, "R002_success_after_failures": _sigma_r002,
              "R003_high_failure_rate": _sigma_r003, "R004_single_ip_many_accounts": _sigma_r004,
              "R005_lockout_then_success": _sigma_r005_lockout, "R005_off_hours_new_source": _sigma_r005_off_hours,
              "R005_rapid_source_change": _sigma_r005_rapid},
    "spl": {"R001_multiple_failed_logons": _spl_r001, "R002_success_after_failures": _spl_r002,
            "R003_high_failure_rate": _spl_r003, "R004_single_ip_many_accounts": _spl_r004,
            "R005_lockout_then_success": _spl_r005_lockout, "R005_off_hours_new_source": _spl_r005_off_hours,
            "R005_rapid_source_change": _spl_r005_rapid},
    "kql": {"R001_multiple_failed_logons": _kql_r001, "R002_success_after_failures": _kql_r002,
            "R003_high_failure_rate": _kql_r003, "R004_single_ip_many_accounts": _kql_r004,
            "R005_lockout_then_success": _kql_r005_lockout, "R005_off_hours_new_source": _kql_r005_off_hours,
            "R005_rapid_source_change": _kql_r005_rapid},
}
