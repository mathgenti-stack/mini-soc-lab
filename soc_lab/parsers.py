"""Convert real-world log formats into the lab's event schema.

Supported formats (all parsed with the Python standard library):

- linux_auth   Linux /var/log/auth.log (OpenSSH, pam_faillock, passwd), syslog or RFC 3339 timestamps
- windows_xml  Windows Security events saved as XML from Event Viewer ("Save Selected Events... > XML")
               or exported with  Get-WinEvent ... | ForEach-Object { $_.ToXml() }
- entra_json   Microsoft Entra ID sign-in logs as JSON (portal download or the Graph API "value" array)

Every source record becomes at most one lab event (see docs/log_format.md for the schema).
Records that are not authentication activity, or that the lab cannot represent, are skipped and
counted by reason - nothing is dropped silently. The converted events then go through the same
validation as any CSV, so the rules never see unvalidated data.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

from .i18n import Msg
from .models import ALL_COLUMNS, EVENT_CODES, EventType, Result

FORMATS = ["lab_csv", "linux_auth", "windows_xml", "entra_json"]
# Fixed English codes stored with the skip counts; "conversion.skip.<code>" translates them.
SKIP_REASONS = ("not_auth_event", "duplicate_ssh_line", "machine_account", "anonymous_logon", "unsupported_event_id",
                "mfa_interrupt", "invalid_record")


@dataclass
class ConversionResult:
    fmt: str
    records_read: int = 0
    events: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=list(ALL_COLUMNS)))
    skipped: Counter = field(default_factory=Counter)

    @property
    def records_skipped(self) -> int:
        return sum(self.skipped.values())

    def to_csv_bytes(self) -> bytes:
        return self.events.to_csv(index=False).encode("utf-8")


class ConversionError(ValueError):
    """The input cannot be read as the chosen format at all."""


def detect_format(data: bytes, filename: str = "") -> str:
    """Guess the format from the file name and the first bytes."""
    head = data[:4096].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
    name = filename.lower()
    if name.endswith(".xml") or head.startswith("<"):
        return "windows_xml"
    if name.endswith(".json") or head.startswith(("{", "[")):
        return "entra_json"
    first_line = head.splitlines()[0] if head else ""
    if "event_id" in first_line and "timestamp" in first_line:
        return "lab_csv"
    if _SYSLOG_LINE.match(first_line) or name.endswith((".log", ".txt")) or "sshd[" in head:
        return "linux_auth"
    return "lab_csv"


def convert(data: bytes, fmt: str = "auto", filename: str = "", year: int | None = None) -> ConversionResult:
    """Convert `data` to lab events. `year` is needed for classic syslog lines, which have no year."""
    fmt = detect_format(data, filename) if fmt == "auto" else fmt
    if fmt == "lab_csv":
        return ConversionResult(fmt=fmt)  # already in the lab schema; load_events reads it directly
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16")  # Event Viewer and PowerShell often write UTF-16
        except UnicodeDecodeError as exc:
            raise ConversionError(Msg("conversion.error.encoding", detail=str(exc))) from exc
    result = ConversionResult(fmt=fmt)
    parser = {"linux_auth": _parse_linux_auth, "windows_xml": _parse_windows_xml, "entra_json": _parse_entra}[fmt]
    rows = parser(text, result, year or datetime.now(timezone.utc).year)
    frame = pd.DataFrame(rows, columns=list(ALL_COLUMNS)).fillna("").astype(str)
    result.events = frame
    return result


def _event(event_id, ts: datetime, username, source_ip, event_type, result, hostname="", failure_reason="",
           logon_type="", event_code=None) -> dict:
    return {
        "event_id": event_id,
        "timestamp": ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "username": username,
        "source_ip": source_ip or "-",
        "event_type": event_type,
        "result": result,
        "hostname": hostname,
        "event_code": event_code or EVENT_CODES.get((event_type, result), ""),
        "failure_reason": failure_reason,
        "logon_type": logon_type,
    }


# ---------------------------------------------------------------------------
# Linux auth.log
# ---------------------------------------------------------------------------
_SYSLOG_LINE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"|(?P<classic>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}))"
    r" (?P<host>\S+) (?P<program>[\w.\-/]+)(?:\[\d+\])?: (?P<message>.*)$")
_SSH_FAILED = re.compile(r"^Failed (?:password|publickey|keyboard-interactive/pam) for (?P<invalid>invalid user )?"
                         r"(?P<user>\S+) from (?P<ip>\S+) port \d+")
_SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic) "
                           r"for (?P<user>\S+) from (?P<ip>\S+) port \d+")
_SSH_DUPLICATES = re.compile(r"^(?:Invalid user |Connection closed by |Disconnected from |Received disconnect |"
                             r"pam_unix\(sshd:auth\): authentication failure|PAM \d+ more authentication failure)")
_FAILLOCK = re.compile(r"Consecutive login failures for user (?P<user>\S+) account temporarily locked")
_SESSION_CLOSED = re.compile(r"pam_unix\(sshd:session\): session closed for user (?P<user>\S+)")
_PASSWORD_CHANGED = re.compile(r"pam_unix\(passwd:chauthtok\): password changed for (?P<user>\S+)")


def _parse_linux_auth(text: str, result: ConversionResult, year: int) -> list[dict]:
    rows = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        result.records_read += 1
        match = _SYSLOG_LINE.match(line.strip())
        if not match:
            result.skipped["invalid_record"] += 1
            continue
        try:
            if match["iso"]:
                ts = datetime.fromisoformat(match["iso"].replace("Z", "+00:00"))
                ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            else:  # classic syslog has no year or time zone: the given year and UTC are assumed
                ts = datetime.strptime(f"{year} {match['classic']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            result.skipped["invalid_record"] += 1
            continue
        host, message, event_id = match["host"], match["message"], f"AUTH-{number:06d}"
        if found := _SSH_FAILED.match(message):
            reason = "UNKNOWN_USER" if found["invalid"] else "BAD_PASSWORD"
            rows.append(_event(event_id, ts, found["user"], found["ip"], EventType.LOGON, Result.FAILURE, host,
                               reason, "SSH"))
        elif found := _SSH_ACCEPTED.match(message):
            rows.append(_event(event_id, ts, found["user"], found["ip"], EventType.LOGON, Result.SUCCESS, host,
                               "", "SSH"))
        elif found := _FAILLOCK.search(message):
            rows.append(_event(event_id, ts, found["user"], "-", EventType.ACCOUNT_LOCKOUT, Result.INFO, host))
        elif found := _SESSION_CLOSED.search(message):
            rows.append(_event(event_id, ts, found["user"], "-", EventType.LOGOFF, Result.INFO, host, "", "SSH"))
        elif found := _PASSWORD_CHANGED.search(message):
            rows.append(_event(event_id, ts, found["user"], "-", EventType.PASSWORD_CHANGE, Result.SUCCESS, host))
        elif match["program"] == "sshd" and _SSH_DUPLICATES.match(message):
            result.skipped["duplicate_ssh_line"] += 1  # the same attempt is already counted from its Failed line
        else:
            result.skipped["not_auth_event"] += 1
    return rows


# ---------------------------------------------------------------------------
# Windows Security events (XML)
# ---------------------------------------------------------------------------
WINDOWS_EVENTS = {
    "4624": (EventType.LOGON, Result.SUCCESS),
    "4625": (EventType.LOGON, Result.FAILURE),
    "4634": (EventType.LOGOFF, Result.INFO),
    "4647": (EventType.LOGOFF, Result.INFO),
    "4723": (EventType.PASSWORD_CHANGE, Result.SUCCESS),
    "4724": (EventType.PASSWORD_CHANGE, Result.SUCCESS),
    "4740": (EventType.ACCOUNT_LOCKOUT, Result.INFO),
    "4767": (EventType.ACCOUNT_UNLOCK, Result.INFO),
}
LOGON_TYPES = {"2": "INTERACTIVE", "3": "NETWORK", "4": "BATCH", "5": "SERVICE", "7": "UNLOCK",
               "8": "NETWORK_CLEARTEXT", "9": "NEW_CREDENTIALS", "10": "REMOTE_INTERACTIVE", "11": "CACHED_INTERACTIVE"}
# NTSTATUS codes in 4625 Status / SubStatus.
FAILURE_STATUS = {"0xc000006a": "BAD_PASSWORD", "0xc0000064": "UNKNOWN_USER", "0xc0000234": "ACCOUNT_LOCKED",
                  "0xc0000071": "EXPIRED_PASSWORD", "0xc0000224": "EXPIRED_PASSWORD", "0xc0000072": "ACCOUNT_DISABLED",
                  "0xc000006f": "OUTSIDE_LOGON_HOURS", "0xc0000070": "WORKSTATION_RESTRICTION"}
ANONYMOUS_USERS = {"anonymous logon", "-", ""}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_windows_xml(text: str, result: ConversionResult, year: int) -> list[dict]:
    # Python's XML parser does not fetch external entities; the input is still treated as untrusted data.
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    if "<!DOCTYPE" in text or "<!ENTITY" in text:  # event exports never need them; refuse entity tricks
        raise ConversionError(Msg("conversion.error.xml", detail="DOCTYPE/ENTITY declarations are not allowed"))
    try:
        root = ET.fromstring(f"<Events>{text}</Events>")
    except ET.ParseError as exc:
        raise ConversionError(Msg("conversion.error.xml", detail=str(exc))) from exc
    rows = []
    for element in root.iter():
        if _local(element.tag) != "Event":
            continue
        result.records_read += 1
        system = {_local(child.tag): child for child in next((c for c in element if _local(c.tag) == "System"), [])}
        data = {item.get("Name"): (item.text or "").strip() for item in element.iter()
                if _local(item.tag) == "Data" and item.get("Name")}
        event_code = (system["EventID"].text or "").strip() if "EventID" in system else ""
        created = system["TimeCreated"].get("SystemTime", "") if "TimeCreated" in system else ""
        if event_code not in WINDOWS_EVENTS:
            result.skipped["unsupported_event_id" if event_code else "invalid_record"] += 1
            continue
        try:
            ts = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", created).replace("Z", "+00:00"))
        except ValueError:
            result.skipped["invalid_record"] += 1
            continue
        event_type, outcome = WINDOWS_EVENTS[event_code]
        user = data.get("TargetUserName", "")
        if user.lower() in ANONYMOUS_USERS:
            result.skipped["anonymous_logon"] += 1
            continue
        if user.endswith("$"):
            result.skipped["machine_account"] += 1  # computer accounts authenticate constantly; not people
            continue
        status = (data.get("SubStatus", "") if data.get("SubStatus", "0x0") not in ("", "0x0")
                  else data.get("Status", "")).lower()
        record = (system["EventRecordID"].text or "").strip() if "EventRecordID" in system else str(result.records_read)
        host = (system["Computer"].text or "").strip() if "Computer" in system else ""
        rows.append(_event(
            f"WIN-{record}", ts, user, data.get("IpAddress", "-"), event_type, outcome, host,
            FAILURE_STATUS.get(status, status.upper()) if outcome == Result.FAILURE else "",
            LOGON_TYPES.get(data.get("LogonType", ""), data.get("LogonType", "")) if event_type == EventType.LOGON else "",
            event_code,
        ))
    return rows


# ---------------------------------------------------------------------------
# Microsoft Entra ID sign-in logs (JSON)
# ---------------------------------------------------------------------------
ENTRA_FAILURES = {50126: "BAD_PASSWORD", 50034: "UNKNOWN_USER", 50053: "ACCOUNT_LOCKED", 50055: "EXPIRED_PASSWORD",
                  50057: "ACCOUNT_DISABLED", 50056: "BAD_PASSWORD", 53003: "BLOCKED_BY_CONDITIONAL_ACCESS"}
# "Interrupted" sign-ins: the password was right but another step (usually MFA) was needed. They are neither a
# success nor a password failure, so they are skipped and counted instead of being guessed.
ENTRA_INTERRUPTS = {50074, 50076, 50079, 50158, 50072, 50097, 50125, 50140, 50199, 16000, 16003, 81010}


def _parse_entra(text: str, result: ConversionResult, year: int) -> list[dict]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConversionError(Msg("conversion.error.json", detail=str(exc))) from exc
    records = document.get("value", []) if isinstance(document, dict) else document
    if not isinstance(records, list):
        raise ConversionError(Msg("conversion.error.json", detail="expected a list of sign-ins"))
    rows = []
    for record in records:
        result.records_read += 1
        try:
            ts = datetime.fromisoformat(str(record["createdDateTime"]).replace("Z", "+00:00"))
            user = str(record["userPrincipalName"])
            status = record.get("status") or {}
            code = int(status.get("errorCode", 0))
        except (KeyError, TypeError, ValueError, AttributeError):
            result.skipped["invalid_record"] += 1
            continue
        if code in ENTRA_INTERRUPTS:
            result.skipped["mfa_interrupt"] += 1
            continue
        outcome = Result.SUCCESS if code == 0 else Result.FAILURE
        rows.append(_event(
            f"ENTRA-{record.get('id') or result.records_read}", ts, user, str(record.get("ipAddress", "") or "-"),
            EventType.LOGON, outcome, str(record.get("appDisplayName", "")),
            "" if code == 0 else ENTRA_FAILURES.get(code, f"ENTRA_{code}"),
            str(record.get("clientAppUsed", "") or "CLOUD"),
        ))
    return rows
