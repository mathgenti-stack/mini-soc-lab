"""Synthetic authentication log generator for a fictional London organisation.

All users, hostnames and IP addresses are fictional. Public-looking addresses come
only from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), which are reserved for examples and never routed on the internet.

Every generated event carries a `scenario` label. The label is ground truth for
testing and learning only: it is written to a separate file and is never read by
the detection rules.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from .models import ALL_COLUMNS, EVENT_CODES, EventType, Result

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class StaffMember:
    username: str
    department: str
    workstation: str
    internal_ip: str
    home_ip: str | None = None  # set for remote workers who connect via VPN
    vpn_ip: str | None = None  # static VPN pool address assigned to remote workers

    @property
    def is_remote(self) -> bool:
        return self.home_ip is not None


STAFF = [
    StaffMember("a.patel", "Finance", "LON-WS-001", "10.10.1.11"),
    StaffMember("j.smith", "Finance", "LON-WS-002", "10.10.1.12"),
    StaffMember("m.jones", "Sales", "LON-WS-003", "10.10.1.13"),
    StaffMember("r.khan", "Sales", "LON-WS-004", "10.10.1.14"),
    StaffMember("e.wilson", "HR", "LON-WS-005", "10.10.1.15"),
    StaffMember("l.taylor", "HR", "LON-WS-006", "10.10.1.16"),
    StaffMember("c.evans", "Operations", "LON-WS-007", "10.10.1.17"),
    StaffMember("h.wright", "IT", "LON-WS-008", "10.10.1.30"),
    StaffMember("o.hughes", "Operations", "LON-WS-009", "10.10.1.19"),
    StaffMember("p.green", "Marketing", "LON-WS-010", "10.10.1.20"),
    StaffMember("t.walker", "Marketing", "LON-WS-011", "10.10.1.21"),
    StaffMember("f.hall", "Legal", "LON-WS-012", "10.10.1.22"),
    StaffMember("g.clarke", "Legal", "LON-WS-013", "10.10.1.23"),
    StaffMember("b.wood", "Operations", "LON-WS-014", "10.10.1.24"),
    StaffMember("i.roberts", "Finance", "LON-WS-015", "10.10.1.25"),
    StaffMember("z.ali", "Sales", "LON-WS-016", "10.10.1.26"),
    StaffMember("s.ahmed", "Sales", "LON-LT-101", "10.20.0.11", "198.51.100.23", "10.20.0.11"),
    StaffMember("d.brown", "IT", "LON-LT-102", "10.20.0.12", "198.51.100.41", "10.20.0.12"),
    StaffMember("k.obrien", "Marketing", "LON-LT-103", "10.20.0.13", "198.51.100.57", "10.20.0.13"),
    StaffMember("n.lewis", "Legal", "LON-LT-104", "10.20.0.14", "198.51.100.62", "10.20.0.14"),
]
STAFF_BY_NAME = {member.username: member for member in STAFF}

VPN_GATEWAY = "LON-VPN-01"
FILE_SERVER = "LON-FS-01"
APP_SERVER = "LON-APP-01"
DOMAIN_CONTROLLER = "LON-DC-01"
BACKUP_SERVER_IP = "10.10.5.20"
SCANNER_IP = "10.10.99.5"
HELPDESK_IP = STAFF_BY_NAME["h.wright"].internal_ip

# Scenario labels (ground truth).
NORMAL = "normal"
SCENARIO_DESCRIPTIONS = {
    NORMAL: "Normal working-hours activity, including occasional password typos.",
    "simulated_brute_force": "Simulated: repeated password guessing against one account from an external IP, ending in lockout.",
    "simulated_password_spray": "Simulated: one external IP tries one password against many accounts; one attempt succeeds.",
    "simulated_credential_compromise": "Simulated: repeated failures then a successful evening VPN logon from a new external IP.",
    "ambiguous_rapid_source_change": "Ambiguous: two VPN logons from different external IPs within minutes (could be mobile tethering).",
    "benign_forgotten_password": "Benign: user forgot a recently changed password, was locked out and unlocked by the service desk.",
    "benign_authorised_scan": "Benign: authorised internal vulnerability scan testing default account names.",
    "benign_on_call_engineer": "Benign: on-call IT engineer connects overnight from a hotel network.",
    "benign_service_account_expired": "Benign: backup service account keeps retrying with an expired password until IT updates it.",
    "data_quality_test": "Deliberately malformed or duplicated rows used to demonstrate input validation.",
}

DEFAULT_START_DATE = date(2026, 10, 5)  # a Monday


@dataclass
class GeneratorSettings:
    start_date: date = DEFAULT_START_DATE
    days: int = 14
    seed: int = 42
    inject_quality_issues: bool = True


class _EventLog:
    """Small helper that collects event dictionaries."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(
        self,
        ts: datetime,
        username: str,
        source_ip: str,
        hostname: str,
        event_type: str,
        result: str,
        failure_reason: str = "",
        logon_type: str = "",
        scenario: str = NORMAL,
    ) -> None:
        self.rows.append(
            {
                "timestamp": ts,
                "username": username,
                "source_ip": source_ip,
                "hostname": hostname,
                "event_type": event_type,
                "event_code": EVENT_CODES.get((event_type, result), ""),
                "result": result,
                "failure_reason": failure_reason,
                "logon_type": logon_type,
                "scenario": scenario,
            }
        )

    def logon(self, ts, user, ip, host, success, logon_type, reason="", scenario=NORMAL):
        self.add(
            ts, user, ip, host, EventType.LOGON,
            Result.SUCCESS if success else Result.FAILURE,
            "" if success else reason, logon_type, scenario,
        )


def _day_start(start_date: date, offset: int) -> datetime:
    return datetime(start_date.year, start_date.month, start_date.day, tzinfo=timezone.utc) + timedelta(days=offset)


def _normal_workday(log: _EventLog, rng: random.Random, member: StaffMember, day: datetime) -> None:
    """Typical office day: morning logon, a few file/app server connections, evening logoff."""
    arrival = day + timedelta(hours=8, minutes=rng.randint(0, 75), seconds=rng.randint(0, 59))
    if member.is_remote:
        entry_ip, entry_host, entry_type, network_ip = member.home_ip, VPN_GATEWAY, "VPN", member.vpn_ip
    else:
        entry_ip, entry_host, entry_type, network_ip = member.internal_ip, member.workstation, "INTERACTIVE", member.internal_ip

    if rng.random() < 0.06:  # a mistyped password now and then is normal
        log.logon(arrival - timedelta(seconds=rng.randint(5, 40)), member.username, entry_ip, entry_host,
                  False, entry_type, "BAD_PASSWORD")
    log.logon(arrival, member.username, entry_ip, entry_host, True, entry_type)

    for _ in range(rng.randint(1, 3)):
        ts = arrival + timedelta(minutes=rng.randint(10, 480), seconds=rng.randint(0, 59))
        log.logon(ts, member.username, network_ip, rng.choice([FILE_SERVER, APP_SERVER]), True, "NETWORK")

    departure = day + timedelta(hours=17, minutes=rng.randint(0, 90), seconds=rng.randint(0, 59))
    log.add(departure, member.username, entry_ip, entry_host, EventType.LOGOFF, Result.INFO, logon_type=entry_type)


def _weekend_check_in(log: _EventLog, rng: random.Random, member: StaffMember, day: datetime) -> None:
    ts = day + timedelta(hours=rng.randint(9, 12), minutes=rng.randint(0, 59))
    log.logon(ts, member.username, member.home_ip, VPN_GATEWAY, True, "VPN")
    log.add(ts + timedelta(minutes=rng.randint(10, 40)), member.username, member.home_ip, VPN_GATEWAY,
            EventType.LOGOFF, Result.INFO, logon_type="VPN")


def _nightly_backup(log: _EventLog, rng: random.Random, day: datetime, password_expired: bool) -> None:
    start = day + timedelta(hours=1, seconds=rng.randint(0, 30))
    if not password_expired:
        log.logon(start, "svc_backup", BACKUP_SERVER_IP, FILE_SERVER, True, "NETWORK")
        return
    # The backup job retries every four minutes for an hour, then gives up.
    for attempt in range(16):
        log.logon(start + timedelta(minutes=4 * attempt), "svc_backup", BACKUP_SERVER_IP, FILE_SERVER,
                  False, "NETWORK", "EXPIRED_PASSWORD", "benign_service_account_expired")


# ---------------------------------------------------------------------------
# Scenario builders. Each returns the (day_offset, username) pairs whose normal
# day it replaces, so the scenario does not overlap with routine activity.
# ---------------------------------------------------------------------------
def _scenario_brute_force(log, rng, day):
    label, ip, user = "simulated_brute_force", "203.0.113.45", "m.jones"
    ts = day + timedelta(hours=2, minutes=14, seconds=7)
    for attempt in range(1, 26):
        reason = "BAD_PASSWORD" if attempt <= 10 else "ACCOUNT_LOCKED"
        log.logon(ts, user, ip, VPN_GATEWAY, False, "VPN", reason, label)
        if attempt == 10:  # domain lockout policy: 10 failed attempts
            log.add(ts + timedelta(seconds=1), user, ip, DOMAIN_CONTROLLER, EventType.ACCOUNT_LOCKOUT,
                    Result.INFO, scenario=label)
        ts += timedelta(seconds=rng.randint(6, 15))


def _scenario_on_call(log, rng, day):
    label, member = "benign_on_call_engineer", STAFF_BY_NAME["d.brown"]
    hotel_ip = "198.51.100.150"
    ts = day + timedelta(hours=2, minutes=31, seconds=12)
    log.logon(ts, member.username, hotel_ip, VPN_GATEWAY, True, "VPN", scenario=label)
    log.logon(ts + timedelta(minutes=4), member.username, member.vpn_ip, APP_SERVER, True, "NETWORK", scenario=label)
    log.add(ts + timedelta(minutes=39), member.username, hotel_ip, VPN_GATEWAY, EventType.LOGOFF, Result.INFO,
            logon_type="VPN", scenario=label)


def _scenario_password_change(log, rng, day):
    member = STAFF_BY_NAME["e.wilson"]
    log.add(day + timedelta(hours=16, minutes=52, seconds=3), member.username, member.internal_ip, DOMAIN_CONTROLLER,
            EventType.PASSWORD_CHANGE, Result.SUCCESS, scenario="benign_forgotten_password")


def _scenario_forgotten_password(log, rng, day):
    label, member = "benign_forgotten_password", STAFF_BY_NAME["e.wilson"]
    ts = day + timedelta(hours=8, minutes=40, seconds=21)
    for attempt in range(1, 11):
        log.logon(ts, member.username, member.internal_ip, member.workstation, False, "INTERACTIVE",
                  "BAD_PASSWORD", label)
        ts += timedelta(seconds=rng.randint(10, 25))
    log.add(ts, member.username, member.internal_ip, DOMAIN_CONTROLLER, EventType.ACCOUNT_LOCKOUT, Result.INFO,
            scenario=label)
    unlock = day + timedelta(hours=9, minutes=20, seconds=44)
    log.add(unlock, member.username, HELPDESK_IP, DOMAIN_CONTROLLER, EventType.ACCOUNT_UNLOCK, Result.INFO,
            scenario=label)
    log.logon(unlock + timedelta(minutes=2), member.username, member.internal_ip, member.workstation, True,
              "INTERACTIVE", scenario=label)
    log.logon(unlock + timedelta(minutes=30), member.username, member.internal_ip, FILE_SERVER, True, "NETWORK",
              scenario=label)
    log.add(day + timedelta(hours=17, minutes=31), member.username, member.internal_ip, member.workstation,
            EventType.LOGOFF, Result.INFO, logon_type="INTERACTIVE", scenario=label)


def _scenario_password_spray(log, rng, day):
    label, ip = "simulated_password_spray", "203.0.113.88"
    targets = ["a.patel", "j.smith", "admin", "m.jones", "r.khan", "administrator", "c.evans", "o.hughes",
               "l.taylor", "p.green", "test", "t.walker", "f.hall", "guest", "g.clarke", "b.wood"]
    ts = day + timedelta(hours=11, minutes=2, seconds=33)
    for user in targets:
        if user == "l.taylor":
            log.logon(ts, user, ip, VPN_GATEWAY, True, "VPN", scenario=label)
            log.add(ts + timedelta(minutes=3), user, ip, VPN_GATEWAY, EventType.LOGOFF, Result.INFO,
                    logon_type="VPN", scenario=label)
        else:
            reason = "BAD_PASSWORD" if user in STAFF_BY_NAME else "UNKNOWN_USER"
            log.logon(ts, user, ip, VPN_GATEWAY, False, "VPN", reason, label)
        ts += timedelta(seconds=rng.randint(40, 90))


def _scenario_authorised_scan(log, rng, day):
    label = "benign_authorised_scan"
    accounts = ["admin", "administrator", "guest", "root", "test"]
    hosts = [f"LON-WS-{n:03d}" for n in range(1, 11)] + [FILE_SERVER, APP_SERVER]
    ts = day + timedelta(hours=23, minutes=0, seconds=5)
    for host in hosts:
        for account in accounts:
            reason = "BAD_PASSWORD" if account == "administrator" else "UNKNOWN_USER"
            log.logon(ts, account, SCANNER_IP, host, False, "NETWORK", reason, label)
            ts += timedelta(seconds=rng.randint(40, 60))


def _scenario_credential_compromise(log, rng, day):
    label, ip, user = "simulated_credential_compromise", "203.0.113.120", "r.khan"
    ts = day + timedelta(hours=21, minutes=40, seconds=2)
    for _ in range(8):
        log.logon(ts, user, ip, VPN_GATEWAY, False, "VPN", "BAD_PASSWORD", label)
        ts += timedelta(seconds=rng.randint(15, 30))
    log.logon(ts, user, ip, VPN_GATEWAY, True, "VPN", scenario=label)
    log.add(ts + timedelta(minutes=24), user, ip, VPN_GATEWAY, EventType.LOGOFF, Result.INFO,
            logon_type="VPN", scenario=label)


def _scenario_rapid_source_change(log, rng, day):
    label, member = "ambiguous_rapid_source_change", STAFF_BY_NAME["s.ahmed"]
    second_ip = "203.0.113.200"
    first = day + timedelta(hours=10, minutes=5, seconds=40)
    log.logon(first, member.username, member.home_ip, VPN_GATEWAY, True, "VPN", scenario=label)
    log.logon(first + timedelta(minutes=7), member.username, second_ip, VPN_GATEWAY, True, "VPN", scenario=label)
    log.logon(first + timedelta(minutes=20), member.username, member.vpn_ip, FILE_SERVER, True, "NETWORK",
              scenario=label)
    log.add(day + timedelta(hours=17, minutes=45), member.username, second_ip, VPN_GATEWAY, EventType.LOGOFF,
            Result.INFO, logon_type="VPN", scenario=label)


def _scenario_service_password_reset(log, rng, day):
    log.add(day + timedelta(hours=10, minutes=15), "svc_backup", HELPDESK_IP, DOMAIN_CONTROLLER,
            EventType.PASSWORD_CHANGE, Result.SUCCESS, scenario="benign_service_account_expired")


# day offset -> (builder, users whose normal day is replaced)
SCENARIO_SCHEDULE = [
    (2, _scenario_brute_force, []),
    (3, _scenario_on_call, []),
    (4, _scenario_password_change, []),
    (5, _scenario_authorised_scan, []),
    (7, _scenario_forgotten_password, ["e.wilson"]),
    (7, _scenario_password_spray, []),
    (8, _scenario_credential_compromise, []),
    (9, _scenario_rapid_source_change, ["s.ahmed"]),
    (12, _scenario_service_password_reset, []),
]
SERVICE_PASSWORD_EXPIRED_DAYS = {11, 12}  # backup job fails on these nights, fixed on day 12


def generate_events(settings: GeneratorSettings | None = None) -> pd.DataFrame:
    """Generate a DataFrame of synthetic authentication events (including the `scenario` label)."""
    settings = settings or GeneratorSettings()
    if settings.days < 1:
        raise ValueError("days must be at least 1")
    rng = random.Random(settings.seed)
    log = _EventLog()

    replaced: set[tuple[int, str]] = set()
    for offset, _builder, users in SCENARIO_SCHEDULE:
        replaced.update((offset, user) for user in users)

    for offset in range(settings.days):
        day = _day_start(settings.start_date, offset)
        is_weekday = day.weekday() < 5
        for member in STAFF:
            if (offset, member.username) in replaced:
                continue
            if is_weekday:
                _normal_workday(log, rng, member, day)
            elif member.is_remote and rng.random() < 0.35:
                _weekend_check_in(log, rng, member, day)
        _nightly_backup(log, rng, day, password_expired=offset in SERVICE_PASSWORD_EXPIRED_DAYS)

    for offset, builder, _users in SCENARIO_SCHEDULE:
        if offset < settings.days:
            builder(log, rng, _day_start(settings.start_date, offset))

    events = pd.DataFrame(log.rows).sort_values("timestamp", kind="stable").reset_index(drop=True)
    events["timestamp"] = events["timestamp"].dt.strftime(TIMESTAMP_FORMAT)
    events.insert(0, "event_id", [f"EVT-{n:06d}" for n in range(1, len(events) + 1)])

    if settings.inject_quality_issues and len(events) > 10:
        events = _inject_quality_issues(events, rng)
    return events[list(ALL_COLUMNS) + ["scenario"]]


def _inject_quality_issues(events: pd.DataFrame, rng: random.Random) -> pd.DataFrame:
    """Append a handful of bad rows so the loader's validation can be demonstrated."""
    label = "data_quality_test"
    template = events.iloc[rng.randrange(len(events))].to_dict()
    duplicate = dict(template, scenario=label)  # exact duplicate of an existing event
    bad_timestamp = dict(template, event_id="EVT-900001", timestamp="2026-13-45T25:61:00Z", scenario=label)
    missing_user = dict(template, event_id="EVT-900002", username="", scenario=label)
    bad_type = dict(template, event_id="EVT-900003", event_type="LOGIN_ATTEMPT", scenario=label)
    extra = pd.DataFrame([duplicate, bad_timestamp, missing_user, bad_type])
    return pd.concat([events, extra], ignore_index=True)


def write_dataset(events: pd.DataFrame, output_path: str | Path) -> tuple[Path, Path]:
    """Write the log CSV (without labels) and a separate ground-truth CSV next to it."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    events[list(ALL_COLUMNS)].to_csv(output_path, index=False)
    truth_path = output_path.with_name(f"{output_path.stem}_ground_truth.csv")
    events[["event_id", "scenario"]].to_csv(truth_path, index=False)
    return output_path, truth_path


def generate_csv_text(settings: GeneratorSettings | None = None) -> str:
    """Generate events and return the log CSV as text (used by the dashboard)."""
    return generate_events(settings)[list(ALL_COLUMNS)].to_csv(index=False)
