"""Offline IP enrichment: geolocation, ASN and threat intelligence from local, fictional files.

A real SOC looks addresses up in GeoIP databases and threat-intelligence feeds. This lab never
contacts external services, so the same lookups run against two small CSV files in data/enrichment/:

- geoip.csv         network -> country, city, coordinates, ASN, organisation, network type
- threat_intel.csv  address or network -> verdict, confidence, source, category, dates, description

All entries are fictional: networks are RFC 5737 documentation ranges and ASNs come from the
RFC 5398 documentation range. Enrichment is context for the analyst, never a verdict: geolocation
shows where an address is registered, not where a person is, and an address missing from the
threat-intelligence list is not proof that it is safe.
"""

from __future__ import annotations

import csv
import ipaddress
import math
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .i18n import DEFAULT_LANGUAGE, Msg, t

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENRICHMENT_DIR = PROJECT_ROOT / "data" / "enrichment"
GEOIP_FILE, INTEL_FILE = "geoip.csv", "threat_intel.csv"
GEOIP_COLUMNS = ("network", "country_code", "country", "city", "latitude", "longitude", "asn", "as_org",
                 "network_type")
INTEL_COLUMNS = ("indicator", "verdict", "confidence", "source", "category", "first_seen", "last_seen",
                 "description")
NETWORK_TYPES = ("residential", "mobile", "public_wifi", "hosting", "anonymiser", "corporate")
VERDICTS = ("malicious", "suspicious")
CONFIDENCES = ("low", "medium", "high")
# Faster than a commercial flight: two logons this far apart in this little time are hard to explain by travel.
IMPOSSIBLE_SPEED_KMH = 900


@dataclass(frozen=True)
class GeoRecord:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    country_code: str
    country: str
    city: str
    latitude: float
    longitude: float
    asn: int
    as_org: str
    network_type: str


@dataclass(frozen=True)
class IntelRecord:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    indicator: str
    verdict: str
    confidence: str
    source: str
    category: str
    first_seen: str
    last_seen: str
    description: str


@dataclass(frozen=True)
class IpInfo:
    """Everything known about one address."""

    ip: str
    internal: bool
    geo: GeoRecord | None = None
    intel: tuple[IntelRecord, ...] = ()

    @property
    def location(self) -> str:
        return f"{self.geo.city}, {self.geo.country} ({self.geo.country_code})" if self.geo else ""

    def to_record(self) -> dict:
        """A flat row of plain strings for tables and CSV."""
        geo = self.geo
        return {
            "ip": self.ip,
            "scope": "internal" if self.internal else "external",
            "location": self.location,
            "asn": f"AS{geo.asn}" if geo else "",
            "as_org": geo.as_org if geo else "",
            "network_type": geo.network_type if geo else "",
            "threat_intel": "; ".join(f"{hit.verdict} ({hit.confidence}) - {hit.source}: {hit.category}"
                                      for hit in self.intel),
        }


def display_rows(infos: list[IpInfo], lang: str = DEFAULT_LANGUAGE) -> list[dict]:
    """External addresses as table rows, with network types and verdicts in `lang` (data values stay as recorded)."""
    rows = []
    for info in infos:
        if info.internal:
            continue
        row = info.to_record()
        del row["scope"]
        if info.geo:
            row["network_type"] = t(f"enrichment.type.{info.geo.network_type}", lang)
        row["threat_intel"] = "; ".join(
            f"{t(f'enrichment.verdict.{hit.verdict}', lang)} ({t(f'enrichment.confidence.{hit.confidence}', lang)})"
            f" - {hit.source}: {hit.category}" for hit in info.intel)
        rows.append(row)
    return rows


@dataclass
class EnrichmentData:
    geo: list[GeoRecord] = field(default_factory=list)
    intel: list[IntelRecord] = field(default_factory=list)
    warnings: list[Msg] = field(default_factory=list)

    def lookup(self, ip: str, internal_networks=()) -> IpInfo:
        """Geolocation (most specific network wins) and every threat-intelligence entry that covers `ip`."""
        address = _parse_ip(ip)
        if address is None:
            return IpInfo(ip=ip, internal=False)
        internal = any(address in ipaddress.ip_network(net, strict=False) for net in internal_networks)
        if internal:  # private addresses have no public geolocation; the asset inventory would know them
            return IpInfo(ip=ip, internal=True)
        geo = max((record for record in self.geo if address in record.network),
                  key=lambda record: record.network.prefixlen, default=None)
        intel = tuple(sorted((record for record in self.intel if address in record.network),
                             key=lambda record: (VERDICTS.index(record.verdict), -record.network.prefixlen)))
        return IpInfo(ip=ip, internal=False, geo=geo, intel=intel)


def load_enrichment(directory: str | Path | None = None) -> EnrichmentData:
    """Read both files. Missing files give empty data; invalid rows are skipped with a warning."""
    return _load(str(Path(directory) if directory else DEFAULT_ENRICHMENT_DIR))


@lru_cache(maxsize=4)
def _load(directory: str) -> EnrichmentData:
    data = EnrichmentData()
    for name, columns, parse, target in ((GEOIP_FILE, GEOIP_COLUMNS, _geo_record, data.geo),
                                         (INTEL_FILE, INTEL_COLUMNS, _intel_record, data.intel)):
        path = Path(directory) / name
        if not path.is_file():
            data.warnings.append(Msg("enrichment.warning.missing", file=name))
            continue
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            missing = [column for column in columns if column not in (reader.fieldnames or [])]
            if missing:
                data.warnings.append(Msg("enrichment.warning.columns", file=name, columns=", ".join(missing)))
                continue
            for line, row in enumerate(reader, start=2):
                try:
                    target.append(parse({key: (row[key] or "").strip() for key in columns}))
                except (ValueError, TypeError):
                    data.warnings.append(Msg("enrichment.warning.row", file=name, line=line))
    return data


def _geo_record(row: dict) -> GeoRecord:
    latitude, longitude = float(row["latitude"]), float(row["longitude"])
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180) or row["network_type"] not in NETWORK_TYPES:
        raise ValueError(row)
    return GeoRecord(network=ipaddress.ip_network(row["network"], strict=False), country_code=row["country_code"],
                     country=row["country"], city=row["city"], latitude=latitude, longitude=longitude,
                     asn=int(row["asn"]), as_org=row["as_org"], network_type=row["network_type"])


def _intel_record(row: dict) -> IntelRecord:
    if row["verdict"] not in VERDICTS or row["confidence"] not in CONFIDENCES:
        raise ValueError(row)
    return IntelRecord(network=ipaddress.ip_network(row["indicator"], strict=False), **row)


def _parse_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def distance_km(first: GeoRecord, second: GeoRecord) -> float:
    """Great-circle (haversine) distance between two locations."""
    lat1, lon1, lat2, lon2 = map(math.radians, (first.latitude, first.longitude, second.latitude, second.longitude))
    a = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(a))


# ---------------------------------------------------------------------------
# Findings for investigation reports (facts, worded as context - never as conclusions)
# ---------------------------------------------------------------------------
def enrichment_findings(infos: list[IpInfo], travel: tuple[IpInfo, IpInfo, float] | None = None) -> list[Msg]:
    findings = []
    for info in infos:
        if info.internal:
            continue
        if info.geo:
            findings.append(Msg("enrichment.finding.geo", ip=info.ip, location=info.location, asn=info.geo.asn,
                                org=info.geo.as_org, type=Msg(f"enrichment.type.{info.geo.network_type}")))
        else:
            findings.append(Msg("enrichment.finding.no_geo", ip=info.ip))
        if info.intel:
            for hit in info.intel:
                findings.append(Msg("enrichment.finding.intel", ip=info.ip, verdict=Msg(f"enrichment.verdict.{hit.verdict}"),
                                    confidence=Msg(f"enrichment.confidence.{hit.confidence}"), source=hit.source,
                                    indicator=hit.indicator, category=hit.category, first=hit.first_seen,
                                    last=hit.last_seen))
        else:
            findings.append(Msg("enrichment.finding.no_intel", ip=info.ip))
    if travel:
        first, second, minutes = travel
        if first.geo and second.geo:
            km = distance_km(first.geo, second.geo)
            speed = km / (minutes / 60) if minutes > 0 else math.inf
            if km < 50:
                findings.append(Msg("enrichment.finding.same_area", first=first.ip, second=second.ip,
                                    location=first.location))
            elif speed > IMPOSSIBLE_SPEED_KMH:
                findings.append(Msg("enrichment.finding.impossible_travel", first=first.ip, second=second.ip,
                                    km=round(km), minutes=round(minutes), limit=IMPOSSIBLE_SPEED_KMH))
            else:
                findings.append(Msg("enrichment.finding.possible_travel", first=first.ip, second=second.ip,
                                    km=round(km), minutes=round(minutes)))
    return findings
