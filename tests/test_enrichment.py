"""Offline IP enrichment: geolocation, ASN and threat intelligence from local fictional files."""

import ipaddress
from pathlib import Path

import pytest

from soc_lab.cli import main
from soc_lab.config import load_config
from soc_lab.detection import run_detection
from soc_lab.enrichment import (DEFAULT_ENRICHMENT_DIR, GEOIP_COLUMNS, INTEL_COLUMNS, distance_km, display_rows,
                                enrichment_findings, load_enrichment)
from soc_lab.i18n import LANGUAGES, t, tr
from soc_lab.log_loader import load_events
from soc_lab.reporting import build_investigation_report, render_markdown

ROOT = Path(__file__).resolve().parent.parent
APP_PATH = ROOT / "streamlit_app.py"
SAMPLE = ROOT / "data" / "sample_auth_logs.csv"
INTERNAL = ["10.0.0.0/8"]
DOCUMENTATION_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.fixture(scope="module")
def data():
    return load_enrichment()


@pytest.fixture(scope="module")
def sample():
    events = load_events(SAMPLE).events
    config = load_config()
    return events, config, run_detection(events, config)


def _report(sample, alert_id, enrichment):
    events, config, alerts = sample
    alert = next(a for a in alerts if a.alert_id == alert_id)
    return build_investigation_report(alert, events, config, all_alerts=alerts, enrichment=enrichment,
                                      generated_at=events["timestamp"].max())


def _write(directory, geo_rows, intel_rows):
    directory.mkdir(exist_ok=True)
    (directory / "geoip.csv").write_text("\n".join([",".join(GEOIP_COLUMNS), *geo_rows]) + "\n", encoding="utf-8")
    (directory / "threat_intel.csv").write_text("\n".join([",".join(INTEL_COLUMNS), *intel_rows]) + "\n",
                                                encoding="utf-8")
    return load_enrichment(directory)


# ---------------------------------------------------------------------------
# Data files
# ---------------------------------------------------------------------------
def test_bundled_files_load_and_stay_fictional(data):
    assert data.warnings == []
    assert len(data.geo) == 7 and len(data.intel) == 4
    for record in [*data.geo, *data.intel]:
        assert any(record.network.subnet_of(doc) for doc in DOCUMENTATION_RANGES), record.network
    assert all(64496 <= record.asn <= 64511 for record in data.geo)  # RFC 5398 documentation ASNs
    assert all("Example" in record.as_org for record in data.geo)
    assert all("Example" in record.source for record in data.intel)


def test_every_external_address_in_the_sample_has_geolocation(data, sample):
    events, _config, _alerts = sample
    external = [ip for ip in events["source_ip"].unique() if not ip.startswith("10.")]
    assert external and all(data.lookup(ip, INTERNAL).geo for ip in external)


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------
def test_lookup(data):
    spray = data.lookup("203.0.113.88", INTERNAL)
    assert (spray.geo.city, spray.geo.asn, spray.geo.network_type) == ("Bucharest", 64501, "hosting")
    assert [hit.category for hit in spray.intel] == ["password_spraying"]

    compromise = data.lookup("203.0.113.120", INTERNAL)
    assert [hit.verdict for hit in compromise.intel] == ["malicious", "suspicious"]  # most severe first
    assert [hit.indicator for hit in compromise.intel] == ["203.0.113.120", "203.0.113.96/27"]

    brute_force = data.lookup("203.0.113.45", INTERNAL)
    assert brute_force.geo.country_code == "NL" and brute_force.intel == ()  # not listed is not "safe"

    internal = data.lookup("10.10.1.15", INTERNAL)
    assert internal.internal and internal.geo is None and internal.intel == ()
    assert data.lookup("not-an-ip", INTERNAL).geo is None


def test_most_specific_network_wins(tmp_path):
    data = _write(tmp_path, ["203.0.113.0/24,NL,Netherlands,Amsterdam,52.37,4.90,64500,Wide,hosting",
                             "203.0.113.0/28,GB,United Kingdom,London,51.51,-0.13,64501,Narrow,mobile"], [])
    assert data.lookup("203.0.113.5").geo.as_org == "Narrow"
    assert data.lookup("203.0.113.50").geo.as_org == "Wide"


def test_invalid_rows_and_missing_files_give_warnings(tmp_path):
    data = _write(tmp_path, ["203.0.113.0/24,NL,Netherlands,Amsterdam,52.37,4.90,64500,Org,hosting",
                             "not-a-network,NL,Netherlands,Amsterdam,52.37,4.90,64500,Org,hosting",
                             "203.0.113.0/24,NL,Netherlands,Amsterdam,152.37,4.90,64500,Org,hosting",
                             "203.0.113.0/24,NL,Netherlands,Amsterdam,52.37,4.90,64500,Org,spaceship"],
                  ["203.0.113.9,evil,high,Feed,x,2026-01-01,2026-01-02,bad verdict"])
    assert len(data.geo) == 1 and data.intel == []
    assert [str(w) for w in data.warnings] == [f"Enrichment file geoip.csv, line {n}: invalid row skipped."
                                               for n in (3, 4, 5)] + [
        "Enrichment file threat_intel.csv, line 2: invalid row skipped."]
    empty = load_enrichment(tmp_path / "missing")
    assert empty.geo == [] and len(empty.warnings) == 2
    (tmp_path / "cols").mkdir()
    (tmp_path / "cols" / "geoip.csv").write_text("network,city\n", encoding="utf-8")
    assert "missing column(s)" in str(load_enrichment(tmp_path / "cols").warnings[0])


def test_distance(data):
    london = data.lookup("198.51.100.23").geo
    amsterdam = data.lookup("203.0.113.45").geo
    assert distance_km(london, amsterdam) == pytest.approx(358, abs=5)
    assert distance_km(london, london) == 0


def test_travel_findings(data):
    london = data.lookup("198.51.100.23", INTERNAL)
    london_mobile = data.lookup("203.0.113.200", INTERNAL)
    bucharest = data.lookup("203.0.113.88", INTERNAL)
    same = enrichment_findings([], (london, london_mobile, 7))
    assert [m.key for m in same] == ["enrichment.finding.same_area"]
    impossible = enrichment_findings([], (london, bucharest, 30))[0]
    assert impossible.key == "enrichment.finding.impossible_travel" and impossible.params["km"] > 2000
    possible = enrichment_findings([], (london, bucharest, 6 * 60))[0]
    assert possible.key == "enrichment.finding.possible_travel"


def test_display_rows_are_translated_but_keep_data(data):
    info = data.lookup("203.0.113.120", INTERNAL)
    english, portuguese = display_rows([info]), display_rows([info], "pt-BR")
    assert english[0]["network_type"] == "anonymising VPN" and portuguese[0]["network_type"] == "VPN de anonimização"
    assert portuguese[0]["threat_intel"].startswith("malicioso (média) - Example Botnet Tracker: credential_stuffing")
    assert english[0]["asn"] == portuguese[0]["asn"] == "AS64502"
    assert display_rows([data.lookup("10.10.1.15", INTERNAL)]) == []


# ---------------------------------------------------------------------------
# Investigation reports
# ---------------------------------------------------------------------------
def test_reports_without_enrichment_are_unchanged(sample):
    report = _report(sample, "ALR-0010", None)
    assert report.ip_enrichment == []
    assert not any("Enrichment" in finding or "Threat intelligence" in finding for finding in report.context_findings)
    assert "No threat-intelligence or geolocation enrichment was performed." in report.limitations
    assert "IP enrichment" not in render_markdown(report)


def test_reports_with_enrichment(sample, data):
    spray = _report(sample, "ALR-0010", data)
    findings = [str(f) for f in spray.context_findings]
    assert ("Enrichment: 203.0.113.88 is registered in Bucharest, Romania (RO), AS64501 Example VPS SRL "
            "(hosting / cloud provider).") in findings
    assert any(f.startswith("Threat intelligence: 203.0.113.88 matches 203.0.113.88 in 'Example Shared Blocklist'")
               for f in findings)
    assert "No threat-intelligence or geolocation enrichment was performed." not in spray.limitations
    assert any(getattr(item, "key", None) == "enrichment.limitation" for item in spray.limitations)
    assert spray.conclusion == _report(sample, "ALR-0010", None).conclusion  # context, never a verdict

    markdown = render_markdown(spray)
    assert "**IP enrichment (offline, fictional data)**" in markdown
    assert "| 203.0.113.88 | Bucharest, Romania (RO) | AS64501 | Example VPS SRL | hosting / cloud provider |" in markdown
    portuguese = render_markdown(spray, "pt-BR")
    assert "**Enriquecimento de IP (dados offline e fictícios)**" in portuguese
    assert "hospedagem / provedor de nuvem | suspeito (alta) - Example Shared Blocklist" in portuguese


def test_rapid_source_change_gets_a_travel_check(sample, data):
    report = _report(sample, "ALR-0014", data)  # s.ahmed: home broadband, then a mobile network
    travel = [f for f in report.context_findings if getattr(f, "key", "") == "enrichment.finding.same_area"]
    assert len(travel) == 1 and travel[0].params["first"] == "198.51.100.23"
    assert "No geolocation or ASN data is available in this lab." not in report.limitations
    assert tr(travel[0], "pt-BR").startswith("Os dois endereços 198.51.100.23 e 203.0.113.200")


def test_internal_only_alerts_get_no_enrichment_rows(sample, data):
    report = _report(sample, "ALR-0007", data)  # e.wilson, office workstation
    assert all(info.internal for info in report.ip_enrichment)
    assert "IP enrichment" not in render_markdown(report)


# ---------------------------------------------------------------------------
# CLI and dashboard
# ---------------------------------------------------------------------------
def test_cli_lookup_ip(capsys):
    assert main(["lookup-ip", "203.0.113.120", "10.10.1.15"]) == 0
    output = capsys.readouterr().out
    assert "Example Privacy VPN GmbH (anonymising VPN)" in output
    assert "as malicious (medium confidence" in output
    assert "10.10.1.15\n  Internal address" in output


def test_cli_report_enrichment_switch(tmp_path):
    assert main(["report", "--alert-id", "ALR-0010", "--output-dir", str(tmp_path / "on")]) == 0
    assert main(["report", "--alert-id", "ALR-0010", "--output-dir", str(tmp_path / "off"), "--no-enrichment"]) == 0
    assert "Example Shared Blocklist" in (tmp_path / "on" / "INC-0010.md").read_text(encoding="utf-8")
    assert "Example Shared Blocklist" not in (tmp_path / "off" / "INC-0010.md").read_text(encoding="utf-8")


@pytest.fixture
def app(tmp_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_LAB_ANSWERS_DIR", str(tmp_path))
    return testing.AppTest.from_file(str(APP_PATH), default_timeout=120)


def _tables_with(app, value):
    return [frame for frame in app.dataframe if "ip" in frame.value.columns and value in set(frame.value["ip"])]


@pytest.mark.parametrize("lang", list(LANGUAGES))
def test_dashboard_investigation_shows_enrichment(app, lang):
    app.run()
    app.segmented_control(key="lang").set_value(lang).run()
    next(s for s in app.selectbox if s.label.startswith(t("ui.inv.select_alert", lang))).set_value("ALR-0010").run()
    # Training mode: the lookup table is evidence and is shown; the written findings stay hidden until revealed.
    assert _tables_with(app, "203.0.113.88")
    assert not any("Example Shared Blocklist" in m.value for m in app.markdown)

    app.toggle(key="training_mode").set_value(False).run()
    assert not app.exception
    assert any(t("ui.enrichment.title", lang) in m.value for m in app.markdown)
    assert any("Example Shared Blocklist" in m.value for m in app.markdown)  # context findings

    app.toggle(key="use_enrichment").set_value(False).run()
    assert not app.exception
    assert not _tables_with(app, "203.0.113.88")
    assert not any("Example Shared Blocklist" in m.value for m in app.markdown)


def test_dashboard_event_explorer_lists_external_addresses(app):
    app.run()
    rows = _tables_with(app, "203.0.113.45")
    assert rows and "10.10.1.15" not in set(rows[0].value["ip"])
    assert set(rows[0].value["ip"]) == {"198.51.100.23", "198.51.100.41", "198.51.100.57", "198.51.100.62",
                                        "198.51.100.150", "203.0.113.45", "203.0.113.88", "203.0.113.120",
                                        "203.0.113.200"}
