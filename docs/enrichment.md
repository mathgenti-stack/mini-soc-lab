# Offline IP enrichment

In a real SOC, an analyst looks every external address up: *where is it registered, which provider owns it, is it on a threat-intelligence list?* This lab never contacts external services, so the same lookups run against two small local files in `data/enrichment/`. **All entries are fictional.**

## Data files

### `geoip.csv`: geolocation and ASN

| Column | Example | Meaning |
| --- | --- | --- |
| `network` | `203.0.113.64/27` | Address range (the most specific matching range wins) |
| `country_code`, `country`, `city` | `RO`, `Romania`, `Bucharest` | Where the range is registered |
| `latitude`, `longitude` | `44.4268`, `26.1025` | Used for distance checks |
| `asn`, `as_org` | `64501`, `Example VPS SRL` | Autonomous system number and the organisation that owns it |
| `network_type` | `hosting` | `residential`, `mobile`, `public_wifi`, `hosting`, `anonymiser` or `corporate` |

### `threat_intel.csv`: threat intelligence

| Column | Example | Meaning |
| --- | --- | --- |
| `indicator` | `203.0.113.88` or `203.0.113.96/27` | An address or a range |
| `verdict` | `suspicious` | `malicious` or `suspicious` |
| `confidence` | `high` | `low`, `medium` or `high` |
| `source` | `Example Shared Blocklist` | The (fictional) feed |
| `category` | `password_spraying` | What the address was reported for |
| `first_seen`, `last_seen` | `2026-09-28` | When the feed saw it |
| `description` | free text | Context from the feed |

Networks come only from the RFC 5737 documentation ranges, and ASNs only from the RFC 5398 documentation range (64496-64511), so nothing points at a real organisation. A test checks this. Invalid rows are skipped with a warning (shown in the dashboard sidebar and the CLI), and missing files simply give no data.

## What the sample addresses look like

| Address | Used in | Enrichment |
| --- | --- | --- |
| 198.51.100.23 / .41 / .57 / .62 | Remote staff at home | London, residential broadband |
| 198.51.100.150 | On-call engineer `d.brown` | Manchester, hotel Wi-Fi |
| 203.0.113.45 | Brute force against `m.jones` | Amsterdam, hosting provider; **not** on the threat-intel list |
| 203.0.113.88 | Password spray | Bucharest, hosting provider; listed as *suspicious* (password spraying) |
| 203.0.113.120 | Compromise of `r.khan` | Frankfurt, anonymising VPN; listed as *malicious* (credential stuffing) and its range as *suspicious* (anonymising VPN) |
| 203.0.113.200 | Second address of `s.ahmed` | London, mobile network |

The brute-force address is deliberately absent from the list: **an address missing from threat intelligence is not proof that it is safe.**

## Where enrichment appears

- **Investigation tab:** a table of the alert's external addresses. In training mode the table is shown with the evidence, because a Tier 1 analyst would look the addresses up while triaging. The written findings stay hidden until the answer is revealed.
- **Context checks and Markdown report:** one finding per address (location and ASN, then each threat-intel match or *"not in the local list"*), plus a table in the report.
- **Rapid source change (R005):** the distance between the two addresses is compared with the time between the logons. Under 50 km gives *"same area, no travel needed"*. A speed above 900 km/h, faster than a commercial flight, gives *"travel cannot explain it"*. Anything else gives *"travel could explain it"*. For `s.ahmed`, both addresses are in London (home broadband, then a mobile network).
- **Event Explorer:** an expander lists the enrichment of every external address in view.
- **CLI:** `python -m soc_lab.cli lookup-ip 203.0.113.88` for quick lookups. `report` includes enrichment unless you pass `--no-enrichment`.

The dashboard sidebar has an **Offline IP enrichment** switch to turn all of this off.

## What enrichment does not do

- **It never changes detection.** Rules, alerts, severities and conclusions are the same with or without enrichment. Enrichment is context for the analyst, written as facts.
- **Geolocation is not a person's location.** It shows where an address range is registered. VPNs, mobile networks and cloud hosting hide where the person really is.
- **Threat intelligence is a lead, not proof.** Lists are incomplete and go stale, and an address can be reassigned to someone innocent. Check the confidence and the dates.
- **Internal addresses are not enriched.** They have no public geolocation; an asset inventory would be needed, and this lab has none.
