# Interview preparation

## Five-minute demo script

| Time | Action | What to say |
| --- | --- | --- |
| 0:00-0:30 | Show the README | "This is a mini SOC lab I built to practise Tier 1 triage. It generates synthetic authentication logs, runs five configurable detection rules, and produces investigation reports. All the data is fictional - external IPs come from RFC 5737 documentation ranges." |
| 0:30-1:15 | Dashboard, Overview tab | "About 1,000 events over two weeks. These KPIs are calculated from the processed data. There are 18 alerts: one Critical, five High. The timeline shows failed logons per hour, with alert markers on top." |
| 1:15-1:45 | Data Quality tab | "Before detection, the loader validates the input. Here it removed a duplicate and rejected three rows - an invalid timestamp, a missing username and an unknown event type. I reject bad data rather than guess, because evidence needs to be trustworthy." |
| 1:45-3:15 | Investigation, ALR-0010 | "The Critical alert is R004: one external address failed against 15 accounts in 15 minutes, four of them unrecognised names - consistent with password spraying. What made it Critical is this fact: l.taylor logged on successfully from the same address, with no failures. A spray only needs one hit. The report separates facts from hypotheses, lists benign explanations such as an authorised scanner, and the conclusion says 'consistent with possible unauthorised access but does not confirm it'. I'd escalate and export the report." Click *Export report (Markdown)*. |
| 3:15-4:00 | Investigation, ALR-0007 | "Not every alert is an attack. e.wilson had ten failures and a lockout, but the context checks find a password change three days earlier and a service desk unlock. The tool flags these as possible benign indicators, and the analyst confirms them against a ticket before closing." |
| 4:00-4:30 | Sidebar thresholds | "Thresholds come from a JSON config. If I lower R003's minimum attempts from 15 to 10, alerts go from 18 to 26 - mostly duplicates from the authorised scan. That's the detection-versus-noise trade-off, and I documented why I tuned it." |
| 4:30-5:00 | Terminal: `python -m pytest` | "99 automated tests cover each rule's thresholds, normal activity that must not alert, invalid input, metrics and exports. Next I'd like to rewrite these rules as Sentinel KQL or Splunk SPL queries." |

## Ten likely interview questions

**1. Walk me through how an event becomes an alert.**
> The CSV is loaded as text and validated: duplicates removed, bad rows rejected with a reason, timestamps parsed to UTC. The clean events go to a detection engine that runs each enabled rule from a JSON config. Each rule is a pure function that returns alerts containing the trigger criteria, severity rationale, supporting event IDs, observed facts and hypotheses. The dashboard and the CLI then present those alerts and build investigation reports from them.

**2. What is the difference between R001 and R004, and why do you need both?**
> R001 looks for many failures against one account, which is the shape of password guessing. R004 looks for one source failing against many accounts, which is the shape of password spraying. A spray deliberately stays under per-account lockout thresholds, so R001 alone would miss it. In my sample data the spray triggers R004 but not R001.

**3. How do you decide severity?**
> Each rule starts at a base level and raises it based on explicit, documented factors: an external source, volume above a high threshold, or a successful logon linked to the activity. For example, R004 is Medium, rises to High for an external source, and becomes Critical if any account logged on successfully from that address during the activity. The alert stores the reason, so the analyst can see why it got that severity.

**4. How did you handle false positives?**
> In three ways. First, the data includes realistic benign scenarios - a forgotten password, an authorised scanner, a service account with an expired password, an on-call engineer - so I could see how the rules behave on them. Second, I built in safeguards: a minimum number of attempts for failure rates, a failure counter that resets after each success, and a baseline learning period. Third, the reports run context checks, such as recent password changes, unlock events, service-account naming and internal sources, and present them as possible benign indicators to verify, not as automatic closures.

**5. Give an example of tuning a rule.**
> R003 originally required 10 attempts per day. The authorised scan then produced five near-identical alerts, one per default account name, and R004 already covered the scan as a single alert. I raised the minimum to 15, which removed the noise while all planted scenarios were still detected. The tests confirm that every scenario is still detected.

**6. An alert says a user logged in after eight failures from an external IP. What do you do?**
> I treat it as a lead, not proof. I check whether the external address was seen before for that account, whether the failures and the success came from the same address, what the session did afterwards, and whether other alerts involve the same address or account. I contact the user through a known-good channel. If they don't recognise the activity, I escalate and propose a password reset and session revocation through the proper process. That is the r.khan scenario in my data.

**7. Why not say the IP address is malicious?**
> An IP address doesn't identify a person. It could be a shared NAT, a VPN, a mobile carrier or a compromised third-party device. The logs only show behaviour from that address. So the reports say "consistent with" and list benign explanations, and the conclusion is limited to what the evidence supports.

**8. How do you know your detections work?**
> I generate data with known scenarios and keep a separate ground-truth file that detection never reads. Tests check that every planted scenario triggers the expected rules, and that normal activity alone produces zero alerts. Unit tests on small hand-built datasets check each threshold boundary - for example, four failures don't trigger R001, five do, and six spaced four minutes apart don't.

**9. What are the main limitations?**
> It uses only authentication logs from synthetic data - no endpoint, email or proxy telemetry, and geolocation and threat intelligence only from small offline, fictional files. The rules are threshold-based, so slow or distributed attacks can evade them, and credential theft with no failures is largely invisible. Business hours are in UTC without daylight saving. I've documented all of this in the repository.

**10. How would this map to a real SOC?**
> The rules mirror common SIEM use cases built on Windows events 4625, 4624 and 4740, and I mapped them to MITRE ATT&CK T1110 and T1078. In a real SOC they would be KQL in Microsoft Sentinel or SPL in Splunk, running against centralised logs, with enrichment and a case-management tool for status and notes. The repository already exports them as Sigma, Splunk SPL and Sentinel KQL, but I have not yet run those queries on a live SIEM.

## Skills this project demonstrates

- Authentication log analysis (logon success and failure, lockouts, unlocks, password changes; Windows event ID equivalents)
- Designing threshold-based detections with sliding time windows
- Severity assessment with documented rationale
- Distinguishing facts, hypotheses and conclusions in incident write-ups
- Identifying and documenting false positives, and tuning detections
- Mapping detections to MITRE ATT&CK techniques
- Data validation and data-quality reporting
- Python, pandas, Streamlit and pytest; modular code with separate configuration
- Technical documentation written for other analysts

## Skills still to develop

- Hands-on use of a real SIEM (Microsoft Sentinel / KQL, Splunk / SPL, Elastic)
- Real log sources: Windows Event Viewer and EVTX, Sysmon, Linux `auth.log`, Entra ID sign-in logs, firewall and proxy logs
- EDR tooling and endpoint investigation
- Threat-intelligence enrichment (IP and domain reputation, VirusTotal, AbuseIPDB)
- Email and phishing analysis
- Networking fundamentals in depth (TCP/IP, DNS, packet capture with Wireshark)
- Incident response frameworks (NIST SP 800-61, NCSC guidance) and ticketing workflows
- Certifications commonly requested for UK junior roles, e.g. CompTIA Security+, Microsoft SC-200, Blue Team Level 1

## CV entry

**Mini SOC Lab - personal project** (Python, pandas, Streamlit, pytest)

- Built a lab that generates synthetic authentication logs and detects suspicious logon patterns using five configurable rules (failed-logon bursts, success after failures, failure rate, password spraying, out-of-hours and rapid source changes), mapped to MITRE ATT&CK.
- Developed a Streamlit dashboard for alert triage, with filters, a timeline and investigation reports that separate observed facts from hypotheses and list benign explanations; reports export to Markdown and CSV.
- Implemented input validation for malformed and duplicate records, and wrote 99 automated pytest tests, including detection-coverage tests against labelled scenarios.
- Documented the detection logic, false-positive handling, rule tuning and limitations.

## GitHub repository description

> Mini SOC Lab: synthetic authentication log generator, configurable brute-force/password-spray detection rules (MITRE ATT&CK mapped), Streamlit triage dashboard and evidence-based incident reports. Python, pandas, pytest.

Suggested topics: `soc`, `blue-team`, `detection-engineering`, `log-analysis`, `incident-response`, `streamlit`, `python`, `mitre-attack`
