"""Command-line interface.

    python -m soc_lab.cli generate [--output data/sample_auth_logs.csv] [--days 14] [--seed 42]
    python -m soc_lab.cli analyse  [--input data/sample_auth_logs.csv] [--format auto] [--export-csv reports/alerts.csv]
    python -m soc_lab.cli convert  --input data/examples/linux_auth.log [--year 2026] [--output converted.csv]
    python -m soc_lab.cli report   --alert-id ALR-0010 | --all  [--output-dir reports]
    python -m soc_lab.cli export-rules [--format all|sigma|spl|kql] [--output-dir rules_export]
    python -m soc_lab.cli lookup-ip 203.0.113.88 [more addresses]
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .config import DEFAULT_CONFIG_PATH, PROJECT_ROOT, ConfigError, load_config
from .correlation import cases_to_csv, correlate_alerts, correlation_window
from .detection import run_detection
from .detection.export import FORMATS, export_rules
from .enrichment import enrichment_findings, load_enrichment
from .log_generator import GeneratorSettings, generate_events, write_dataset
from .log_loader import LogFileError, load_events
from .parsers import FORMATS as LOG_FORMATS, ConversionError, convert
from .metrics import compute_kpis
from .reporting import alerts_to_csv, build_investigation_report, save_report

DEFAULT_LOG_PATH = PROJECT_ROOT / "data" / "sample_auth_logs.csv"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"
DEFAULT_EXPORT_DIR = PROJECT_ROOT / "rules_export"


def _cmd_generate(args: argparse.Namespace) -> int:
    settings = GeneratorSettings(start_date=args.start_date, days=args.days, seed=args.seed,
                                 inject_quality_issues=not args.no_quality_issues)
    events = generate_events(settings)
    log_path, truth_path = write_dataset(events, args.output)
    print(f"Generated {len(events)} events ({settings.days} days, seed {settings.seed}).")
    print(f"  Logs:         {log_path}")
    print(f"  Ground truth: {truth_path}  (for learning/testing only - not used by detection)")
    return 0


def _load(args: argparse.Namespace):
    """Load a lab CSV directly, or convert a real-world log format first."""
    path = Path(args.input)
    if args.format == "lab_csv" or not path.is_file():
        return load_events(args.input)  # load_events reports missing files and directories
    conversion = convert(path.read_bytes(), args.format, path.name, args.year)
    if conversion.fmt == "lab_csv":
        return load_events(args.input)
    _print_conversion(conversion)
    return load_events(conversion.to_csv_bytes(), str(path))


def _print_conversion(conversion) -> None:
    print(f"Converted from {conversion.fmt}: {conversion.records_read} records read, "
          f"{len(conversion.events)} events, {conversion.records_skipped} skipped")
    for reason, count in conversion.skipped.most_common():
        print(f"  skipped {count:>4}  {reason}")


def _cmd_convert(args: argparse.Namespace) -> int:
    path = Path(args.input)
    if not path.is_file():
        raise LogFileError(f"Log file not found: {path}")
    conversion = convert(path.read_bytes(), args.format, path.name, args.year)
    if conversion.fmt == "lab_csv":
        print("The file is already a lab CSV; nothing to convert.")
        return 0
    _print_conversion(conversion)
    output = Path(args.output or path.with_name(f"{path.stem}_converted.csv"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(conversion.to_csv_bytes())
    print(f"Lab CSV written to {output}")
    return 0


def _analyse(args: argparse.Namespace):
    result = _load(args)
    config = load_config(args.config)
    alerts = run_detection(result.events, config)
    return result, config, alerts


def _cmd_analyse(args: argparse.Namespace) -> int:
    result, _config, alerts = _analyse(args)
    quality, kpis = result.quality, compute_kpis(result.events, alerts)
    print(f"Source: {quality.source}")
    print(f"Rows read: {quality.rows_read} | accepted: {quality.rows_accepted} | rejected: {quality.rows_rejected} "
          f"| exact duplicates removed: {quality.exact_duplicates_removed}")
    for warning in quality.warnings:
        print(f"  ! {warning}")
    print(f"Successful logons: {kpis['successful_logins']} | failed logons: {kpis['failed_logins']} "
          f"| failure rate: {kpis['failure_rate']:.1%}")
    severity_summary = ", ".join(f"{name}: {count}" for name, count in kpis["alerts_by_severity"].items())
    print(f"Alerts: {kpis['total_alerts']} ({severity_summary})\n")
    for alert in alerts:
        print(f"{alert.alert_id}  {alert.severity.value:<8}  {alert.rule_id}  "
              f"{alert.first_seen:%Y-%m-%d %H:%M}  {alert.title}")

    window = correlation_window(_config)
    cases = correlate_alerts(alerts, window)
    print(f"\nCases: {len(cases)} (alerts sharing an account or address, at most {window:g} min apart)")
    for case in cases:
        print(f"{case.case_id}  {case.severity.value:<8}  {', '.join(case.alert_ids):<28}  {case.title}")
    for option, text, label in ((args.export_csv, alerts_to_csv(alerts), "Alert list"),
                                (args.export_cases_csv, cases_to_csv(cases), "Case list")):
        if option:
            path = Path(option)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="")
            print(f"\n{label} written to {path}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    result, config, alerts = _analyse(args)
    selected = alerts if args.all else [a for a in alerts if a.alert_id == args.alert_id]
    if not selected:
        print(f"No alert with ID {args.alert_id}. Run 'analyse' to list alert IDs.", file=sys.stderr)
        return 1
    enrichment = None if args.no_enrichment else load_enrichment()
    for warning in enrichment.warnings if enrichment else []:
        print(f"  ! {warning}", file=sys.stderr)
    for alert in selected:
        report = build_investigation_report(alert, result.events, config, all_alerts=alerts, enrichment=enrichment)
        markdown_path, csv_path = save_report(report, args.output_dir)
        print(f"{report.incident_id}: {markdown_path} | {csv_path}")
    return 0


def _cmd_export_rules(args: argparse.Namespace) -> int:
    formats = list(FORMATS) if args.format == "all" else [args.format]
    exported = export_rules(load_config(args.config), formats)
    if not exported:
        print("All rules are disabled in the configuration; nothing to export.", file=sys.stderr)
        return 1
    for rule in exported:
        path = Path(args.output_dir) / rule.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rule.text, encoding="utf-8", newline="\n")
        print(f"{path}" + ("" if rule.supported else "  (not expressible in this format - see the file)"))
    print(f"\n{len(exported)} file(s) written. Not tested on a live SIEM: review before production use.")
    return 0


def _cmd_lookup_ip(args: argparse.Namespace) -> int:
    enrichment = load_enrichment()
    internal = load_config(args.config)["environment"]["internal_networks"]
    for warning in enrichment.warnings:
        print(f"  ! {warning}", file=sys.stderr)
    for ip in args.ips:
        info = enrichment.lookup(ip, internal)
        print(ip)
        if info.internal:
            print("  Internal address (configured internal network): no public geolocation.")
        for finding in enrichment_findings([info]):
            print(f"  {finding}")
    print("\nOffline, fictional enrichment data (data/enrichment/). Context for the analyst, not a verdict.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_lab", description="Mini SOC Lab - authentication log analysis.")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a synthetic authentication log dataset.")
    gen.add_argument("--output", default=str(DEFAULT_LOG_PATH))
    gen.add_argument("--days", type=int, default=14)
    gen.add_argument("--seed", type=int, default=42)
    gen.add_argument("--start-date", type=date.fromisoformat, default=GeneratorSettings().start_date,
                     help="First day of the dataset (YYYY-MM-DD).")
    gen.add_argument("--no-quality-issues", action="store_true",
                     help="Do not append the deliberately malformed demonstration rows.")
    gen.set_defaults(handler=_cmd_generate)

    for name, handler, help_text in (("analyse", _cmd_analyse, "Validate logs and run detection rules."),
                                     ("report", _cmd_report, "Write investigation reports (Markdown + CSV).")):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--input", default=str(DEFAULT_LOG_PATH))
        cmd.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
        _format_arguments(cmd)
        cmd.set_defaults(handler=handler)
        if name == "analyse":
            cmd.add_argument("--export-csv", help="Also write the alert list to this CSV file.")
            cmd.add_argument("--export-cases-csv", help="Also write the case list to this CSV file.")
        else:
            group = cmd.add_mutually_exclusive_group(required=True)
            group.add_argument("--alert-id", help="Alert to report on, e.g. ALR-0010.")
            group.add_argument("--all", action="store_true", help="Write a report for every alert.")
            cmd.add_argument("--output-dir", default=str(DEFAULT_REPORT_DIR))
            cmd.add_argument("--no-enrichment", action="store_true",
                             help="Do not add the offline IP enrichment (geolocation, ASN, threat intelligence).")

    conv = sub.add_parser("convert", help="Convert Linux auth.log, Windows XML or Entra ID JSON to a lab CSV.")
    conv.add_argument("--input", required=True)
    conv.add_argument("--output", help="Default: <input name>_converted.csv next to the input.")
    _format_arguments(conv)
    conv.set_defaults(handler=_cmd_convert)

    export = sub.add_parser("export-rules", help="Export the detection rules as Sigma, Splunk SPL and Sentinel KQL.")
    export.add_argument("--format", choices=["all", *FORMATS], default="all")
    export.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    export.add_argument("--output-dir", default=str(DEFAULT_EXPORT_DIR))
    export.set_defaults(handler=_cmd_export_rules)

    lookup = sub.add_parser("lookup-ip", help="Look addresses up in the offline enrichment files.")
    lookup.add_argument("ips", nargs="+", metavar="IP")
    lookup.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    lookup.set_defaults(handler=_cmd_lookup_ip)
    return parser


def _format_arguments(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument("--format", choices=["auto", *LOG_FORMATS], default="auto",
                     help="Input format (default: detect from the file name and contents).")
    cmd.add_argument("--year", type=int, default=None,
                     help="Year for classic syslog lines in auth.log, which have none (default: current year).")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (LogFileError, ConfigError, ConversionError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
