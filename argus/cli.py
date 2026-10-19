"""Command-line interface for ARGUS.EXE.

Usage::

    python -m argus sigdb init [path]       build a signature database
    python -m argus sigdb info [path]       show database details
    python -m argus scan <path> [options]   scan a file or folder
    python -m argus watch [options]         real-time protection (foreground)
    python -m argus watch-status            show real-time protection status

Exit codes: 0 = clean, 1 = detections found, 2 = error (bad arguments,
missing/unverified signature database, unscannable target).
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from . import __version__
from .config import DEFAULT_CONFIG_NAME, ArgusConfig
from .detections import Verdict
from .realtime import RealtimeEvent
from .rules import BUILTIN_RULES, Rule, RuleError, load_rules
from .scanner import ScanReport, scan_path
from .service import ArgusService, read_status_file
from .signatures import DEFAULT_DB_NAME, SignatureDB, SignatureError, init_db

EXIT_CLEAN = 0
EXIT_DETECTIONS = 1
EXIT_ERROR = 2


# ----------------------------------------------------------------------
# Human-readable output
# ----------------------------------------------------------------------
def _print_human(report: ScanReport) -> None:
    print(f"ARGUS scan of {report.root}")
    print("=" * 60)
    for scanned in report.detections:
        verdict = scanned.verdict.value.upper()
        print(f"\n[{verdict}] {scanned.path}")
        assessment = scanned.assessment
        if assessment.max_severity:
            print(f"  Highest severity: {assessment.max_severity.capitalize()}")
        for det in assessment.detections:
            print(f"  - {det.name} ({det.severity.capitalize()})")
            print(f"    {det.reason}")
        if assessment.signals:
            print(f"  Heuristic signals (risk score: {assessment.score}):")
            for sig in assessment.signals:
                print(f"  - {sig.name} ({sig.severity.capitalize()}, +{sig.points})")
                print(f"    {sig.explanation}")
        for note in assessment.notes:
            print(f"  Note: {note}")
        if scanned.result.sha256:
            print(f"    SHA-256: {scanned.result.sha256}")

    skipped = [f for f in report.files if not f.result.ok]
    if skipped:
        print("\nCould not read:")
        for scanned in skipped:
            print(f"  - {scanned.path}: {scanned.result.error}")

    stats = report.stats
    print("\n" + "-" * 60)
    print(f"Files scanned: {stats.files_scanned}  "
          f"Skipped (unreadable): {stats.files_skipped}  "
          f"Excluded by you: {stats.files_excluded}  "
          f"Folders skipped: {stats.dirs_skipped}")
    print(f"Data scanned: {stats.bytes_scanned / (1024 * 1024):.1f} MB")
    n = len(report.detections)
    if n:
        print(f"Detections: {n} file(s) flagged — review them above.")
        print("Argus never deletes anything on its own. Quarantine and "
              "removal are your call (coming in Phase 4).")
    else:
        print("Detections: none. Everything scanned came back clean.")


def _report_to_dict(report: ScanReport) -> dict:
    return {
        "root": str(report.root),
        "verdict": report.verdict.value,
        "stats": {
            "files_seen": report.stats.files_seen,
            "files_scanned": report.stats.files_scanned,
            "files_skipped": report.stats.files_skipped,
            "files_excluded": report.stats.files_excluded,
            "dirs_skipped": report.stats.dirs_skipped,
            "bytes_scanned": report.stats.bytes_scanned,
        },
        "files": [
            {
                "path": str(f.path),
                "size": f.result.size,
                "sha256": f.result.sha256,
                "error": f.result.error,
                "excluded": f.excluded,
                "verdict": f.verdict.value,
                "max_severity": f.assessment.max_severity,
                "score": f.assessment.score,
                "rules_skipped_reason": f.rules_skipped_reason,
                "detections": [
                    {
                        "kind": d.kind,
                        "name": d.name,
                        "family": d.family,
                        "severity": d.severity,
                        "reason": d.reason,
                    }
                    for d in f.assessment.detections
                ],
                "signals": [
                    {
                        "name": s.name,
                        "severity": s.severity,
                        "points": s.points,
                        "explanation": s.explanation,
                    }
                    for s in f.assessment.signals
                ],
                "notes": list(f.assessment.notes),
            }
            for f in report.files
        ],
    }


# ----------------------------------------------------------------------
# Subcommands
# ----------------------------------------------------------------------
def _cmd_sigdb_init(args: argparse.Namespace) -> int:
    info = init_db(args.path, seed=not args.no_seed)
    print(f"Signature database created: {args.path}")
    print(f"  Version: {info.version} (schema {info.schema_version})")
    print(f"  Built:   {info.built_at}")
    print(f"  Signatures: {info.count}")
    if not args.no_seed:
        print("  Includes the EICAR test signature so you can verify "
              "detection works.")
    return EXIT_CLEAN


def _cmd_sigdb_info(args: argparse.Namespace) -> int:
    try:
        with SignatureDB.open(args.path) as db:
            info = db.info
    except SignatureError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Signature database: {args.path}")
    print(f"  Version: {info.version} (schema {info.schema_version})")
    print(f"  Built:   {info.built_at}")
    print(f"  Signatures: {info.count}")
    print("  Integrity: OK")
    return EXIT_CLEAN


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Error: nothing to scan at {target}", file=sys.stderr)
        return EXIT_ERROR

    try:
        db = SignatureDB.open(args.db)
    except SignatureError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(f"Build a database first: python -m argus sigdb init {args.db}",
              file=sys.stderr)
        return EXIT_ERROR

    rules: list[Rule] = BUILTIN_RULES
    if args.rules:
        try:
            rules = load_rules(args.rules)
        except (RuleError, OSError) as exc:
            print(f"Error loading rules: {exc}", file=sys.stderr)
            db.close()
            return EXIT_ERROR

    exclusions = None
    if args.config:
        config = ArgusConfig.load(args.config)
        for warning in config.load_warnings:
            print(f"Config warning: {warning}", file=sys.stderr)
        exclusions = config.exclusions

    try:
        report = scan_path(target, db, rules, heuristics=not args.no_heuristics,
                           exclusions=exclusions)
    finally:
        db.close()

    if args.json:
        print(json.dumps(_report_to_dict(report), indent=2))
    else:
        _print_human(report)

    if report.verdict is Verdict.CLEAN:
        return EXIT_CLEAN
    return EXIT_DETECTIONS


# ----------------------------------------------------------------------
# Real-time protection commands
# ----------------------------------------------------------------------
def _print_event(event: RealtimeEvent) -> None:
    tag = {
        "detection": "DETECTION",
        "action": "ACTION   ",
        "process": "PROCESS  ",
        "info": "INFO     ",
    }.get(event.kind, event.kind.upper())
    print(f"[{tag}] {event.message}", flush=True)


def _cmd_watch(args: argparse.Namespace) -> int:
    config = ArgusConfig.load(args.config)
    if args.dirs:
        config.watch_dirs = [Path(d.strip()) for d in args.dirs.split(",") if d.strip()]
    if args.db:
        config.signature_db = args.db
    if args.no_process_monitor:
        config.process_monitor_enabled = False
    if args.status_file:
        config.status_file = args.status_file

    for warning in config.load_warnings:
        print(f"Config warning: {warning}", file=sys.stderr)

    detections_seen = 0

    def on_event(event: RealtimeEvent) -> None:
        nonlocal detections_seen
        if event.kind == "detection":
            detections_seen += 1
        _print_event(event)

    service = ArgusService(config=config, on_event=on_event)
    stop_event = threading.Event()

    def _request_stop(signum, frame):  # noqa: ANN001 — signal handler shape
        stop_event.set()

    signal.signal(signal.SIGINT, _request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _request_stop)

    print("ARGUS.EXE real-time protection")
    print("=" * 60)
    print("Watching:")
    for folder in config.watch_dirs:
        print(f"  - {folder}")
    print(f"Process monitor: {'on' if config.process_monitor_enabled else 'off'}")
    print("Argus scans files as they finish downloading or changing, and")
    print("programs as they start. It never deletes anything on its own —")
    print("detections are reported, and actions wait for your say-so.")
    print("Press Ctrl+C to stop.\n")

    try:
        service.run_forever(stop_event)
    except SignatureError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(f"Build a database first: python -m argus sigdb init "
              f"{config.signature_db}", file=sys.stderr)
        return EXIT_ERROR

    status = service.status()
    print("\nReal-time protection stopped.")
    print(f"Scans completed: {status['scans_completed']}  "
          f"Detections: {status['detections']}  "
          f"Excluded: {status['files_excluded']}")
    return EXIT_DETECTIONS if detections_seen else EXIT_CLEAN


def _cmd_watch_status(args: argparse.Namespace) -> int:
    status = read_status_file(args.status_file)
    if status is None:
        print("Argus real-time protection: NOT RUNNING "
              f"(no status file at {args.status_file}).")
        print("Start it with: python -m argus watch")
        return EXIT_ERROR
    if args.json:
        print(json.dumps(status, indent=2))
        return EXIT_CLEAN
    state = status.get("state", "unknown")
    uptime = status.get("uptime_seconds")
    uptime_text = f"{uptime}s" if uptime is not None else "—"
    print(f"Argus real-time protection: {state.upper()}")
    print(f"  Version: {status.get('version')}  "
          f"Started: {status.get('started_at')}  "
          f"Uptime: {uptime_text}")
    print(f"  Watching: {', '.join(status.get('watch_dirs', []))}")
    print(f"  Files being watched: {status.get('files_watched')}  "
          f"Scans completed: {status.get('scans_completed')}  "
          f"Detections: {status.get('detections')}")
    print(f"  Programs seen starting: {status.get('processes_seen')}  "
          f"Files excluded: {status.get('files_excluded')}  "
          f"Scan errors: {status.get('scan_errors')}")
    print(f"  Last heartbeat: {status.get('heartbeat_at')}")
    return EXIT_CLEAN


# ----------------------------------------------------------------------
# Argument parsing / entry point
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="ARGUS.EXE — antivirus & malware detection by "
                    "Sentinel Safeguard LLC. Security For Everyone.",
    )
    parser.add_argument("--version", action="version",
                        version=f"ARGUS.EXE {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a file or folder")
    p_scan.add_argument("path", help="file or folder to scan")
    p_scan.add_argument("--db", default=DEFAULT_DB_NAME,
                        help=f"signature database path (default: {DEFAULT_DB_NAME})")
    p_scan.add_argument("--rules", default=None,
                        help="optional JSON file with extra/replacement rules")
    p_scan.add_argument("--no-heuristics", action="store_true",
                        help="skip Phase 2 heuristic analysis (PE structure, "
                             "entropy, script signals) — signatures and "
                             "pattern rules only")
    p_scan.add_argument("--config", default=None,
                        help="config file to take exclusions from — files "
                             "you have told Argus to leave alone are left "
                             "alone in scans too")
    p_scan.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of text")
    p_scan.set_defaults(func=_cmd_scan)

    p_watch = sub.add_parser(
        "watch", help="run real-time protection in the foreground")
    p_watch.add_argument("--config", default=DEFAULT_CONFIG_NAME,
                         help=f"config file (default: {DEFAULT_CONFIG_NAME}; "
                              "missing file = built-in defaults)")
    p_watch.add_argument("--dirs", default=None,
                         help="comma-separated folders to watch "
                              "(overrides the config file)")
    p_watch.add_argument("--db", default=None,
                         help="signature database path (overrides config)")
    p_watch.add_argument("--no-process-monitor", action="store_true",
                         help="do not watch for programs starting")
    p_watch.add_argument("--status-file", default=None,
                         help="where to write the heartbeat status file")
    p_watch.set_defaults(func=_cmd_watch)

    p_status = sub.add_parser(
        "watch-status", help="show real-time protection status")
    p_status.add_argument("--status-file", default="argus-status.json",
                          help="status file to read (default: argus-status.json)")
    p_status.add_argument("--json", action="store_true",
                          help="print the raw status JSON")
    p_status.set_defaults(func=_cmd_watch_status)

    p_sigdb = sub.add_parser("sigdb", help="manage the signature database")
    sigsub = p_sigdb.add_subparsers(dest="sigdb_command")

    p_init = sigsub.add_parser("init", help="create a new signature database")
    p_init.add_argument("path", nargs="?", default=DEFAULT_DB_NAME,
                        help=f"database path (default: {DEFAULT_DB_NAME})")
    p_init.add_argument("--no-seed", action="store_true",
                        help="do not include the EICAR test signature")
    p_init.set_defaults(func=_cmd_sigdb_init)

    p_info = sigsub.add_parser("info", help="show signature database details")
    p_info.add_argument("path", nargs="?", default=DEFAULT_DB_NAME,
                        help=f"database path (default: {DEFAULT_DB_NAME})")
    p_info.set_defaults(func=_cmd_sigdb_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return EXIT_ERROR
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
