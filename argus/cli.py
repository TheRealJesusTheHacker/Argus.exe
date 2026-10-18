"""Command-line interface for ARGUS.EXE.

Usage::

    python -m argus sigdb init [path]       build a signature database
    python -m argus sigdb info [path]       show database details
    python -m argus scan <path> [options]   scan a file or folder

Exit codes: 0 = clean, 1 = detections found, 2 = error (bad arguments,
missing/unverified signature database, unscannable target).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .detections import Verdict
from .rules import BUILTIN_RULES, Rule, RuleError, load_rules
from .scanner import ScanReport, scan_path
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
            "dirs_skipped": report.stats.dirs_skipped,
            "bytes_scanned": report.stats.bytes_scanned,
        },
        "files": [
            {
                "path": str(f.path),
                "size": f.result.size,
                "sha256": f.result.sha256,
                "error": f.result.error,
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

    try:
        report = scan_path(target, db, rules, heuristics=not args.no_heuristics)
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
    p_scan.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of text")
    p_scan.set_defaults(func=_cmd_scan)

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
