"""Command-line interface for ARGUS.EXE.

Usage::

    python -m argus sigdb init [path]       build a signature database
    python -m argus sigdb info [path]       show database details
    python -m argus scan <path> [options]   scan a file or folder
    python -m argus watch [options]         real-time protection (foreground)
    python -m argus watch-status            show real-time protection status
    python -m argus service <command>       manage the Windows service (Phase 5)
    python -m argus quarantine list         what's in the quarantine vault
    python -m argus quarantine restore <id> put a quarantined file back
    python -m argus quarantine delete <id>  permanently delete a vault file
    python -m argus quarantine allow <id>   restore + vouch for a file
    python -m argus pending list            actions waiting for your decision
    python -m argus pending approve <id>    carry out a queued action
    python -m argus pending reject <id>     decline a queued action
    python -m argus report [--days N]       plain-language activity report
    python -m argus history                 recent scans and detections

Exit codes: 0 = clean, 1 = detections found, 2 = error (bad arguments,
missing/unverified signature database, unscannable target).
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from . import action_requests
from .actions import (
    ActionEngine,
    ActionError,
    DetectionInfo,
)
from .config import DEFAULT_CONFIG_NAME, ArgusConfig
from .detections import Verdict
from .paths import (
    data_dir,
    default_history_db,
    default_pending_db,
    default_vault_dir,
    pending_view_path,
    vault_view_path,
)
from .quarantine import (
    QuarantineEntry,
    QuarantineError,
    Vault,
    read_pending_db,
    read_pending_view,
)
from .realtime import RealtimeEvent
from .reporting import (
    DetectionRecord,
    History,
    render_text_report,
    report_dict,
)
from .rules import BUILTIN_RULES, Rule, RuleError, load_rules
from .scanner import (
    ARCHIVE_NOT_FULLY_SCANNED_PREFIX,
    ScanReport,
    ScannedFile,
    scan_path,
)
from .service import ArgusService, read_status_file
from .signatures import (
    DEFAULT_DB_NAME,
    SignatureDB,
    SignatureError,
    bootstrap_signature_db,
    ensure_signature_db,
    init_db,
)

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
    not_scanned = [f for f in report.files if f.verdict is Verdict.NOT_SCANNED]
    if not_scanned:
        print(f"Not scanned: {len(not_scanned)} file(s) could not be "
              "read (locked or unreadable) — they were NOT cleared "
              "as safe; close the program using them and scan again.")
    partial_archives = [
        f for f in report.files if f.archive_not_fully_scanned
    ]
    undetailed_partials = [
        f for f in partial_archives if f not in report.detections
    ]
    if undetailed_partials:
        print("\nNot fully scanned:")
        for scanned in undetailed_partials:
            print(f"  - {scanned.path}")
            for reason in scanned.archive_incomplete_reasons:
                print(f"    {reason}")
    if partial_archives:
        print(f"Archives not fully scanned: {len(partial_archives)} "
              "archive(s) could not be checked completely — they were "
              "NOT cleared as safe.")
    if stats.archives_seen:
        print(f"Archives checked: {stats.archives_seen} "
              f"({stats.archive_members_scanned} file(s) inside them)")
    print(f"Data scanned: {stats.bytes_scanned / (1024 * 1024):.1f} MB")
    n = len(report.detections)
    if n:
        print(f"Detections: {n} file(s) flagged — review them above.")
        print("Argus never deletes anything on its own. Malicious files "
              "can be quarantined (--quarantine) or reviewed later with: "
              "argus quarantine list")
    elif partial_archives:
        print("Detections: none — but some archives were not fully "
              "scanned (see above), so this is not a clean bill of "
              "health for them.")
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
            "archives_seen": report.stats.archives_seen,
            "archive_members_scanned": report.stats.archive_members_scanned,
            "archives_not_fully_scanned":
                report.stats.archives_not_fully_scanned,
        },
        "files": [
            {
                "path": str(f.path),
                "size": f.result.size,
                "sha256": f.result.sha256,
                "error": f.result.error,
                "excluded": f.excluded,
                "archive_not_fully_scanned": f.archive_not_fully_scanned,
                "archive_incomplete_reasons":
                    list(f.archive_incomplete_reasons),
                "archive_members_scanned": f.archive_members_scanned,
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
def _resolve_sigdb_path(args: argparse.Namespace) -> Path:
    """The signature database a sigdb command works on: the path
    named on the command line, else the CONFIG's signature_db
    (which itself defaults to the data folder — never a bare
    CWD-relative filename)."""
    if getattr(args, "path", None):
        return Path(args.path)
    return Path(load_config(args).signature_db)


def _cmd_sigdb_init(args: argparse.Namespace) -> int:
    db_path = _resolve_sigdb_path(args)
    info = init_db(db_path, seed=not args.no_seed)
    print(f"Signature database created: {db_path}")
    print(f"  Version: {info.version} (schema {info.schema_version})")
    print(f"  Built:   {info.built_at}")
    print(f"  Signatures: {info.count}")
    if not args.no_seed:
        print("  Includes the EICAR test signature so you can verify "
              "detection works.")
    return EXIT_CLEAN


def _cmd_sigdb_info(args: argparse.Namespace) -> int:
    db_path = _resolve_sigdb_path(args)
    try:
        with SignatureDB.open(db_path) as db:
            info = db.info
    except SignatureError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Signature database: {db_path}")
    print(f"  Version: {info.version} (schema {info.schema_version})")
    print(f"  Built:   {info.built_at}")
    print(f"  Signatures: {info.count}")
    print("  Integrity: OK")
    return EXIT_CLEAN


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_config_path(args: argparse.Namespace) -> Path:
    """THE config resolver (P1-15): every subcommand resolves its
    config the same way — an explicit ``--config`` wins; otherwise
    the machine config at ``<data dir>/argus-config.json``. No
    subcommand defaults to a bare CWD-relative filename anymore
    (watch and quarantine-allow used to read ``argus-config.json``
    from whatever directory the shell happened to be in, while
    others read none at all — the same command meant different
    settings depending on where it was typed)."""
    explicit = getattr(args, "config", None)
    if explicit:
        return Path(explicit)
    return data_dir() / DEFAULT_CONFIG_NAME


def load_config(args: argparse.Namespace) -> ArgusConfig:
    """Load the config :func:`resolve_config_path` names for this
    invocation, warning loudly (stderr) about a config that exists
    but has problems. A missing default config is the normal
    fresh-install case — defaults apply silently."""
    path = resolve_config_path(args)
    config = ArgusConfig.load(path)
    if getattr(args, "config", None) or path.is_file():
        for warning in config.load_warnings:
            print(f"Config warning: {warning}", file=sys.stderr)
    return config


def _resolve_vault_dir(args, config: ArgusConfig | None) -> Path:
    explicit = getattr(args, "vault_dir", None)
    if explicit:
        return Path(explicit)
    if config is not None and config.vault_dir:
        return Path(config.vault_dir)
    return default_vault_dir()


def _resolve_history_db(args, config: ArgusConfig | None) -> Path:
    explicit = getattr(args, "history_db", None)
    if explicit:
        return Path(explicit)
    if config is not None and config.history_db:
        return Path(config.history_db)
    return default_history_db()


def _resolve_pending_db(args, config: ArgusConfig | None) -> Path:
    if config is not None and config.pending_db:
        return Path(config.pending_db)
    return default_pending_db()


def _read_pending_loose(args, config: ArgusConfig | None) -> list:
    """Pending rows for a caller that could NOT open the vault.

    The pending database is service-owned and lives in the trusted
    vault directory: an ELEVATED or portable/dev process can read
    it directly (and does — that route keeps working), but a
    standard-user process in the installed layout cannot, and must
    NOT be handed the trusted path as its source. There the
    service-published pending VIEW (shared/pending-view.json) is
    the display source — the same interface the GUI uses.
    """
    db_path = _resolve_pending_db(args, config)
    try:
        readable = db_path.is_file() and os.access(db_path, os.R_OK)
    except OSError:
        readable = False
    if readable:
        return read_pending_db(db_path)
    return read_pending_view(pending_view_path())


def _open_vault(args, config: ArgusConfig | None) -> Vault:
    """Open the vault the way every production caller does: entries
    in the vault directory, the pending queue in its shared
    database (v1.0.4 trust split)."""
    return Vault.open(
        _resolve_vault_dir(args, config), _resolve_pending_db(args, config)
    )


def _prompt_scan_action(scanned: ScannedFile) -> str | None:
    """Ask what to do with one Malicious file. Returns "quarantine",
    "delete", or None (leave it). EOF/Ctrl-C means leave everything."""
    print(f"\n{scanned.path} was flagged MALICIOUS.")
    try:
        choice = input(
            "  [q]uarantine it, [d]elete it permanently, or press "
            "Enter to leave it: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if choice in ("q", "quarantine"):
        return "quarantine"
    if choice in ("d", "delete"):
        return "delete"
    return None


def _run_scan_actions(
    args: argparse.Namespace,
    report: ScanReport,
    config: ArgusConfig | None,
) -> dict[str, str]:
    """Offer/apply actions for Malicious files after a scan.

    Returns {path: action_taken} for history. Without --quarantine,
    --delete, or an interactive terminal, NOTHING is touched — the
    scan reports only. That is the never-silent rule at the CLI.
    """
    malicious = [f for f in report.detections if f.verdict is Verdict.MALICIOUS]
    if not malicious:
        return {}
    mode: str | None = None
    if getattr(args, "quarantine", False):
        mode = "quarantine"
    elif getattr(args, "delete", False):
        mode = "delete"
    elif not args.json and sys.stdin.isatty():
        mode = "ask"
    if mode is None:
        return {}

    vault = _open_vault(args, config)
    history = History.open(_resolve_history_db(args, config))
    try:
        engine = ActionEngine(
            vault, config or ArgusConfig(),
            config_path=str(resolve_config_path(args)), history=history,
        )
        taken: dict[str, str] = {}
        for scanned in malicious:
            action = mode
            if mode == "ask":
                action = _prompt_scan_action(scanned) or "none"
            if action == "none":
                taken[str(scanned.path)] = "none"
                continue
            info = DetectionInfo.from_scanned(scanned)
            try:
                if action == "quarantine":
                    outcome = engine.quarantine(
                        scanned.path, info, confirmed=True
                    )
                    taken[str(scanned.path)] = "quarantined"
                else:
                    outcome = engine.delete(
                        scanned.path, info, confirmed=True
                    )
                    taken[str(scanned.path)] = "deleted"
                stream = sys.stderr if args.json else sys.stdout
                print(outcome.message, file=stream)
            except (ActionError, QuarantineError) as exc:
                print(f"Could not {action} {scanned.path}: {exc}",
                      file=sys.stderr)
                taken[str(scanned.path)] = "none"
        return taken
    finally:
        history.close()
        vault.close()


def _record_scan_history(
    args: argparse.Namespace,
    report: ScanReport,
    config: ArgusConfig | None,
    started_at: str,
    action_taken: dict[str, str],
) -> None:
    """Write the scan into history. Bookkeeping must never fail a scan
    the user asked for — problems are reported, not raised."""
    try:
        history = History.open(_resolve_history_db(args, config))
        try:
            records = [
                DetectionRecord(
                    path=str(f.path),
                    verdict=f.verdict.value,
                    severity=f.assessment.max_severity,
                    score=f.assessment.score,
                    name=(
                        f.assessment.detections[0].name
                        if f.assessment.detections
                        else (f.assessment.signals[0].name
                              if f.assessment.signals else None)
                    ),
                    reasons=[d.reason for d in f.assessment.detections]
                    + [s.explanation for s in f.assessment.signals]
                    + [
                        note for note in f.assessment.notes
                        if note.startswith(ARCHIVE_NOT_FULLY_SCANNED_PREFIX)
                    ],
                    sha256=f.result.sha256,
                    action_taken=action_taken.get(str(f.path), "none"),
                )
                for f in report.detections
            ]
            history.record_scan(
                kind="ondemand",
                root=str(report.root),
                files_scanned=report.stats.files_scanned,
                files_skipped=report.stats.files_skipped,
                files_excluded=report.stats.files_excluded,
                bytes_scanned=report.stats.bytes_scanned,
                detections=records,
                started_at=started_at,
                finished_at=_utcnow_iso(),
                files_not_fully_scanned=
                report.stats.archives_not_fully_scanned,
            )
        finally:
            history.close()
    except Exception as exc:  # history is bookkeeping, not the scan
        print(f"Warning: could not record scan history: {exc}", file=sys.stderr)


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Error: nothing to scan at {target}", file=sys.stderr)
        return EXIT_ERROR
    if getattr(args, "quarantine", False) and getattr(args, "delete", False):
        print("Error: --quarantine and --delete are opposites — pick one.",
              file=sys.stderr)
        return EXIT_ERROR

    # Config first: without an explicit --db, the scan uses the
    # CONFIG's signature_db (the same database protection uses).
    # The config is the resolved machine config (see
    # resolve_config_path) — its exclusions apply to scans whether
    # or not --config was typed, the same answers the GUI and the
    # service read.
    config = load_config(args)
    exclusions = config.exclusions

    # Database bootstrap: with no explicit --db, Argus uses the
    # configured database — creating + seeding it on first run ONLY
    # at the default location, so a fresh install scans out of the
    # box. An explicitly named --db is the user's own file: if it is
    # missing, that is an error worth saying out loud, not something
    # to quietly paper over. The bootstrap runs inside the same try
    # as the open, so its errors take the same loud exit.
    if args.db is not None:
        db_path = Path(args.db)
        try:
            db = SignatureDB.open(db_path)
        except SignatureError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print(f"Build a database first: python -m argus sigdb init {db_path}",
                  file=sys.stderr)
            return EXIT_ERROR
    else:
        db_path = Path(config.signature_db)
        try:
            info = bootstrap_signature_db(db_path)
            if info is None:
                info = ensure_signature_db(db_path)
            db = SignatureDB.open(db_path)
        except SignatureError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            print(f"Build a database first: python -m argus sigdb init {db_path}",
                  file=sys.stderr)
            return EXIT_ERROR
        if info is not None and getattr(info, "auth_deferred", False):
            # Fix round 2 (FIX 3): this account cannot read the
            # signature-authentication key (it is kept with the
            # protection service), so the database was verified
            # structurally here; the service verifies it in full.
            # The scan proceeds; the exit code is unaffected.
            print(
                "Note: this account can't read Argus's "
                "signature-authentication key (it's kept with the "
                "protection service), so this scan verified the "
                "signature database's structure only — the "
                "protection service verifies it in full."
            )

    rules: list[Rule] = BUILTIN_RULES
    if args.rules:
        try:
            rules = load_rules(args.rules)
        except (RuleError, OSError) as exc:
            print(f"Error loading rules: {exc}", file=sys.stderr)
            db.close()
            return EXIT_ERROR

    started_at = _utcnow_iso()
    try:
        report = scan_path(target, db, rules, heuristics=not args.no_heuristics,
                           exclusions=exclusions)
    finally:
        db.close()

    if not args.json:
        _print_human(report)

    action_taken = _run_scan_actions(args, report, config)

    if args.json:
        payload = _report_to_dict(report)
        if action_taken:
            payload["actions_taken"] = action_taken
        print(json.dumps(payload, indent=2))

    _record_scan_history(args, report, config, started_at, action_taken)

    if report.verdict is Verdict.CLEAN:
        # An archive that could not be fully scanned is never a
        # clean result, even when nothing inside it was flagged.
        if any(f.archive_not_fully_scanned for f in report.files):
            return EXIT_DETECTIONS
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
    config = load_config(args)
    if args.dirs:
        config.watch_dirs = [Path(d.strip()) for d in args.dirs.split(",") if d.strip()]
    if args.db:
        config.signature_db = args.db
    if args.no_process_monitor:
        config.process_monitor_enabled = False
    if args.status_file:
        config.status_file = args.status_file

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
    print(f"Real-time action policy: {config.realtime_default}")
    print("Argus scans files as they finish downloading or changing, and")
    print("programs as they start. Detections go into history; quarantine")
    print("and delete requests follow your policy — by default they wait")
    print("in the pending queue (argus pending list) for your decision.")
    print("Argus never deletes a file on its own.")
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
    # Status path: an explicit --status-file wins; otherwise the
    # RESOLVED config's status_file (whose default is the shared
    # data folder — never a bare CWD-relative name).
    config = load_config(args)
    status_path = Path(args.status_file or config.status_file)
    status = read_status_file(status_path)
    if status is None:
        print("Argus real-time protection: NOT RUNNING "
              f"(no status file at {status_path}).")
        print("Start it with: python -m argus watch")
        return EXIT_ERROR
    # The GUI's gates, verbatim (P2 parity): the Service Control
    # Manager's word outranks the heartbeat file — SCM running
    # means RUNNING even when the heartbeat is stale (details
    # syncing); SCM stopped + stale heartbeat means NOT RUNNING,
    # said out loud.
    from .winservice import assess_service_status, query_service_state

    verdict, note = assess_service_status(status, query_service_state())
    if args.json:
        print(json.dumps(status, indent=2))
        return EXIT_CLEAN if verdict == "running" else EXIT_ERROR
    state = status.get("state", "unknown")
    uptime = status.get("uptime_seconds")
    uptime_text = f"{uptime}s" if uptime is not None else "—"
    if verdict == "running":
        print(f"Argus real-time protection: {state.upper()}")
    else:
        print("Argus real-time protection: NOT RUNNING")
    if note:
        print(f"  Note: {note}")
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
    return EXIT_CLEAN if verdict == "running" else EXIT_ERROR


def _cmd_service(args: argparse.Namespace) -> int:
    """Windows service management (Phase 5). The winservice module is
    imported lazily so the CLI — and this command's argument errors —
    work on every platform; off Windows the module explains, in plain
    language, why service management cannot run there."""
    from .winservice import (
        ServiceUnavailable,
        perform_service_command,
        route_service_command,
    )

    try:
        command = route_service_command([args.service_command])
    except ValueError as exc:
        print(str(exc))
        return EXIT_ERROR
    try:
        code = perform_service_command(
            command, config_path=str(resolve_config_path(args))
        )
    except ServiceUnavailable as exc:
        print(f"argus service: {exc}")
        return EXIT_ERROR
    return EXIT_CLEAN if code == 0 else EXIT_ERROR


# ----------------------------------------------------------------------
# Quarantine / pending / report / history commands (Phase 4)
# ----------------------------------------------------------------------
def _find_entry(vault: Vault, idish: str) -> QuarantineEntry | None:
    """Resolve a full entry id or a unique id prefix (what a human
    copies from a list). Ambiguous prefixes resolve to None."""
    exact = vault.get_entry(idish)
    if exact is not None:
        return exact
    matches = [e for e in vault.list_entries() if e.id.startswith(idish)]
    return matches[0] if len(matches) == 1 else None


def _confirm(prompt: str, yes_flag: bool) -> bool:
    """The never-silent rule at the CLI: destructive commands ask,
    unless the user explicitly passed --yes. A non-interactive shell
    without --yes is a no."""
    if yes_flag:
        return True
    if not sys.stdin.isatty():
        print("Refusing to act without confirmation: this is not an "
              "interactive terminal. Re-run with --yes if you mean it.",
              file=sys.stderr)
        return False
    try:
        answer = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def _cmd_quarantine_list(args: argparse.Namespace) -> int:
    try:
        vault = _open_vault(args, load_config(args))
    except PermissionError:
        return _quarantine_list_from_view(args)
    try:
        entries = vault.list_entries(status=args.status)
        if args.json:
            print(json.dumps([e.to_dict() for e in entries], indent=2))
            return EXIT_CLEAN
        if not entries:
            print("The quarantine vault is empty"
                  + (f" (no entries with status '{args.status}')."
                     if args.status else "."))
            print("Files Argus neutralizes will be listed here — "
                  "harmless, reversible, waiting for your decision.")
            return EXIT_CLEAN
        print(f"Quarantine vault — {len(entries)} entr"
              f"{'y' if len(entries) == 1 else 'ies'}:")
        for entry in entries:
            severity = (entry.severity or "unknown").capitalize()
            print(f"\n  {entry.id[:12]}…  [{entry.status.upper()}] "
                  f"{entry.original_path}")
            print(f"    Caught: {entry.detection_name} "
                  f"(severity: {severity}, verdict: {entry.verdict})")
            print(f"    Taken: {entry.quarantined_at}  "
                  f"Size: {entry.size} bytes")
            for reason in entry.reasons:
                print(f"    Why: {reason}")
            print(f"    Full id: {entry.id}")
        return EXIT_CLEAN
    finally:
        vault.close()


def _quarantine_list_from_view(args: argparse.Namespace) -> int:
    """Quarantine list when the vault itself is not readable by
    this process: the service-published snapshot is the source."""
    entries = _view_entry_dicts()
    if args.status:
        entries = [e for e in entries if e.get("status") == args.status]
    if args.json:
        print(json.dumps(entries, indent=2))
        return EXIT_CLEAN
    if not entries:
        print("The quarantine vault is empty (per the protection "
              "service's snapshot).")
        return EXIT_CLEAN
    print("Quarantine vault (from the protection service's snapshot — "
          "this account cannot open the vault directly):")
    for entry in entries:
        print(f"\n  {str(entry.get('id', ''))[:12]}…  "
              f"[{str(entry.get('status', '')).upper()}] "
              f"{entry.get('original_path')}")
        print(f"    Caught: {entry.get('detection_name')} "
              f"(severity: {entry.get('severity')}, "
              f"verdict: {entry.get('verdict')})")
        print(f"    Full id: {entry.get('id')}")
    return EXIT_CLEAN


def _cmd_quarantine_restore(args: argparse.Namespace) -> int:
    try:
        vault = _open_vault(args, load_config(args))
    except PermissionError:
        entry, details, error_exit = _service_entry_details(args.id)
        if entry is None:
            print(f"Error: no vault entry matches '{args.id}'.", file=sys.stderr)
            return EXIT_ERROR
        if error_exit is not None:
            return error_exit
        if details is not None:
            print(
                "The protection service reports: "
                f"{details['original_path']} "
                f"(detection: {details.get('detection_name') or '—'})."
            )
            return _via_service(
                "restore",
                entry_id=details["entry_id"],
                sha256=details["sha256"],
            )
        return _via_service(
            "restore", entry_id=entry["id"], sha256=entry.get("sha256")
        )
    try:
        entry = _find_entry(vault, args.id)
        if entry is None:
            print(f"Error: no vault entry matches '{args.id}'.", file=sys.stderr)
            return EXIT_ERROR
        restored = vault.restore(entry.id)
        print(f"Restored: {entry.original_path} -> {restored}")
        print("The file is back where it was (or next to it, if "
              "something new took its place — Argus never overwrites).")
        return EXIT_CLEAN
    except QuarantineError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        vault.close()


def _cmd_quarantine_delete(args: argparse.Namespace) -> int:
    try:
        vault = _open_vault(args, load_config(args))
    except PermissionError:
        entry, details, error_exit = _service_entry_details(args.id)
        if entry is None:
            print(f"Error: no vault entry matches '{args.id}'.", file=sys.stderr)
            return EXIT_ERROR
        if error_exit is not None:
            return error_exit
        shown_path = (
            details["original_path"] if details is not None
            else entry.get("original_path")
        )
        if details is not None:
            print(
                "The protection service reports: "
                f"{shown_path} "
                f"(detection: {details.get('detection_name') or '—'})."
            )
        if not _confirm(
            f"Permanently delete {shown_path} from the "
            "vault? This cannot be undone. [y/N] ",
            args.yes,
        ):
            print("Left as it is — still safe in the vault.")
            return EXIT_CLEAN
        return _via_service(
            "delete",
            entry_id=details["entry_id"] if details is not None else entry["id"],
            sha256=details["sha256"] if details is not None else entry.get("sha256"),
        )
    try:
        entry = _find_entry(vault, args.id)
        if entry is None:
            print(f"Error: no vault entry matches '{args.id}'.", file=sys.stderr)
            return EXIT_ERROR
        if not _confirm(
            f"Permanently delete {entry.original_path} from the vault? "
            "This cannot be undone. [y/N] ",
            args.yes,
        ):
            print("Left as it is — still safe in the vault.")
            return EXIT_CLEAN
        vault.delete_permanent(entry.id)
        print(f"Permanently deleted: {entry.original_path}")
        print("The vault keeps a record that it was here and why; "
              "the file itself is gone.")
        return EXIT_CLEAN
    except QuarantineError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        vault.close()


def _cmd_quarantine_allow(args: argparse.Namespace) -> int:
    config = load_config(args)
    try:
        vault = _open_vault(args, config)
    except PermissionError:
        entry, details, error_exit = _service_entry_details(args.id)
        if entry is None:
            print(f"Error: no vault entry matches '{args.id}'.", file=sys.stderr)
            return EXIT_ERROR
        if error_exit is not None:
            return error_exit
        shown_path = (
            details["original_path"] if details is not None
            else entry.get("original_path")
        )
        if details is not None:
            print(
                "The protection service reports: "
                f"{shown_path} "
                f"(detection: {details.get('detection_name') or '—'})."
            )
        if not _confirm(
            f"Vouch for {shown_path}? Argus will restore "
            "it and leave this exact file alone from now on. [y/N] ",
            args.yes,
        ):
            print("Left as it is — still in the vault.")
            return EXIT_CLEAN
        return _via_service(
            "allow",
            entry_id=details["entry_id"] if details is not None else entry["id"],
            sha256=details["sha256"] if details is not None else entry.get("sha256"),
        )
    history = History.open(_resolve_history_db(args, config))
    try:
        entry = _find_entry(vault, args.id)
        if entry is None:
            print(f"Error: no vault entry matches '{args.id}'.", file=sys.stderr)
            return EXIT_ERROR
        if not _confirm(
            f"Vouch for {entry.original_path}? Argus will restore it "
            "and leave this exact file alone from now on. [y/N] ",
            args.yes,
        ):
            print("Left as it is — still in the vault.")
            return EXIT_CLEAN
        engine = ActionEngine(
            vault, config,
            config_path=str(resolve_config_path(args)), history=history,
        )
        outcome = engine.allow_entry(entry.id, confirmed=True)
        print(outcome.message)
        return EXIT_CLEAN
    except (ActionError, QuarantineError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        history.close()
        vault.close()


def _cmd_pending_list(args: argparse.Namespace) -> int:
    config = load_config(args)
    try:
        vault = _open_vault(args, config)
        pending = vault.list_pending("pending")
        vault.close()
    except PermissionError:
        # This process cannot open the service-owned queue: read
        # it the loose way (directly when this process may, else
        # from the service-published pending view).
        pending = [
            p for p in _read_pending_loose(args, config)
            if p.status == "pending"
        ]
        return _print_pending_list(args, pending)
    return _print_pending_list(args, pending)


def _print_pending_list(args: argparse.Namespace, pending) -> int:
    if args.json:
        print(json.dumps([p.to_dict() for p in pending], indent=2))
        return EXIT_CLEAN
    if not pending:
        print("No actions are waiting for your decision.")
        return EXIT_CLEAN
    print(f"{len(pending)} action(s) waiting for your decision:")
    for item in pending:
        severity = (item.severity or "unknown").capitalize()
        print(f"\n  {item.id[:12]}…  {item.action.upper()} {item.path}")
        print(f"    Flagged: {item.detection_name} "
              f"(severity: {severity}, verdict: {item.verdict})")
        print(f"    Since: {item.created_at}  Source: {item.source}")
        for reason in item.reasons:
            print(f"    Why: {reason}")
        print(f"    Decide: argus pending approve {item.id[:12]}  |  "
              f"argus pending reject {item.id[:12]}")
    return EXIT_CLEAN


def _find_pending(vault: Vault, idish: str):
    exact = vault.get_pending(idish)
    if exact is not None:
        return exact
    matches = [p for p in vault.list_pending(None) if p.id.startswith(idish)]
    return matches[0] if len(matches) == 1 else None


# ----------------------------------------------------------------------
# Service request channel fallback (v1.0.4 trust split)
#
# On an installed machine the vault sits in the trusted root: this
# process may not be able to open it at all (PermissionError). The
# action is then handed to the protection service, which executes
# it against its own records — the human's confirmation happened
# here at the CLI, the service re-verifies the fingerprint.
# ----------------------------------------------------------------------
def _view_entry_dicts() -> list[dict]:
    try:
        raw = json.loads(vault_view_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [e for e in raw.get("entries", []) if isinstance(e, dict)]


def _find_view_entry(idish: str) -> dict | None:
    entries = _view_entry_dicts()
    for entry in entries:
        if entry.get("id") == idish:
            return entry
    matches = [e for e in entries if str(e.get("id", "")).startswith(idish)]
    return matches[0] if len(matches) == 1 else None


def _via_service(
    kind: str,
    *,
    entry_id: str | None = None,
    pending_id: str | None = None,
    sha256: str | None = None,
) -> int:
    result = action_requests.submit_and_wait(
        kind,
        entry_id=entry_id,
        pending_id=pending_id,
        sha256=sha256,
        requested_by="Argus CLI",
    )
    print(result.message)
    return EXIT_CLEAN if result.ok else EXIT_ERROR


def _service_entry_details(idish: str):
    """Resolve one vault entry for a via-service action, asking
    the protection service for its OWN record when the verified
    pipe is required (fix round 2, FIX 1).

    Returns ``(view_entry, service_details, error_exit)``. The
    snapshot view resolves WHICH record the typed id means; when
    the pipe is required, the service's record — never the
    unsigned view — supplies the path shown in prompts and the
    fingerprint submitted. An unobtainable service record is a
    hard stop (error_exit set, message already printed)."""
    entry = _find_view_entry(idish)
    if entry is None:
        return None, None, None
    try:
        details = action_requests.fetch_entry_details(entry["id"])
    except action_requests.PipeUnavailableError as exc:
        print(
            f"Error: {action_requests.pipe_failure_message(exc)}",
            file=sys.stderr,
        )
        return entry, None, EXIT_ERROR
    except action_requests.ServiceDetailsError as exc:
        print(
            f"Error: the protection service would not confirm "
            f"that record: {exc}",
            file=sys.stderr,
        )
        return entry, None, EXIT_ERROR
    return entry, details, None


def _service_pending_details(args, config, idish: str):
    """The pending twin of :func:`_service_entry_details`."""
    pending = _find_pending_loose(args, config, idish)
    if pending is None:
        return None, None, None
    try:
        details = action_requests.fetch_pending_details(pending.id)
    except action_requests.PipeUnavailableError as exc:
        print(
            f"Error: {action_requests.pipe_failure_message(exc)}",
            file=sys.stderr,
        )
        return pending, None, EXIT_ERROR
    except action_requests.ServiceDetailsError as exc:
        print(
            f"Error: the protection service would not confirm "
            f"that record: {exc}",
            file=sys.stderr,
        )
        return pending, None, EXIT_ERROR
    return pending, details, None


def _find_pending_loose(args, config, idish: str):
    rows = _read_pending_loose(args, config)
    for row in rows:
        if row.id == idish:
            return row
    matches = [p for p in rows if p.id.startswith(idish)]
    return matches[0] if len(matches) == 1 else None


def _cmd_pending_approve(args: argparse.Namespace) -> int:
    config = load_config(args)
    try:
        vault = _open_vault(args, config)
    except PermissionError:
        pending, details, error_exit = _service_pending_details(
            args, config, args.id
        )
        if pending is None:
            print(f"Error: no pending action matches '{args.id}'.",
                  file=sys.stderr)
            return EXIT_ERROR
        if error_exit is not None:
            return error_exit
        if details is not None:
            print(
                "The protection service reports: "
                f"{details['action']} {details['path']} "
                f"(detection: {details.get('detection_name') or '—'})."
            )
            return _via_service(
                "approve-pending",
                pending_id=details["pending_id"],
                sha256=details["sha256"],
            )
        return _via_service(
            "approve-pending", pending_id=pending.id, sha256=pending.sha256
        )
    history = History.open(_resolve_history_db(args, config))
    try:
        pending = _find_pending(vault, args.id)
        if pending is None:
            print(f"Error: no pending action matches '{args.id}'.",
                  file=sys.stderr)
            return EXIT_ERROR
        engine = ActionEngine(
            vault, config,
            config_path=str(resolve_config_path(args)), history=history,
        )
        outcome = engine.approve(pending.id)
        print(outcome.message)
        return EXIT_CLEAN
    except (ActionError, QuarantineError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        history.close()
        vault.close()


def _cmd_pending_reject(args: argparse.Namespace) -> int:
    config = load_config(args)
    try:
        vault = _open_vault(args, config)
    except PermissionError:
        pending, details, error_exit = _service_pending_details(
            args, config, args.id
        )
        if pending is None:
            print(f"Error: no pending action matches '{args.id}'.",
                  file=sys.stderr)
            return EXIT_ERROR
        if error_exit is not None:
            return error_exit
        if details is not None:
            print(
                "The protection service reports: "
                f"{details['action']} {details['path']} "
                f"(detection: {details.get('detection_name') or '—'})."
            )
            return _via_service(
                "reject-pending",
                pending_id=details["pending_id"],
                sha256=details["sha256"],
            )
        return _via_service(
            "reject-pending", pending_id=pending.id, sha256=pending.sha256
        )
    history = History.open(_resolve_history_db(args, config))
    try:
        pending = _find_pending(vault, args.id)
        if pending is None:
            print(f"Error: no pending action matches '{args.id}'.",
                  file=sys.stderr)
            return EXIT_ERROR
        engine = ActionEngine(
            vault, config,
            config_path=str(resolve_config_path(args)), history=history,
        )
        engine.reject(pending.id)
        print(f"Declined. {pending.path} is left exactly as it is.")
        return EXIT_CLEAN
    except (ActionError, QuarantineError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        history.close()
        vault.close()


def _cmd_report(args: argparse.Namespace) -> int:
    history = History.open(_resolve_history_db(args, load_config(args)))
    try:
        if args.json:
            print(json.dumps(report_dict(history, args.days), indent=2))
        else:
            print(render_text_report(history, args.days))
        return EXIT_CLEAN
    finally:
        history.close()


def _cmd_history(args: argparse.Namespace) -> int:
    history = History.open(_resolve_history_db(args, load_config(args)))
    try:
        scans = history.recent_scans(args.limit)
        detections = history.recent_detections(args.limit)
        if args.json:
            print(json.dumps({
                "scans": [s.to_dict() for s in scans],
                "detections": [d.to_dict() for d in detections],
            }, indent=2))
            return EXIT_CLEAN
        if not scans and not detections:
            print("No history yet — run a scan (argus scan <path>) or "
                  "start real-time protection (argus watch) and Argus "
                  "will start keeping notes.")
            return EXIT_CLEAN
        print("Recent scans:")
        for scan in scans:
            print(f"  #{scan.id} [{scan.kind}] {scan.started_at}  "
                  f"{scan.root or ''} — {scan.files_scanned} file(s), "
                  f"{scan.detections_count} flagged")
        if detections:
            print("\nRecent detections:")
            for det in detections:
                verdict = (det.verdict or "Flagged").upper()
                print(f"  [{verdict}] {det.path}")
                print(f"      {det.recorded_at} — action: {det.action_taken}")
        return EXIT_CLEAN
    finally:
        history.close()


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
    p_scan.add_argument("--db", default=None,
                        help="signature database path (default: "
                             f"{DEFAULT_DB_NAME} in the Argus data "
                             "folder, created and seeded on first use)")
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
    p_scan.add_argument("--quarantine", action="store_true",
                        help="move Malicious files into the quarantine "
                             "vault after the scan (your explicit action — "
                             "Argus never does this unasked)")
    p_scan.add_argument("--delete", action="store_true",
                        help="permanently delete Malicious files after "
                             "the scan, via the vault (explicit action)")
    p_scan.add_argument("--vault-dir", default=None,
                        help="quarantine vault location "
                             "(default: your Argus data folder)")
    p_scan.add_argument("--history-db", default=None,
                        help="scan history database location "
                             "(default: your Argus data folder)")
    p_scan.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of text")
    p_scan.set_defaults(func=_cmd_scan)

    p_watch = sub.add_parser(
        "watch", help="run real-time protection in the foreground")
    p_watch.add_argument("--config", default=None,
                         help="config file (default: argus-config.json "
                              "in the Argus data folder; missing file = "
                              "built-in defaults)")
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
    p_status.add_argument("--status-file", default=None,
                          help="status file to read (default: the "
                               "configured status file in the Argus "
                               "data folder)")
    p_status.add_argument("--config", default=None,
                          help="config file (default: argus-config.json "
                               "in the Argus data folder)")
    p_status.add_argument("--json", action="store_true",
                          help="print the raw status JSON")
    p_status.set_defaults(func=_cmd_watch_status)

    # ---- Phase 5: Windows service management ----
    p_service = sub.add_parser(
        "service",
        help="manage the ARGUS.EXE Windows service (Windows only)")
    p_service.add_argument(
        "service_command",
        choices=["install", "uninstall", "start", "stop", "restart",
                 "status", "run", "register", "unregister"],
        help="what to do with the service")
    p_service.add_argument("--config", default=None,
                           help="config file the service should use")
    p_service.set_defaults(func=_cmd_service)

    p_sigdb = sub.add_parser("sigdb", help="manage the signature database")
    sigsub = p_sigdb.add_subparsers(dest="sigdb_command")

    p_init = sigsub.add_parser("init", help="create a new signature database")
    p_init.add_argument("path", nargs="?", default=None,
                        help="database path (default: the configured "
                             "signature database in the Argus data folder)")
    p_init.add_argument("--config", default=None,
                        help="config file naming the default database")
    p_init.add_argument("--no-seed", action="store_true",
                        help="do not include the EICAR test signature")
    p_init.set_defaults(func=_cmd_sigdb_init)

    p_info = sigsub.add_parser("info", help="show signature database details")
    p_info.add_argument("path", nargs="?", default=None,
                        help="database path (default: the configured "
                             "signature database in the Argus data folder)")
    p_info.add_argument("--config", default=None,
                        help="config file naming the default database")
    p_info.set_defaults(func=_cmd_sigdb_info)

    # ---- Phase 4: quarantine vault ----
    p_quar = sub.add_parser(
        "quarantine", help="manage the quarantine vault")
    quarsub = p_quar.add_subparsers(dest="quarantine_command")

    p_qlist = quarsub.add_parser("list", help="list vault entries")
    p_qlist.add_argument("--status", default=None,
                         help="only show entries with this status "
                              "(quarantined, restored, deleted, allowed)")
    p_qlist.add_argument("--vault-dir", default=None,
                         help="vault location (default: Argus data folder)")
    p_qlist.add_argument("--config", default=None,
                         help="config file (default: Argus data folder)")
    p_qlist.add_argument("--json", action="store_true",
                         help="print machine-readable JSON")
    p_qlist.set_defaults(func=_cmd_quarantine_list)

    p_qrestore = quarsub.add_parser(
        "restore", help="put a quarantined file back where it was")
    p_qrestore.add_argument("id", help="entry id (or unique prefix)")
    p_qrestore.add_argument("--vault-dir", default=None,
                            help="vault location (default: Argus data folder)")
    p_qrestore.add_argument("--config", default=None,
                            help="config file (default: Argus data folder)")
    p_qrestore.set_defaults(func=_cmd_quarantine_restore)

    p_qdelete = quarsub.add_parser(
        "delete", help="permanently delete a quarantined file")
    p_qdelete.add_argument("id", help="entry id (or unique prefix)")
    p_qdelete.add_argument("--vault-dir", default=None,
                           help="vault location (default: Argus data folder)")
    p_qdelete.add_argument("--config", default=None,
                           help="config file (default: Argus data folder)")
    p_qdelete.add_argument("--yes", action="store_true",
                           help="confirm without prompting")
    p_qdelete.set_defaults(func=_cmd_quarantine_delete)

    p_qallow = quarsub.add_parser(
        "allow", help="restore a file and vouch for it (exclusion)")
    p_qallow.add_argument("id", help="entry id (or unique prefix)")
    p_qallow.add_argument("--vault-dir", default=None,
                          help="vault location (default: Argus data folder)")
    p_qallow.add_argument("--config", default=None,
                          help="config file the exclusion is saved to "
                               "(default: argus-config.json in the Argus "
                               "data folder)")
    p_qallow.add_argument("--history-db", default=None,
                          help="history database location")
    p_qallow.add_argument("--yes", action="store_true",
                          help="confirm without prompting")
    p_qallow.set_defaults(func=_cmd_quarantine_allow)

    # ---- Phase 4: pending actions ----
    p_pend = sub.add_parser(
        "pending", help="actions waiting for your decision")
    pendsub = p_pend.add_subparsers(dest="pending_command")

    p_plist = pendsub.add_parser("list", help="list pending actions")
    p_plist.add_argument("--vault-dir", default=None,
                         help="vault location (default: Argus data folder)")
    p_plist.add_argument("--config", default=None,
                         help="config file (default: Argus data folder)")
    p_plist.add_argument("--json", action="store_true",
                         help="print machine-readable JSON")
    p_plist.set_defaults(func=_cmd_pending_list)

    p_papprove = pendsub.add_parser(
        "approve", help="carry out a queued action")
    p_papprove.add_argument("id", help="pending action id (or unique prefix)")
    p_papprove.add_argument("--vault-dir", default=None,
                            help="vault location (default: Argus data folder)")
    p_papprove.add_argument("--config", default=None,
                            help="config file (for context + exclusions)")
    p_papprove.add_argument("--history-db", default=None,
                            help="history database location")
    p_papprove.set_defaults(func=_cmd_pending_approve)

    p_preject = pendsub.add_parser(
        "reject", help="decline a queued action (file left as it is)")
    p_preject.add_argument("id", help="pending action id (or unique prefix)")
    p_preject.add_argument("--vault-dir", default=None,
                           help="vault location (default: Argus data folder)")
    p_preject.add_argument("--config", default=None,
                           help="config file (for context)")
    p_preject.add_argument("--history-db", default=None,
                           help="history database location")
    p_preject.set_defaults(func=_cmd_pending_reject)

    # ---- Phase 4: reporting ----
    p_report = sub.add_parser(
        "report", help="plain-language report of Argus activity")
    p_report.add_argument("--days", type=int, default=7,
                          help="how far back to look (default: 7 days)")
    p_report.add_argument("--history-db", default=None,
                          help="history database location")
    p_report.add_argument("--config", default=None,
                          help="config file (default: Argus data folder)")
    p_report.add_argument("--json", action="store_true",
                          help="print machine-readable JSON")
    p_report.set_defaults(func=_cmd_report)

    p_history = sub.add_parser(
        "history", help="recent scans and detections")
    p_history.add_argument("--limit", type=int, default=20,
                           help="how many entries to show (default: 20)")
    p_history.add_argument("--history-db", default=None,
                           help="history database location")
    p_history.add_argument("--config", default=None,
                           help="config file (default: Argus data folder)")
    p_history.add_argument("--json", action="store_true",
                           help="print machine-readable JSON")
    p_history.set_defaults(func=_cmd_history)

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
