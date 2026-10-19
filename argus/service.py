"""Service core for ARGUS.EXE real-time protection.

:class:`ArgusService` is the daemon-shaped heart of Argus: it owns the
configuration, the signature database, and the real-time engine, and
it publishes a JSON **heartbeat/status file** so anything else — the
CLI today, the tray app and GUI in Phase 5 — can see at a glance
whether protection is on and what it has been doing.

It is deliberately *not* a Windows service yet. Phase 5 wraps this
exact class in a pywin32 service host (``win32serviceutil``) so Argus
can start at boot before anyone logs in; everything the wrapper needs
— start, stop, pause, resume, config reload, status — already lives
here and is testable without Windows.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__, pipe_channel
from .action_requests import PRIVILEGED_KINDS, REQUEST_KINDS
from .actions import ActionEngine, ActionError
from .config import ArgusConfig, default_watch_dirs
from .paths import (
    default_history_db,
    default_pending_db,
    default_vault_dir,
    legacy_shared_pending_db,
    pending_view_path,
    requests_dir,
    results_dir,
    vault_view_path,
    write_text_atomic,
)
from .quarantine import QuarantineError, Vault, read_pending_db
from .scanner import hash_file
from .realtime import RealtimeEngine, RealtimeEvent
from .reporting import History
from .rules import BUILTIN_RULES, Rule, load_rules
from .signatures import SignatureDB, SignatureError, bootstrap_signature_db

log = logging.getLogger("argus.service")

#: How often the service scans the shared requests folder for
#: GUI/CLI action requests (restore/delete/allow/approve/reject).
REQUEST_POLL_INTERVAL_SECONDS = 2.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat(timespec="seconds")


def _same_path(a: str | None, b: str | None) -> bool:
    """Spelling-insensitive path equality: expanded, normalised,
    platform case-folded. Used where two records of the SAME
    file's path must agree (legacy-migration binding) — the file
    itself is usually gone (quarantined), so this is a string
    comparison, never a filesystem resolution."""

    def _norm(value: str) -> str:
        return os.path.normcase(
            os.path.normpath(
                os.path.expandvars(os.path.expanduser(value))
            )
        )

    return bool(a) and bool(b) and _norm(a) == _norm(b)


class ArgusService:
    """Owns config + engine; start/stop/pause/resume/reload/status."""

    def __init__(
        self,
        config_path: Path | str | None = None,
        *,
        config: ArgusConfig | None = None,
        on_event: Callable[[RealtimeEvent], None] | None = None,
        pipe_identity_provider=None,
        pipe_canonical_exe: Path | str | None = None,
        pipe_recorded_sha256: str | None = None,
        pipe_required: bool | None = None,
        serve_pipe: bool | None = None,
    ) -> None:
        self.config_path = Path(config_path) if config_path else None
        self._config_override = config
        self.on_event = on_event
        # Verified-pipe seams (fix round 2, FIX 1): injectable so
        # the channel's caller verification is testable off-Windows.
        # None = production resolution (Windows identity provider,
        # the canonical install path, the fingerprint setup
        # recorded; pipe required exactly when the layout says so;
        # the pipe is served on Windows).
        self._pipe_identity_provider = pipe_identity_provider
        self._pipe_canonical_exe = pipe_canonical_exe
        self._pipe_recorded_sha256 = pipe_recorded_sha256
        self._pipe_required = pipe_required
        self._serve_pipe = serve_pipe
        self._pipe_server: pipe_channel.WindowsPipeServer | None = None
        #: Pending rows the one-time legacy migration dropped as
        #: unverifiable (fix round 2, FIX 2) — published in status
        #: so the GUI can show its one-time notice.
        self._legacy_pending_dropped = 0
        self._last_results_prune = 0.0
        self.config: ArgusConfig = config or ArgusConfig()
        self.engine: RealtimeEngine | None = None
        self.vault: Vault | None = None
        self.history: History | None = None
        self.actions: ActionEngine | None = None
        self._db: SignatureDB | None = None
        self._stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._requests_thread: threading.Thread | None = None
        self._started_at: datetime | None = None
        self.state: str = "stopped"  # stopped | running | paused
        self.last_error: str | None = None
        #: True when the open signature database carries no
        #: verifiable HMAC auth tag — surfaced in status, loudly.
        self._sig_auth_missing = False
        #: Fingerprint of the last published vault view, so the
        #: view is only rewritten when the vault actually changed.
        self._vault_view_fingerprint: tuple | None = None
        self._pending_view_fingerprint: tuple | None = None
        #: Serializes request execution against stop()/reload_config
        #: swap sections (P2): an action must never execute against
        #: a half-closed stack.
        self._execution_lock = threading.Lock()
        #: Cumulative counters carried across config reloads.
        self._carried = {
            "scans_completed": 0,
            "detections": 0,
            "actions_emitted": 0,
            "files_excluded": 0,
            "files_oversized": 0,
            "scan_errors": 0,
            "processes_seen": 0,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Load config (unless overridden), open the DB, start the engine.

        A *missing* signature database is created and seeded on the
        spot — a fresh install must come up protected, not fail on a
        file nobody built yet. A database that exists but fails
        verification raises :class:`SignatureError`: protection that
        cannot verify its signatures must say so, not pretend. If
        anything fails partway, whatever was opened is closed again —
        a failed start leaves nothing half-open behind.
        """
        if self.state in ("running", "paused"):
            return
        if self._config_override is None:
            self.config = ArgusConfig.load(self.config_path)
        for warning in self.config.load_warnings:
            log.warning("config: %s", warning)
        self._apply_system_watch_dirs()

        try:
            stack = self._open_stack()
        except Exception as exc:
            self.last_error = str(exc)
            raise
        try:
            stack[4].start()
        except Exception as exc:
            self._close_stack(stack)
            self.last_error = str(exc)
            raise
        self._db, self.vault, self.history, self.actions, self.engine = stack
        self._note_signature_auth(self._db)
        self._started_at = _utcnow()
        self.state = "running"
        self.last_error = None
        self._stop.clear()
        if self._heartbeat_thread is None or not self._heartbeat_thread.is_alive():
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop, name="argus-heartbeat", daemon=True
            )
            self._heartbeat_thread.start()
        if self._requests_thread is None or not self._requests_thread.is_alive():
            self._requests_thread = threading.Thread(
                target=self._requests_loop, name="argus-requests", daemon=True
            )
            self._requests_thread.start()
        self._start_pipe_server()
        self._prune_old_results()
        self._publish_vault_view(force=True)
        self._publish_pending_view(force=True)
        self.write_status()
        log.info("Argus service started (config: %s)", self.config_path or "defaults")

    def stop(self) -> None:
        if self.state == "stopped":
            return
        self._stop.set()
        # The pipe stops accepting first; an in-flight verified
        # session either finishes or finds the stack closing and
        # is refused — it never executes against a half-closed
        # stack, because execution holds the same lock as teardown.
        self._stop_pipe_server()
        # Drain (P2): holding the execution lock while the stack is
        # torn down means any in-flight request execution finishes
        # (or no new one starts) before anything is closed — an
        # action never runs against a half-closed stack.
        with self._execution_lock:
            if self.engine is not None:
                self._fold_engine_stats()
                self.engine.stop()
                self.engine = None
            self.actions = None
            if self.history is not None:
                self.history.close()
                self.history = None
            if self.vault is not None:
                self.vault.close()
                self.vault = None
            if self._db is not None:
                self._db.close()
                self._db = None
            self.state = "stopped"
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2.0)
            self._heartbeat_thread = None
        if self._requests_thread is not None:
            self._requests_thread.join(timeout=2.0)
            self._requests_thread = None
        # Final status is written AFTER the engine has stopped, via
        # the shared atomic writer on the configured path.
        self.write_status()
        log.info("Argus service stopped")

    def pause(self) -> None:
        if self.state != "running" or self.engine is None:
            return
        self.engine.pause()
        self.state = "paused"
        self.write_status()

    def resume(self) -> None:
        if self.state != "paused" or self.engine is None:
            return
        self.engine.resume()
        self.state = "running"
        self.write_status()

    def reload_config(self) -> None:
        """Serialized wrapper: the swap never races request execution."""
        with self._execution_lock:
            self._reload_config_impl()

    def _reload_config_impl(self) -> None:
        """Re-read the config file and restart the engine with it.

        Counters are carried over so the heartbeat keeps a truthful
        running total for the session. If no config path is set (pure
        defaults), reload simply re-applies the current config.

        Fail-safe: the replacement stack (config, signature DB,
        vault, history, engine) is fully opened and validated BEFORE
        the running engine is touched. If the new setup cannot be
        opened — a corrupt database, an unreadable vault — the old
        engine keeps running untouched, the failure is logged and
        recorded in ``last_error``, and the old configuration stays
        in force.
        """
        was_running = self.state in ("running", "paused")
        if not was_running:
            if self._config_override is None:
                self.config = ArgusConfig.load(self.config_path)
            return
        was_paused = self.state == "paused"
        old_config = self.config
        if self._config_override is None:
            new_config = ArgusConfig.load(self.config_path)
            for warning in new_config.load_warnings:
                log.warning("config: %s", warning)
        else:
            new_config = self._config_override
        # _open_stack reads self.config — point it at the candidate
        # while validating, and restore it if validation fails.
        self.config = new_config
        try:
            stack = self._open_stack()
        except Exception as exc:
            self.config = old_config
            self.last_error = (
                f"configuration reload failed — the previous setup "
                f"is still protecting you: {exc}"
            )
            log.error("%s", self.last_error)
            return
        # The new stack validates. Commit: fold the old engine's
        # counters in, stop it, close its resources, swap, start.
        if self.engine is not None:
            self._fold_engine_stats()
            self.engine.stop()
            self.engine = None
        self.actions = None
        if self.history is not None:
            self.history.close()
            self.history = None
        if self.vault is not None:
            self.vault.close()
            self.vault = None
        if self._db is not None:
            self._db.close()
            self._db = None
        self._db, self.vault, self.history, self.actions, self.engine = stack
        self._note_signature_auth(self._db)
        try:
            self.engine.start()
        except Exception as exc:
            # The new stack validated but its engine will not start.
            # Do not leave the machine unprotected if the PREVIOUS
            # setup can still run: reopen it and start it again.
            self._close_stack(stack)
            self.engine = None
            log.error(
                "reloaded configuration failed to start (%s) — "
                "attempting to restore the previous setup", exc,
            )
            self.config = old_config
            try:
                previous = self._open_stack()
                previous[4].start()
            except Exception:
                self.state = "stopped"
                self.last_error = (
                    f"configuration reload failed ({exc}) and the "
                    "previous setup could not be restarted either — "
                    "protection is OFF until this is fixed"
                )
                log.error("%s", self.last_error)
                raise
            self._db, self.vault, self.history, self.actions, self.engine = (
                previous
            )
            self._note_signature_auth(self._db)
            self._started_at = _utcnow()
            self.state = "paused" if was_paused else "running"
            if was_paused:
                self.engine.pause()
            self.last_error = (
                f"configuration reload failed to start ({exc}) — the "
                "previous setup was restored and is protecting you"
            )
            log.error("%s", self.last_error)
            self.write_status()
            return
        self._started_at = _utcnow()
        if was_paused:
            self.engine.pause()
            self.state = "paused"
        else:
            self.state = "running"
        self.last_error = None
        self.write_status()
        log.info("Argus service configuration reloaded")

    def run_forever(self, stop_event: threading.Event | None = None) -> None:
        """Start and block until *stop_event* (or this service's own
        stop signal) fires, then shut down cleanly. Signal handling is
        installed by the caller (the CLI) — services and tests drive
        the event directly."""
        self.start()
        waiter = stop_event or self._stop
        try:
            while not waiter.is_set() and not self._stop.is_set():
                waiter.wait(0.25)
        finally:
            self.stop()

    # ------------------------------------------------------------------
    # Event dispatch: action policy first, then the caller's callback
    # ------------------------------------------------------------------
    def _dispatch_event(self, event: RealtimeEvent) -> None:
        """Route engine events through the Phase 4 action layer
        (history recording, pending queue, policy), then hand the
        event to the user's own callback. Action-layer failures are
        logged loudly and never take protection down."""
        if self.actions is not None:
            try:
                outcome = self.actions.handle_realtime_event(event)
            except Exception:
                log.exception("action layer failed on a real-time event")
                outcome = None
            if outcome is not None:
                log.info("real-time action: %s", outcome.message)
                # The queue and/or vault may have changed — republish
                # the read-only views the GUI reads (fingerprinted,
                # so an unchanged view is not rewritten).
                self._publish_pending_view()
                if outcome.done:
                    self._publish_vault_view()
        if self.on_event is not None:
            self.on_event(event)

    # ------------------------------------------------------------------
    # Status / heartbeat
    # ------------------------------------------------------------------
    def status(self) -> dict:
        """A snapshot suitable for JSON: is Argus on, since when, and
        what has it done."""
        engine_stats = (
            self.engine.status_snapshot()
            if self.engine is not None
            else {"files_watched": 0}
        )
        totals = dict(self._carried)
        for key in totals:
            totals[key] += engine_stats.get(key, 0)
        uptime = None
        if self._started_at is not None and self.state != "stopped":
            uptime = int((_utcnow() - self._started_at).total_seconds())
        return {
            "product": "ARGUS.EXE",
            "vendor": "Sentinel Safeguard LLC",
            "version": __version__,
            "state": self.state,
            "running": self.state in ("running", "paused"),
            "paused": self.state == "paused",
            "started_at": self._started_at.isoformat(timespec="seconds")
            if self._started_at
            else None,
            "heartbeat_at": _utcnow_iso(),
            "uptime_seconds": uptime,
            "watch_dirs": [str(d) for d in self.config.watch_dirs],
            "process_monitor_enabled": self.config.process_monitor_enabled,
            "realtime_default": self.config.realtime_default,
            "files_watched": engine_stats.get("files_watched", 0),
            "quarantined_files": (
                self.vault.count("quarantined") if self.vault is not None else 0
            ),
            "pending_actions": (
                self.vault.pending_count() if self.vault is not None else 0
            ),
            "signature_db_auth": (
                "verified"
                if self._db is not None and self._db.info.auth_verified
                else "missing" if self._sig_auth_missing else "unknown"
            ),
            "legacy_pending_dropped": self._legacy_pending_dropped,
            **totals,
            "last_error": self.last_error,
        }

    def write_status(self) -> None:
        """Write the status file atomically on the CONFIGURED
        status_file path (via paths.write_text_atomic), so a reader
        never sees a half-written heartbeat. Also republishes the
        vault / pending views when they changed."""
        self._publish_vault_view()
        self._publish_pending_view()
        status_path = Path(self.config.status_file)
        try:
            write_text_atomic(
                status_path, json.dumps(self.status(), indent=2) + "\n"
            )
        except OSError:
            log.exception("could not write status file %s", status_path)

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.config.heartbeat_interval)
            if self._stop.is_set():
                break
            self.write_status()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _open_stack(self):
        """Open and validate every resource a running service needs,
        WITHOUT starting the engine: the signature database
        (bootstrapped first if the DEFAULT one is missing — a
        missing database at a *configured* path is a loud error,
        never silently replaced), the rules, the vault, the
        history, and the action engine wired to all of them.

        The signature database is opened with ``require_auth=True``:
        a present-but-wrong HMAC tag fails the open; a missing tag
        or key is recorded (see :meth:`_note_signature_auth`) and
        warned about in status without bricking protection.

        Returns ``(db, vault, history, actions, engine)``. On any
        failure, whatever was already opened is closed again and the
        exception propagates — callers never see a half-open stack.
        """
        bootstrap_signature_db(self.config.signature_db)
        db = None
        vault = None
        history = None
        try:
            db = SignatureDB.open(self.config.signature_db, require_auth=True)
            rules = self._load_rules()
            # Phase 4 wiring: the vault, history, and action engine
            # are opened BEFORE the engine starts, so every real-time
            # event is routed through the action policy from the
            # first second.
            vault_dir = (
                Path(self.config.vault_dir)
                if self.config.vault_dir
                else default_vault_dir()
            )
            history_path = (
                Path(self.config.history_db)
                if self.config.history_db
                else default_history_db()
            )
            pending_path = (
                Path(self.config.pending_db)
                if self.config.pending_db
                else default_pending_db()
            )
            vault = Vault.open(vault_dir, pending_path)
            self._migrate_legacy_pending(vault)
            history = History.open(history_path)
            actions = ActionEngine(
                vault,
                self.config,
                config_path=self.config_path,
                history=history,
            )
            engine = RealtimeEngine(
                self.config, db, rules, on_event=self._dispatch_event
            )
        except Exception:
            for resource in (history, vault, db):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        log.exception("cleanup after a failed open failed")
            raise
        return (db, vault, history, actions, engine)

    def _note_signature_auth(self, db: SignatureDB | None) -> None:
        """Record (and loudly log) whether the open signature
        database could be authenticated."""
        self._sig_auth_missing = bool(
            db is not None and db.info.auth_missing and not db.info.auth_verified
        )
        if self._sig_auth_missing:
            log.warning(
                "SIGNATURE DATABASE IS NOT AUTHENTICATED: %s carries no "
                "verifiable HMAC tag (missing tag or key file). Argus "
                "will keep protecting you, but the database cannot be "
                "proven genuine — rebuild it with 'argus sigdb init' "
                "from a trusted copy to restore authentication.",
                self.config.signature_db,
            )

    def _apply_system_watch_dirs(self) -> None:
        """When the service runs as LocalSystem on Windows, the
        process "home" is the system profile — the default watch
        list (that profile's Downloads/Desktop/Documents) would
        watch folders no user ever touches. Substitute every real
        user profile's Downloads/Desktop/Documents plus
        ``C:\\Windows\\Temp``. Only applies when the configured
        watch list IS the untouched default; an explicit list in
        the config always wins.
        """
        if sys.platform != "win32":
            return
        if "systemprofile" not in str(Path.home()).lower():
            return
        if [str(d) for d in self.config.watch_dirs] != [
            str(d) for d in default_watch_dirs()
        ]:
            return
        dirs: list[Path] = []
        users_root = Path(r"C:\Users")
        try:
            profiles = sorted(users_root.iterdir())
        except OSError:
            profiles = []
        for profile in profiles:
            if not profile.is_dir() or profile.name.lower() in (
                "public", "default", "default user", "all users",
            ):
                continue
            for sub in ("Downloads", "Desktop", "Documents"):
                candidate = profile / sub
                if candidate.is_dir():
                    dirs.append(candidate)
        windows_temp = Path(r"C:\Windows\Temp")
        if windows_temp.is_dir():
            dirs.append(windows_temp)
        if dirs:
            self.config.watch_dirs = dirs
            log.info(
                "running as SYSTEM: watching user profile folders %s",
                [str(d) for d in dirs],
            )

    # ------------------------------------------------------------------
    # Vault view (read-only snapshot for user-side processes)
    # ------------------------------------------------------------------
    def _publish_vault_view(self, *, force: bool = False) -> None:
        """Republish ``shared/vault-view.json`` when the vault
        changed: the standard-user GUI cannot read the vault in the
        trusted root, so the service mirrors the entry list (never
        blobs, never the key) into the shared folder. Best-effort —
        a failed publish is logged, never fatal."""
        if self.vault is None:
            return
        try:
            entries = self.vault.list_entries()
        except Exception:
            log.exception("could not read the vault for the view publish")
            return
        fingerprint = tuple(
            (e.id, e.status, e.resolved_at, e.note) for e in entries
        )
        if not force and fingerprint == self._vault_view_fingerprint:
            return
        payload = {
            "generated_at": _utcnow_iso(),
            "entries": [entry.to_dict() for entry in entries],
        }
        try:
            write_text_atomic(
                vault_view_path(), json.dumps(payload, indent=2) + "\n"
            )
            self._vault_view_fingerprint = fingerprint
        except OSError:
            log.exception("could not publish the vault view")

    # ------------------------------------------------------------------
    # Pending view + legacy pending migration (P0-1)
    # ------------------------------------------------------------------
    def _publish_pending_view(self, *, force: bool = False) -> None:
        """Republish ``shared/pending-view.json`` when the queue
        changed: user-side processes read the queue from this
        snapshot, never from the service-owned database itself."""
        if self.vault is None:
            return
        try:
            pending = self.vault.list_pending(None)
        except Exception:
            log.exception("could not read the pending queue for the view publish")
            return
        fingerprint = tuple(
            (p.id, p.status, p.entry_id, p.error) for p in pending
        )
        if not force and fingerprint == self._pending_view_fingerprint:
            return
        payload = {
            "generated_at": _utcnow_iso(),
            "pending": [p.to_dict() for p in pending],
        }
        try:
            write_text_atomic(
                pending_view_path(), json.dumps(payload, indent=2) + "\n"
            )
            self._pending_view_fingerprint = fingerprint
        except OSError:
            log.exception("could not publish the pending view")

    def _migration_marker_path(self, vault: Vault) -> Path:
        """The one-time gate for the legacy migration: a marker in
        the trusted root beside the service-owned pending
        database. Its presence means the migration already ran;
        its payload records how many rows were dropped."""
        return (
            Path(vault.pending_path).parent
            / "legacy-pending-migration.json"
        )

    def _migrate_legacy_pending(self, vault: Vault) -> None:
        """One-time, service-side migration of the legacy SHARED
        pending database into the trusted queue — provenance or
        nothing (fix round 2, FIX 2).

        A row migrates ONLY when it is bound to a vault entry
        whose blob decrypts under the vault key to content
        hashing exactly to the row's sha256
        (:meth:`Vault.entry_content_matches`) AND whose recorded
        original path IS the row's path (fix round 3) —
        provenance anchored in vault records and cryptography
        only the service could have produced. The path binding
        matters because provenance otherwise covers only
        (entry, fingerprint): a fabricated row could borrow a
        real entry's identity while naming an arbitrary victim
        path and attacker-authored action text. Such a row
        could never have executed (approval re-binds the live
        file at the row's path to the row's fingerprint), but a
        fabricated queue item should not exist at all. The original pass's second
        leg ("the live file at the row's path hashes to the row's
        sha256") is GONE: anyone can hash any file, so it proved
        nothing — a fabricated row (an arbitrary victim's path
        plus the victim's real hash) rode it into the trusted
        queue, and one approval later the service deleted the
        victim.

        Non-entry rows are DROPPED: counted (published in status
        as ``legacy_pending_dropped``; the GUI shows a one-time
        notice from it) and logged loudly. The pass runs ONCE per
        install, gated by the marker file; config reloads never
        re-run it. The legacy database is read from a snapshot
        copy (WAL sidecars included) so a crash-stranded queue
        cannot corrupt the read or silently lose entry-bound
        rows to a hot WAL.
        """
        try:
            marker = self._migration_marker_path(vault)
            if marker.is_file():
                try:
                    recorded = json.loads(
                        marker.read_text(encoding="utf-8")
                    )
                    self._legacy_pending_dropped = int(
                        recorded.get("dropped", 0)
                    )
                except (OSError, ValueError, TypeError, AttributeError):
                    self._legacy_pending_dropped = 0
                return
            kept = dropped = 0
            legacy = legacy_shared_pending_db()
            same_file = False
            if legacy.is_file():
                try:
                    same_file = legacy.resolve() == Path(
                        vault.pending_path
                    ).resolve()
                except OSError:
                    same_file = False
            if legacy.is_file() and not same_file:
                rows = self._read_legacy_pending_snapshot(legacy)
                for row in rows:
                    entry = (
                        vault.verified_entry(row.entry_id)
                        if row.entry_id
                        else None
                    )
                    if (
                        entry is not None
                        and vault.entry_content_matches(
                            row.entry_id, row.sha256 or ""
                        )
                        and _same_path(row.path, entry.original_path)
                    ):
                        try:
                            vault.import_pending(row)
                        except QuarantineError:
                            # Already in the trusted queue (a
                            # previous pass wrote it but its
                            # marker write failed) — that IS the
                            # migrated state, not a drop.
                            log.info(
                                "legacy pending row %s is already "
                                "in the trusted queue", row.id,
                            )
                        kept += 1
                    else:
                        dropped += 1
                        log.error(
                            "LEGACY PENDING ROW DROPPED: id=%s "
                            "path=%s — it is not fully bound to a "
                            "verifiable vault entry (the entry "
                            "must exist, its content must match "
                            "the row's fingerprint, and the row's "
                            "path must be the entry's own original "
                            "path), so it was NOT migrated into "
                            "the trusted queue.",
                            row.id, row.path,
                        )
                try:
                    legacy.rename(
                        legacy.with_name(legacy.name + ".migrated")
                    )
                except OSError:
                    log.exception(
                        "legacy pending migration processed %d "
                        "row(s) but could not rename %s away",
                        kept + dropped, legacy,
                    )
            self._legacy_pending_dropped = dropped
            try:
                marker.parent.mkdir(parents=True, exist_ok=True)
                write_text_atomic(
                    marker,
                    json.dumps(
                        {
                            "kept": kept,
                            "dropped": dropped,
                            "migrated_at": _utcnow_iso(),
                        },
                        indent=2,
                    )
                    + "\n",
                )
            except OSError:
                log.exception(
                    "could not write the legacy-migration marker; "
                    "imported rows are id-keyed, so a re-run at the "
                    "next start is harmless"
                )
            if kept or dropped:
                log.warning(
                    "LEGACY PENDING MIGRATION: %d row(s) migrated "
                    "into the trusted queue; %d row(s) DROPPED as "
                    "unverifiable (gone from the queue; the files "
                    "they named were never touched).",
                    kept, dropped,
                )
        except Exception:
            log.exception("legacy pending migration failed")

    @staticmethod
    def _read_legacy_pending_snapshot(legacy: Path) -> list:
        """Read legacy pending rows from a private snapshot copy
        (database + WAL/SHM sidecars), so a crash-stranded hot
        WAL is honoured instead of silently losing its rows."""
        tmpdir = Path(tempfile.mkdtemp(prefix="argus-legacy-pending-"))
        try:
            snapshot = tmpdir / legacy.name
            shutil.copy2(legacy, snapshot)
            for suffix in ("-wal", "-shm"):
                sidecar = legacy.with_name(legacy.name + suffix)
                if sidecar.is_file():
                    shutil.copy2(
                        sidecar, tmpdir / (legacy.name + suffix)
                    )
            return read_pending_db(snapshot)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Action-request channel (see argus.action_requests)
    # ------------------------------------------------------------------
    def _requests_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.process_requests_once()
                now = time.monotonic()
                if now - self._last_results_prune >= 3600.0:
                    self._last_results_prune = now
                    self._prune_old_results()
            except Exception:
                log.exception("action-request scan failed")
            self._stop.wait(REQUEST_POLL_INTERVAL_SECONDS)

    #: Result files older than this are garbage (fix round 2):
    #: a result matters only until its caller has read it.
    _RESULTS_RETENTION_SECONDS = 24 * 3600

    def _prune_old_results(self) -> None:
        """Delete spent action-request results older than 24h
        (fix round 2, FIX 6): without this, every action anyone
        ever took leaves a permanent file — with the caller's
        nonce in it — in the shared results folder forever."""
        try:
            folder = results_dir()
            cutoff = time.time() - self._RESULTS_RETENTION_SECONDS
            for result_path in folder.glob("*.json"):
                try:
                    if result_path.stat().st_mtime < cutoff:
                        result_path.unlink(missing_ok=True)
                except OSError:
                    continue
        except OSError:
            pass

    #: Requests larger than this are rejected unread (channel P2).
    _MAX_REQUEST_BYTES = 64 * 1024

    def _reject_request(self, request_path: Path, reason: str) -> None:
        """Move a bad request to requests/rejected/ with a logged
        reason (unlinking when the move itself fails) — never a
        silent drop, and never a reason to starve the batch."""
        log.warning("rejecting action request %s: %s", request_path, reason)
        try:
            rejected_dir = request_path.parent / "rejected"
            rejected_dir.mkdir(parents=True, exist_ok=True)
            request_path.replace(rejected_dir / request_path.name)
        except OSError:
            try:
                request_path.unlink(missing_ok=True)
            except OSError:
                log.exception("could not dispose of rejected request %s", request_path)

    def process_requests_once(self) -> int:
        """Execute every pending action request once. Returns how
        many were processed. Public so tests (and a future admin
        tool) can drive the channel without the polling thread.

        Per-file isolation: a directory named ``*.json``, an
        oversized file, malformed JSON, an id mismatch, or an
        unknown kind lands in ``requests/rejected/`` and NEVER
        starves the rest of the batch. Ordering: a result is
        written BEFORE its request file is removed. Restart
        safety: a request whose result already exists is removed
        WITHOUT re-execution.
        """
        folder = requests_dir()
        try:
            candidates = sorted(folder.glob("*.json"))
        except OSError:
            return 0
        processed = 0
        for request_path in candidates:
            try:
                # Restart safety first: the result is the record
                # that this request was already executed.
                if (results_dir() / f"{request_path.stem}.json").exists():
                    request_path.unlink(missing_ok=True)
                    processed += 1
                    continue
                if request_path.is_dir():
                    self._reject_request(
                        request_path, "it is a directory, not a request file"
                    )
                    continue
                try:
                    size = request_path.stat().st_size
                except OSError as exc:
                    self._reject_request(request_path, f"it cannot be read: {exc}")
                    continue
                if size > self._MAX_REQUEST_BYTES:
                    self._reject_request(
                        request_path,
                        f"it is {size} bytes, over the 64 KB request limit",
                    )
                    continue
                try:
                    raw = json.loads(request_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    self._reject_request(
                        request_path, f"it is not readable JSON: {exc}"
                    )
                    continue
                if not isinstance(raw, dict) or raw.get("id") != request_path.stem:
                    self._reject_request(
                        request_path,
                        "its id does not match its file name, or it is not an object",
                    )
                    continue
                if raw.get("kind") not in REQUEST_KINDS:
                    self._reject_request(
                        request_path, f"unknown request kind {raw.get('kind')!r}"
                    )
                    continue
                if (
                    raw.get("kind") in PRIVILEGED_KINDS
                    and self._privileged_pipe_required()
                ):
                    # Fix round 2 (FIX 1): in the installed
                    # Windows layout a file drop proves nothing
                    # about WHO is asking — privileged kinds are
                    # executed only over the verified pipe.
                    self._reject_request(
                        request_path,
                        "privileged actions require the verified "
                        "Argus program",
                    )
                    continue
                result = self._execute_request(raw)
                result["id"] = raw["id"]
                # Result BEFORE the request file is removed.
                try:
                    write_text_atomic(
                        results_dir() / f"{raw['id']}.json",
                        json.dumps(result, indent=2) + "\n",
                    )
                except OSError:
                    log.exception("could not write action-request result")
                    continue  # leave the request for a later pass
                request_path.unlink(missing_ok=True)
                processed += 1
            except Exception:
                # One bad file must never starve the batch.
                log.exception("action request %s failed in isolation", request_path)
                try:
                    self._reject_request(request_path, "processing failed unexpectedly")
                except Exception:
                    pass
        return processed

    def _execute_request(
        self, request: dict, *, live_sha: str | None = None
    ) -> dict:
        """Serialized execution wrapper: acquires the execution lock
        (vs stop()/reload swaps) and echoes the v2 nonce.

        The approve-pending target's live re-hash happens BEFORE
        the lock is taken (fix round 2, FIX 6): hashing a huge
        file must not hold the lifecycle lock that stop() waits
        on. Inside the lock the pending row is re-read and
        re-verified against that hash, so moving the hash out is
        a change of WHERE the work happens, never a weakening of
        the check."""
        if live_sha is None and request.get("kind") == "approve-pending":
            live_sha = self._prehash_pending_target(request)
        with self._execution_lock:
            result = self._execute_request_impl(request, live_sha=live_sha)
        if "nonce" in request:
            result = {**result, "nonce": request.get("nonce")}
        return result

    def _prehash_pending_target(self, request: dict) -> str | None:
        """Hash an approve-pending request's target OUTSIDE the
        execution lock. None when the row or file cannot be read
        — the in-lock path then decides (and refuses) exactly as
        it did before the hash moved out here."""
        if self.vault is None:
            return None
        pending_id = request.get("pending_id")
        if not pending_id:
            return None
        try:
            pending = self.vault.get_pending(pending_id)
        except Exception:
            return None
        if pending is None or not pending.sha256:
            return None
        target = Path(pending.path)
        if not target.is_file():
            return None
        try:
            live, _ = hash_file(target)
        except OSError:
            return None
        return live

    def _execute_request_impl(
        self, request: dict, *, live_sha: str | None = None
    ) -> dict:
        """Carry out one action request against the service's OWN
        records. The request names an entry/pending id and the
        fingerprint the human saw; anything that does not match the
        service's records is refused, in writing."""
        kind = request.get("kind")
        if kind not in REQUEST_KINDS:
            return {"ok": False, "message": f"unknown request kind {kind!r}"}
        if self.actions is None or self.vault is None:
            return {
                "ok": False,
                "message": "Argus protection is not running, so the "
                "request could not be carried out.",
            }
        seen_sha = request.get("sha256")
        # sha256 is REQUIRED for every kind (P0-1): without the
        # fingerprint the human reviewed there is nothing to verify
        # the service's own records against.
        if not seen_sha or not isinstance(seen_sha, str):
            return {
                "ok": False,
                "message": "this request did not include the file's "
                "fingerprint, so Argus could not verify it is acting "
                "on the file you reviewed. Nothing was done — "
                "reopen the page and try again.",
            }
        try:
            if kind in ("restore", "delete", "allow"):
                entry_id = request.get("entry_id")
                # The vault row's MAC gates execution too (P1-4).
                entry = (
                    self.vault.verified_entry(entry_id) if entry_id else None
                )
                if entry is None:
                    return {
                        "ok": False,
                        "message": f"no vault entry with id {entry_id} — "
                        "it may already have been resolved.",
                    }
                if seen_sha.lower() != entry.sha256.lower():
                    return {
                        "ok": False,
                        "message": "the vault record for this file does "
                        "not match the fingerprint you reviewed — Argus "
                        "refused to act on a different file than the one "
                        "you saw. Reopen the quarantine page and try again.",
                    }
                if kind == "restore":
                    outcome = self.actions.restore_entry(
                        entry.id, confirmed=True
                    )
                elif kind == "delete":
                    outcome = self.actions.delete_entry(
                        entry.id, confirmed=True
                    )
                else:
                    outcome = self.actions.allow_entry(
                        entry.id, confirmed=True
                    )
                self._publish_vault_view()
                return {
                    "ok": outcome.done,
                    "message": outcome.message,
                    "restored_path": outcome.restored_path,
                }
            # approve-pending / reject-pending
            pending_id = request.get("pending_id")
            pending = self.vault.get_pending(pending_id) if pending_id else None
            if pending is None or pending.status != "pending":
                return {
                    "ok": False,
                    "message": f"no waiting action with id {pending_id} — "
                    "it may already have been decided.",
                }
            if not pending.sha256 or seen_sha.lower() != pending.sha256.lower():
                return {
                    "ok": False,
                    "message": "the queued action's fingerprint does not "
                    "match the one you reviewed — Argus refused to act "
                    "on a different file than the one you saw.",
                }
            if kind == "approve-pending":
                # Execute ONLY against the service's own trusted row,
                # and only when the LIVE file still hashes to the
                # row's fingerprint (re-hashed at execution time).
                # A mismatch or a missing file is a refusal — and
                # nothing is marked.
                target = Path(pending.path)
                if not target.is_file():
                    return {
                        "ok": False,
                        "message": "the file this queued action was "
                        "about is no longer there, so Argus refused "
                        "to carry it out. Nothing was marked or moved.",
                    }
                if live_sha is None:
                    # No pre-hash (a caller reached the impl
                    # directly): hash here, as before.
                    live_sha, _ = hash_file(target)
                if live_sha.lower() != pending.sha256.lower():
                    return {
                        "ok": False,
                        "message": "the file has changed since it was "
                        "queued — its fingerprint no longer matches "
                        "the queued action, so Argus refused to act "
                        "on a different file than the one you "
                        "approved. Nothing was marked or moved; "
                        "scan it again.",
                    }
                outcome = self.actions.approve(pending.id)
                self._publish_pending_view()
                self._publish_vault_view()
                return {"ok": outcome.done, "message": outcome.message}
            decided = self.actions.reject(pending.id)
            self._publish_pending_view()
            return {
                "ok": True,
                "message": (
                    f"Rejected — Argus will leave {decided.path} as it "
                    f"is; the queued {decided.action} was declined."
                ),
            }
        except (ActionError, QuarantineError) as exc:
            # Already user-facing plain language — keep as-is.
            # The technical detail was logged at the raise site;
            # note the refusal here so the channel's story is
            # complete in the service log.
            log.info(
                "action request %s refused: %s",
                request.get("id"), exc,
            )
            return {"ok": False, "message": str(exc)}
        except SignatureError as exc:
            # P1-10: no raw errors via the channel — detail to the
            # service log only, plain language to the user.
            log.exception(
                "action request %s hit a signature problem: %r",
                request.get("id"), exc,
            )
            return {
                "ok": False,
                "message": "Argus has a problem with its signature "
                "database, so this action could not be carried out. "
                "Nothing was changed.",
            }
        except OSError as exc:
            log.exception(
                "action request %s hit an access problem: %r",
                request.get("id"), exc,
            )
            return {
                "ok": False,
                "message": "Argus could not access the file or folder "
                "it needed for this action — it may be in use or "
                "Argus may not have permission. Nothing was changed; "
                "close other programs and try again.",
            }
        except Exception as exc:  # never leave a request unanswered
            log.exception(
                "action request %s failed: %r", request.get("id"), exc
            )
            return {
                "ok": False,
                "message": "The action could not be carried out. "
                "Argus left everything as it was — try again, and "
                "if it keeps failing, restart Argus.",
            }

    # ------------------------------------------------------------------
    # Verified pipe channel (fix round 2, FIX 1) — see pipe_channel
    # ------------------------------------------------------------------
    def _privileged_pipe_required(self) -> bool:
        """Whether file-channel privileged requests must be
        refused here: the override when one was injected (tests),
        else the layout's own answer."""
        if self._pipe_required is not None:
            return self._pipe_required
        from .action_requests import pipe_channel_required

        return pipe_channel_required()

    def _pipe_session(self, stream, client_pid: int):
        """One pipe session: verification inputs resolved fresh
        (the recorded fingerprint can change across an upgrade),
        then the shared session core."""
        from . import selftrust
        from .setup_engine import canonical_exe_path

        provider = (
            self._pipe_identity_provider
            or pipe_channel.WindowsClientIdentityProvider()
        )
        canonical = (
            Path(self._pipe_canonical_exe)
            if self._pipe_canonical_exe is not None
            else canonical_exe_path()
        )
        recorded = self._pipe_recorded_sha256
        if recorded is None:
            try:
                recorded = selftrust.load_recorded_exe_sha256()
            except Exception:
                recorded = None
        return pipe_channel.serve_pipe_stream(
            stream,
            client_pid=client_pid,
            identity_provider=provider,
            canonical_exe=canonical,
            recorded_sha256=recorded,
            execute=self._dispatch_pipe_request,
        )

    def _dispatch_pipe_request(self, request: dict) -> dict:
        """Route one pipe request — reached ONLY after
        :func:`pipe_channel.verify_pipe_client` proved the caller
        is the genuine Argus program. Privileged kinds execute
        through the same :meth:`_execute_request` as the file
        channel (every row/fingerprint/live-rehash validation
        still applies); the details queries answer from the
        service's OWN records for confirmation dialogs."""
        kind = request.get("kind")
        if kind == "entry-details":
            result = self._entry_details(request)
        elif kind == "pending-details":
            result = self._pending_details(request)
        elif kind in REQUEST_KINDS:
            result = self._execute_request(request)
        else:
            result = {
                "ok": False,
                "message": f"unknown request kind {kind!r}",
            }
        result = dict(result)
        result.setdefault("id", request.get("id"))
        if "nonce" in request:
            result["nonce"] = request.get("nonce")
        return result

    def _entry_details(self, request: dict) -> dict:
        """The service's OWN vault row (MAC-verified before
        anything is reported) — what a restore/delete/allow
        confirmation must show, never the unsigned view file."""
        if self.vault is None:
            return {
                "ok": False,
                "message": "Argus protection is not running.",
            }
        entry_id = request.get("entry_id")
        entry = None
        if entry_id:
            try:
                entry = self.vault.verified_entry(entry_id)
            except QuarantineError as exc:
                return {"ok": False, "message": str(exc)}
        if entry is None:
            return {
                "ok": False,
                "message": f"no vault entry with id {entry_id} — "
                "it may already have been resolved.",
            }
        return {
            "ok": True,
            "message": "",
            "details": {
                "entry_id": entry.id,
                "original_path": entry.original_path,
                "detection_name": entry.detection_name,
                "severity": entry.severity,
                "verdict": entry.verdict,
                "sha256": entry.sha256,
                "status": entry.status,
                "size": entry.size,
                "quarantined_at": entry.quarantined_at,
            },
        }

    def _pending_details(self, request: dict) -> dict:
        """The service's OWN pending-queue row — what an
        approve/reject confirmation must show."""
        if self.vault is None:
            return {
                "ok": False,
                "message": "Argus protection is not running.",
            }
        pending_id = request.get("pending_id")
        pending = (
            self.vault.get_pending(pending_id) if pending_id else None
        )
        if pending is None:
            return {
                "ok": False,
                "message": f"no queued action with id {pending_id} — "
                "it may already have been decided.",
            }
        return {
            "ok": True,
            "message": "",
            "details": {
                "pending_id": pending.id,
                "action": pending.action,
                "path": pending.path,
                "detection_name": pending.detection_name,
                "severity": pending.severity,
                "sha256": pending.sha256,
                "status": pending.status,
                "source": pending.source,
                "reasons": list(pending.reasons),
            },
        }

    def _start_pipe_server(self) -> None:
        serve = self._serve_pipe
        if serve is None:
            serve = sys.platform == "win32"
        if not serve:
            return
        try:
            server = pipe_channel.WindowsPipeServer(self._pipe_session)
            server.start()
            self._pipe_server = server
        except Exception:
            # Loud, never fatal: protection continues, but
            # privileged actions from the Argus window will be
            # refused (by design) until the service starts cleanly
            # with its pipe.
            log.exception(
                "could not start the verified-action pipe — "
                "privileged actions from the Argus window will be "
                "refused until the service restarts cleanly"
            )

    def _stop_pipe_server(self) -> None:
        if self._pipe_server is not None:
            try:
                self._pipe_server.stop()
            except Exception:
                log.exception("stopping the action pipe failed")
            self._pipe_server = None

    @staticmethod
    def _close_stack(stack) -> None:
        """Close a stack returned by :meth:`_open_stack` (used when
        the engine itself fails to start after validation passed).
        The engine is not running yet at that point, so there is
        nothing to stop — just the opened resources to release."""
        db, vault, history, _actions, _engine = stack
        for resource in (history, vault, db):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    log.exception("closing a failed service stack failed")

    def _load_rules(self) -> list[Rule]:
        if not self.config.rules_file:
            return BUILTIN_RULES
        try:
            return load_rules(self.config.rules_file)
        except Exception as exc:
            self.last_error = f"could not load rules file: {exc}"
            log.error("%s — falling back to built-in rules", self.last_error)
            return BUILTIN_RULES

    def _fold_engine_stats(self) -> None:
        if self.engine is None:
            return
        snapshot = self.engine.status_snapshot()
        for key in self._carried:
            self._carried[key] += snapshot.get(key, 0)


def read_status_file(path: Path | str) -> dict | None:
    """Read a heartbeat/status file written by :class:`ArgusService`.

    Returns None when there is no readable, valid status file — which
    is exactly what "Argus is not running" looks like from outside.
    """
    status_path = Path(path)
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None
