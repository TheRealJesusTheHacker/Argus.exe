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
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .actions import ActionEngine
from .config import ArgusConfig
from .paths import default_history_db, default_vault_dir
from .quarantine import Vault
from .realtime import RealtimeEngine, RealtimeEvent
from .reporting import History
from .rules import BUILTIN_RULES, Rule, load_rules
from .signatures import SignatureDB, SignatureError

log = logging.getLogger("argus.service")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat(timespec="seconds")


class ArgusService:
    """Owns config + engine; start/stop/pause/resume/reload/status."""

    def __init__(
        self,
        config_path: Path | str | None = None,
        *,
        config: ArgusConfig | None = None,
        on_event: Callable[[RealtimeEvent], None] | None = None,
    ) -> None:
        self.config_path = Path(config_path) if config_path else None
        self._config_override = config
        self.on_event = on_event
        self.config: ArgusConfig = config or ArgusConfig()
        self.engine: RealtimeEngine | None = None
        self.vault: Vault | None = None
        self.history: History | None = None
        self.actions: ActionEngine | None = None
        self._db: SignatureDB | None = None
        self._stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._started_at: datetime | None = None
        self.state: str = "stopped"  # stopped | running | paused
        self.last_error: str | None = None
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

        Raises :class:`SignatureError` if the signature database is
        missing or fails verification — protection that cannot verify
        its signatures must say so, not pretend.
        """
        if self.state in ("running", "paused"):
            return
        if self._config_override is None:
            self.config = ArgusConfig.load(self.config_path)
        for warning in self.config.load_warnings:
            log.warning("config: %s", warning)

        self._db = SignatureDB.open(self.config.signature_db)
        rules = self._load_rules()
        # Phase 4 wiring: the vault, history, and action engine are
        # opened BEFORE the engine starts, so every real-time event
        # is routed through the action policy from the first second.
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
        self.vault = Vault.open(vault_dir)
        self.history = History.open(history_path)
        self.actions = ActionEngine(
            self.vault,
            self.config,
            config_path=self.config_path,
            history=self.history,
        )
        self.engine = RealtimeEngine(
            self.config, self._db, rules, on_event=self._dispatch_event
        )
        self.engine.start()
        self._started_at = _utcnow()
        self.state = "running"
        self.last_error = None
        self._stop.clear()
        if self._heartbeat_thread is None or not self._heartbeat_thread.is_alive():
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop, name="argus-heartbeat", daemon=True
            )
            self._heartbeat_thread.start()
        self.write_status()
        log.info("Argus service started (config: %s)", self.config_path or "defaults")

    def stop(self) -> None:
        if self.state == "stopped":
            return
        self._stop.set()
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
        """Re-read the config file and restart the engine with it.

        Counters are carried over so the heartbeat keeps a truthful
        running total for the session. If no config path is set (pure
        defaults), reload simply re-applies the current config.
        """
        was_running = self.state in ("running", "paused")
        if not was_running:
            if self._config_override is None:
                self.config = ArgusConfig.load(self.config_path)
            return
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
        if self._config_override is None:
            self.config = ArgusConfig.load(self.config_path)
        self.start()
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
            **totals,
            "last_error": self.last_error,
        }

    def write_status(self) -> None:
        """Write the status file atomically (tmp file + rename), so a
        reader never sees a half-written heartbeat."""
        status_path = Path(self.config.status_file)
        try:
            if status_path.parent and not status_path.parent.exists():
                status_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = status_path.with_suffix(status_path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.status(), indent=2), encoding="utf-8")
            os.replace(tmp, status_path)
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
