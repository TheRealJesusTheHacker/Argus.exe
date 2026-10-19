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
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .action_requests import REQUEST_KINDS
from .actions import ActionEngine, ActionError
from .config import ArgusConfig, default_watch_dirs
from .paths import (
    default_history_db,
    default_pending_db,
    default_vault_dir,
    requests_dir,
    results_dir,
    vault_view_path,
    write_text_atomic,
)
from .quarantine import QuarantineError, Vault
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
        self._publish_vault_view(force=True)
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
        if self._requests_thread is not None:
            self._requests_thread.join(timeout=2.0)
            self._requests_thread = None
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
                if outcome.done:
                    # The vault just changed — republish the
                    # read-only view the GUI reads.
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
            **totals,
            "last_error": self.last_error,
        }

    def write_status(self) -> None:
        """Write the status file atomically (tmp file + rename), so a
        reader never sees a half-written heartbeat. Also republishes
        the vault view when the vault changed since the last one."""
        self._publish_vault_view()
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
    # Action-request channel (see argus.action_requests)
    # ------------------------------------------------------------------
    def _requests_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.process_requests_once()
            except Exception:
                log.exception("action-request scan failed")
            self._stop.wait(REQUEST_POLL_INTERVAL_SECONDS)

    def process_requests_once(self) -> int:
        """Execute every pending action request once. Returns how
        many were processed. Public so tests (and a future admin
        tool) can drive the channel without the polling thread."""
        folder = requests_dir()
        try:
            candidates = sorted(folder.glob("*.json"))
        except OSError:
            return 0
        processed = 0
        for request_path in candidates:
            try:
                raw = json.loads(request_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                log.warning("ignoring unreadable action request %s", request_path)
                request_path.unlink(missing_ok=True)
                continue
            if not isinstance(raw, dict) or raw.get("id") != request_path.stem:
                log.warning("ignoring malformed action request %s", request_path)
                request_path.unlink(missing_ok=True)
                continue
            result = self._execute_request(raw)
            result["id"] = raw["id"]
            try:
                write_text_atomic(
                    results_dir() / f"{raw['id']}.json",
                    json.dumps(result, indent=2) + "\n",
                )
            except OSError:
                log.exception("could not write action-request result")
            request_path.unlink(missing_ok=True)
            processed += 1
        return processed

    def _execute_request(self, request: dict) -> dict:
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
        try:
            if kind in ("restore", "delete", "allow"):
                entry_id = request.get("entry_id")
                entry = self.vault.get_entry(entry_id) if entry_id else None
                if entry is None:
                    return {
                        "ok": False,
                        "message": f"no vault entry with id {entry_id} — "
                        "it may already have been resolved.",
                    }
                if seen_sha and seen_sha.lower() != entry.sha256.lower():
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
                    "ok": True,
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
            if (
                seen_sha
                and pending.sha256
                and seen_sha.lower() != pending.sha256.lower()
            ):
                return {
                    "ok": False,
                    "message": "the queued action's fingerprint does not "
                    "match the one you reviewed — Argus refused to act "
                    "on a different file than the one you saw.",
                }
            if kind == "approve-pending":
                outcome = self.actions.approve(pending.id)
                return {"ok": True, "message": outcome.message}
            decided = self.actions.reject(pending.id)
            return {
                "ok": True,
                "message": (
                    f"Rejected — Argus will leave {decided.path} as it "
                    f"is; the queued {decided.action} was declined."
                ),
            }
        except (ActionError, QuarantineError) as exc:
            return {"ok": False, "message": str(exc)}
        except Exception as exc:  # never leave a request unanswered
            log.exception("action request %s failed", request.get("id"))
            return {"ok": False, "message": f"the action failed: {exc}"}

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
