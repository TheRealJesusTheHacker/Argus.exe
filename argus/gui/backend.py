"""The GUI's bridge to the engine.

Pages never import engine internals beyond this module. GuiBackend
owns the loaded config, the Dev Toolkit settings, the lazily-opened
vault / history / action engine, and answers the questions pages ask
(dashboard numbers, scan roots). ProtectionController wraps the
Phase 3 ArgusService for in-app real-time protection, and ScanWorker
runs scans off the UI thread with progress signals.

Simulation mode is honored by the ACTIONS layer itself, which
consults the persisted Dev Toolkit flag at act time through
:func:`argus.devtools.simulation_status` — the ONE reader of the
devtools settings (fix round 2): the GUI's banner view below reads
through the same function, and a settings file that cannot be
parsed means simulation is ON (fail-safe) everywhere, with the
warning surfaced on the dashboard.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from .. import action_requests, devtools, setup_engine
from ..actions import ActionEngine
from ..config import DEFAULT_CONFIG_NAME, ArgusConfig
from ..devtools import DevSettings, evaluate_signals
from ..heuristics.analyze import analyze_file, waive_oversize_floor
from ..paths import data_dir, default_pending_db, pending_view_path, vault_view_path
from ..quarantine import QuarantineEntry, Vault, read_pending_view
from ..reporting import History
from ..rules import BUILTIN_RULES
from ..scanner import ScannedFile, iter_files, scan_file
from ..service import ArgusService
from ..signatures import (
    SignatureDB,
    SignatureError,
    bootstrap_signature_db,
    ensure_signature_db,
)

log = logging.getLogger("argus.gui")

#: A heartbeat from an external Argus service counts as "live" for
#: this long. The service heartbeats every few seconds, so anything
#: older means the writer is gone (crashed/killed), not managing
#: protection right now.
SERVICE_HEARTBEAT_FRESH_SECONDS = 45.0


class GuiBackend:
    def __init__(
        self,
        config_path: Path | str | None = None,
        devtools_path: Path | str | None = None,
    ):
        base = data_dir()
        if config_path:
            self.config_path = Path(config_path)
        elif sys.platform.startswith("linux"):
            # The .deb edition (v1.2.0): an admin-placed config in
            # /etc/argus wins for the GUI exactly as it does for
            # the service — one helper, one answer, so the window
            # and the protection service can never read different
            # settings (see argus.linuxservice.preferred_config_path).
            from .. import linuxservice

            self.config_path = linuxservice.preferred_config_path()
        else:
            self.config_path = base / DEFAULT_CONFIG_NAME
        self.config = ArgusConfig.load(self.config_path)
        # First-run bootstrap: a fresh install has no signature
        # database yet — create + seed the DEFAULT one so the first
        # scan (and protection start) works instead of failing on a
        # missing file. A missing database at a configured path is
        # an error, but it must never stop the GUI from opening:
        # record it, log it loudly, and let scans surface it.
        self.signature_db_error: str | None = None
        #: True when the signature database could only be
        # verified structurally from THIS account because its
        # authentication key lives where standard users cannot
        # read it (the installed layout's service-only vault
        # subtree) — verification is deferred to the protection
        # service, which reports its own verdict in its status
        # (fix round 2, FIX 3). The dashboard must NOT show the
        # red couldn't-open banner for this state.
        self.signature_db_auth_deferred: bool = False
        try:
            info = bootstrap_signature_db(self.config.signature_db)
            if info is None:
                info = ensure_signature_db(self.config.signature_db)
            if info is not None and getattr(info, "auth_deferred", False):
                self.signature_db_auth_deferred = True
        except SignatureError as exc:
            self.signature_db_error = str(exc)
            log.error("signature database bootstrap: %s", exc)
        # The Dev Toolkit settings live at the devtools module's
        # OWN default (the shared folder): the ActionEngine's
        # act-time simulation check reads
        # devtools.default_devtools_path(), so the GUI's toggle
        # must write the SAME file or the two would silently
        # disagree about whether simulation is on.
        self.devtools_path = (
            Path(devtools_path)
            if devtools_path
            else devtools.default_devtools_path()
        )
        self.dev = DevSettings.load(self.devtools_path)
        self._vault: Vault | None = None
        self._history: History | None = None
        self._actions: ActionEngine | None = None
        #: Plain-language notice when the scan history is NOT where
        #: it should be — the dashboard shows it verbatim, so a
        #: degraded history is honest, never silent. None when
        #: history opened at its configured/default location and
        #: reads back fine (see :meth:`history`'s recovery ladder).
        self.history_notice: str | None = None
        #: Where the scan history actually opened. None until it is
        #: first opened — and None again when no file location
        #: could be opened and history is being kept in memory for
        #: this session only.
        self.history_path: Path | None = None

    # -- persistence ---------------------------------------------------
    def save_config(self) -> None:
        # Merge the on-disk exclusions first: the service may have
        # vouched for files since this copy was loaded, and saving
        # must never erase its vouches (lost update).
        self.config.absorb_disk_exclusions(self.config_path)
        self.config.save(self.config_path)

    def save_dev(self) -> None:
        self.dev.save(self.devtools_path)

    def simulation_status(self) -> tuple[bool, str | None]:
        """(simulation_on, warning) for banners and routing —
        read through :func:`argus.devtools.simulation_status`,
        the ONE settings reader the actions seam also uses (fix
        round 2, FIX 6), OR'd with this session's settings
        object: the Dev Toolkit toggle flips the object and
        saves it in the same gesture, and either one saying ON
        means ON — for a safety flag, the safe direction wins
        every disagreement. A corrupt settings file forces ON
        plus the warning, whatever the object says."""
        on, warning = devtools.simulation_status(self.devtools_path)
        if warning is not None:
            return True, warning
        return bool(on or self.dev.simulation_mode), None

    @property
    def simulation_mode(self) -> bool:
        """The Dev Toolkit simulation flag as the GUI knows it —
        see :meth:`simulation_status`. This property is a VIEW
        for banners and routing only; whether an action is
        actually simulated is decided inside the engine, which
        consults the same single reader at act time."""
        return self.simulation_status()[0]

    # -- stores ---------------------------------------------------------
    def pending_db_path(self) -> Path:
        if self.config.pending_db:
            return Path(self.config.pending_db)
        return default_pending_db()

    def vault(self) -> Vault:
        if self._vault is None:
            self._vault = Vault.open(
                Path(self.config.vault_dir or _default_vault()),
                self.pending_db_path(),
            )
        return self._vault

    def vault_writable(self) -> bool:
        """Can THIS process write to the vault? False on an
        installed machine for a standard user (the vault sits in
        the trusted root) — vault actions then go through the
        service request channel instead."""
        vault_dir = Path(self.config.vault_dir or _default_vault())
        return action_requests.path_writable(vault_dir)

    def vault_entries_view(self) -> tuple[list[QuarantineEntry], bool]:
        """Quarantine entries for display: ``(entries, direct)``.

        Direct when this process can open the vault; otherwise the
        service-published ``shared/vault-view.json`` snapshot is
        read (entries only — never blobs). When neither is
        available, the entry list is empty and ``direct`` is False,
        and the page shows its administrator guidance.
        """
        try:
            return self.vault().list_entries(), True
        except Exception:
            log.exception("vault not directly readable — using the vault view")
        try:
            raw = json.loads(vault_view_path().read_text(encoding="utf-8"))
            entries = []
            for item in raw.get("entries", []):
                if isinstance(item, dict):
                    entries.append(
                        QuarantineEntry(
                            id=item["id"],
                            original_path=item["original_path"],
                            sha256=item["sha256"],
                            size=item["size"],
                            quarantined_at=item["quarantined_at"],
                            detection_name=item["detection_name"],
                            severity=item.get("severity"),
                            verdict=item.get("verdict"),
                            reasons=list(item.get("reasons") or []),
                            status=item.get("status", "quarantined"),
                            blob_name=item.get("blob_name"),
                            resolved_at=item.get("resolved_at"),
                            restored_path=item.get("restored_path"),
                            note=item.get("note"),
                            mode=item.get("mode"),
                        )
                    )
            return entries, False
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            return [], False

    def pending_actions_loose(self):
        """Pending actions for DISPLAY from the service-published
        pending view (``shared/pending-view.json``).

        The pending database itself now lives in the trusted,
        service-owned vault directory (see
        :func:`argus.paths.default_pending_db`): in the installed
        layout this process must NOT read or write it directly —
        the view the service publishes is the display source."""
        return read_pending_view(pending_view_path())

    def owns_pending_store(self) -> bool:
        """True when THIS process owns the pending store: the
        portable edition (data beside the exe) or a process that
        can write the vault directory (elevated / dev tree). Only
        then may the GUI open the pending database directly."""
        if setup_engine.is_portable():
            return True
        vault_dir = Path(self.config.vault_dir or _default_vault())
        return action_requests.path_writable(vault_dir)

    def pending_display(self) -> tuple[list, bool]:
        """Pending actions for display: ``(rows, via_service)``.

        Direct from the action engine when this process owns the
        store; otherwise from the service-published pending view,
        with decisions routed through the service request channel
        (``via_service`` True)."""
        if self.owns_pending_store():
            try:
                return self.actions().list_pending(), False
            except Exception:
                log.exception(
                    "pending store not readable directly — using the view"
                )
        return (
            [p for p in self.pending_actions_loose() if p.status == "pending"],
            True,
        )

    def history(self) -> History:
        """The scan history — and it can never take the app down.

        Field failure (fixed in v1.2.14): on a machine whose
        configured history location could not be opened — a stale
        path pinned by an older install, a drive that is gone, a
        parent that is a file, a folder Windows would not let the
        account write (Controlled Folder Access) — opening history
        raised, the dashboard's first refresh called it unguarded,
        and the GUI died at launch behind a raw SQLite error.

        The open now walks a recovery ladder, logging every rung:

        1. the configured location (or the standard one when no
           location is configured) — a working configured path is
           NEVER overridden;
        2. the standard app-data location, created if needed;
        3. an in-memory history for this session.

        Whenever the ladder had to move, :attr:`history_notice`
        says so in plain language for the dashboard. This method
        does not raise.
        """
        if self._history is None:
            self._history = self._open_history()
        return self._history

    def _open_history(self) -> History:
        configured = self.config.history_db
        primary = Path(configured or _default_history())
        standard = Path(_default_history())
        rungs = [primary]
        if configured and standard != primary:
            rungs.append(standard)
        first_failure: str | None = None
        for rung in rungs:
            try:
                opened = History.open(rung)
            except Exception as exc:  # HistoryError by contract —
                # the ladder is the last line, so it trusts nothing
                log.error(
                    "scan history could not be opened at %s: %s",
                    rung, exc,
                )
                if first_failure is None:
                    first_failure = str(exc)
                continue
            self.history_path = rung
            if first_failure is not None:
                self.history_notice = (
                    f"Argus couldn't open its scan history — "
                    f"{first_failure}. It's keeping history at "
                    f"{rung} instead; history stored at the old "
                    f"location isn't shown."
                )
            return opened
        # No file location could be opened: keep history in memory
        # so the app still runs and this session's scans still
        # record. Nothing is written to disk, and the notice says
        # exactly that.
        log.error(
            "scan history: no file location could be opened — "
            "keeping history in memory for this session only"
        )
        self.history_path = None
        self.history_notice = (
            f"Argus couldn't open its scan history — "
            f"{first_failure}. History is being kept only for this "
            f"session, so the history numbers start empty. "
            f"Protection is not affected."
        )
        return History.open(":memory:")

    def actions(self) -> ActionEngine:
        """The action surface for destructive operations — the
        ONE engine seam. Simulation is the actions layer's own
        concern (it consults the persisted Dev Toolkit flag), so
        this always returns the real engine; there is no parallel
        simulated engine to route to."""
        if self._actions is None:
            self._actions = ActionEngine(
                self.vault(),
                self.config,
                config_path=self.config_path,
                history=self.history(),
            )
        return self._actions

    def real_actions(self) -> ActionEngine:
        """Backwards-compatible alias of :meth:`actions` — the
        real/simulated split this name used to mark has collapsed
        into the single engine seam."""
        return self.actions()

    # -- dashboard numbers ---------------------------------------------
    def dashboard_numbers(self) -> dict:
        """Counts for the dashboard stat cards, from the real stores."""
        try:
            history = self.history()
            summary = history.summary(days=7)
            recent = history.recent_scans(limit=1)
            last_scan = recent[0] if recent else None
        except Exception:
            # The ladder in history() already degrades the OPEN;
            # this covers a store that opens but cannot be READ
            # (v1.2.14): the dashboard shows honest zeroes with the
            # notice set, never a dead launch.
            log.exception(
                "scan history could not be read — dashboard "
                "history numbers show zero"
            )
            if self.history_notice is None:
                self.history_notice = (
                    "Argus couldn't read its scan history, so the "
                    "history numbers show zero for now. Protection "
                    "is not affected."
                )
            summary = _empty_history_summary(days=7)
            last_scan = None
        try:
            quarantined = self.vault().count(status="quarantined")
            pending_rows, _via = self.pending_display()
            pending = len(pending_rows)
        except Exception:
            # Installed layout, standard user: the vault is not
            # readable here — count from the published views (the
            # vault view and the pending view) instead of failing
            # the page. The trusted pending database itself is
            # never touched by this process in that layout.
            entries, _direct = self.vault_entries_view()
            quarantined = sum(
                1 for e in entries if e.status == "quarantined"
            )
            pending = sum(
                1 for p in self.pending_actions_loose() if p.status == "pending"
            )
        return {
            "detections_7d": summary["detections"],
            "scans_7d": summary["scans"],
            "files_scanned_7d": summary["files_scanned"],
            "quarantined": quarantined,
            "pending": pending,
            "last_scan": last_scan,
            "summary": summary,
        }

    # -- scanning ---------------------------------------------------------
    def quick_scan_roots(self) -> list[Path]:
        """Where threats land: Downloads, Desktop, Documents, temp."""
        home = Path.home()
        roots = [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            Path(_temp_dir()),
        ]
        return [r for r in roots if r.exists()]

    def full_scan_roots(self) -> list[Path]:
        """Everything: the drive/filesystem anchor the home folder
        lives on. Home is NOT scanned separately — it sits inside
        the anchor, so scanning both would walk (and count) the
        user's own files twice."""
        home = Path.home()
        anchor = Path(home.anchor) if home.anchor else None
        if anchor is not None and anchor.exists() and anchor != home:
            return [anchor]
        return [home]

    def close(self) -> None:
        if self._vault is not None:
            self._vault.close()
            self._vault = None
        if self._history is not None:
            self._history.close()
            self._history = None


def _default_vault() -> str:
    from ..paths import default_vault_dir

    return str(default_vault_dir())


def _default_history() -> str:
    from ..paths import default_history_db

    return str(default_history_db())


def _empty_history_summary(days: int) -> dict:
    """The zero shape of :meth:`History.summary` — the honest
    answer when history cannot be read at all (v1.2.14)."""
    return {
        "days": days,
        "scans": 0,
        "on_demand_scans": 0,
        "realtime_events": 0,
        "files_scanned": 0,
        "files_skipped": 0,
        "files_excluded": 0,
        "files_not_fully_scanned": 0,
        "bytes_scanned": 0,
        "detections": 0,
        "by_severity": {},
        "by_verdict": {},
        "by_action": {},
    }


def _temp_dir() -> str:
    import tempfile

    return tempfile.gettempdir()


class ProtectionController(QObject):
    """Runs ArgusService inside the GUI process and republishes its
    events as Qt signals."""

    status_changed = Signal(dict)
    detection = Signal(dict)
    failed = Signal(str)

    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        self._service: ArgusService | None = None
        self._last_external_status: dict | None = None
        self._last_setup_state = None
        # When no in-process engine runs, protection state comes
        # from the service heartbeat file — poll it so the
        # dashboard cannot freeze on a stale "protected" (a service
        # that stopped heartbeating must turn the banner red, and a
        # service that came back must clear it). The setup state is
        # polled alongside: a setup finishing (or a service being
        # removed) in another process must re-render the dashboard's
        # setup states without anyone reopening the window.
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(5000)
        self._poll_timer.timeout.connect(self._poll_external_status)
        self._poll_timer.start()

    def setup_state(self) -> setup_engine.SetupState:
        """How protection is set up on this machine right now
        (installed? running? portable?) — the dashboard renders its
        states from this. Cheap enough to poll: one SCM query."""
        return setup_engine.detect_state()

    def _poll_external_status(self) -> None:
        if self._service is not None:
            return  # the in-process engine reports its own changes
        current = self.status()
        state = self.setup_state()
        if (
            current != self._last_external_status
            or state != self._last_setup_state
        ):
            self._last_external_status = current
            self._last_setup_state = state
            self.status_changed.emit(current)

    def _on_engine_event(self, event) -> None:
        self.detection.emit(event.to_dict())
        self.status_changed.emit(self.status())

    def begin_setup(self) -> bool:
        """Kick off the one-time setup: relaunch this same program
        elevated with ``--run-setup`` (one Windows permission
        prompt) and let the polling notice when protection comes
        up. A declined prompt is a designed state, not an error
        dump: the dashboard shows the permission message with the
        same button to try again."""
        if setup_engine.relaunch_as_admin(["--run-setup"]):
            return True
        self.failed.emit(
            "Argus needs your permission to finish setting up. "
            "Choose “Set up protection” and allow the Windows "
            "prompt to continue."
        )
        return False

    def start(self) -> bool:
        if self._service is not None:
            return True
        if self._backend.simulation_mode:
            # Honesty: simulation mode means "report what you WOULD
            # do" — starting real protection under it would move
            # files while the UI claims nothing will be touched.
            self.failed.emit(
                "Simulation mode is on (Dev Toolkit), so real "
                "protection cannot start — in simulation Argus only "
                "reports what it would do. Turn simulation mode off "
                "in the Dev Toolkit to start real protection."
            )
            return False
        if IS_WINDOWS:
            state = self.setup_state()
            if state is setup_engine.SetupState.NOT_INSTALLED:
                # Never start a local engine here: on an installed
                # layout this window cannot (and must not) touch
                # the protection vault — setup is the only honest
                # next step, and the dashboard offers it as one.
                self.failed.emit(
                    "Protection isn't set up on this PC yet. "
                    "Choose “Set up protection” to finish — it "
                    "takes a few seconds."
                )
                return False
            if state is setup_engine.SetupState.INSTALLED_INCOMPLETE:
                # A partial install (service present, registration
                # incomplete): starting is not the fix — finishing
                # setup is. Re-entering install() heals it, because
                # install is resumable per-step.
                self.failed.emit(
                    "Protection was only partly set up on this PC. "
                    "Choose “Finish setting up protection” — Argus "
                    "will complete the missing pieces."
                )
                return False
            if state is setup_engine.SetupState.INSTALLED_STOPPED:
                # The service exists but is stopped: starting IT is
                # the action (through one permission prompt). The
                # in-process engine must never run against the
                # installed layout — that was the v1.0.5 dead end
                # (a raw "Access is denied" on the vault).
                if setup_engine.start_service_elevated():
                    return True
                self.failed.emit(
                    "Argus needs your permission to turn protection "
                    "on. Choose “Turn protection on” and allow the "
                    "Windows prompt to continue."
                )
                return False
            if state is setup_engine.SetupState.RUNNING:
                return True  # the service already has it
        service = ArgusService(
            config_path=str(self._backend.config_path),
            on_event=self._on_engine_event,
        )
        try:
            service.start()
        except PermissionError:
            # Belt and braces for the v1.0.5 failure class: any
            # local start that hits the installed layout's locked
            # folders becomes plain language and a route, never a
            # raw OS error on screen.
            log.exception("protection start hit a locked folder")
            self.failed.emit(
                "Argus can't start protection from this window on "
                "an installed copy. Choose “Set up protection” so "
                "Argus can protect this PC the way it's meant to."
            )
            return False
        except Exception:  # reported, never swallowed, never raw
            log.exception("protection failed to start")
            self.failed.emit(
                "Protection couldn't start. Close Argus, open it "
                "again, and try once more — if it keeps failing, "
                "contact Sentinel Safeguard."
            )
            return False
        self._service = service
        self.status_changed.emit(self.status())
        return True

    def stop(self) -> None:
        if self._service is not None:
            self._service.stop()
            self._service = None
        self.status_changed.emit(self.status())

    def pause(self) -> None:
        if self._service is not None:
            self._service.pause()
            self.status_changed.emit(self.status())

    def resume(self) -> None:
        if self._service is not None:
            self._service.resume()
            self.status_changed.emit(self.status())

    def reload_config(self) -> None:
        if self._service is not None:
            try:
                self._service.reload_config()
            except Exception:  # reported, never swallowed, never raw
                log.exception("protection config reload failed")
                self.failed.emit(
                    "Your new settings couldn't be applied. "
                    "Protection is still running with the previous "
                    "settings."
                )
                return
            self.status_changed.emit(self.status())

    @property
    def running(self) -> bool:
        return self._service is not None

    def service_managed(self, status: dict | None) -> bool:
        """True when *status* describes protection run by an
        EXTERNAL Argus service (the installed Windows service), not
        by this process: this controller runs no service of its own,
        the status says protection is running, and its heartbeat is
        fresh. A stale heartbeat is a service that died — not
        something managing protection.

        On Windows the heartbeat alone is not trusted: the status
        file lives in the user-writable shared folder, so anything
        could write one. The Service Control Manager must ALSO
        report ArgusProtection as running (see
        :func:`argus.winservice.query_service_state`); the status
        file then only supplies the details.
        """
        if self._service is not None or not status:
            return False
        if not status.get("running"):
            return False
        heartbeat = status.get("heartbeat_at")
        if not heartbeat:
            return False
        try:
            stamp = datetime.fromisoformat(str(heartbeat))
        except ValueError:
            return False
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
        if not (-60.0 <= age <= SERVICE_HEARTBEAT_FRESH_SECONDS):
            return False
        if IS_WINDOWS:
            from ..winservice import query_service_state

            return query_service_state() == "running"
        return True

    def scm_running(self) -> bool:
        """The Service Control Manager's own word: is
        ArgusProtection running? (Windows only — anywhere else
        there is no SCM to ask, and the answer is False.)"""
        if not IS_WINDOWS:
            return False
        from ..winservice import query_service_state

        return query_service_state() == "running"

    def service_managed_stale(self, status: dict | None) -> bool:
        """The P1-12 branch: the SCM says the service IS running
        but the heartbeat is stale (or missing), so
        :meth:`service_managed` — which also demands a fresh
        heartbeat for its details — does not apply. Protection is
        still ON (the SCM cannot be fooled by a stale file); only
        the details are syncing. The dashboard must show exactly
        that, never "off"."""
        if self._service is not None:
            return False
        if self.service_managed(status):
            return False  # the fresh-heartbeat branch already covers it
        return self.scm_running()

    def request_status_refresh(self) -> None:
        """Force a status re-check NOW (the primary action of the
        stale-heartbeat dashboard branch): re-read the status
        file, re-poll the SCM/setup state, and republish."""
        self._last_external_status = None
        current = self.status()
        self._last_external_status = current
        self._last_setup_state = self.setup_state()
        self.status_changed.emit(current)

    def status(self) -> dict:
        if self._service is not None:
            return self._service.status()
        from ..service import read_status_file

        stored = read_status_file(self._backend.config.status_file)
        return stored or {"running": False, "state": "stopped"}


class ScanWorker(QObject):
    """Runs a scan off the UI thread.

    :meth:`execute` does the work synchronously (tests call it
    directly); :meth:`run` is the thread entry point. The scan uses
    the engine pipeline for fingerprints, signatures, and rules, then
    scores heuristics through the Dev Toolkit's evaluator so the
    sensitivity slider and signal steering genuinely steer scans run
    from this window.
    """

    progress = Signal(int, int)          # files done, files total
    flagged = Signal(dict)               # one flagged file (row dict)
    finished_scan = Signal(dict)         # summary
    failed = Signal(str)

    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        self._roots: list[Path] = []
        self._cancel = threading.Event()

    def configure(self, roots: list[Path]) -> None:
        self._roots = list(roots)

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:  # thread entry point
        try:
            self.execute(self._roots)
        except Exception:  # surfaced, never swallowed, never raw
            log.exception("scan failed")
            self.failed.emit(
                "The scan couldn't finish. Try the scan again — "
                "if it keeps failing, restart Argus."
            )

    def execute(self, roots: list[Path]) -> dict:
        """Scan *roots* now (blocking). Returns the summary dict that
        the finished_scan signal also carries."""
        from .format import scan_result_row

        backend = self._backend
        config = backend.config
        self._cancel.clear()
        files: list[Path] = []
        from ..scanner import ScanStats

        stats = ScanStats()
        for root in roots:
            if root.is_file():
                files.append(root)
            elif root.exists():
                files.extend(iter_files(root, stats))
        total = len(files)
        flagged_rows: list[dict] = []
        scanned_files: list[ScannedFile] = []
        errors = 0
        db_path = Path(config.signature_db)
        with SignatureDB.open(db_path) as db:
            for index, path in enumerate(files):
                if self._cancel.is_set():
                    break
                scanned = scan_file(
                    path,
                    db,
                    BUILTIN_RULES,
                    heuristics=False,
                    exclusions=config.exclusions,
                )
                if config.heuristics and not scanned.excluded:
                    self._apply_heuristics(scanned)
                scanned_files.append(scanned)
                if scanned.result.error:
                    errors += 1
                if scanned.verdict.value != "Clean":
                    row = scan_result_row(scanned)
                    flagged_rows.append(row)
                    self.flagged.emit(row)
                if index % 5 == 0 or index == total - 1:
                    self.progress.emit(index + 1, total)
        summary = {
            "files": total,
            "scanned": len(scanned_files),
            "flagged": flagged_rows,
            "detections": sum(
                1 for f in scanned_files if f.verdict.value == "Malicious"
            ),
            "suspicious": sum(
                1 for f in scanned_files if f.verdict.value == "Suspicious"
            ),
            "errors": errors,
            "cancelled": self._cancel.is_set(),
            "scanned_files": scanned_files,
            "roots": [str(r) for r in roots],
        }
        self.finished_scan.emit(summary)
        return summary

    def _apply_heuristics(self, scanned: ScannedFile) -> None:
        if scanned.result.error or scanned.result.sha256 is None:
            return
        report = analyze_file(scanned.result.path, scanned.result.size)
        assessment = scanned.assessment
        # The scanner's oversize-floor waiver, applied identically
        # here (one shared helper — the verdicts cannot diverge):
        # this fresh report re-derives the floor, so it is waived
        # again under the same conditions, with the rule half
        # decided by the detections the scanner recorded.
        waive_oversize_floor(
            report,
            rule_detection_count=sum(
                1 for det in assessment.detections if det.kind == "rule"
            ),
        )
        # Signals the SCANNER already surfaced on this assessment
        # must survive the toolkit re-scoring — above all the
        # tamper signal (argus_program_file_replaced), which the
        # scanner attaches when a file sits at Argus's own program
        # address without an identity proof. The fresh analysis
        # report cannot know about it, so overwriting
        # assessment.signals with the report's signals alone would
        # silently drop the tamper indicator from the GUI surface.
        report_names = {sig.name for sig in report.signals}
        carried = [
            sig for sig in assessment.signals if sig.name not in report_names
        ]
        evaluation = evaluate_signals(
            list(report.signals) + carried, self._backend.dev,
            # The signed trim is EARNED (P1-20): a DER-parsed PKCS#7
            # SignedData with an extracted signer — the same
            # eligibility argus.scoring requires — never the mere
            # structural presence of a certificate table.
            signed=getattr(report, "signed_trim_eligible", report.signed),
            trusted_system_file=report.trusted_system_file,
        )
        assessment.signals = evaluation.counted_signals
        assessment.score = evaluation.score
        assessment.heuristic_verdict = evaluation.verdict
        assessment.notes.extend(report.notes)


def relaunch_gui_as_admin() -> bool:
    """Relaunch the Argus GUI elevated (Windows "runas" verb).

    Used when a settings save fails because the config file lives
    in the trusted root: there is deliberately NO delegation
    channel for config writes, so the honest route is the user
    re-running the app as administrator. Returns True when the
    elevated launch was accepted; False anywhere else (non-Windows,
    no shell, user declined the prompt).
    """
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        params = "" if getattr(sys, "frozen", False) else "-m argus.gui"
        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", sys.executable, params, None, 1
        )
        return int(result) > 32
    except Exception:
        log.exception("elevated relaunch failed")
        return False


IS_WINDOWS = sys.platform == "win32"
