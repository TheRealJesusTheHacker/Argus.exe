"""The GUI's bridge to the engine.

Pages never import engine internals beyond this module. GuiBackend
owns the loaded config, the Dev Toolkit settings, the lazily-opened
vault / history / action engine, and answers the questions pages ask
(dashboard numbers, scan roots). ProtectionController wraps the
Phase 3 ArgusService for in-app real-time protection, and ScanWorker
runs scans off the UI thread with progress signals.

Simulation mode is honored here at the single choke point: when the
Dev Toolkit's simulation toggle is on, :meth:`GuiBackend.actions`
returns the simulated engine that records intent and touches
nothing.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from .. import action_requests
from ..actions import ActionEngine
from ..config import DEFAULT_CONFIG_NAME, ArgusConfig
from ..devtools import DevSettings, SimulatedActionEngine, evaluate_signals
from ..heuristics.analyze import analyze_file
from ..paths import data_dir, default_pending_db, vault_view_path
from ..quarantine import QuarantineEntry, Vault, read_pending_db
from ..reporting import History
from ..rules import BUILTIN_RULES
from ..scanner import ScannedFile, iter_files, scan_file
from ..service import ArgusService
from ..signatures import SignatureDB, SignatureError, bootstrap_signature_db

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
        self.config_path = (
            Path(config_path)
            if config_path
            else base / DEFAULT_CONFIG_NAME
        )
        self.config = ArgusConfig.load(self.config_path)
        # First-run bootstrap: a fresh install has no signature
        # database yet — create + seed the DEFAULT one so the first
        # scan (and protection start) works instead of failing on a
        # missing file. A missing database at a configured path is
        # an error, but it must never stop the GUI from opening:
        # record it, log it loudly, and let scans surface it.
        self.signature_db_error: str | None = None
        try:
            bootstrap_signature_db(self.config.signature_db)
        except SignatureError as exc:
            self.signature_db_error = str(exc)
            log.error("signature database bootstrap: %s", exc)
        self.devtools_path = (
            Path(devtools_path)
            if devtools_path
            else base / "argus-devtools.json"
        )
        self.dev = DevSettings.load(self.devtools_path)
        self._vault: Vault | None = None
        self._history: History | None = None
        self._actions: ActionEngine | None = None
        self.simulated = SimulatedActionEngine()

    # -- persistence ---------------------------------------------------
    def save_config(self) -> None:
        # Merge the on-disk exclusions first: the service may have
        # vouched for files since this copy was loaded, and saving
        # must never erase its vouches (lost update).
        self.config.absorb_disk_exclusions(self.config_path)
        self.config.save(self.config_path)

    def save_dev(self) -> None:
        self.dev.save(self.devtools_path)

    @property
    def simulation_mode(self) -> bool:
        return self.dev.simulation_mode

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
        """Pending actions read straight from the shared pending
        database — for when the vault itself cannot be opened by
        this process (installed layout, standard user)."""
        return read_pending_db(self.pending_db_path())

    def history(self) -> History:
        if self._history is None:
            self._history = History.open(
                Path(self.config.history_db or _default_history())
            )
        return self._history

    def actions(self) -> ActionEngine | SimulatedActionEngine:
        """The action surface for destructive operations — real or
        simulated, decided here and nowhere else."""
        if self.dev.simulation_mode:
            return self.simulated
        if self._actions is None:
            self._actions = ActionEngine(
                self.vault(),
                self.config,
                config_path=self.config_path,
                history=self.history(),
            )
        return self._actions

    def real_actions(self) -> ActionEngine:
        """The real action engine even in simulation mode. Used for
        read-only bookkeeping (dashboard counts) — decisions
        themselves route through :meth:`actions` like everywhere
        else, so simulation mode records intent instead of acting."""
        if self._actions is None:
            self._actions = ActionEngine(
                self.vault(),
                self.config,
                config_path=self.config_path,
                history=self.history(),
            )
        return self._actions

    # -- dashboard numbers ---------------------------------------------
    def dashboard_numbers(self) -> dict:
        """Counts for the dashboard stat cards, from the real stores."""
        history = self.history()
        summary = history.summary(days=7)
        recent = history.recent_scans(limit=1)
        try:
            quarantined = self.vault().count(status="quarantined")
            pending = len(self.real_actions().list_pending())
        except Exception:
            # Installed layout, standard user: the vault is not
            # readable here — count from the published view and the
            # shared pending database instead of failing the page.
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
            "last_scan": recent[0] if recent else None,
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
        # When no in-process engine runs, protection state comes
        # from the service heartbeat file — poll it so the
        # dashboard cannot freeze on a stale "protected" (a service
        # that stopped heartbeating must turn the banner red, and a
        # service that came back must clear it).
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(5000)
        self._poll_timer.timeout.connect(self._poll_external_status)
        self._poll_timer.start()

    def _poll_external_status(self) -> None:
        if self._service is not None:
            return  # the in-process engine reports its own changes
        current = self.status()
        if current != self._last_external_status:
            self._last_external_status = current
            self.status_changed.emit(current)

    def _on_engine_event(self, event) -> None:
        self.detection.emit(event.to_dict())
        self.status_changed.emit(self.status())

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
        service = ArgusService(
            config_path=str(self._backend.config_path),
            on_event=self._on_engine_event,
        )
        try:
            service.start()
        except Exception as exc:  # reported, never swallowed
            self.failed.emit(f"Protection could not start: {exc}")
            log.exception("protection failed to start")
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
            except Exception as exc:  # reported, never swallowed
                self.failed.emit(f"Settings could not be applied: {exc}")
                log.exception("protection config reload failed")
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
        except Exception as exc:  # surfaced, never swallowed
            log.exception("scan failed")
            self.failed.emit(f"The scan could not finish: {exc}")

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
        evaluation = evaluate_signals(
            report.signals, self._backend.dev, signed=report.signed
        )
        assessment = scanned.assessment
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
