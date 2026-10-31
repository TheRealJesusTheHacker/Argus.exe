"""Dashboard page — the first thing Argus shows.

One question answered big and clearly: *am I protected right now?*
Then the numbers that matter (detections, quarantine, pending
decisions) and the way to act on them.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .backend import GuiBackend, ProtectionController
from .format import protection_headline
from .widgets import StatCard
from ..setup_engine import SetupState

_TONE_COLORS = {
    "protected": theme.GREEN,
    "paused": theme.SEVERITY_COLORS["medium"],
    "attention": theme.SEVERITY_COLORS["critical"],
    "off": theme.SEVERITY_COLORS["critical"],
}


class DashboardPage(QWidget):
    def __init__(
        self,
        backend: GuiBackend,
        protection: ProtectionController,
        *,
        on_quick_scan=None,
        on_open_pending=None,
        parent=None,
    ):
        super().__init__(parent)
        self._backend = backend
        self._protection = protection
        self._stale_service_branch = False
        self._on_quick_scan = on_quick_scan
        self._on_open_pending = on_open_pending

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # -- protection banner -------------------------------------
        banner = QWidget()
        banner_layout = QHBoxLayout(banner)
        banner_layout.setContentsMargins(4, 4, 4, 4)
        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"font-size: 44px; color: {theme.GREEN};")
        banner_layout.addWidget(self.status_dot)
        text_box = QVBoxLayout()
        self.headline_label = QLabel("Protection is off")
        self.headline_label.setObjectName("Headline")
        self.detail_label = QLabel("")
        self.detail_label.setObjectName("Subhead")
        self.detail_label.setWordWrap(True)
        text_box.addWidget(self.headline_label)
        text_box.addWidget(self.detail_label)
        banner_layout.addLayout(text_box, 1)
        layout.addWidget(banner)

        # -- protection controls ------------------------------------
        controls = QHBoxLayout()
        self.toggle_button = QPushButton("Turn protection on")
        self.toggle_button.setObjectName("Primary")
        self.toggle_button.clicked.connect(self._toggle_protection)
        controls.addWidget(self.toggle_button)
        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(self._toggle_pause)
        controls.addWidget(self.pause_button)
        scan_button = QPushButton("Quick scan now")
        scan_button.clicked.connect(lambda: self._on_quick_scan and self._on_quick_scan())
        controls.addWidget(scan_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        # -- stat cards ----------------------------------------------
        cards = QHBoxLayout()
        self.detections_card = StatCard("Detections (last 7 days)")
        self.quarantine_card = StatCard("Files in quarantine")
        self.pending_card = StatCard("Waiting for your decision")
        self.scans_card = StatCard("Files scanned (last 7 days)")
        for card in (
            self.detections_card,
            self.quarantine_card,
            self.pending_card,
            self.scans_card,
        ):
            cards.addWidget(card)
        layout.addLayout(cards)

        # -- last scan + simulation banner ---------------------------
        self.last_scan_label = QLabel("No scans yet in the last 7 days.")
        self.last_scan_label.setObjectName("Subhead")
        layout.addWidget(self.last_scan_label)

        self.pending_button = QPushButton("Review pending actions")
        self.pending_button.clicked.connect(
            lambda: self._on_open_pending and self._on_open_pending()
        )
        layout.addWidget(self.pending_button)

        self.sim_banner = QLabel(
            "Simulation mode is ON (Dev Toolkit): Argus will report "
            "what it would do, but it will not move or delete any file."
        )
        self.sim_banner.setWordWrap(True)
        self.sim_banner.setStyleSheet(
            f"background: {theme.GREEN_DEEP}; border-radius: 8px; "
            "padding: 8px 12px; font-weight: 600;"
        )
        layout.addWidget(self.sim_banner)

        # Signature-database disclosure: when the backend could not
        # bootstrap/open the signature database, that failure is a
        # designed dashboard status with a next action — never a
        # silent log line while the page claims all is well.
        self._sigdb_alarm_style = (
            f"background: {theme.DANGER_BG}; "
            f"border: 1px solid {theme.DANGER_BORDER}; "
            f"color: {theme.DANGER_TEXT}; border-radius: 8px; "
            "padding: 8px 12px; font-weight: 600;"
        )
        self._sigdb_info_style = (
            f"background: {theme.PANEL_RAISED}; "
            f"border: 1px solid {theme.BORDER}; "
            f"color: {theme.TEXT}; border-radius: 8px; "
            "padding: 8px 12px;"
        )
        self.sigdb_banner = QLabel("")
        self.sigdb_banner.setWordWrap(True)
        self.sigdb_banner.setStyleSheet(self._sigdb_alarm_style)
        layout.addWidget(self.sigdb_banner)

        # Scan-history disclosure (v1.2.14): when the history store
        # had to move — the backend's recovery ladder fell back to
        # the standard location or to a session-only in-memory
        # history — the dashboard says so in plain language. The
        # numbers must never silently pretend a complete history
        # stands behind them. Informational, not an alarm: the
        # degradation is handled, and protection is unaffected.
        self.history_banner = QLabel("")
        self.history_banner.setWordWrap(True)
        self.history_banner.setStyleSheet(self._sigdb_info_style)
        self.history_banner.setVisible(False)
        layout.addWidget(self.history_banner)

        # One-time legacy-migration notice (fix round 2, FIX 2):
        # when the service's one-time queue migration dropped
        # unverifiable pending items, say so ONCE per window
        # session — informational, never an alarm: the files the
        # dropped items named were never touched.
        self._legacy_notice_shown = False
        self.legacy_banner = QLabel("")
        self.legacy_banner.setWordWrap(True)
        self.legacy_banner.setStyleSheet(self._sigdb_info_style)
        self.legacy_banner.setVisible(False)
        layout.addWidget(self.legacy_banner)
        layout.addStretch(1)

        protection.status_changed.connect(self.set_status)
        protection.failed.connect(
            lambda message: self.detail_label.setText(message)
        )
        self.set_status(protection.status())
        self.refresh_numbers()

    # ------------------------------------------------------------------
    def set_status(self, status: dict) -> None:
        self._refresh_legacy_notice(status)
        headline, detail, tone = protection_headline(status)
        self.headline_label.setText(headline)
        self.status_dot.setStyleSheet(
            f"font-size: 44px; color: {_TONE_COLORS[tone]};"
        )
        running = bool(status.get("running"))
        paused = bool(status.get("paused"))
        self._stale_service_branch = False
        if self._protection.service_managed_stale(status):
            # P1-12: Windows confirms the service is running, but
            # its heartbeat (the details channel) is stale. The
            # headline is "on" — NEVER off — the details are
            # syncing, and the primary action forces a fresh
            # status check instead of a start attempt or a no-op.
            self._stale_service_branch = True
            self.headline_label.setText("Protection is on")
            self.status_dot.setStyleSheet(
                f"font-size: 44px; color: {_TONE_COLORS['protected']};"
            )
            self.detail_label.setText(
                "Protection is managed by the Argus Windows "
                "service and Windows confirms it is running, but "
                "its latest status details haven't arrived yet — "
                "details are syncing. “Check again” forces a fresh "
                "status check."
            )
            self.toggle_button.setText("Check again")
            self.toggle_button.setEnabled(True)
            self.pause_button.setText("Pause")
            self.pause_button.setEnabled(False)
            self.pause_button.setToolTip(
                "Protection is managed by the Argus service"
            )
            return
        if self._protection.service_managed(status):
            # Protection is run by the installed Windows service.
            # This window must never start a SECOND engine next to
            # it — the controls hand over to the service instead.
            self.detail_label.setText(
                detail + " Protection is managed by the Argus "
                "Windows service — it started with Windows and runs "
                "whether or not this window is open."
            )
            self.toggle_button.setText("Managed by the Windows service")
            self.toggle_button.setEnabled(False)
            self.pause_button.setText("Pause")
            self.pause_button.setEnabled(False)
            self.pause_button.setToolTip(
                "Protection is managed by the Argus service"
            )
            return
        if self._protection.setup_state() is SetupState.INSTALLED_INCOMPLETE:
            # P1-6: a partial install — the service exists but a
            # registration piece is missing. One action heals it:
            # re-enter setup (install() is resumable per-step).
            self.headline_label.setText(
                "Protection was only partly set up on this PC"
            )
            self.status_dot.setStyleSheet(
                f"font-size: 44px; color: {_TONE_COLORS['attention']};"
            )
            self.detail_label.setText(
                "Argus's always-on service is here, but part of "
                "its registration with Windows is missing, so "
                "protection can't be counted on yet. Finishing "
                "setup completes only the missing pieces — Windows "
                "will ask your permission once."
            )
            self.toggle_button.setText("Finish setting up protection")
            self.toggle_button.setEnabled(True)
            self.pause_button.setText("Pause")
            self.pause_button.setEnabled(False)
            return
        if self._protection.setup_state() is SetupState.NOT_INSTALLED:
            # The designed first-run state of the one-executable
            # product: Argus is here, protection is not set up,
            # and there is exactly one thing to do about it. (In
            # portable mode this state never occurs — portable
            # Argus runs protection in this window by design.)
            self.headline_label.setText(
                "Argus is on this PC, but protection isn't set up yet"
            )
            self.status_dot.setStyleSheet(
                f"font-size: 44px; color: {_TONE_COLORS['attention']};"
            )
            self.detail_label.setText(
                "One quick step turns on always-on protection: "
                "Argus will watch files the moment they arrive, "
                "starting before you even sign in. Windows will "
                "ask your permission once."
            )
            self.toggle_button.setText("Set up protection")
            self.toggle_button.setEnabled(True)
            self.pause_button.setText("Pause")
            self.pause_button.setEnabled(False)
            return
        self.detail_label.setText(detail)
        self.toggle_button.setEnabled(True)
        self.toggle_button.setText(
            "Turn protection off" if running else "Turn protection on"
        )
        self.pause_button.setText("Resume" if paused else "Pause")
        self.pause_button.setEnabled(running)
        self.pause_button.setToolTip("")

    def refresh_numbers(self) -> None:
        numbers = self._backend.dashboard_numbers()
        self.detections_card.set_value(str(numbers["detections_7d"]))
        self.quarantine_card.set_value(str(numbers["quarantined"]))
        self.pending_card.set_value(str(numbers["pending"]))
        self.scans_card.set_value(f"{numbers['files_scanned_7d']:,}")
        last_scan = numbers["last_scan"]
        if last_scan is not None:
            self.last_scan_label.setText(
                f"Last scan: {last_scan.started_at} — "
                f"{last_scan.files_scanned:,} files checked, "
                f"{numbers['detections_7d']} detection(s) in the "
                "last 7 days."
            )
        self.pending_button.setVisible(numbers["pending"] > 0)
        self._refresh_sim_banner()
        self._refresh_sigdb_banner()
        self._refresh_history_banner()

    def _refresh_history_banner(self) -> None:
        notice = getattr(self._backend, "history_notice", None)
        self.history_banner.setText(notice or "")
        self.history_banner.setVisible(bool(notice))

    #: The simulation banner's standard text (restored whenever
    #: no settings warning is being surfaced instead).
    _SIM_BANNER_TEXT = (
        "Simulation mode is ON (Dev Toolkit): Argus will report "
        "what it would do, but it will not move or delete any file."
    )

    def _refresh_sim_banner(self) -> None:
        status_fn = getattr(self._backend, "simulation_status", None)
        if callable(status_fn):
            on, warning = status_fn()
        else:
            on, warning = bool(self._backend.simulation_mode), None
        if warning:
            # Fail-safe state (fix round 2): the settings file
            # could not be read, so simulation is being treated
            # as ON — the banner says THAT, not the standard text.
            self.sim_banner.setText(warning)
            self.sim_banner.setVisible(True)
            return
        self.sim_banner.setText(self._SIM_BANNER_TEXT)
        self.sim_banner.setVisible(bool(on))

    def _refresh_legacy_notice(self, status: dict) -> None:
        """One-time notice (fix round 2, FIX 2): the service's
        status reports how many legacy pending items its
        one-time migration dropped as unverifiable. Shown once
        per window session — the "shown" state lives here,
        GUI-side, by design (the service just keeps reporting
        the count)."""
        try:
            dropped = int(status.get("legacy_pending_dropped") or 0)
        except (TypeError, ValueError):
            dropped = 0
        if dropped > 0 and not self._legacy_notice_shown:
            self._legacy_notice_shown = True
            self.legacy_banner.setText(
                f"{dropped} older pending item(s) couldn't be "
                "verified and were cleared when Argus tidied its "
                "decision queue. Argus only carries over queued "
                "actions it can prove came from its own records — "
                "the files those items named were never touched."
            )
            self.legacy_banner.setVisible(True)
        elif dropped <= 0:
            self.legacy_banner.setVisible(False)

    def _refresh_sigdb_banner(self) -> None:
        error = getattr(self._backend, "signature_db_error", None)
        if error:
            self.sigdb_banner.setStyleSheet(self._sigdb_alarm_style)
            self.sigdb_banner.setText(
                "Argus couldn't open its threat-signature database, "
                "so scans and protection can't check files against "
                "known threats right now. Next step: close Argus "
                "and open it again — if this message comes back, "
                "reinstall Argus or contact Sentinel Safeguard."
            )
            self.sigdb_banner.setVisible(True)
            return
        if getattr(self._backend, "signature_db_auth_deferred", False):
            # Fix round 2 (FIX 3): the auth key lives where this
            # Windows account cannot read it (by design), so this
            # window verified the database's STRUCTURE only and
            # defers authentication to the protection service.
            # When the service reports the database verified,
            # there is nothing to banner at all; otherwise an
            # informational (never red-alarm) note.
            service_auth = None
            try:
                service_auth = self._protection.status().get(
                    "signature_db_auth"
                )
            except Exception:
                service_auth = None
            if service_auth == "verified":
                self.sigdb_banner.setText("")
                self.sigdb_banner.setVisible(False)
                return
            self.sigdb_banner.setStyleSheet(self._sigdb_info_style)
            self.sigdb_banner.setText(
                "This Windows account can't read Argus's signature "
                "authentication key (it's kept with the protection "
                "service, on purpose), so this window checked the "
                "signature database's structure only. The protection "
                "service verifies it in full whenever it runs."
            )
            self.sigdb_banner.setVisible(True)
            return
        self.sigdb_banner.setText("")
        self.sigdb_banner.setVisible(False)

    # ------------------------------------------------------------------
    def _toggle_protection(self) -> None:
        if self._stale_service_branch:
            # P1-12 primary action: force a status re-check — the
            # service is already running, so a start attempt would
            # be wrong and a no-op would be a dead button.
            self._protection.request_status_refresh()
            self.refresh_numbers()
            return
        if self._protection.service_managed(self._protection.status()):
            return  # the Windows service owns protection right now
        if self._protection.setup_state() in (
            SetupState.NOT_INSTALLED,
            SetupState.INSTALLED_INCOMPLETE,
        ):
            self._protection.begin_setup()
            return
        if self._protection.running:
            self._protection.stop()
        else:
            self._protection.start()
        self.refresh_numbers()

    def _toggle_pause(self) -> None:
        status = self._protection.status()
        if status.get("paused"):
            self._protection.resume()
        else:
            self._protection.pause()
