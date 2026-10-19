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
        layout.addStretch(1)

        protection.status_changed.connect(self.set_status)
        protection.failed.connect(
            lambda message: self.detail_label.setText(message)
        )
        self.set_status(protection.status())
        self.refresh_numbers()

    # ------------------------------------------------------------------
    def set_status(self, status: dict) -> None:
        headline, detail, tone = protection_headline(status)
        self.headline_label.setText(headline)
        self.detail_label.setText(detail)
        self.status_dot.setStyleSheet(
            f"font-size: 44px; color: {_TONE_COLORS[tone]};"
        )
        running = bool(status.get("running"))
        paused = bool(status.get("paused"))
        self.toggle_button.setText(
            "Turn protection off" if running else "Turn protection on"
        )
        self.pause_button.setText("Resume" if paused else "Pause")
        self.pause_button.setEnabled(running)

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
        self.sim_banner.setVisible(self._backend.simulation_mode)

    # ------------------------------------------------------------------
    def _toggle_protection(self) -> None:
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
