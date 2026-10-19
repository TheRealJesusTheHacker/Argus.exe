"""System tray presence for ARGUS.EXE.

A tray icon that tells the truth at a glance: green eye when
protected, grey when off, red when a detection needs attention. The
menu offers Open, Quick Scan, Pause/Resume, and Quit; detections
raised by real-time protection become tray notifications.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from .widgets import make_app_icon


class TrayController(QObject):
    open_requested = Signal()
    quick_scan_requested = Signal()
    toggle_pause_requested = Signal()
    quit_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._paused = False
        self._running = False
        self.tray = QSystemTrayIcon(make_app_icon(protected=False), parent)
        self.tray.setToolTip("ARGUS.EXE — protection is off")

        menu = QMenu()
        self.open_action = QAction("Open Argus", menu)
        self.open_action.triggered.connect(self.open_requested.emit)
        self.scan_action = QAction("Quick Scan", menu)
        self.scan_action.triggered.connect(self.quick_scan_requested.emit)
        self.pause_action = QAction("Pause protection", menu)
        self.pause_action.triggered.connect(self._toggle_pause)
        quit_action = QAction("Quit", menu)
        quit_action.triggered.connect(self.quit_requested.emit)
        menu.addAction(self.open_action)
        menu.addAction(self.scan_action)
        menu.addAction(self.pause_action)
        menu.addSeparator()
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._activated)

    # ------------------------------------------------------------------
    def show(self) -> None:
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def hide(self) -> None:
        self.tray.hide()

    def _activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.open_requested.emit()

    def _toggle_pause(self) -> None:
        self.toggle_pause_requested.emit()

    # ------------------------------------------------------------------
    def set_protection_state(self, status: dict) -> None:
        self._running = bool(status.get("running"))
        self._paused = bool(status.get("paused"))
        if not self._running:
            self.tray.setIcon(make_app_icon(protected=False))
            self.tray.setToolTip("ARGUS.EXE — protection is off")
            self.pause_action.setEnabled(False)
        else:
            self.tray.setIcon(make_app_icon(protected=True))
            state = "paused" if self._paused else "on"
            self.tray.setToolTip(f"ARGUS.EXE — protection is {state}")
            self.pause_action.setEnabled(True)
            self.pause_action.setText(
                "Resume protection" if self._paused else "Pause protection"
            )

    def alert(self) -> None:
        """Flash the red state (a detection needs the user)."""
        self.tray.setIcon(make_app_icon(alert=True))

    def notify_detection(self, event: dict) -> None:
        """Raise a tray notification for a real-time event.

        *event* is a :meth:`RealtimeEvent.to_dict` dict: it carries
        ``kind`` / ``message`` / ``severity`` / ``action`` / ``path``
        — keyed exactly as the engine emits them."""
        kind = event.get("kind", "")
        if kind == "detection":
            verdict = event.get("verdict") or "flagged"
            detail = event.get("message") or (
                f"Argus flagged a file as {verdict}."
            )
            self.alert()
            self.tray.showMessage(
                "ARGUS.EXE found a threat",
                detail,
                QSystemTrayIcon.MessageIcon.Warning,
                8000,
            )
        elif kind == "action":
            detail = event.get("message") or (
                f"Argus asks to {event.get('action') or 'act on'} "
                f"{event.get('path', '')}"
            )
            self.tray.showMessage(
                "ARGUS.EXE needs your decision",
                detail,
                QSystemTrayIcon.MessageIcon.Information,
                6000,
            )
            if (event.get("severity") or "").lower() in ("critical", "high"):
                self.alert()
