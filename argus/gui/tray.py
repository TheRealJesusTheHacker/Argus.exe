"""System tray presence for ARGUS.EXE.

A tray icon that tells the truth at a glance: green eye when
protected, grey when off, amber pause bars when paused, red when a
detection needs attention. The menu offers Open, Quick Scan,
Pause/Resume, and Quit; detections raised by real-time protection
become tray notifications.

In service-managed mode (the installed Windows service owns
protection) the tray's Pause/Resume mirrors the dashboard exactly:
disabled, with the honest tooltip "Protection is managed by the
Argus service" — this window cannot pause what it does not run.
The red alert state persists while unacknowledged detections
exist: unrelated status updates never clear it; only an explicit
acknowledgement (the user opening Argus to look) does.
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

    #: Tooltip shown whenever pausing is not this window's to do.
    SERVICE_MANAGED_TOOLTIP = "Protection is managed by the Argus service"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._paused = False
        self._running = False
        self._service_managed = False
        self._alert_active = False
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
        if self._service_managed:
            return  # the service owns protection; the action is disabled
        self.toggle_pause_requested.emit()

    # ------------------------------------------------------------------
    def set_service_managed(self, managed: bool) -> None:
        """Mirror the dashboard's service-managed mode (P1-11):
        Pause/Resume is disabled with an honest tooltip — in
        in-process mode it behaves exactly as before."""
        self._service_managed = bool(managed)
        if self._service_managed:
            self.pause_action.setEnabled(False)
            self.pause_action.setToolTip(self.SERVICE_MANAGED_TOOLTIP)
            self.tray.setToolTip(
                "ARGUS.EXE — protection is managed by the Argus service"
            )
        else:
            self.pause_action.setToolTip("")
            self.pause_action.setEnabled(self._running)
            self._refresh_icon_and_tooltip()

    @property
    def alert_active(self) -> bool:
        """True while an unacknowledged detection alert stands."""
        return self._alert_active

    def acknowledge_alerts(self) -> None:
        """The user has seen the alert (opened Argus): clear the
        red state and re-render the icon for the current state."""
        if self._alert_active:
            self._alert_active = False
            self._refresh_icon_and_tooltip()

    def _refresh_icon_and_tooltip(self) -> None:
        if self._alert_active:
            self.tray.setIcon(make_app_icon(alert=True))
            return
        if not self._running:
            self.tray.setIcon(make_app_icon(protected=False))
            self.tray.setToolTip("ARGUS.EXE — protection is off")
        elif self._paused:
            self.tray.setIcon(make_app_icon(paused=True))
            self.tray.setToolTip("ARGUS.EXE — protection is paused")
        else:
            self.tray.setIcon(make_app_icon(protected=True))
            self.tray.setToolTip("ARGUS.EXE — protection is on")

    # ------------------------------------------------------------------
    def set_protection_state(self, status: dict) -> None:
        self._running = bool(status.get("running"))
        self._paused = bool(status.get("paused"))
        # An unacknowledged alert survives unrelated status
        # updates — the icon stays red until the user looks.
        self._refresh_icon_and_tooltip()
        if self._service_managed:
            self.pause_action.setEnabled(False)
            self.pause_action.setToolTip(self.SERVICE_MANAGED_TOOLTIP)
        elif not self._running:
            self.pause_action.setEnabled(False)
        else:
            self.pause_action.setEnabled(True)
            self.pause_action.setText(
                "Resume protection" if self._paused else "Pause protection"
            )

    def alert(self) -> None:
        """Raise the red state (a detection needs the user). It
        persists until :meth:`acknowledge_alerts` — an unrelated
        event or status refresh never clears it."""
        self._alert_active = True
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
