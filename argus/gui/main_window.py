"""The ARGUS.EXE main window: sidebar navigation over the pages."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from .backend import GuiBackend, ProtectionController
from .dashboard import DashboardPage
from .manage_pages import HistoryPage, PendingPage, QuarantinePage
from .scan_page import ScanPage
from .settings_pages import DevToolkitPage, SettingsPage
from .tray import TrayController

PAGE_NAMES = [
    "Dashboard",
    "Scan",
    "Quarantine",
    "Pending Actions",
    "History",
    "Settings",
    "Dev Toolkit",
]


class MainWindow(QMainWindow):
    def __init__(
        self,
        backend: GuiBackend,
        *,
        start_protection: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._backend = backend
        self.setWindowTitle(f"ARGUS.EXE — Sentinel Safeguard v{__version__}")
        self.resize(1080, 720)

        self.protection = ProtectionController(backend, self)

        central = QWidget()
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # -- sidebar ---------------------------------------------------
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(210)
        side_layout = QVBoxLayout(sidebar)
        brand = QLabel("◉ ARGUS.EXE")
        brand.setStyleSheet("font-size: 18px; font-weight: 700; padding: 14px 12px 2px;")
        tagline = QLabel("All eyes. All detection.")
        tagline.setObjectName("Subhead")
        tagline.setStyleSheet("padding: 0 12px 10px;")
        side_layout.addWidget(brand)
        side_layout.addWidget(tagline)
        self.nav = QListWidget()
        self.nav.setObjectName("NavList")
        for name in PAGE_NAMES:
            self.nav.addItem(QListWidgetItem(name))
        self.nav.currentRowChanged.connect(self._page_changed)
        side_layout.addWidget(self.nav, 1)
        vendor = QLabel("Sentinel Safeguard LLC\nSecurity For Everyone")
        vendor.setObjectName("Subhead")
        vendor.setStyleSheet("padding: 10px 12px;")
        side_layout.addWidget(vendor)
        root_layout.addWidget(sidebar)

        # -- pages -------------------------------------------------------
        self.stack = QStackedWidget()
        self.dashboard = DashboardPage(
            backend,
            self.protection,
            on_quick_scan=self.quick_scan,
            on_open_pending=lambda: self.show_page("Pending Actions"),
        )
        self.scan_page = ScanPage(backend)
        self.quarantine_page = QuarantinePage(backend)
        self.pending_page = PendingPage(backend)
        self.history_page = HistoryPage(backend)
        self.settings_page = SettingsPage(backend, self.protection)
        self.devkit_page = DevToolkitPage(backend)
        self.pages = {
            "Dashboard": self.dashboard,
            "Scan": self.scan_page,
            "Quarantine": self.quarantine_page,
            "Pending Actions": self.pending_page,
            "History": self.history_page,
            "Settings": self.settings_page,
            "Dev Toolkit": self.devkit_page,
        }
        for name in PAGE_NAMES:
            self.stack.addWidget(self.pages[name])
        root_layout.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        self.nav.setCurrentRow(0)

        # -- tray --------------------------------------------------------
        self.tray = TrayController(self)
        self.tray.open_requested.connect(self._show_from_tray)
        self.tray.quick_scan_requested.connect(self.quick_scan)
        self.tray.toggle_pause_requested.connect(self._tray_toggle_pause)
        self.tray.quit_requested.connect(self.close)
        self.protection.status_changed.connect(self.tray.set_protection_state)
        self.protection.status_changed.connect(self._sync_tray_mode)
        self.tray.open_requested.connect(self.tray.acknowledge_alerts)
        self.protection.detection.connect(self.tray.notify_detection)
        self.protection.detection.connect(lambda _e: self._refresh_pages())
        # Initial tray state: reflect protection as it is right now,
        # not just after the first status change arrives.
        self.tray.set_protection_state(self.protection.status())
        self._sync_tray_mode(self.protection.status())

        self.statusBar().showMessage(
            "Real-time protection runs in this window, or as the "
            "ArgusProtection Windows service when installed."
        )
        if start_protection:
            self.protection.start()

    # ------------------------------------------------------------------
    def show_page(self, name: str) -> None:
        index = PAGE_NAMES.index(name)
        self.nav.setCurrentRow(index)

    def _page_changed(self, index: int) -> None:
        if 0 <= index < len(PAGE_NAMES):
            self.stack.setCurrentIndex(index)
            name = PAGE_NAMES[index]
            page = self.pages[name]
            if hasattr(page, "refresh"):
                page.refresh()
            if name == "Dashboard" and hasattr(page, "refresh_numbers"):
                page.refresh_numbers()

    def quick_scan(self) -> None:
        self.showNormal()
        self.raise_()
        self.show_page("Scan")
        self.scan_page.start_quick_scan()

    def _show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _sync_tray_mode(self, status: dict) -> None:
        """Keep the tray's Pause/Resume mirroring the dashboard:
        in service-managed mode (fresh heartbeat OR the P1-12
        SCM-running/stale-heartbeat branch) the tray pause is
        disabled with the managed tooltip."""
        managed = self.protection.service_managed(
            status
        ) or self.protection.service_managed_stale(status)
        self.tray.set_service_managed(managed)

    def _tray_toggle_pause(self) -> None:
        status = self.protection.status()
        if status.get("paused"):
            self.protection.resume()
        elif status.get("running"):
            self.protection.pause()

    def _refresh_pages(self) -> None:
        self.dashboard.refresh_numbers()
        self.pending_page.refresh()

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt name)
        self.tray.hide()
        self.protection.stop()
        self._backend.close()
        super().closeEvent(event)
