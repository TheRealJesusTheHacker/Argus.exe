"""Application entry point for the ARGUS.EXE GUI.

``python -m argus.gui`` and the ``argus-gui`` script both land here.
On first run the onboarding wizard runs before the main window;
afterwards the main window opens directly and protection starts if
the user runs Argus as their foreground protector (the installed
product runs protection as the Windows service instead, and the GUI
then just observes via the heartbeat).
"""

from __future__ import annotations

import logging
import sys


def run_gui(argv: list[str] | None = None) -> int:
    from PySide6.QtWidgets import QApplication

    from . import theme
    from .backend import GuiBackend
    from .main_window import MainWindow
    from .onboarding import OnboardingWizard, needs_onboarding
    from .widgets import make_app_icon

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    app = QApplication(list(argv) if argv is not None else sys.argv)
    app.setApplicationName("ARGUS.EXE")
    app.setOrganizationName("Sentinel Safeguard LLC")
    app.setStyleSheet(theme.STYLESHEET)
    app.setWindowIcon(make_app_icon())

    backend = GuiBackend()
    for warning in backend.config.load_warnings:
        logging.getLogger("argus.gui").warning("config: %s", warning)
    for warning in backend.dev.load_warnings:
        logging.getLogger("argus.gui").warning("devtools: %s", warning)
    from ..devtools import apply_logging

    apply_logging(backend.dev.verbose_logging)

    if needs_onboarding(backend.config):
        wizard = OnboardingWizard(backend)
        wizard.exec()

    window = MainWindow(backend)
    window.tray.show()
    window.show()
    return app.exec()
