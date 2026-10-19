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


def extract_page_argument(argv: list[str]) -> tuple[list[str], str | None]:
    """Pull Argus's own ``--page <name>`` option out of *argv*.

    Returns ``(clean_argv, page_name)`` — the argv with the option
    removed (safe to hand to QApplication, which would choke on
    unknown options) and the canonical page name it asked for, or
    None. Names match the sidebar loosely: "devtoolkit",
    "Dev Toolkit", and "dev-toolkit" all mean the Dev Toolkit page
    (the installer shortcut passes ``--page devtoolkit``). An
    unrecognized name is consumed and ignored — a bad shortcut must
    never stop the app from opening.
    """
    from .main_window import PAGE_NAMES

    args = list(argv)
    page: str | None = None
    if "--page" in args:
        index = args.index("--page")
        value = args[index + 1] if index + 1 < len(args) else None
        if value is not None:
            del args[index : index + 2]
        else:
            del args[index : index + 1]
        if value:
            wanted = value.replace("-", " ").replace("_", " ").strip().lower()
            for name in PAGE_NAMES:
                if name.lower() == wanted or name.replace(" ", "").lower() == (
                    wanted.replace(" ", "")
                ):
                    page = name
                    break
    return args, page


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
    raw_argv = list(argv) if argv is not None else sys.argv
    clean_argv, start_page = extract_page_argument(raw_argv)
    app = QApplication(clean_argv)
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
    if start_page is not None:
        window.show_page(start_page)
    window.tray.show()
    window.show()
    return app.exec()
