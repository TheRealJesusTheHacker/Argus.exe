"""ARGUS.EXE graphical interface (Phase 5) — an optional layer.

Importing this package does **not** import PySide6: the engine core
stays standard-library pure, and Qt is only loaded when the GUI
actually starts (:func:`main`). If PySide6 is missing, :func:`main`
says so in plain language instead of tracebacking.
"""

from __future__ import annotations

__all__ = ["main", "is_available"]


def is_available() -> bool:
    """True when PySide6 can be imported on this machine."""
    import importlib.util

    return importlib.util.find_spec("PySide6") is not None


def main(argv: list[str] | None = None) -> int:
    """Start the GUI. Entry point for ``argus-gui`` and
    ``python -m argus.gui``."""
    if not is_available():
        print(
            "The ARGUS.EXE graphical interface needs PySide6, which "
            "is not installed here.\n"
            "Install it with:  pip install \"argus-exe[gui]\"\n"
            "The command-line interface works without it:  "
            "python -m argus --help"
        )
        return 2
    from .app import run_gui

    return run_gui(argv)
