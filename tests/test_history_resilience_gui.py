"""Launch resilience, window half (v1.2.14): the real main window
must construct with scan history forced dead.

Companion to test_history_resilience.py (which pins the reporting
translation and the backend recovery ladder without widgets). The
field failure was a launch death — PyInstaller's "Failed to
execute script 'launch_argus'" — so the proof belongs at the same
altitude: MainWindow construction (which builds every page,
including the dashboard's first refresh and the History page's
first refresh) and the packaged entry point's own Qt self-check,
both with the history store unopenable at its configured AND its
standard location.

Skips cleanly where PySide6's widget layer is unavailable; the
release workflow runs these on both platforms.
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

try:
    import PySide6.QtWidgets  # noqa: F401
except ImportError:
    # Either PySide6 is absent or its widget layer cannot load
    # (e.g. no libEGL on a headless box) — skip, never error.
    pytest.skip(
        "PySide6 widgets unavailable — GUI tests skip",
        allow_module_level=True,
    )

from PySide6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture()
def dead_history_backend(tmp_path, monkeypatch):
    """A GuiBackend whose history can open NOWHERE on disk: the
    configured path's parent is a file, and so is the standard
    location's parent — the ladder must land on in-memory history
    and set the notice."""
    data_root = tmp_path / "argus-data"
    data_root.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    (data_root / "shared").write_text("a file, not a folder")
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder")

    from argus.gui.backend import GuiBackend

    config_path = tmp_path / "argus-config.json"
    config_path.write_text(
        json.dumps({"history_db": str(blocker / "history.db")}),
        encoding="utf-8",
    )
    backend = GuiBackend(
        config_path=config_path,
        devtools_path=tmp_path / "devtools.json",
    )
    yield backend
    backend.close()


def test_main_window_constructs_with_dead_history(qapp, dead_history_backend):
    from argus.gui.main_window import MainWindow

    window = MainWindow(dead_history_backend)  # the launch itself
    try:
        assert dead_history_backend.history_path is None
        assert dead_history_backend.history_notice is not None
        # The dashboard rendered honest zeroes and shows the notice.
        assert window.dashboard.detections_card.value_label.text() == "0"
        assert window.dashboard.scans_card.value_label.text() == "0"
        banner = window.dashboard.history_banner
        assert not banner.isHidden()
        assert banner.text() == dead_history_backend.history_notice
        # The History page (constructed in the same window) read
        # the dead store as empty instead of raising.
        assert "session" in dead_history_backend.history_notice
    finally:
        window.close()


def test_history_page_reads_failed_store_as_empty(qapp, dead_history_backend):
    import sqlite3

    from argus.gui.manage_pages import HistoryPage

    history = dead_history_backend.history()

    def _corrupt(*args, **kwargs):
        raise sqlite3.DatabaseError("database disk image is malformed")

    history.summary = _corrupt  # type: ignore[method-assign]
    page = HistoryPage(dead_history_backend)  # __init__ calls refresh()
    assert "unavailable" in page.summary_label.text()
    assert page.table.rowCount() == 0


def test_entry_qt_self_check_with_dead_history(qapp, tmp_path, monkeypatch):
    """The packaged entry point's own launch proof
    (``--self-check-qt``) with history dead via the real default
    config location — the closest reproduction of the field
    failure this suite can build."""
    data_root = tmp_path / "argus-data"
    data_root.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    (data_root / "shared").write_text("a file, not a folder")
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder")
    (data_root / "argus-config.json").write_text(
        json.dumps(
            {
                "history_db": str(blocker / "history.db"),
                "onboarding_completed": True,
            }
        ),
        encoding="utf-8",
    )

    from argus.entry import run_self_check_qt

    assert run_self_check_qt() == 0
