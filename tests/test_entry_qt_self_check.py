"""Tests for the Qt self-check (argus.entry.run_self_check_qt).

``--self-check`` proves the packaged build can IMPORT PySide6;
``--self-check-qt`` proves it can START: Qt loads its platform
plugin only when a QApplication is created, so a frozen build can
pass the import census and still die on launch. The release
pipeline runs both. These tests pin the routing, the staged
failure messages, and — in the GUI environment — a real
construction of the application, theme, and main window.
"""

import pytest

from argus.entry import main, route_invocation, run_self_check_qt


# -- routing ---------------------------------------------------------

def test_route_self_check_qt():
    assert route_invocation(["--self-check-qt"]) == "self-check-qt"


def test_route_plain_self_check_unchanged():
    assert route_invocation(["--self-check"]) == "self-check"


def test_route_self_check_qt_marker_is_exact():
    # A lookalike word must not route into the Qt check.
    assert route_invocation(["--self-check-qt2"]) == "gui"
    assert route_invocation(["self-check-qt"]) == "gui"


# -- the check itself, through the injectable seam -------------------

class _FakeApp:
    def __init__(self):
        self.events_processed = 0

    def processEvents(self):
        self.events_processed += 1


class _FakeWindow:
    def __init__(self):
        self.shown = False
        self.closed = False

    def show(self):
        self.shown = True

    def close(self):
        self.closed = True


def test_self_check_qt_success_builds_shows_and_closes():
    app = _FakeApp()
    window = _FakeWindow()
    rc = run_self_check_qt(
        app_factory=lambda: app,
        window_factory=lambda created_app: window,
    )
    assert rc == 0
    assert window.shown is True
    assert window.closed is True
    assert app.events_processed >= 1


def test_self_check_qt_app_failure_is_nonzero_with_plain_message(capsys):
    def broken_app():
        raise RuntimeError("qt.qpa.plugin: could not load the platform plugin")

    rc = run_self_check_qt(
        app_factory=broken_app,
        window_factory=lambda app: _FakeWindow(),
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "Qt self-check FAILED" in err
    assert "could not load the platform plugin" in err


def test_self_check_qt_window_failure_is_nonzero_with_plain_message(capsys):
    def broken_window(app):
        raise ValueError("theme stylesheet would not parse")

    rc = run_self_check_qt(
        app_factory=_FakeApp,
        window_factory=broken_window,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "Qt self-check FAILED" in err
    assert "main window could not be built" in err


def test_self_check_qt_show_failure_is_nonzero(capsys):
    class _ExplodingWindow(_FakeWindow):
        def show(self):
            raise RuntimeError("no screen available")

    rc = run_self_check_qt(
        app_factory=_FakeApp,
        window_factory=lambda app: _ExplodingWindow(),
    )
    assert rc == 1
    assert "Qt self-check FAILED" in capsys.readouterr().err


def test_main_dispatches_self_check_qt(monkeypatch):
    import argus.entry as entry

    monkeypatch.setattr(entry, "run_self_check_qt", lambda: 7)
    assert main(["--self-check-qt"]) == 7


def test_main_plain_self_check_still_dispatches_to_import_census(monkeypatch):
    import argus.entry as entry

    monkeypatch.setattr(entry, "run_self_check", lambda: 3)
    monkeypatch.setattr(
        entry, "run_self_check_qt", lambda: pytest.fail("wrong check ran")
    )
    assert main(["--self-check"]) == 3


# -- the real stack (GUI environment only) ----------------------------

def test_self_check_qt_real_constructs_application_and_main_window(
    tmp_path, monkeypatch
):
    pytest.importorskip("PySide6")
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    # Isolate the backend's first-run files (config, signature DB)
    # in the test's temp dir, like the GUI smoke fixture does.
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    assert run_self_check_qt() == 0
