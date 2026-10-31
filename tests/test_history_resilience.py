"""Launch resilience: scan history can never kill the app (v1.2.14).

Field failure behind this file: on the owner's Windows laptop the
GUI died at launch — PyInstaller's "Failed to execute script
'launch_argus'" over a raw ``sqlite3.OperationalError: unable to
open database file``. The chain was MainWindow construction →
dashboard refresh → ``GuiBackend.dashboard_numbers`` →
``GuiBackend.history`` (unguarded) → ``History.open``, where the
``sqlite3.connect`` sat OUTSIDE the module's error translation, so
an unopenable history file escaped as a raw database error.

Two layers are pinned here:

- ``argus.reporting`` — EVERY open-phase failure (folder creation,
  connect, schema setup) is translated to :class:`HistoryError`
  naming the path and the cause. No raw ``sqlite3.Error`` /
  ``OSError`` may escape ``History.open``.
- ``argus.gui.backend`` — the GUI opens history through a recovery
  ladder (configured location → standard app-data location →
  in-memory for the session), logs each rung, and surfaces a
  plain-language ``history_notice`` whenever it had to move. The
  dashboard reads a failed store as honest zeroes.

The GUI-window half of the proof (real MainWindow construction with
history forced dead) lives in test_history_resilience_gui.py.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

pytest.importorskip("PySide6", reason="PySide6 not installed — backend tests skip")

from argus.reporting import History, HistoryError  # noqa: E402


# ----------------------------------------------------------------------
# Layer 1 — History.open translates every open-phase failure
# ----------------------------------------------------------------------
def test_open_parent_is_a_file_raises_history_error(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder")
    target = blocker / "history.db"
    with pytest.raises(HistoryError) as caught:
        History.open(target)
    assert str(target) in str(caught.value)
    assert not isinstance(caught.value, sqlite3.Error)
    assert not isinstance(caught.value, OSError)


def test_open_connect_failure_is_translated(tmp_path, monkeypatch):
    def _boom(*args, **kwargs):
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(sqlite3, "connect", _boom)
    with pytest.raises(HistoryError) as caught:
        History.open(tmp_path / "history.db")
    assert "unable to open database file" in str(caught.value)


def test_open_folder_creation_failure_is_translated(tmp_path, monkeypatch):
    from pathlib import Path

    def _denied(self, *args, **kwargs):
        raise PermissionError("access denied (Controlled Folder Access)")

    monkeypatch.setattr(Path, "mkdir", _denied)
    target = tmp_path / "missing" / "history.db"
    with pytest.raises(HistoryError) as caught:
        History.open(target)
    assert str(target) in str(caught.value)
    assert "access denied" in str(caught.value)


def test_open_corrupt_file_is_translated(tmp_path):
    target = tmp_path / "history.db"
    target.write_bytes(b"this is not a sqlite database at all" * 8)
    with pytest.raises(HistoryError):
        History.open(target)


def test_open_memory_history_works():
    with History.open(":memory:") as history:
        scan_id = history.record_scan(kind="ondemand", root="x")
        assert scan_id >= 1
        assert history.summary(days=7)["scans"] == 1


# ----------------------------------------------------------------------
# Layer 2 — the backend recovery ladder
# ----------------------------------------------------------------------
@pytest.fixture()
def backend_factory(tmp_path, monkeypatch):
    """Build GuiBackends rooted entirely in tmp_path.

    The data root is a dedicated subfolder (the smoke suite's
    convention). ``config`` is written as the real config file the
    backend loads, so a stale ``history_db`` value arrives exactly
    the way an older install would leave it.
    """
    data_root = tmp_path / "argus-data"
    data_root.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))

    from argus.gui.backend import GuiBackend

    def _make(config: dict | None = None) -> GuiBackend:
        config_path = tmp_path / "argus-config.json"
        if config is not None:
            config_path.write_text(json.dumps(config), encoding="utf-8")
        return GuiBackend(
            config_path=config_path,
            devtools_path=tmp_path / "devtools.json",
        )

    return _make, data_root


def _blocked_db_path(tmp_path):
    """A history path that can never open: its parent is a FILE."""
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder")
    return blocker / "history.db"


def test_ladder_falls_back_to_standard_location(backend_factory, tmp_path):
    make, data_root = backend_factory
    bad = _blocked_db_path(tmp_path)
    backend = make({"history_db": str(bad)})
    try:
        history = backend.history()  # must not raise
        standard = data_root / "shared" / "history.db"
        assert backend.history_path == standard
        assert history.path == standard
        assert backend.history_notice is not None
        assert str(bad) in backend.history_notice
        # The fallback store is a real, working store.
        history.record_scan(kind="ondemand", root="x")
        assert history.summary(days=7)["scans"] == 1
        assert standard.is_file()
    finally:
        backend.close()


def test_ladder_falls_back_to_memory_when_no_file_opens(
    backend_factory, tmp_path
):
    make, data_root = backend_factory
    # The standard location is dead too: "shared" exists as a FILE,
    # so the standard history path's parent is not a folder.
    (data_root / "shared").write_text("a file, not a folder")
    bad = _blocked_db_path(tmp_path)
    backend = make({"history_db": str(bad)})
    try:
        history = backend.history()  # must not raise
        assert backend.history_path is None
        assert backend.history_notice is not None
        assert "session" in backend.history_notice
        # Session history still records and reads back.
        history.record_scan(kind="ondemand", root="x")
        assert history.summary(days=7)["scans"] == 1
    finally:
        backend.close()


def test_working_configured_path_is_never_overridden(
    backend_factory, tmp_path
):
    make, data_root = backend_factory
    custom = tmp_path / "custom" / "my-history.db"
    backend = make({"history_db": str(custom)})
    try:
        backend.history()
        assert backend.history_path == custom
        assert backend.history_notice is None
        assert custom.is_file()
        assert not (data_root / "shared" / "history.db").exists()
    finally:
        backend.close()


def test_default_location_opens_clean(backend_factory):
    make, data_root = backend_factory
    backend = make()
    try:
        backend.history()
        assert backend.history_path == data_root / "shared" / "history.db"
        assert backend.history_notice is None
    finally:
        backend.close()


def test_dashboard_numbers_survive_dead_history(backend_factory, tmp_path):
    make, data_root = backend_factory
    (data_root / "shared").write_text("a file, not a folder")
    backend = make({"history_db": str(_blocked_db_path(tmp_path))})
    try:
        numbers = backend.dashboard_numbers()  # the launch-killer call
        assert numbers["detections_7d"] == 0
        assert numbers["scans_7d"] == 0
        assert numbers["files_scanned_7d"] == 0
        assert numbers["last_scan"] is None
        assert backend.history_notice is not None
    finally:
        backend.close()


def test_dashboard_numbers_zeroed_when_history_reads_fail(
    backend_factory, monkeypatch
):
    make, _data_root = backend_factory
    backend = make()
    try:
        history = backend.history()

        def _corrupt(*args, **kwargs):
            raise sqlite3.DatabaseError("database disk image is malformed")

        monkeypatch.setattr(history, "summary", _corrupt)
        numbers = backend.dashboard_numbers()  # must not raise
        assert numbers["detections_7d"] == 0
        assert numbers["scans_7d"] == 0
        assert numbers["last_scan"] is None
        assert numbers["summary"]["detections"] == 0
        assert backend.history_notice is not None
    finally:
        backend.close()


def test_actions_engine_gets_the_recovered_history(backend_factory, tmp_path):
    """actions() also calls history() — it receives the ladder's
    recovered store, not a raise."""
    make, data_root = backend_factory
    backend = make({"history_db": str(_blocked_db_path(tmp_path))})
    try:
        engine = backend.actions()  # must not raise
        assert engine.history is backend.history()
        assert backend.history_path == data_root / "shared" / "history.db"
    finally:
        backend.close()
