"""GUI smoke tests (Phase 5) — Qt offscreen.

These run the real widgets against a throwaway data dir: the main
window and every page construct, the dashboard renders a service
status, a scan finds the EICAR test file, the test bench scores a
fixture, and the onboarding flag flips exactly once. If PySide6 is
not installed, the whole module skips cleanly — the engine suite
must never depend on a GUI toolkit being present.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6", reason="PySide6 not installed — GUI tests skip")

from PySide6.QtWidgets import QApplication  # noqa: E402

from argus import devtools  # noqa: E402
from argus.signatures import init_db  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture()
def backend(tmp_path, monkeypatch):
    """A GuiBackend rooted entirely in tmp_path, with a seeded
    signature database wired into its config."""
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    from argus.gui.backend import GuiBackend

    config_path = tmp_path / "argus-config.json"
    db_path = tmp_path / "signatures.sigdb"
    init_db(db_path, seed=True)
    gui_backend = GuiBackend(
        config_path=config_path,
        devtools_path=tmp_path / "devtools.json",
    )
    gui_backend.config.signature_db = str(db_path)
    gui_backend.config.watch_dirs = [str(tmp_path)]
    gui_backend.config.vault_dir = str(tmp_path / "vault")
    gui_backend.config.history_db = str(tmp_path / "history.db")
    gui_backend.config.status_file = str(tmp_path / "status.json")
    gui_backend.save_config()
    yield gui_backend
    gui_backend.close()


@pytest.fixture()
def window(qapp, backend):
    from argus.gui.main_window import MainWindow

    win = MainWindow(backend)
    yield win
    win.close()


def test_gui_package_imports_without_qt_side_effects():
    import argus.gui

    assert argus.gui.is_available() is True
    assert argus.gui.main is not None


def test_main_window_constructs_all_pages(window):
    from argus.gui.main_window import PAGE_NAMES

    assert window.stack.count() == len(PAGE_NAMES) == 7
    for name in PAGE_NAMES:
        window.show_page(name)  # every page activates without error
    assert window.dashboard is not None
    assert window.devkit_page is not None


def test_dashboard_renders_protection_status(window):
    window.dashboard.set_status(
        {
            "running": True,
            "paused": False,
            "state": "running",
            "watch_dirs": ["/home/user/Downloads"],
            "pending_actions": 0,
        }
    )
    assert "protected" in window.dashboard.headline_label.text().lower()
    window.dashboard.set_status({"running": False, "state": "stopped"})
    assert "off" in window.dashboard.headline_label.text().lower()


def test_scan_worker_finds_eicar(qapp, backend, tmp_path):
    from argus.gui.backend import ScanWorker

    target_dir = tmp_path / "landing"
    target_dir.mkdir()
    (target_dir / "eicar-test.txt").write_bytes(devtools.EICAR_BYTES)
    (target_dir / "notes.txt").write_text("perfectly ordinary text")

    worker = ScanWorker(backend)
    summary = worker.execute([target_dir])
    assert summary["detections"] == 1
    flagged_paths = [row["path"] for row in summary["flagged"]]
    assert any("eicar" in p for p in flagged_paths)
    row = next(r for r in summary["flagged"] if "eicar" in r["path"])
    assert row["verdict"] == "Malicious"
    assert row["severity"] == "high"  # the engine's seeded EICAR severity


def test_scan_page_records_history(qapp, backend, tmp_path, window):
    target_dir = tmp_path / "landing2"
    target_dir.mkdir()
    (target_dir / "eicar-test.txt").write_bytes(devtools.EICAR_BYTES)
    from argus.gui.backend import ScanWorker

    worker = ScanWorker(backend)
    summary = worker.execute([target_dir])
    window.scan_page._on_finished(summary)
    numbers = backend.dashboard_numbers()
    assert numbers["detections_7d"] == 1
    assert numbers["scans_7d"] == 1


def test_bench_page_scores_powershell_fixture(qapp, backend, tmp_path, window):
    fixture = tmp_path / "dropper.ps1"
    fixture.write_bytes(b"powershell -enc " + b"A" * 80 + b"\n")
    page = window.devkit_page
    page.bench_path_edit.setText(str(fixture))
    page._run_bench()
    # The bench runs OFF the UI thread (fix #24) so dissecting a
    # file can never freeze the window. Drive the event loop while
    # waiting — the worker's completion signal is delivered through
    # it (a bare blocking wait() would starve exactly that loop).
    import time

    deadline = time.monotonic() + 15
    while page.last_bench is None and time.monotonic() < deadline:
        qapp.processEvents()
        if page._bench_thread is not None:
            page._bench_thread.wait(50)
    result = page.last_bench
    assert result is not None
    assert result.verdict in ("Suspicious", "Malicious")
    names = {s.name for s in result.signals}
    assert "encoded_powershell_command" in names
    assert page.bench_ring.score() == result.score


def test_quarantine_and_pending_pages_render_real_data(qapp, backend, tmp_path, window):
    """Exercise the vault pages against a real quarantined file —
    catches field drift between the engine dataclasses and the GUI.
    Pages are used through the main window, as in the real app."""
    from argus.actions import DetectionInfo

    suspect = tmp_path / "suspect.exe"
    suspect.write_bytes(b"MZ pretend malware")
    info = DetectionInfo(
        name="Test.Threat", severity="high", verdict="Malicious"
    )
    outcome = backend.real_actions().quarantine(suspect, info, confirmed=True)
    assert outcome.done and outcome.entry_id

    window.show_page("Quarantine")  # navigation refreshes the page
    page = window.quarantine_page
    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == "suspect.exe"
    assert "1 file(s)" in page.status_label.text()

    window.show_page("Pending Actions")
    assert window.pending_page.table.rowCount() == 0  # nothing pending here


def test_devkit_simulation_toggle_saves(qapp, backend, window):
    page = window.devkit_page
    page.sim_toggle.set_checked(True, emit=True)
    assert backend.dev.simulation_mode is True
    assert backend.simulation_mode is True
    # The backend now hands out the simulated engine.
    from argus.devtools import SimulatedActionEngine

    assert isinstance(backend.actions(), SimulatedActionEngine)


def _fresh_gui_backend(tmp_path):
    """A bare GuiBackend like the onboarding fixture, without the
    pre-saved config — onboarding starts from defaults."""
    from argus.gui.backend import GuiBackend

    return GuiBackend(
        config_path=tmp_path / "cfg.json",
        devtools_path=tmp_path / "dev.json",
    )


def test_onboarding_flag_shown_once(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    from argus.config import ArgusConfig
    from argus.gui.onboarding import OnboardingWizard, needs_onboarding

    backend = _fresh_gui_backend(tmp_path)
    assert backend.config.onboarding_completed is False
    assert needs_onboarding(backend.config) is True

    wizard = OnboardingWizard(backend)
    wizard.apply()  # what finishing the wizard does
    assert backend.config.onboarding_completed is True

    reloaded = ArgusConfig.load(tmp_path / "cfg.json")
    assert reloaded.onboarding_completed is True
    assert needs_onboarding(reloaded) is False
    backend.close()


# ----------------------------------------------------------------------
# v1.0.2 fix-pass GUI regressions
# ----------------------------------------------------------------------

def test_tray_notification_uses_real_event_keys(qapp, backend):
    """Fix #6: RealtimeEvent.to_dict() emits kind/message/severity —
    the tray used to read type/detection_name/outcome (keys that
    never exist), so notifications could never fire."""
    from datetime import datetime, timezone

    from argus.gui.tray import TrayController as ArgusTray
    from argus.realtime import RealtimeEvent

    tray = ArgusTray()
    alerts = []
    tray.alert = lambda: alerts.append("alert")  # observe the branch taken
    event = RealtimeEvent(
        kind="detection",
        message="Argus flagged evil.exe as Malicious.",
        path="evil.exe",
        verdict="Malicious",
        severity="critical",
    )
    tray.notify_detection(event.to_dict())  # must not raise
    assert alerts == ["alert"]  # the detection branch actually fired
    # An action event with a plain dict in the real shape works too:
    tray.notify_detection(
        {
            "kind": "action",
            "message": "Argus wants to quarantine evil.exe.",
            "severity": "high",
            "action": "quarantine",
            "path": "evil.exe",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def test_tray_initial_state_reflects_protection(qapp, backend, window):
    """Fix #26: the tray is set from protection.status() at startup,
    not left in its construction default until the first change."""
    assert "off" in window.tray.tray.toolTip().lower()


def test_dashboard_service_managed_disables_toggle(qapp, backend, window, monkeypatch):
    """Fix #8: a live external (Windows service) heartbeat means
    protection is service-managed — the dashboard must not offer to
    start a second engine next to it.

    Since the v1.0.4 heartbeat-trust fix, the heartbeat alone is
    not enough on Windows: the SCM must also confirm the service
    is running (see the companion test below). This test simulates
    exactly that confirmation. ``service_managed()`` imports
    ``query_service_state`` lazily from ``argus.winservice`` at
    call time, so that module attribute is the patch seam; forcing
    ``IS_WINDOWS`` on makes the gate run on every platform (on a
    real Windows machine it already has that value, so the patch
    only matters off Windows — where the pre-fix test silently
    took the trusting path and then failed on Windows CI, which
    has no ArgusProtection service installed)."""
    from datetime import datetime, timezone

    monkeypatch.setattr(
        "argus.winservice.query_service_state", lambda *a, **k: "running"
    )
    monkeypatch.setattr("argus.gui.backend.IS_WINDOWS", True)

    status = {
        "running": True,
        "paused": False,
        "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        "state": "running",
    }
    assert window.protection.service_managed(status) is True
    window.dashboard.set_status(status)
    assert window.dashboard.toggle_button.isEnabled() is False
    assert "Windows service" in window.dashboard.toggle_button.text()
    # A stale heartbeat is a dead service, not a managing one:
    stale = dict(status, heartbeat_at="2020-01-01T00:00:00+00:00")
    assert window.protection.service_managed(stale) is False
    # And no heartbeat at all (plain dicts/tests) is not managed:
    plain = {"running": True, "paused": False}
    assert window.protection.service_managed(plain) is False


def test_dashboard_service_managed_requires_scm_confirmation(
    qapp, backend, window, monkeypatch
):
    """Spoofing regression (v1.0.4 P0): the status file lives in a
    user-writable shared folder, so ANY process could write a
    fresh "running" heartbeat. On Windows a fresh heartbeat must
    therefore count for nothing unless the Service Control
    Manager confirms ArgusProtection is actually running — if the
    SCM says the service is stopped, absent, or cannot be queried,
    protection is NOT service-managed."""
    from datetime import datetime, timezone

    monkeypatch.setattr("argus.gui.backend.IS_WINDOWS", True)
    status = {
        "running": True,
        "paused": False,
        "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        "state": "running",
    }
    for scm_state in ("stopped", "not-installed", False):
        monkeypatch.setattr(
            "argus.winservice.query_service_state",
            lambda *a, _state=scm_state, **k: _state,
        )
        assert window.protection.service_managed(status) is False
    # The same heartbeat, with the SCM confirming the service is
    # running, is service-managed:
    monkeypatch.setattr(
        "argus.winservice.query_service_state", lambda *a, **k: "running"
    )
    assert window.protection.service_managed(status) is True


def test_pending_reject_does_not_crash(qapp, backend, tmp_path, window, monkeypatch):
    """Fix #5: reject() returns a PendingAction, which has no
    .message — the page used to crash reading it."""
    vault = backend.vault()
    pending = vault.add_pending(
        source="realtime",
        path=str(tmp_path / "evil.exe"),
        action="quarantine",
        sha256="0" * 64,
        severity="high",
        verdict="Malicious",
        detection_name="Test.Detection",
        reasons=["looked bad"],
    )
    page = window.pending_page
    page.refresh()
    assert page.table.rowCount() == 1
    page.table.selectRow(0)
    monkeypatch.setattr("argus.gui.manage_pages._confirm", lambda *a, **k: True)
    page._act("reject")
    assert "Rejected" in page.status_label.text()
    assert vault.get_pending(pending.id).status == "rejected"


def test_quarantine_page_simulation_records_intent_only(
    qapp, backend, tmp_path, window, monkeypatch
):
    """Fix #7: with Dev Toolkit simulation mode on, the Quarantine
    page's restore/delete go through the simulated engine — intent
    is recorded, the vault is never touched."""
    vault = backend.vault()
    target = tmp_path / "evil.exe"
    target.write_bytes(b"MZ" + b"x" * 64)
    entry = vault.quarantine_file(
        target, detection_name="Test.Detection", severity="high"
    )
    backend.dev.simulation_mode = True
    page = window.quarantine_page
    page.refresh()
    page.table.selectRow(0)
    monkeypatch.setattr("argus.gui.manage_pages._confirm", lambda *a, **k: True)
    page._act("restore")
    assert "Simulation mode is on" in page.status_label.text()
    assert vault.get_entry(entry.id).status == "quarantined"
    sim = backend.actions()  # the same simulated engine the page used
    assert [r.action for r in sim.records] == ["restore"]
    page._act("delete")
    assert vault.get_entry(entry.id).status == "quarantined"
    assert [r.action for r in sim.records] == [
        "restore",
        "delete",
    ]


def test_protection_start_refused_in_simulation(qapp, backend, window):
    """v1.0.4 sim honesty: with Dev Toolkit simulation mode on,
    ProtectionController.start refuses to start REAL protection
    (which would move files) and explains why, in plain language."""
    backend.dev.simulation_mode = True
    failures: list[str] = []
    window.protection.failed.connect(failures.append)
    assert window.protection.start() is False
    assert failures and "Simulation mode is on" in failures[0]
    assert window.protection.running is False


def test_pending_page_shows_fingerprint_and_source(
    qapp, backend, tmp_path, window
):
    """v1.0.4 approval safety: the Pending page table shows the
    short SHA-256 and the source alongside the action."""
    vault = backend.vault()
    vault.add_pending(
        source="realtime",
        path=str(tmp_path / "evil.exe"),
        action="quarantine",
        sha256="abcdef0123456789" + "0" * 48,
        severity="high",
        verdict="Malicious",
        detection_name="Test.Detection",
        reasons=["looked bad"],
    )
    page = window.pending_page
    page.refresh()
    assert page.table.rowCount() == 1
    assert page.table.item(0, 4).text().startswith("abcdef012345")
    assert page.table.item(0, 5).text() == "realtime"


def test_extract_page_argument():
    """Fix #22: --page selects the start page (the Dev Toolkit
    shortcut passes '--page devtoolkit') and is stripped from the
    argv handed to QApplication."""
    from argus.gui.app import extract_page_argument

    argv, page = extract_page_argument(["argus", "--page", "devtoolkit"])
    assert argv == ["argus"]
    assert page == "Dev Toolkit"
    argv, page = extract_page_argument(["argus", "--page", "Scan"])
    assert page == "Scan"
    argv, page = extract_page_argument(["argus"])
    assert argv == ["argus"] and page is None
    # An unrecognized page is consumed quietly — never a crash:
    argv, page = extract_page_argument(["argus", "--page", "nonsense"])
    assert argv == ["argus"] and page is None


def test_full_scan_roots_never_double_home(qapp, backend):
    """Fix #21: a full scan walks the filesystem anchor OR home,
    never both (home lives inside the anchor)."""
    roots = backend.full_scan_roots()
    assert len(roots) == 1
