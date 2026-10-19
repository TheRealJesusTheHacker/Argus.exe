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
    result = page.last_bench
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
