"""GUI tests for the v1.1.0 one-executable setup states.

The dashboard is the whole first-run experience now: not set up →
one "Set up protection" button; set up but stopped → "Turn
protection on" starts the SERVICE (never a second in-process
engine against the installed layout — the v1.0.5 vault dead end);
permission declined → a designed message, not an error dump.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6", reason="PySide6 not installed — GUI tests skip")

from PySide6.QtWidgets import QApplication  # noqa: E402

from argus.signatures import init_db  # noqa: E402
from argus.setup_engine import SetupState  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture()
def backend(tmp_path, monkeypatch):
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
def controller(backend):
    from argus.gui.backend import ProtectionController

    return ProtectionController(backend)


@pytest.fixture()
def dashboard(qapp, backend, controller):
    from argus.gui.dashboard import DashboardPage

    page = DashboardPage(backend, controller)
    yield page
    page.close()


def _force_state(monkeypatch, controller, state):
    monkeypatch.setattr(controller, "setup_state", lambda: state)


# ----------------------------------------------------------------------
# Dashboard rendering of the setup states
# ----------------------------------------------------------------------
def test_dashboard_not_installed_shows_setup_state(
    qapp, dashboard, controller, monkeypatch
):
    _force_state(monkeypatch, controller, SetupState.NOT_INSTALLED)
    dashboard.set_status({"running": False, "state": "stopped"})
    assert "isn't set up yet" in dashboard.headline_label.text()
    assert dashboard.toggle_button.text() == "Set up protection"
    assert dashboard.toggle_button.isEnabled() is True
    assert dashboard.pause_button.isEnabled() is False
    # The one next step is explained, in plain words:
    assert "permission" in dashboard.detail_label.text()


def test_dashboard_toggle_in_setup_state_begins_setup(
    qapp, dashboard, controller, monkeypatch
):
    _force_state(monkeypatch, controller, SetupState.NOT_INSTALLED)
    began = []
    monkeypatch.setattr(
        controller, "begin_setup", lambda: began.append(True) or True
    )

    def bomb_start():  # pragma: no cover - must never be reached
        raise AssertionError("in-process start in the setup state")

    monkeypatch.setattr(controller, "start", bomb_start)
    dashboard.set_status({"running": False, "state": "stopped"})
    dashboard._toggle_protection()
    assert began == [True]


def test_dashboard_portable_keeps_in_window_controls(
    qapp, dashboard, controller, monkeypatch
):
    """Portable mode (ARGUS_DATA_DIR set, as in this fixture) is
    NOT the setup state: protection runs in this window, so the
    classic on/off controls stay."""
    _force_state(monkeypatch, controller, SetupState.PORTABLE)
    dashboard.set_status({"running": False, "state": "stopped"})
    assert dashboard.toggle_button.text() == "Turn protection on"
    assert dashboard.headline_label.text() == "Protection is off"


# ----------------------------------------------------------------------
# Controller routing: the service is started, never a local engine
# ----------------------------------------------------------------------
def test_turn_on_starts_service_not_in_process_engine(
    qapp, backend, controller, monkeypatch
):
    monkeypatch.setattr("argus.gui.backend.IS_WINDOWS", True)
    _force_state(monkeypatch, controller, SetupState.INSTALLED_STOPPED)
    started = []
    monkeypatch.setattr(
        "argus.setup_engine.start_service_elevated",
        lambda: started.append(True) or True,
    )

    def bomb_service(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("in-process engine started in installed layout")

    monkeypatch.setattr("argus.gui.backend.ArgusService", bomb_service)
    assert controller.start() is True
    assert started == [True]
    assert controller.running is False  # no local engine was kept


def test_start_in_not_installed_state_refuses_plainly(
    qapp, backend, controller, monkeypatch
):
    monkeypatch.setattr("argus.gui.backend.IS_WINDOWS", True)
    _force_state(monkeypatch, controller, SetupState.NOT_INSTALLED)
    failures = []
    controller.failed.connect(failures.append)

    def bomb_service(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("in-process engine started before setup")

    monkeypatch.setattr("argus.gui.backend.ArgusService", bomb_service)
    assert controller.start() is False
    (message,) = failures
    assert "Set up protection" in message
    assert "WinError" not in message and "[" not in message


def test_begin_setup_declined_prompt_is_a_designed_state(
    qapp, backend, controller, monkeypatch
):
    """UAC declined: no exception text, no dead end — a plain
    message that names the way forward (the same button)."""
    monkeypatch.setattr(
        "argus.setup_engine.relaunch_as_admin", lambda args: False
    )
    failures = []
    controller.failed.connect(failures.append)
    assert controller.begin_setup() is False
    (message,) = failures
    assert "permission" in message
    assert "Set up protection" in message


def test_begin_setup_accepted_prompt(qapp, backend, controller, monkeypatch):
    seen = []
    monkeypatch.setattr(
        "argus.setup_engine.relaunch_as_admin",
        lambda args: seen.append(list(args)) or True,
    )
    assert controller.begin_setup() is True
    assert seen == [["--run-setup"]]


# ----------------------------------------------------------------------
# The setup progress window itself
# ----------------------------------------------------------------------
def test_setup_progress_dialog_speaks_plainly(qapp):
    from argus.gui.setup_app import ProgressDialog

    dialog = ProgressDialog("Setting up ARGUS.EXE", "Setting up protection…")
    dialog.show_step("placing")
    assert dialog.status_label.text() == "Putting Argus in place…"
    dialog.show_step("verifying")
    assert "really on" in dialog.status_label.text()
    dialog.finish_error("Argus couldn't finish. Try again.")
    assert dialog.heading.text() == "Something needs your attention"
    assert dialog.status_label.text() == "Argus couldn't finish. Try again."
    assert dialog.done_button.isEnabled() is True
    dialog.close()
