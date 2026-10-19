"""The setup and uninstall flows of the one-executable product.

These run in their own (elevated) process: the GUI relaunches the
same Argus.exe with ``--run-setup`` or ``--uninstall`` and Windows
shows its one familiar permission prompt. What the person sees
here is deliberately tiny — a short progress window that tells the
truth step by step, then either "you're protected" or one plain
sentence about what went wrong and what to do next. Technical
detail goes to the setup result file and the log, never the
screen.

The uninstall flow mirrors it: one plain confirmation (with the
data choice as an explicit, defaulted-off checkbox), progress,
done — including the honest note when the program file itself can
only be deleted at the next restart because this very process is
running from it.
"""

from __future__ import annotations

import logging
import threading

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from .. import setup_engine
from ..setup_engine import SetupError
from . import theme


def _themed_app() -> QApplication:
    """The QApplication for the setup/uninstall flows, with the
    full Argus theme applied. These flows run in their own
    process, separate from the main GUI — without this they came
    up in the default light Windows palette while the rest of
    Argus is dark (the v1.1.0 theme defect)."""
    app = QApplication.instance() or QApplication([])
    theme.apply_theme(app)
    return app

log = logging.getLogger("argus.setup")

STEP_LABELS = {
    setup_engine.STEP_PLACING: "Putting Argus in place…",
    setup_engine.STEP_SECURING: "Securing Argus's folders…",
    setup_engine.STEP_INSTALLING: "Setting up always-on protection…",
    setup_engine.STEP_REGISTERING: "Telling Windows Security about Argus…",
    setup_engine.STEP_STARTING: "Starting protection…",
    setup_engine.STEP_VERIFYING: "Checking that protection is really on…",
    "removing-service": "Turning off always-on protection…",
    "unregistering": "Telling Windows Security Argus is leaving…",
    "removing-data": "Removing Argus's data…",
    "removing-program": "Removing the Argus program…",
}


class _Bridge(QObject):
    step = Signal(str)
    finished = Signal(object)  # result object or SetupError


class ProgressDialog(QDialog):
    """One label, one status line, one button that enables at the
    end. Nothing else — a non-technical person should never have to
    wonder what this window wants from them.

    Close-hardened (P2): while the work is running, the window
    cannot be closed — not by the X, not by Esc. Closing mid-setup
    would strand the machine in exactly the half-set-up state the
    resumable engine then has to heal, and a person who clicked
    the X by accident deserves a sentence explaining why nothing
    happened, not a vanished window and a half install. A close
    attempt during the run is ignored and the status line says so,
    honestly. Once the work finishes (ok or error), closing works.
    """

    def __init__(self, title: str, first_line: str, parent=None):
        super().__init__(parent)
        self._running = True
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        self.heading = QLabel(first_line)
        self.heading.setWordWrap(True)
        self.heading.setObjectName("Headline")
        layout.addWidget(self.heading)
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("Subhead")
        layout.addWidget(self.status_label)
        self.done_button = QPushButton("Done")
        self.done_button.setObjectName("Primary")
        self.done_button.setEnabled(False)
        self.done_button.clicked.connect(self.accept)
        layout.addWidget(self.done_button)

    def show_step(self, step_key: str) -> None:
        self.status_label.setText(STEP_LABELS.get(step_key, "Working…"))

    @property
    def running(self) -> bool:
        return self._running

    def _defer_close(self) -> None:
        self.status_label.setText(
            "Still working — please wait for this to finish. "
            "Closing now could leave Argus half set up."
        )

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt name)
        if self._running:
            event.ignore()
            self._defer_close()
            return
        super().closeEvent(event)

    def reject(self) -> None:
        # Esc / reject() gets the same treatment as the X.
        if self._running:
            self._defer_close()
            return
        super().reject()

    def finish_ok(self, message: str) -> None:
        self._running = False
        self.heading.setText(message)
        self.status_label.setText("")
        self.done_button.setEnabled(True)

    def finish_error(self, message: str) -> None:
        self._running = False
        self.heading.setText("Something needs your attention")
        self.status_label.setText(message)
        self.done_button.setText("Close")
        self.done_button.setEnabled(True)


def _write_result_safe(payload: dict) -> None:
    """Write the setup result hand-off file, guarded (P2): the
    result file is how the GUI learns the outcome, but a failure
    to write it (folder locked, disk full) must never throw past
    the progress dialog and mask the outcome itself — it is
    logged, and the dialog the person is looking at still tells
    them the truth directly."""
    try:
        setup_engine.write_setup_result(payload)
    except Exception:
        log.exception("could not write the setup result file")


def _run_with_progress(title, first_line, work, on_result) -> int:
    """Run *work(progress_callback)* off the UI thread behind a
    ProgressDialog; *on_result(result, error)* runs on the UI
    thread when it ends. Returns the dialog's exit code path."""
    app = _themed_app()
    dialog = ProgressDialog(title, first_line)
    bridge = _Bridge()

    def _dispatch(payload):
        result, error = payload
        on_result(dialog, result, error)

    bridge.step.connect(dialog.show_step)
    bridge.finished.connect(_dispatch)

    def target():
        try:
            result = work(bridge.step.emit)
        except SetupError as exc:
            bridge.finished.emit((None, exc))
        except Exception as exc:  # never a traceback window
            log.exception("setup flow failed unexpectedly")
            bridge.finished.emit(
                (
                    None,
                    SetupError(
                        "Something unexpected went wrong. Try again; "
                        "if it keeps happening, contact Sentinel "
                        "Safeguard.",
                        detail=repr(exc),
                    ),
                )
            )
        else:
            bridge.finished.emit((result, None))

    threading.Thread(target=target, name="argus-setup", daemon=True).start()
    dialog.show()
    return app.exec()


def run_setup() -> int:
    """``--run-setup``: the elevated half of "Set up protection"."""
    if not setup_engine.is_elevated():
        # The GUI normally arranges elevation before relaunching;
        # if this process still isn't elevated, ask once more —
        # and if the person says no, leave the designed result the
        # GUI knows how to show.
        if setup_engine.relaunch_as_admin(["--run-setup"]):
            return 0
        _write_result_safe(
            {
                "ok": False,
                "needs_permission": True,
                "message": (
                    "Argus needs your permission to finish setting "
                    "up. Choose “Set up protection” and allow the "
                    "Windows prompt to continue."
                ),
                "detail": "elevation declined before setup started",
            }
        )
        return 1

    def work(progress):
        return setup_engine.install(progress=progress)

    def on_result(dialog, result, error):
        if error is not None:
            _write_result_safe(
                {
                    "ok": False,
                    "message": error.user_message,
                    "detail": error.detail,
                }
            )
            log.error("setup failed: %s (%s)", error.user_message, error.detail)
            dialog.finish_error(error.user_message)
            return
        _write_result_safe(
            {"ok": True, "state": result.state.value, "message": "You're protected."}
        )
        dialog.finish_ok("All done — you're protected.")

    return _run_with_progress(
        "Setting up ARGUS.EXE", "Setting up protection…", work, on_result
    )


def run_uninstall() -> int:
    """``--uninstall``: confirm plainly, then remove Argus."""
    if not setup_engine.is_elevated():
        # Declining the prompt simply aborts the uninstall — the
        # normal Windows behavior, nothing to explain.
        setup_engine.relaunch_as_admin(["--uninstall"])
        return 0

    app = _themed_app()
    confirm = QDialog()
    confirm.setWindowTitle("Remove ARGUS.EXE")
    confirm.setMinimumWidth(440)
    layout = QVBoxLayout(confirm)
    heading = QLabel("Remove ARGUS.EXE from this PC?")
    heading.setObjectName("Headline")
    heading.setWordWrap(True)
    layout.addWidget(heading)
    body = QLabel(
        "Protection will stop, and Windows Security will no longer "
        "list Argus as this PC's antivirus. You can reinstall "
        "Argus at any time."
    )
    body.setWordWrap(True)
    body.setObjectName("Subhead")
    layout.addWidget(body)
    remove_data = QCheckBox(
        "Also remove my Argus data — quarantined files, scan "
        "history, and settings"
    )
    remove_data.setChecked(False)  # data is kept unless asked for
    layout.addWidget(remove_data)
    remove_button = QPushButton("Remove Argus")
    remove_button.setObjectName("Primary")
    cancel_button = QPushButton("Cancel")
    remove_button.clicked.connect(confirm.accept)
    cancel_button.clicked.connect(confirm.reject)
    layout.addWidget(remove_button)
    layout.addWidget(cancel_button)
    if confirm.exec() != QDialog.DialogCode.Accepted:
        return 0
    wipe = remove_data.isChecked()

    def work(progress):
        return setup_engine.uninstall(remove_data=wipe, progress=progress)

    def on_result(dialog, result, error):
        if error is not None:
            log.error(
                "uninstall failed: %s (%s)", error.user_message, error.detail
            )
            dialog.finish_error(error.user_message)
            return
        message = "Argus has been removed."
        if result.leftovers:
            message += "\n\n" + "\n".join(result.leftovers) + "."
        dialog.finish_ok(message)

    return _run_with_progress(
        "Removing ARGUS.EXE", "Removing Argus…", work, on_result
    )
