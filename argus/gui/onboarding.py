"""First-run onboarding wizard.

Shown exactly once — until the config's ``onboarding_completed``
flag is set. Four plain steps: what Argus is, which folders to
watch, how Argus should respond when it finds something, and a
chance to prove detection works with the EICAR self-test before
finishing.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QLabel,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from ..config import ArgusConfig
from ..devtools import run_self_test
from .backend import GuiBackend
from .format import policy_plain_language

POLICY_OPTIONS = (
    ("ask", "Ask me every time"),
    ("auto-quarantine-critical", "Quarantine Critical threats automatically"),
    ("log-only", "Just record it — never touch files"),
)


def needs_onboarding(config: ArgusConfig) -> bool:
    """The wizard shows until the user has completed it once."""
    return not config.onboarding_completed


class OnboardingWizard(QWizard):
    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        self.setWindowTitle("Welcome to ARGUS.EXE")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(560, 420)

        self.addPage(self._welcome_page())
        self._folder_checks = self._folders_page()
        self.addPage(self._folder_checks[0])
        self._policy_radios = self._policy_page()
        self.addPage(self._policy_radios[0])
        self.addPage(self._selftest_page())
        self.finished.connect(self._on_finished)

    # -- pages ---------------------------------------------------------
    def _welcome_page(self) -> QWizardPage:
        page = QWizardPage()
        page.setTitle("All eyes. All detection.")
        layout = QVBoxLayout(page)
        body = QLabel(
            "ARGUS.EXE is Sentinel Safeguard's antivirus, and it is "
            "now this computer's watchman.\n\n"
            "It checks files three ways: fingerprints of known "
            "threats, pattern rules, and behavior analysis that "
            "scores what a program looks like it is trying to do. "
            "Real-time protection watches the folders threats land "
            "in, so new files are checked the moment they appear.\n\n"
            "This short setup asks three things: where to watch, "
            "what to do when something is found, and proof that "
            "detection works."
        )
        body.setWordWrap(True)
        layout.addWidget(body)
        return page

    def _folders_page(self) -> tuple[QWizardPage, list[QCheckBox]]:
        page = QWizardPage()
        page.setTitle("Where should Argus watch?")
        layout = QVBoxLayout(page)
        intro = QLabel(
            "These are the folders threats usually arrive in. "
            "Watching more folders means earlier warnings; you can "
            "change this later in Settings."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        from ..config import default_watch_dirs

        checks: list[QCheckBox] = []
        for folder in default_watch_dirs():
            box = QCheckBox(str(folder))
            box.setChecked(True)  # the recommended set starts checked
            checks.append(box)
            layout.addWidget(box)
        return page, checks

    def _policy_page(self) -> tuple[QWizardPage, list[QRadioButton]]:
        page = QWizardPage()
        page.setTitle("When Argus finds something, it should…")
        layout = QVBoxLayout(page)
        radios: list[QRadioButton] = []
        for policy, label in POLICY_OPTIONS:
            radio = QRadioButton(f"{label} — {policy_plain_language(policy)}")
            radio.setChecked(policy == self._backend.config.realtime_default)
            radios.append(radio)
            layout.addWidget(radio)
        note = QLabel(
            "One promise, whatever you pick: Argus never deletes a "
            "file on its own. Deleting always takes your explicit OK."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        return page, radios

    def _selftest_page(self) -> QWizardPage:
        page = QWizardPage()
        page.setTitle("Prove it works")
        layout = QVBoxLayout(page)
        intro = QLabel(
            "The EICAR test file is a harmless string that every "
            "antivirus is expected to catch. Run the self-test and "
            "Argus will write it to a scratch folder, scan it, and "
            "clean up — proving the whole pipeline works."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        button = QPushButton("Run the self-test")
        self.selftest_result = QLabel("Not run yet — recommended before you finish.")
        self.selftest_result.setWordWrap(True)
        button.clicked.connect(self._run_selftest)
        layout.addWidget(button)
        layout.addWidget(self.selftest_result)
        return page

    # -- behaviour -------------------------------------------------------
    def _run_selftest(self) -> None:
        result = run_self_test()
        detail = "\n".join(
            f"{'✓' if step.ok else '✗'} {step.name}: {step.detail}"
            for step in result.steps
        )
        self.selftest_result.setText(result.summary() + "\n" + detail)

    def chosen_policy(self) -> str:
        for radio, (policy, _label) in zip(self._policy_radios[1], POLICY_OPTIONS):
            if radio.isChecked():
                return policy
        return "ask"

    def chosen_watch_dirs(self) -> list[str]:
        return [
            box.text() for box in self._folder_checks[1] if box.isChecked()
        ]

    def apply(self) -> None:
        """Write the wizard's answers into the config and mark
        onboarding complete. Called on finish; also directly
        testable without driving the wizard UI."""
        config = self._backend.config
        chosen = self.chosen_watch_dirs()
        if chosen:
            config.watch_dirs = [Path(folder) for folder in chosen]
        config.realtime_default = self.chosen_policy()
        config.onboarding_completed = True
        self._backend.save_config()

    def _on_finished(self, result_code: int) -> None:
        if result_code == QWizard.DialogCode.Accepted:
            self.apply()
