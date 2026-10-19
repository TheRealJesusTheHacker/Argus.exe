"""Settings page and the Dev Toolkit page.

Settings edits the real protection config (watch folders, real-time
policy, exclusions, size caps) and saves through ArgusConfig, so the
GUI, CLI, and service all read the same answers.

The Dev Toolkit is the workbench: sensitivity, per-signal steering,
simulation mode, the rule test bench, the EICAR self-test, verbose
logging, and the live log. Everything it shows comes from
:mod:`argus.devtools`; this page is the face, not the brain.
"""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSlider,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..devtools import (
    SIGNAL_CATALOG,
    LogCapture,
    apply_logging,
    run_self_test,
    run_test_bench,
)
from ..rules import BUILTIN_RULES
from ..signatures import SignatureDB
from . import theme
from .backend import GuiBackend, ProtectionController
from .format import policy_plain_language, score_band
from .widgets import ScoreRing, SeverityBadge, ToggleSwitch, severity_item

POLICIES = ("ask", "auto-quarantine-critical", "log-only")
_POLICY_LABELS = {
    "ask": "Ask me every time",
    "auto-quarantine-critical": "Auto-quarantine Critical threats",
    "log-only": "Log only (hands off)",
}


def _section(title: str) -> QLabel:
    label = QLabel(title)
    label.setObjectName("SectionTitle")
    return label


class SettingsPage(QWidget):
    def __init__(
        self,
        backend: GuiBackend,
        protection: ProtectionController | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._backend = backend
        self._protection = protection
        config = backend.config

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("Settings")
        title.setObjectName("Headline")
        layout.addWidget(title)

        # -- watch folders ------------------------------------------
        layout.addWidget(_section("Folders real-time protection watches"))
        self.watch_list = QListWidget()
        for folder in config.watch_dirs:
            self.watch_list.addItem(str(folder))
        layout.addWidget(self.watch_list)
        watch_buttons = QHBoxLayout()
        add_watch = QPushButton("Add folder…")
        add_watch.clicked.connect(self._add_watch_folder)
        remove_watch = QPushButton("Remove selected")
        remove_watch.clicked.connect(
            lambda: self._remove_selected(self.watch_list)
        )
        watch_buttons.addWidget(add_watch)
        watch_buttons.addWidget(remove_watch)
        watch_buttons.addStretch(1)
        layout.addLayout(watch_buttons)

        # -- behaviour ------------------------------------------------
        layout.addWidget(_section("When protection finds something"))
        form = QFormLayout()
        self.policy_combo = QComboBox()
        for policy in POLICIES:
            self.policy_combo.addItem(_POLICY_LABELS[policy], policy)
        index = self.policy_combo.findData(config.realtime_default)
        self.policy_combo.setCurrentIndex(max(0, index))
        self.policy_help = QLabel(policy_plain_language(config.realtime_default))
        self.policy_help.setWordWrap(True)
        self.policy_help.setObjectName("Subhead")
        self.policy_combo.currentIndexChanged.connect(
            lambda: self.policy_help.setText(
                policy_plain_language(self.policy_combo.currentData())
            )
        )
        form.addRow("Real-time response:", self.policy_combo)
        form.addRow("", self.policy_help)

        self.process_check = QCheckBox(
            "Also watch for programs starting (catches droppers early)"
        )
        self.process_check.setChecked(config.process_monitor_enabled)
        form.addRow("", self.process_check)
        self.heuristics_check = QCheckBox(
            "Use behavior analysis (heuristics) as well as known-threat "
            "fingerprints"
        )
        self.heuristics_check.setChecked(config.heuristics)
        form.addRow("", self.heuristics_check)

        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 4096)
        self.max_size_spin.setValue(
            max(1, config.max_realtime_file_size // (1024 * 1024))
        )
        self.max_size_spin.setSuffix(" MB")
        form.addRow("Largest file checked in real time:", self.max_size_spin)
        layout.addLayout(form)

        # -- exclusions ------------------------------------------------
        layout.addWidget(_section("Exclusions — files Argus leaves alone"))
        note = QLabel(
            "Excluding a file means trusting it. Only exclude files "
            "you know are safe."
        )
        note.setObjectName("Subhead")
        note.setWordWrap(True)
        layout.addWidget(note)
        paths_label = QLabel("Excluded folders/files:")
        layout.addWidget(paths_label)
        self.excl_paths = QListWidget()
        for path in config.exclusions.paths:
            self.excl_paths.addItem(path)
        layout.addWidget(self.excl_paths)
        excl_buttons = QHBoxLayout()
        add_path = QPushButton("Add file or folder…")
        # One button, both pickers: excluding a single FILE is just
        # as common as excluding a folder, so the button offers a
        # small menu rather than only ever opening the folder picker.
        add_menu = QMenu(add_path)
        add_file_action = add_menu.addAction("Add file…")
        add_file_action.triggered.connect(self._add_exclusion_file)
        add_folder_action = add_menu.addAction("Add folder…")
        add_folder_action.triggered.connect(self._add_exclusion_path)
        add_path.setMenu(add_menu)
        remove_path = QPushButton("Remove selected")
        remove_path.clicked.connect(
            lambda: self._remove_selected(self.excl_paths)
        )
        excl_buttons.addWidget(add_path)
        excl_buttons.addWidget(remove_path)
        excl_buttons.addStretch(1)
        layout.addLayout(excl_buttons)

        hashes_label = QLabel("Excluded fingerprints (SHA-256):")
        layout.addWidget(hashes_label)
        self.excl_hashes = QListWidget()
        for digest in sorted(config.exclusions.hashes):
            self.excl_hashes.addItem(digest)
        layout.addWidget(self.excl_hashes)
        hash_row = QHBoxLayout()
        self.hash_edit = QLineEdit()
        self.hash_edit.setPlaceholderText("Paste a SHA-256 fingerprint…")
        add_hash = QPushButton("Add fingerprint")
        add_hash.clicked.connect(self._add_exclusion_hash)
        remove_hash = QPushButton("Remove selected")
        remove_hash.clicked.connect(
            lambda: self._remove_selected(self.excl_hashes)
        )
        hash_row.addWidget(self.hash_edit, 1)
        hash_row.addWidget(add_hash)
        hash_row.addWidget(remove_hash)
        layout.addLayout(hash_row)

        # -- save -------------------------------------------------------
        save = QPushButton("Save settings")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        layout.addWidget(save)
        self.saved_label = QLabel("")
        layout.addWidget(self.saved_label)
        layout.addStretch(1)

    # ------------------------------------------------------------------
    @staticmethod
    def _remove_selected(list_widget: QListWidget) -> None:
        for item in list_widget.selectedItems():
            list_widget.takeItem(list_widget.row(item))

    def _add_watch_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Choose a folder to watch")
        if chosen:
            self.watch_list.addItem(chosen)

    def _add_exclusion_path(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Choose a folder to exclude")
        if chosen:
            self.excl_paths.addItem(chosen)

    def _add_exclusion_file(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Choose a file to exclude")
        if chosen:
            self.excl_paths.addItem(chosen)

    def _add_exclusion_hash(self) -> None:
        digest = self.hash_edit.text().strip().lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            QMessageBox.warning(
                self, "That is not a fingerprint",
                "A SHA-256 fingerprint is 64 hexadecimal characters.",
            )
            return
        self.excl_hashes.addItem(digest)
        self.hash_edit.clear()

    def _save(self) -> None:
        config = self._backend.config
        config.watch_dirs = [
            Path(self.watch_list.item(i).text())
            for i in range(self.watch_list.count())
        ]
        config.realtime_default = self.policy_combo.currentData()
        config.process_monitor_enabled = self.process_check.isChecked()
        config.heuristics = self.heuristics_check.isChecked()
        config.max_realtime_file_size = self.max_size_spin.value() * 1024 * 1024
        config.exclusions.paths = tuple(
            self.excl_paths.item(i).text() for i in range(self.excl_paths.count())
        )
        config.exclusions.hashes = frozenset(
            self.excl_hashes.item(i).text()
            for i in range(self.excl_hashes.count())
        )
        self._backend.save_config()
        if self._protection is not None:
            self._protection.reload_config()
        self.saved_label.setText(
            "Settings saved. Running protection picked up the changes."
        )


class BenchWorker(QObject):
    """Runs the rule test bench OFF the UI thread (same pattern as
    the Scan page's worker): dissecting a file reads and analyses
    the whole thing, and the window must never freeze doing it.

    :meth:`execute` does the work synchronously (tests call it
    directly); :meth:`run` is the thread entry point.
    """

    finished_bench = Signal(object)  # TestBenchResult
    failed = Signal(str)

    def __init__(self, backend: GuiBackend, path_text: str, parent=None):
        super().__init__(parent)
        self._backend = backend
        self._path_text = path_text

    def run(self) -> None:  # thread entry point
        try:
            result = self.execute()
        except Exception as exc:  # surfaced, never swallowed
            self.failed.emit(str(exc))
            return
        self.finished_bench.emit(result)

    def execute(self):
        db_path = Path(self._backend.config.signature_db)
        with SignatureDB.open(db_path) as db:
            return run_test_bench(
                self._path_text, db, BUILTIN_RULES, self._backend.dev
            )


class DevToolkitPage(QWidget):
    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        self._bench_thread: QThread | None = None
        self._bench_worker: BenchWorker | None = None
        self.last_bench = None
        dev = backend.dev

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("Dev Toolkit")
        title.setObjectName("Headline")
        layout.addWidget(title)
        intro = QLabel(
            "See how Argus thinks, and steer it. Changes here apply "
            "to scans run from this window and to the test bench."
        )
        intro.setObjectName("Subhead")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        # -- simulation + verbose --------------------------------------
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Simulation mode (detect only, touch nothing):"))
        self.sim_toggle = ToggleSwitch(dev.simulation_mode)
        self.sim_toggle.toggled.connect(self._on_simulation)
        mode_row.addWidget(self.sim_toggle)
        mode_row.addSpacing(24)
        mode_row.addWidget(QLabel("Verbose logging:"))
        self.verbose_toggle = ToggleSwitch(dev.verbose_logging)
        self.verbose_toggle.toggled.connect(self._on_verbose)
        mode_row.addWidget(self.verbose_toggle)
        mode_row.addStretch(1)
        layout.addLayout(mode_row)

        # -- sensitivity -----------------------------------------------
        layout.addWidget(_section("Detection sensitivity"))
        slider_row = QHBoxLayout()
        slider_row.addWidget(QLabel("Relaxed"))
        self.sensitivity_slider = QSlider(Qt.Orientation.Horizontal)
        self.sensitivity_slider.setRange(0, 100)
        self.sensitivity_slider.setValue(dev.sensitivity)
        self.sensitivity_slider.valueChanged.connect(self._on_sensitivity)
        slider_row.addWidget(self.sensitivity_slider, 1)
        slider_row.addWidget(QLabel("Paranoid"))
        layout.addLayout(slider_row)
        self.sensitivity_label = QLabel("")
        self.sensitivity_label.setObjectName("Subhead")
        layout.addWidget(self.sensitivity_label)
        self._on_sensitivity(dev.sensitivity)

        # -- signal steering -------------------------------------------
        layout.addWidget(_section("Heuristic signals"))
        signal_note = QLabel(
            "Turn a signal off or change how much it counts. Base "
            "points are the engine's own; the weight multiplies them."
        )
        signal_note.setObjectName("Subhead")
        signal_note.setWordWrap(True)
        layout.addWidget(signal_note)
        self.signal_table = QTableWidget(len(SIGNAL_CATALOG), 5)
        self.signal_table.setHorizontalHeaderLabels(
            ["Counts", "Signal", "Severity", "Base points", "Weight"]
        )
        self.signal_table.horizontalHeader().setStretchLastSection(True)
        for row, spec in enumerate(SIGNAL_CATALOG):
            override = dev.override_for(spec.name)
            enabled_box = QCheckBox()
            enabled_box.setChecked(override.enabled)
            self.signal_table.setCellWidget(row, 0, enabled_box)
            name_item = QTableWidgetItem(spec.name)
            name_item.setToolTip(spec.summary)
            self.signal_table.setItem(row, 1, name_item)
            self.signal_table.setItem(row, 2, severity_item(spec.severity))
            self.signal_table.setItem(row, 3, QTableWidgetItem(str(spec.points)))
            weight_spin = QDoubleSpinBox()
            weight_spin.setRange(0.0, 5.0)
            weight_spin.setSingleStep(0.25)
            weight_spin.setValue(override.weight)
            self.signal_table.setCellWidget(row, 4, weight_spin)
        layout.addWidget(self.signal_table)

        save_dev = QPushButton("Save toolkit settings")
        save_dev.setObjectName("Primary")
        save_dev.clicked.connect(self._save_dev)
        layout.addWidget(save_dev)
        self.dev_saved_label = QLabel("")
        layout.addWidget(self.dev_saved_label)

        # -- test bench --------------------------------------------------
        layout.addWidget(_section("Rule test bench"))
        bench_note = QLabel(
            "Pick any file and see everything Argus sees in it: "
            "fingerprint match, pattern rules, every signal with its "
            "points, entropy, program structure, and the final score."
        )
        bench_note.setObjectName("Subhead")
        bench_note.setWordWrap(True)
        layout.addWidget(bench_note)
        bench_row = QHBoxLayout()
        self.bench_path_edit = QLineEdit()
        self.bench_path_edit.setPlaceholderText("File to dissect…")
        bench_browse = QPushButton("Browse…")
        bench_browse.clicked.connect(self._browse_bench)
        self.bench_run_button = QPushButton("Dissect file")
        self.bench_run_button.setObjectName("Primary")
        self.bench_run_button.clicked.connect(self._run_bench)
        bench_row.addWidget(self.bench_path_edit, 1)
        bench_row.addWidget(bench_browse)
        bench_row.addWidget(self.bench_run_button)
        layout.addLayout(bench_row)

        bench_result_row = QHBoxLayout()
        self.bench_ring = ScoreRing()
        bench_result_row.addWidget(self.bench_ring)
        self.bench_badge = SeverityBadge("No result yet")
        bench_result_row.addWidget(self.bench_badge)
        bench_text_box = QVBoxLayout()
        self.bench_verdict_label = QLabel("No file dissected yet.")
        self.bench_verdict_label.setObjectName("SectionTitle")
        self.bench_detail_label = QLabel("")
        self.bench_detail_label.setWordWrap(True)
        bench_text_box.addWidget(self.bench_verdict_label)
        bench_text_box.addWidget(self.bench_detail_label)
        bench_result_row.addLayout(bench_text_box, 1)
        layout.addLayout(bench_result_row)
        self.bench_signals = QTableWidget(0, 4)
        self.bench_signals.setHorizontalHeaderLabels(
            ["Signal", "Severity", "Points", "Why it fired"]
        )
        self.bench_signals.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.bench_signals)

        # -- self-test ---------------------------------------------------
        layout.addWidget(_section("Detection self-test"))
        selftest_note = QLabel(
            "Writes the industry-standard EICAR test file — a "
            "harmless string every antivirus must catch — into a "
            "scratch folder, runs the full pipeline on it, and "
            "cleans up. If this passes, detection works end to end."
        )
        selftest_note.setObjectName("Subhead")
        selftest_note.setWordWrap(True)
        layout.addWidget(selftest_note)
        selftest_button = QPushButton("Run the EICAR self-test")
        selftest_button.clicked.connect(self._run_self_test)
        layout.addWidget(selftest_button)
        self.selftest_label = QLabel("")
        self.selftest_label.setWordWrap(True)
        layout.addWidget(self.selftest_label)

        # -- log view -----------------------------------------------------
        layout.addWidget(_section("Log"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(500)
        layout.addWidget(self.log_view)
        self._log_capture = LogCapture()
        self._log_capture.setFormatter(
            logging.Formatter("%(levelname)s %(name)s: %(message)s")
        )
        logging.getLogger("argus").addHandler(self._log_capture)
        refresh_log = QPushButton("Refresh log")
        refresh_log.clicked.connect(self._refresh_log)
        layout.addWidget(refresh_log)
        layout.addStretch(1)

    # ------------------------------------------------------------------
    def _on_simulation(self, on: bool) -> None:
        self._backend.dev.simulation_mode = on
        self._backend.save_dev()

    def _on_verbose(self, on: bool) -> None:
        self._backend.dev.verbose_logging = on
        apply_logging(on)
        self._backend.save_dev()

    def _on_sensitivity(self, value: int) -> None:
        self._backend.dev.sensitivity = value
        suspicious, malicious = self._backend.dev.thresholds()
        band = (
            "Standard — the engine's own balance."
            if value == 50
            else "More sensitive — weaker evidence will flag a file."
            if value > 50
            else "More relaxed — only stronger evidence flags a file."
        )
        self.sensitivity_label.setText(
            f"Sensitivity {value}/100. Files scoring {suspicious}+ are "
            f"Suspicious, {malicious}+ are Malicious. {band} "
            "(Save toolkit settings to keep this.)"
        )

    def _save_dev(self) -> None:
        dev = self._backend.dev
        for row, spec in enumerate(SIGNAL_CATALOG):
            enabled_box = self.signal_table.cellWidget(row, 0)
            weight_spin = self.signal_table.cellWidget(row, 4)
            dev.set_override(
                spec.name,
                enabled=enabled_box.isChecked(),
                weight=weight_spin.value(),
            )
        self._backend.save_dev()
        self.dev_saved_label.setText(
            "Toolkit settings saved — scans from this window and the "
            "test bench now use them."
        )

    def _browse_bench(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Choose a file to dissect")
        if chosen:
            self.bench_path_edit.setText(chosen)

    def _run_bench(self) -> None:
        path_text = self.bench_path_edit.text().strip()
        if not path_text:
            QMessageBox.warning(self, "Pick a file", "Choose a file to dissect first.")
            return
        if self._bench_thread is not None:
            return  # a dissection is already running
        self.bench_run_button.setEnabled(False)
        self.bench_verdict_label.setText("Dissecting…")
        worker = BenchWorker(self._backend, path_text)
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished_bench.connect(self._bench_done)
        worker.failed.connect(self._bench_failed)
        worker.finished_bench.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._bench_thread_done)
        self._bench_worker = worker
        self._bench_thread = thread
        thread.start()

    def _bench_done(self, result) -> None:
        self._show_bench(result)

    def _bench_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Test bench problem", message)

    def _bench_thread_done(self) -> None:
        if self._bench_thread is not None:
            self._bench_thread.deleteLater()
        self._bench_thread = None
        self._bench_worker = None
        self.bench_run_button.setEnabled(True)

    def _show_bench(self, result) -> None:
        self.last_bench = result
        self.bench_ring.set_score(result.score)
        self.bench_badge.setText(result.verdict if not result.error else "Error")
        self.bench_badge.set_color(
            theme.verdict_color(result.verdict) if not result.error
            else theme.SEVERITY_COLORS["critical"]
        )
        if result.error:
            self.bench_verdict_label.setText("Could not dissect that file")
            self.bench_detail_label.setText(result.error)
            self.bench_signals.setRowCount(0)
            return
        verdict_text = result.verdict
        if result.signature_name:
            verdict_text += f" — known threat: {result.signature_name}"
        self.bench_verdict_label.setText(
            f"Verdict: {verdict_text} ({score_band(result.score)})"
        )
        facts = [
            f"Fingerprint (SHA-256): {result.sha256}",
            f"Size: {result.size:,} bytes · Kind: {result.kind} · "
            f"Signed: {'yes' if result.signed else 'no'}",
        ]
        if result.entropy_whole is not None:
            facts.append(
                f"Randomness (entropy): {result.entropy_whole:.2f} overall, "
                f"{result.entropy_max_window:.2f} in the densest region "
                "(8.0 = pure random / packed)."
            )
        if result.rule_hits:
            facts.append(
                "Pattern rules hit: "
                + ", ".join(hit["name"] for hit in result.rule_hits)
            )
        if result.pe_facts:
            pe = result.pe_facts
            facts.append(
                f"Program facts: {pe['machine']}, "
                f"{'64-bit' if pe['is_64bit'] else '32-bit'}"
                f"{', DLL' if pe['is_dll'] else ''}, "
                f"{len(pe['sections'])} sections, "
                f"{pe['imported_function_count']} imported functions "
                f"from {len(pe['imported_dlls'])} libraries."
            )
        if result.short_circuit:
            facts.append(
                "A critical signal combination fired — that alone "
                "makes the file Malicious regardless of points."
            )
        for note in result.notes:
            facts.append(f"Note: {note}")
        self.bench_detail_label.setText("\n".join(facts))

        self.bench_signals.setRowCount(len(result.signals))
        for row, sig in enumerate(result.signals):
            self.bench_signals.setItem(row, 0, QTableWidgetItem(sig.name))
            self.bench_signals.setItem(row, 1, severity_item(sig.severity))
            points = (
                f"{sig.adjusted_points}"
                if sig.enabled and sig.adjusted_points == sig.base_points
                else f"{sig.adjusted_points} (base {sig.base_points}"
                + (", off)" if not sig.enabled else ")")
            )
            self.bench_signals.setItem(row, 2, QTableWidgetItem(points))
            self.bench_signals.setItem(row, 3, QTableWidgetItem(sig.explanation))

    def _run_self_test(self) -> None:
        result = run_self_test()
        lines = [result.summary(), ""]
        for step in result.steps:
            mark = "✓" if step.ok else "✗"
            lines.append(f"{mark} {step.name}: {step.detail}")
        self.selftest_label.setText("\n".join(lines))
        color = theme.GREEN if result.passed else theme.SEVERITY_COLORS["critical"]
        self.selftest_label.setStyleSheet(f"color: {color};")

    def _refresh_log(self) -> None:
        self.log_view.setPlainText("\n".join(self._log_capture.records))
