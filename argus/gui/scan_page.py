"""Scan page — Quick / Full / Custom scans with live results.

Results appear as they are found, each with its verdict, severity,
score, and the plain-language reasons behind them. Malicious results
carry the response buttons — Quarantine / Delete / Allow — and every
one of them goes through the action engine with an explicit
confirmation dialog first. The never-silent rule is not bypassed
here; there is no code path from a button to a file operation that
skips the ask.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..actions import DetectionInfo
from ..reporting import DetectionRecord
from .backend import GuiBackend, ScanWorker
from . import theme

log = logging.getLogger("argus.gui")


class ScanPage(QWidget):
    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._scanned_by_path: dict[str, object] = {}
        self._row_widgets: list[QWidget] = []
        self.last_summary: dict | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("Scan")
        title.setObjectName("Headline")
        layout.addWidget(title)
        subtitle = QLabel(
            "Check files for malware. Quick looks where threats "
            "usually land; Full checks everything; Custom checks a "
            "folder you choose."
        )
        subtitle.setObjectName("Subhead")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # -- mode chooser -------------------------------------------
        modes = QHBoxLayout()
        self.quick_radio = QRadioButton("Quick scan")
        self.full_radio = QRadioButton("Full scan")
        self.custom_radio = QRadioButton("Custom folder")
        self.quick_radio.setChecked(True)
        for radio in (self.quick_radio, self.full_radio, self.custom_radio):
            modes.addWidget(radio)
        modes.addStretch(1)
        layout.addLayout(modes)

        custom_row = QHBoxLayout()
        self.custom_path_edit = QLineEdit()
        self.custom_path_edit.setPlaceholderText("Folder to scan…")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        custom_row.addWidget(self.custom_path_edit, 1)
        custom_row.addWidget(browse)
        layout.addLayout(custom_row)

        # -- controls + progress --------------------------------------
        controls = QHBoxLayout()
        self.start_button = QPushButton("Start scan")
        self.start_button.setObjectName("Primary")
        self.start_button.clicked.connect(self._start_from_ui)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._stop)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        self.status_label = QLabel("No scan running.")
        self.status_label.setObjectName("Subhead")
        layout.addWidget(self.status_label)

        # -- results ---------------------------------------------------
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(
            ["File", "Verdict", "Severity", "Score", "Actions"]
        )
        self.results_tree.setColumnWidth(0, 320)
        layout.addWidget(self.results_tree, 1)

        self.result_label = QLabel("")
        self.result_label.setWordWrap(True)
        layout.addWidget(self.result_label)

    # ------------------------------------------------------------------
    # Scan control
    # ------------------------------------------------------------------
    def selected_roots(self) -> list[Path]:
        if self.full_radio.isChecked():
            return self._backend.full_scan_roots()
        if self.custom_radio.isChecked():
            text = self.custom_path_edit.text().strip()
            return [Path(text)] if text else []
        return self._backend.quick_scan_roots()

    def start_quick_scan(self) -> None:
        self.quick_radio.setChecked(True)
        self._start_from_ui()

    def _start_from_ui(self) -> None:
        roots = self.selected_roots()
        if not roots:
            QMessageBox.warning(
                self, "Nothing to scan",
                "Choose a folder to scan first.",
            )
            return
        missing = [r for r in roots if not r.exists()]
        if len(missing) == len(roots):
            QMessageBox.warning(
                self, "Nothing to scan",
                "None of the folders to scan exist on this computer.",
            )
            return
        self.begin_scan(roots)

    def begin_scan(self, roots: list[Path]) -> None:
        if self._thread is not None:
            return
        self.results_tree.clear()
        self._row_widgets.clear()
        self._scanned_by_path.clear()
        self.result_label.setText("")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Scanning…")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        worker = ScanWorker(self._backend)
        worker.configure(roots)
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.flagged.connect(self._on_flagged)
        worker.finished_scan.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        worker.finished_scan.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._thread_done)
        self._worker = worker
        self._thread = thread
        thread.start()

    def _stop(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.status_label.setText("Stopping after the current file…")

    def _thread_done(self) -> None:
        if self._thread is not None:
            self._thread.deleteLater()
        self._thread = None
        self._worker = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    # ------------------------------------------------------------------
    # Worker signal handlers
    # ------------------------------------------------------------------
    def _on_progress(self, done: int, total: int) -> None:
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(done)
        self.status_label.setText(f"Scanning… {done:,} of {total:,} files checked.")

    def _on_flagged(self, row: dict) -> None:
        self._add_result_row(row)

    def _add_result_row(self, row: dict) -> None:
        item = QTreeWidgetItem(
            [
                row["name"],
                row["verdict"],
                (row["severity"] or "—").capitalize(),
                str(row["score"]),
                "",
            ]
        )
        item.setData(0, Qt.ItemDataRole.UserRole, row["path"])
        item.setToolTip(0, row["path"])
        reasons = QTreeWidgetItem(
            ["Why: " + ("; ".join(row["reasons"]) or "no details")]
        )
        reasons.setToolTip(0, "\n".join(row["reasons"]))
        item.addChild(reasons)
        self.results_tree.addTopLevelItem(item)
        from PySide6.QtGui import QBrush, QColor

        item.setForeground(
            1, QBrush(QColor(theme.verdict_color(row["verdict"])))
        )
        font = item.font(1)
        font.setBold(True)
        item.setFont(1, font)
        if row["verdict"] == "Malicious":
            buttons = self._action_buttons(row)
            # Hold a strong reference: a temporary widget handed to
            # setItemWidget has ambiguous ownership in PySide6 and
            # corrupts teardown. The page owns the wrappers; Qt owns
            # the C++ objects while they are in the tree.
            self._row_widgets.append(buttons)
            self.results_tree.setItemWidget(item, 4, buttons)

    def _action_buttons(self, row: dict) -> QWidget:
        box = QWidget()
        buttons = QHBoxLayout(box)
        buttons.setContentsMargins(0, 0, 0, 0)
        quarantine = QPushButton("Quarantine")
        quarantine.clicked.connect(
            lambda: self._act("quarantine", row)
        )
        delete = QPushButton("Delete")
        delete.setObjectName("Danger")
        delete.clicked.connect(lambda: self._act("delete", row))
        allow = QPushButton("Allow")
        allow.clicked.connect(lambda: self._act("allow", row))
        for button in (quarantine, delete, allow):
            buttons.addWidget(button)
        return box

    def _on_finished(self, summary: dict) -> None:
        self.last_summary = summary
        self._scanned_by_path = {
            sf.result.path: sf for sf in summary["scanned_files"]
        }
        self.progress_bar.setVisible(False)
        flagged = len(summary["flagged"])
        if summary["cancelled"]:
            self.status_label.setText("Scan stopped.")
        elif flagged == 0:
            self.status_label.setText(
                f"Scan complete — nothing suspicious found in "
                f"{summary['scanned']:,} files."
            )
        else:
            self.status_label.setText(
                f"Scan complete — {flagged} file(s) need your attention "
                f"({summary['detections']} malicious, "
                f"{summary['suspicious']} suspicious) out of "
                f"{summary['scanned']:,} files."
            )
        self._record_history(summary)

    def _on_failed(self, message: str) -> None:
        self.progress_bar.setVisible(False)
        self.status_label.setText(message)
        QMessageBox.critical(self, "Scan problem", message)

    def _record_history(self, summary: dict) -> None:
        records = []
        for sf in summary["scanned_files"]:
            if sf.verdict.value == "Clean":
                continue
            records.append(
                DetectionRecord(
                    path=str(sf.result.path),
                    verdict=sf.verdict.value,
                    severity=sf.assessment.max_severity,
                    score=sf.assessment.score,
                    name=(
                        sf.assessment.detections[0].name
                        if sf.assessment.detections
                        else (
                            sf.assessment.signals[0].name
                            if sf.assessment.signals
                            else None
                        )
                    ),
                    reasons=[d.reason for d in sf.assessment.detections]
                    + [s.explanation for s in sf.assessment.signals]
                    + [
                        note for note in sf.assessment.notes
                        if note.startswith("Archive not fully scanned:")
                    ],
                    sha256=sf.result.sha256,
                )
            )
        try:
            self._backend.history().record_scan(
                kind="ondemand",
                root=", ".join(summary["roots"]),
                files_scanned=summary["scanned"],
                files_skipped=0,
                files_excluded=0,
                bytes_scanned=sum(
                    sf.result.size or 0 for sf in summary["scanned_files"]
                ),
                detections=records,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                files_not_fully_scanned=sum(
                    1 for sf in summary["scanned_files"]
                    if sf.archive_not_fully_scanned
                ),
            )
        except Exception:  # bookkeeping never hides a scan result
            log.exception("scan history could not be saved")
            self.result_label.setText(
                "Note: the scan finished, but its history could "
                "not be saved. The results above are still correct."
            )

    # ------------------------------------------------------------------
    # Response actions (never silent — always a confirm dialog)
    # ------------------------------------------------------------------
    def _act(self, action: str, row: dict) -> None:
        scanned = row.get("scanned") or self._scanned_by_path.get(row["path"])
        path = Path(row["path"])
        prompts = {
            "quarantine": (
                "Quarantine this file?",
                f"Argus will move {path.name} into the encrypted "
                "quarantine vault. It will not be able to run. You can "
                "restore it later from the Quarantine page.",
            ),
            "delete": (
                "Permanently delete this file?",
                f"{path.name} will be deleted for good. This cannot "
                "be undone. Quarantine is the safer choice unless you "
                "are certain.",
            ),
            "allow": (
                "Allow this file?",
                f"You are vouching for {path.name}. Argus will add "
                "its fingerprint to your exclusions and stop flagging "
                "it. Only do this if you are sure it is safe.",
            ),
        }
        title, body = prompts[action]
        answer = QMessageBox.question(
            self, title, body,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        engine = self._backend.actions()
        if scanned is not None:
            info = DetectionInfo.from_scanned(scanned)
        else:
            # Fallback row (no live scan object): the actions layer
            # refuses a fingerprint-less decision now, so a missing
            # sha256 is computed from the file itself — the REAL
            # hash of the file the user is deciding about, never a
            # placeholder.
            sha256 = row.get("sha256")
            if not sha256 and path.is_file():
                try:
                    from ..scanner import hash_file

                    sha256, _size = hash_file(path)
                except OSError:
                    sha256 = None
            info = DetectionInfo(
                name="Flagged file",
                severity=row.get("severity") or "high",
                verdict=row["verdict"],
                sha256=sha256,
                reasons=list(row.get("reasons") or []),
            )
        if action == "quarantine" and not info.sha256:
            # Quarantine REQUIRES a fingerprint: the vault records
            # what it took by hash, and the action engine refuses a
            # sha256=None quarantine outright. One last attempt to
            # hash the file as it stands NOW; if that is impossible
            # (it vanished, or is unreadable), the honest outcome is
            # a note saying exactly that — never a doomed call into
            # the engine and never a placeholder fingerprint.
            hashed = None
            if path.is_file():
                try:
                    from ..scanner import hash_file

                    hashed, _size = hash_file(path)
                except OSError:
                    hashed = None
            if not hashed:
                QMessageBox.warning(
                    self,
                    "Can't quarantine this file",
                    f"Argus couldn't read {path.name} to take its "
                    "fingerprint, so it can't be quarantined safely "
                    "— the file may have moved or been deleted. "
                    "Run the scan again to refresh the results.",
                )
                self.result_label.setText(
                    f"Quarantine not possible for {path.name}: no "
                    "fingerprint could be taken. Re-scan to refresh."
                )
                return
            info.sha256 = hashed
        try:
            if action == "quarantine":
                outcome = engine.quarantine(path, info, confirmed=True)
            elif action == "delete":
                outcome = engine.delete(path, info, confirmed=True)
            else:
                outcome = engine.allow_file(path, confirmed=True)
        except Exception:
            log.exception("scan result action failed")
            QMessageBox.critical(
                self,
                "That did not work",
                "Argus couldn't do that just now. The file was "
                "left exactly as it was. Try again — if it keeps "
                "failing, restart Argus.",
            )
            return
        QMessageBox.information(self, "Done", outcome.message)
        self.result_label.setText(outcome.message)

    def _browse(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
        if chosen:
            self.custom_path_edit.setText(chosen)
            self.custom_radio.setChecked(True)
