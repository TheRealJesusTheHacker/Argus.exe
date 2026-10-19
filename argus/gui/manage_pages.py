"""Quarantine, Pending Actions, and History pages.

- Quarantine: what the vault holds, with Restore / Delete / Allow —
  each behind a confirmation dialog, each through the action engine.
- Pending Actions: the queue real-time "ask" policy fills; Approve
  carries the action out, Reject declines it and leaves the file.
- History: the plain-language record from reporting.py.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..reporting import render_text_report
from .backend import GuiBackend
from .format import human_bytes
from .widgets import severity_item


def _confirm(parent, title: str, body: str) -> bool:
    answer = QMessageBox.question(
        parent, title, body,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    return answer == QMessageBox.StandardButton.Yes


class QuarantinePage(QWidget):
    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)
        title = QLabel("Quarantine")
        title.setObjectName("Headline")
        layout.addWidget(title)
        intro = QLabel(
            "Files Argus has locked away, encrypted, where they "
            "cannot run or harm anything. Restore one if it was a "
            "mistake, delete it for good, or allow it if you vouch "
            "for it."
        )
        intro.setObjectName("Subhead")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["File", "Threat", "Severity", "Size", "Quarantined"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        self.restore_button = QPushButton("Restore")
        self.restore_button.clicked.connect(lambda: self._act("restore"))
        self.allow_button = QPushButton("Restore + allow")
        self.allow_button.clicked.connect(lambda: self._act("allow"))
        self.delete_button = QPushButton("Delete permanently")
        self.delete_button.setObjectName("Danger")
        self.delete_button.clicked.connect(lambda: self._act("delete"))
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        for button in (
            self.restore_button, self.allow_button, self.delete_button, refresh,
        ):
            buttons.addWidget(button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self._entries: list = []
        self.refresh()

    def refresh(self) -> None:
        vault = self._backend.vault()
        self._entries = vault.list_entries(status="quarantined")
        self.table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            entry_name = Path(entry.original_path).name
            self.table.setItem(row, 0, QTableWidgetItem(entry_name))
            self.table.setItem(row, 1, QTableWidgetItem(entry.detection_name or "—"))
            self.table.setItem(row, 2, severity_item(entry.severity))
            self.table.setItem(row, 3, QTableWidgetItem(human_bytes(entry.size)))
            self.table.setItem(row, 4, QTableWidgetItem(entry.quarantined_at))
        if not self._entries:
            self.status_label.setText(
                "The vault is empty — nothing is quarantined right now."
            )
        else:
            self.status_label.setText(
                f"{len(self._entries)} file(s) locked in the vault."
            )

    def _selected_entry(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self._entries):
            QMessageBox.information(
                self, "Pick a file first",
                "Select a quarantined file in the list first.",
            )
            return None
        return self._entries[row]

    def _act(self, action: str) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        engine = self._backend.actions()
        vault = self._backend.vault()
        entry_name = Path(entry.original_path).name
        try:
            if action == "restore":
                if not _confirm(
                    self, "Restore this file?",
                    f"{entry_name} will be put back at "
                    f"{entry.original_path}. Only restore files you "
                    "believe are safe.",
                ):
                    return
                restored_to = vault.restore(entry.id)
                message = f"Restored to {restored_to}"
            elif action == "allow":
                outcome = engine.allow_entry(entry.id, confirmed=True) \
                    if _confirm(
                        self, "Restore and allow this file?",
                        f"{entry_name} will be put back AND "
                        "its fingerprint excluded, so Argus stops "
                        "flagging it. Only vouch for files you trust.",
                    ) else None
                if outcome is None:
                    return
                message = outcome.message
            else:  # delete
                if not _confirm(
                    self, "Delete permanently?",
                    f"{entry_name} will be destroyed for "
                    "good. This cannot be undone.",
                ):
                    return
                vault.delete_permanent(entry.id)
                message = f"{entry_name} deleted permanently."
        except Exception as exc:
            QMessageBox.critical(self, "That did not work", str(exc))
            return
        self.status_label.setText(message)
        self.refresh()


class PendingPage(QWidget):
    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)
        title = QLabel("Pending Actions")
        title.setObjectName("Headline")
        layout.addWidget(title)
        intro = QLabel(
            "When real-time protection is set to ask first, detections "
            "wait here for your decision. Approve to carry the action "
            "out; reject to leave the file alone."
        )
        intro.setObjectName("Subhead")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Action", "File", "Threat", "Severity", "Detected"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        approve = QPushButton("Approve")
        approve.setObjectName("Primary")
        approve.clicked.connect(lambda: self._act("approve"))
        reject = QPushButton("Reject")
        reject.clicked.connect(lambda: self._act("reject"))
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        for button in (approve, reject, refresh):
            buttons.addWidget(button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self._pending: list = []
        self.refresh()

    def refresh(self) -> None:
        engine = self._backend.real_actions()
        self._pending = engine.list_pending()
        self.table.setRowCount(len(self._pending))
        for row, pending in enumerate(self._pending):
            self.table.setItem(row, 0, QTableWidgetItem(pending.action))
            self.table.setItem(row, 1, QTableWidgetItem(pending.path))
            self.table.setItem(row, 2, QTableWidgetItem(pending.detection_name or "—"))
            self.table.setItem(row, 3, severity_item(pending.severity))
            self.table.setItem(row, 4, QTableWidgetItem(pending.created_at))
        self.status_label.setText(
            "Nothing is waiting — you are all caught up."
            if not self._pending
            else f"{len(self._pending)} action(s) waiting for your decision."
        )

    def _act(self, action: str) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._pending):
            QMessageBox.information(
                self, "Pick an action first",
                "Select a pending action in the list first.",
            )
            return
        pending = self._pending[row]
        engine = self._backend.real_actions()
        try:
            if action == "approve":
                if not _confirm(
                    self, f"Approve {pending.action}?",
                    f"Argus will {pending.action} {pending.path} "
                    f"({pending.detection_name or 'detection'}).",
                ):
                    return
                outcome = engine.approve(pending.id)
            else:
                outcome = engine.reject(pending.id)
        except Exception as exc:
            QMessageBox.critical(self, "That did not work", str(exc))
            return
        self.status_label.setText(outcome.message)
        self.refresh()


class HistoryPage(QWidget):
    def __init__(self, backend: GuiBackend, parent=None):
        super().__init__(parent)
        self._backend = backend
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)
        title = QLabel("History")
        title.setObjectName("Headline")
        layout.addWidget(title)
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("Subhead")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["When", "File", "Detection", "Severity", "Action taken"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        report_button = QPushButton("Read the full report")
        report_button.clicked.connect(self._show_report)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        buttons.addWidget(report_button)
        buttons.addWidget(refresh)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self.refresh()

    def refresh(self) -> None:
        history = self._backend.history()
        summary = history.summary(days=30)
        by_action = summary["by_action"]
        self.summary_label.setText(
            f"Last 30 days: {summary['scans']} scan(s), "
            f"{summary['files_scanned']:,} files checked, "
            f"{summary['detections']} detection(s), "
            f"{by_action.get('quarantined', 0)} quarantined, "
            f"{by_action.get('deleted', 0)} deleted."
        )
        detections = history.recent_detections(limit=100)
        self.table.setRowCount(len(detections))
        for row, record in enumerate(detections):
            self.table.setItem(row, 0, QTableWidgetItem(record.recorded_at))
            self.table.setItem(row, 1, QTableWidgetItem(record.path))
            self.table.setItem(
                row, 2, QTableWidgetItem(record.name or "—")
            )
            self.table.setItem(row, 3, severity_item(record.severity))
            self.table.setItem(row, 4, QTableWidgetItem(record.action_taken))

    def _show_report(self) -> None:
        from PySide6.QtWidgets import QDialog

        text = render_text_report(self._backend.history(), days=30)
        dialog = QDialog(self)
        dialog.setWindowTitle("Argus report — last 30 days")
        dialog.resize(640, 480)
        box = QVBoxLayout(dialog)
        view = QTextEdit()
        view.setReadOnly(True)
        view.setPlainText(text)
        box.addWidget(view)
        close = QPushButton("Close")
        close.clicked.connect(dialog.accept)
        box.addWidget(close)
        dialog.exec()
