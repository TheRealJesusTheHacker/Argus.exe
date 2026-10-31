"""Quarantine, Pending Actions, and History pages.

- Quarantine: what the vault holds, with Restore / Delete / Allow —
  each behind a confirmation dialog, each through the action engine.
- Pending Actions: the queue real-time "ask" policy fills; Approve
  carries the action out, Reject declines it and leaves the file.
- History: the plain-language record from reporting.py.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

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

from .. import action_requests
from ..paths import vault_view_path
from ..reporting import render_text_report
from .backend import GuiBackend
from .format import human_bytes

log = logging.getLogger("argus.gui")
from .widgets import severity_item


def _confirm(parent, title: str, body: str) -> bool:
    answer = QMessageBox.question(
        parent, title, body,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    return answer == QMessageBox.StandardButton.Yes


def _fetch_service_details(kind: str, record_id: str):
    """Ask the protection service for its OWN record of one
    vault entry / pending action (fix round 2, FIX 1).

    Returns ``(details, error)``: *details* is the service's
    record dict, or None when the verified pipe is not required
    in this layout (the page's own data is already
    authoritative). *error* is designed status-label text when
    the record could not be obtained — in the installed layout a
    confirmation is NEVER built from the unsigned view files
    when the service cannot be asked, because those files are
    display hints any local process could rewrite."""
    try:
        if kind == "entry":
            return action_requests.fetch_entry_details(record_id), None
        return action_requests.fetch_pending_details(record_id), None
    except action_requests.PipeUnavailableError as exc:
        return None, action_requests.pipe_failure_message(exc)
    except action_requests.ServiceDetailsError as exc:
        return None, (
            f"Argus asked its protection service to confirm that "
            f"record, and the service answered: {exc} Nothing was "
            "done — refresh the list and try again."
        )


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
        #: True when this process opened the vault itself; False
        #: when the list came from the service-published vault view
        #: (installed layout, standard user) — actions then go
        #: through the service request channel.
        self._direct = True
        self.refresh()

    def refresh(self) -> None:
        entries, direct = self._backend.vault_entries_view()
        self._direct = direct
        self._entries = [e for e in entries if e.status == "quarantined"]
        self.table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            entry_name = Path(entry.original_path).name
            self.table.setItem(row, 0, QTableWidgetItem(entry_name))
            self.table.setItem(row, 1, QTableWidgetItem(entry.detection_name or "—"))
            self.table.setItem(row, 2, severity_item(entry.severity))
            self.table.setItem(row, 3, QTableWidgetItem(human_bytes(entry.size)))
            self.table.setItem(row, 4, QTableWidgetItem(entry.quarantined_at))
        if not direct and not vault_view_path().exists():
            # No direct access AND no service snapshot: there is
            # nothing this window can truthfully show or do.
            for button in (
                self.restore_button, self.allow_button, self.delete_button,
            ):
                button.setEnabled(False)
            self.status_label.setText(
                "Argus cannot read the quarantine vault from this "
                "Windows account — the vault is protected so that "
                "only the Argus service and administrators can open "
                "it, and the protection service has not published a "
                "vault snapshot. Run Argus as administrator to "
                "manage quarantine directly."
            )
            return
        for button in (
            self.restore_button, self.allow_button, self.delete_button,
        ):
            button.setEnabled(True)
        if not self._entries:
            self.status_label.setText(
                "The vault is empty — nothing is quarantined right now."
            )
        elif not direct:
            self.status_label.setText(
                f"{len(self._entries)} file(s) locked in the vault. "
                "The list is read from the protection service's "
                "snapshot; actions are carried out by the service."
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
        via_service = not self._direct and not self._backend.simulation_mode
        details = None
        if via_service and action_requests.pipe_channel_required():
            # Authoritative confirmation (fix round 2): the
            # dialog shows the SERVICE's own record — the view
            # file this list came from is unsigned and only a
            # hint about which row to ask about.
            details, error = _fetch_service_details("entry", entry.id)
            if error is not None:
                self.status_label.setText(error)
                return
        entry_name = Path(entry.original_path).name
        if details is not None:
            name = Path(details["original_path"]).name
            reported = (
                "The protection service reports:\n"
                f"File: {details['original_path']}\n"
                f"Detection: {details.get('detection_name') or '—'}\n"
                f"Fingerprint (SHA-256): {details['sha256'][:12]}…\n\n"
            )
            confirms = {
                "restore": (
                    "Restore this file?",
                    reported
                    + f"{name} will be put back at the location "
                    "above. Only restore files you believe are safe.",
                ),
                "allow": (
                    "Restore and allow this file?",
                    reported
                    + f"{name} will be put back AND its fingerprint "
                    "excluded, so Argus stops flagging it. Only "
                    "vouch for files you trust.",
                ),
                "delete": (
                    "Delete permanently?",
                    reported
                    + f"{name} will be destroyed for good. "
                    "This cannot be undone.",
                ),
            }
        else:
            confirms = {
                "restore": (
                    "Restore this file?",
                    f"{entry_name} will be put back at "
                    f"{entry.original_path}. Only restore files you "
                    "believe are safe.",
                ),
                "allow": (
                    "Restore and allow this file?",
                    f"{entry_name} will be put back AND "
                    "its fingerprint excluded, so Argus stops "
                    "flagging it. Only vouch for files you trust.",
                ),
                "delete": (
                    "Delete permanently?",
                    f"{entry_name} will be destroyed for "
                    "good. This cannot be undone.",
                ),
            }
        title, body = confirms[action]
        if not _confirm(self, title, body):
            return
        submit_sha = details["sha256"] if details is not None else entry.sha256
        if via_service:
            # The vault is not this process's to touch (installed
            # layout): the human confirmed HERE, and the protection
            # service carries it out against its own records.
            result = action_requests.submit_and_wait(
                action,
                entry_id=entry.id,
                sha256=submit_sha,
                requested_by="Argus GUI (quarantine page)",
            )
            self.refresh()
            self.status_label.setText(result.message)
            return
        # Direct route (portable / elevated / dev, or simulation —
        # which records intent through the same surface).
        engine = self._backend.actions()
        try:
            if action == "restore":
                outcome = engine.restore_entry(entry.id, confirmed=True)
            elif action == "allow":
                outcome = engine.allow_entry(entry.id, confirmed=True)
            else:  # delete
                outcome = engine.delete_entry(entry.id, confirmed=True)
            message = outcome.message
        except PermissionError:
            # The vault turned out not to be writable by this
            # process after all — hand the confirmed action to the
            # service rather than failing the user.
            result = action_requests.submit_and_wait(
                action,
                entry_id=entry.id,
                sha256=entry.sha256,
                requested_by="Argus GUI (quarantine page)",
            )
            self.refresh()
            self.status_label.setText(result.message)
            return
        except Exception:
            # Plain language on screen; the technical record goes
            # to the log — never a raw exception in a dialog.
            log.exception("quarantine/pending action failed")
            QMessageBox.critical(
                self,
                "That did not work",
                "Argus couldn't do that just now. Nothing was "
                "changed. Try again — if it keeps failing, "
                "restart Argus.",
            )
            return
        # Refresh first: refresh() rewrites the status line with the
        # queue summary, so the outcome message is set after it —
        # otherwise the user would never see what just happened.
        self.refresh()
        self.status_label.setText(message)


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

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Action", "File", "Threat", "Severity", "SHA-256",
             "Source", "Detected"]
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
        #: True when the list came from the service-published
        #: pending VIEW because this process does not own the
        #: (trusted, service-owned) pending store — decisions then
        #: go through the service request channel.
        self._via_service = False
        self.refresh()

    def refresh(self) -> None:
        # The pinned pending interface: direct from the store ONLY
        # when this process owns it (portable / elevated / dev);
        # in the installed layout the pending database lives in
        # the trusted vault directory and the GUI reads the
        # service-published pending view instead — never the
        # service-owned database itself.
        self._pending, self._via_service = self._backend.pending_display()
        self.table.setRowCount(len(self._pending))
        for row, pending in enumerate(self._pending):
            self.table.setItem(row, 0, QTableWidgetItem(pending.action))
            self.table.setItem(row, 1, QTableWidgetItem(pending.path))
            self.table.setItem(row, 2, QTableWidgetItem(pending.detection_name or "—"))
            self.table.setItem(row, 3, severity_item(pending.severity))
            short_sha = (
                pending.sha256[:12] + "…" if pending.sha256 else "none recorded"
            )
            self.table.setItem(row, 4, QTableWidgetItem(short_sha))
            self.table.setItem(row, 5, QTableWidgetItem(pending.source or "—"))
            self.table.setItem(row, 6, QTableWidgetItem(pending.created_at))
        self.status_label.setText(
            "Nothing is waiting — you are all caught up."
            if not self._pending
            else f"{len(self._pending)} action(s) waiting for your decision."
        )

    def _confirm_text(self, pending, verb: str) -> str:
        """The decision dialog text: exactly what will happen, to
        exactly which file — fingerprint, reasons, and source."""
        short_sha = pending.sha256[:12] + "…" if pending.sha256 else "none recorded"
        reasons = " ".join(pending.reasons) if pending.reasons else "—"
        return (
            f"Argus will {verb} {pending.path}\n\n"
            f"Detection: {pending.detection_name or '—'}\n"
            f"Fingerprint (SHA-256): {short_sha}\n"
            f"Source: {pending.source or '—'}\n"
            f"Why it was flagged: {reasons}"
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
        via_service = self._via_service and not self._backend.simulation_mode
        details = None
        if via_service and action_requests.pipe_channel_required():
            # Authoritative confirmation (fix round 2): ask the
            # service for its OWN queue row and build the dialog
            # from THAT — never from the unsigned pending view.
            details, error = _fetch_service_details("pending", pending.id)
            if error is not None:
                self.status_label.setText(error)
                return
        shown = pending
        if details is not None:
            shown = SimpleNamespace(
                id=details["pending_id"],
                action=details["action"],
                path=details["path"],
                detection_name=details.get("detection_name"),
                severity=details.get("severity"),
                sha256=details.get("sha256") or "",
                source=details.get("source"),
                reasons=list(details.get("reasons") or []),
            )
        verb = shown.action if action == "approve" else "leave alone"
        body = self._confirm_text(shown, verb)
        if details is not None:
            body = "The protection service reports:\n\n" + body
        if not _confirm(
            self,
            f"{'Approve' if action == 'approve' else 'Reject'} {shown.action}?",
            body,
        ):
            return
        kind = "approve-pending" if action == "approve" else "reject-pending"
        submit_sha = (
            details["sha256"] if details is not None else pending.sha256
        )
        if via_service:
            result = action_requests.submit_and_wait(
                kind,
                pending_id=pending.id,
                sha256=submit_sha,
                requested_by="Argus GUI (pending page)",
            )
            self.refresh()
            self.status_label.setText(result.message)
            return
        # Decisions route through backend.actions() like every
        # other page: in simulation mode the intent is recorded and
        # the queue is NOT decided.
        engine = self._backend.actions()
        try:
            if action == "approve":
                # approve() returns the ActionOutcome — its message
                # says what was done.
                message = engine.approve(pending.id).message
            else:
                decided = engine.reject(pending.id)
                # The real engine returns the decided PendingAction
                # (no .message); the simulated one returns an
                # ActionOutcome. Handle both honestly.
                if hasattr(decided, "message"):
                    message = decided.message
                else:
                    message = (
                        f"Rejected — Argus will leave "
                        f"{Path(decided.path).name} as it is "
                        f"(the {decided.action} request was declined)."
                    )
        except PermissionError:
            result = action_requests.submit_and_wait(
                kind,
                pending_id=pending.id,
                sha256=pending.sha256,
                requested_by="Argus GUI (pending page)",
            )
            self.refresh()
            self.status_label.setText(result.message)
            return
        except Exception:
            # Plain language on screen; the technical record goes
            # to the log — never a raw exception in a dialog.
            log.exception("quarantine/pending action failed")
            QMessageBox.critical(
                self,
                "That did not work",
                "Argus couldn't do that just now. Nothing was "
                "changed. Try again — if it keeps failing, "
                "restart Argus.",
            )
            return
        # Refresh first: refresh() rewrites the status line with the
        # queue summary, so the outcome message is set after it —
        # otherwise the user would never see what just happened.
        self.refresh()
        self.status_label.setText(message)


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
        try:
            history = self._backend.history()
            summary = history.summary(days=30)
            detections = history.recent_detections(limit=100)
        except Exception:
            # A history store that cannot be read shows as EMPTY
            # with the reason stated (v1.2.14) — this page is
            # constructed with the main window, so raising here
            # would kill the launch the same way the dashboard's
            # unguarded call did.
            log.exception("history page could not read the scan history")
            self.summary_label.setText(
                "History is unavailable right now — Argus couldn't "
                "read its scan history file."
            )
            self.table.setRowCount(0)
            return
        by_action = summary["by_action"]
        self.summary_label.setText(
            f"Last 30 days: {summary['scans']} scan(s), "
            f"{summary['files_scanned']:,} files checked, "
            f"{summary['detections']} detection(s), "
            f"{by_action.get('quarantined', 0)} quarantined, "
            f"{by_action.get('deleted', 0)} deleted."
        )
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

        try:
            text = render_text_report(self._backend.history(), days=30)
        except Exception:
            log.exception("history report could not be rendered")
            text = (
                "History is unavailable right now — Argus couldn't "
                "read its scan history file."
            )
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
