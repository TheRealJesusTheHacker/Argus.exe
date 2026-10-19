"""Scan history and reports for ARGUS.EXE.

Every scan Argus runs — a manual ``argus scan``, a real-time watch
hit, a future scheduled run — is written down here, in a plain SQLite
history file: when it ran, how much it covered, and for every
detection the file, the verdict, the severity, the score, the reasons
in plain language, and what was done about it.

This is Argus's memory and its audit trail. Reports are rendered
from it in the same plain language the rest of Argus uses, because a
report only a security engineer can read is a report nobody reads:

- :func:`render_text_report` — a summary a person can act on;
- :func:`report_dict` — the same facts as JSON, for tools.

History is append-only bookkeeping: recording a scan never changes
any file on the machine.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("argus.reporting")


class HistoryError(Exception):
    """Raised when the scan history database cannot be opened or
    written. Callers treat history as bookkeeping: they report this,
    never let it hide a scan result."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,          -- ondemand | realtime | scheduled
    root            TEXT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    files_scanned   INTEGER NOT NULL DEFAULT 0,
    files_skipped   INTEGER NOT NULL DEFAULT 0,
    files_excluded  INTEGER NOT NULL DEFAULT 0,
    bytes_scanned   INTEGER NOT NULL DEFAULT 0,
    detections_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS detections (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    recorded_at  TEXT NOT NULL,
    path         TEXT NOT NULL,
    verdict      TEXT,
    severity     TEXT,
    score        INTEGER NOT NULL DEFAULT 0,
    name         TEXT,
    reasons      TEXT NOT NULL DEFAULT '[]',
    sha256       TEXT,
    action_taken TEXT NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_detections_scan ON detections(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
"""

#: What happened to a flagged file. ``pending`` means it is waiting in
#: the actions queue for a human decision.
ACTION_TAKEN_VALUES = (
    "none", "pending", "quarantined", "deleted", "allowed", "ignored",
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _cutoff_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(
        timespec="seconds"
    )


@dataclass
class DetectionRecord:
    """One flagged file, ready to be written into history."""

    path: str
    verdict: str | None = None
    severity: str | None = None
    score: int = 0
    name: str | None = None
    reasons: list[str] = field(default_factory=list)
    sha256: str | None = None
    action_taken: str = "none"


@dataclass
class ScanRecord:
    """One finished scan, as read back from history."""

    id: int
    kind: str
    root: str | None
    started_at: str
    finished_at: str
    files_scanned: int
    files_skipped: int
    files_excluded: int
    bytes_scanned: int
    detections_count: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "root": self.root,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_excluded": self.files_excluded,
            "bytes_scanned": self.bytes_scanned,
            "detections_count": self.detections_count,
        }


@dataclass
class StoredDetection:
    """One detection, as read back from history."""

    id: int
    scan_id: int
    recorded_at: str
    path: str
    verdict: str | None
    severity: str | None
    score: int
    name: str | None
    reasons: list[str]
    sha256: str | None
    action_taken: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "recorded_at": self.recorded_at,
            "path": self.path,
            "verdict": self.verdict,
            "severity": self.severity,
            "score": self.score,
            "name": self.name,
            "reasons": list(self.reasons),
            "sha256": self.sha256,
            "action_taken": self.action_taken,
        }


class History:
    """The persistent scan history (one SQLite file)."""

    def __init__(self, conn: sqlite3.Connection, path: Path) -> None:
        self._conn = conn
        self.path = path
        self._lock = threading.Lock()

    @classmethod
    def open(cls, path: Path | str) -> "History":
        db_path = Path(path)
        if db_path.parent and not db_path.parent.exists():
            db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            # The service, the GUI, and the CLI all write history,
            # sometimes at once: WAL + a busy timeout keep concurrent
            # writers from failing each other.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript(_SCHEMA)
            conn.commit()
        except sqlite3.Error as exc:
            conn.close()
            raise HistoryError(
                f"could not open scan history at {db_path}: {exc}"
            ) from exc
        return cls(conn, db_path)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "History":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------
    def record_scan(
        self,
        *,
        kind: str,
        root: str | None,
        files_scanned: int = 0,
        files_skipped: int = 0,
        files_excluded: int = 0,
        bytes_scanned: int = 0,
        detections: list[DetectionRecord] | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> int:
        """Record one finished scan and its detections. Returns scan id."""
        detections = detections or []
        now = _utcnow_iso()
        with self._lock:
            try:
                cursor = self._conn.execute(
                    "INSERT INTO scans (kind, root, started_at, finished_at,"
                    " files_scanned, files_skipped, files_excluded,"
                    " bytes_scanned, detections_count)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        kind, root, started_at or now, finished_at or now,
                        files_scanned, files_skipped, files_excluded,
                        bytes_scanned, len(detections),
                    ),
                )
                scan_id = int(cursor.lastrowid)
                self._conn.executemany(
                    "INSERT INTO detections (scan_id, recorded_at, path,"
                    " verdict, severity, score, name, reasons, sha256,"
                    " action_taken) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            scan_id, now, d.path, d.verdict, d.severity,
                            d.score, d.name, json.dumps(d.reasons), d.sha256,
                            d.action_taken,
                        )
                        for d in detections
                    ],
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                raise HistoryError(
                    f"could not record the scan in history: {exc}"
                ) from exc
        return scan_id

    def record_realtime_detection(
        self,
        *,
        path: str,
        verdict: str | None,
        severity: str | None,
        name: str | None = None,
        reasons: list[str] | None = None,
        sha256: str | None = None,
        action_taken: str = "none",
    ) -> int:
        """Record one real-time detection (a one-file 'scan')."""
        return self.record_scan(
            kind="realtime",
            root=path,
            files_scanned=1,
            detections=[
                DetectionRecord(
                    path=path,
                    verdict=verdict,
                    severity=severity,
                    name=name,
                    reasons=list(reasons or []),
                    sha256=sha256,
                    action_taken=action_taken,
                )
            ],
        )

    def update_detection_action(
        self, *, sha256: str, path: str, action_taken: str
    ) -> None:
        """Annotate the most recent matching detection with the action
        that was ultimately taken (e.g. a pending action approved
        later). Bookkeeping only — newest match wins."""
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT id FROM detections WHERE path = ? AND sha256 IS ?"
                    " ORDER BY id DESC LIMIT 1",
                    (path, sha256),
                ).fetchone()
                if row is None:
                    return
                self._conn.execute(
                    "UPDATE detections SET action_taken = ? WHERE id = ?",
                    (action_taken, row["id"]),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                raise HistoryError(
                    f"could not update the detection record: {exc}"
                ) from exc

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def recent_scans(self, limit: int = 20) -> list[ScanRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            ScanRecord(
                id=r["id"], kind=r["kind"], root=r["root"],
                started_at=r["started_at"], finished_at=r["finished_at"],
                files_scanned=r["files_scanned"],
                files_skipped=r["files_skipped"],
                files_excluded=r["files_excluded"],
                bytes_scanned=r["bytes_scanned"],
                detections_count=r["detections_count"],
            )
            for r in rows
        ]

    def recent_detections(self, limit: int = 50) -> list[StoredDetection]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM detections ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._detection_from_row(r) for r in rows]

    def detections_since(self, days: int) -> list[StoredDetection]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM detections WHERE recorded_at >= ?"
                " ORDER BY id DESC",
                (_cutoff_iso(days),),
            ).fetchall()
        return [self._detection_from_row(r) for r in rows]

    def scans_since(self, days: int) -> list[ScanRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans WHERE started_at >= ? ORDER BY id DESC",
                (_cutoff_iso(days),),
            ).fetchall()
        return [
            ScanRecord(
                id=r["id"], kind=r["kind"], root=r["root"],
                started_at=r["started_at"], finished_at=r["finished_at"],
                files_scanned=r["files_scanned"],
                files_skipped=r["files_skipped"],
                files_excluded=r["files_excluded"],
                bytes_scanned=r["bytes_scanned"],
                detections_count=r["detections_count"],
            )
            for r in rows
        ]

    def summary(self, days: int = 7) -> dict:
        """Aggregate numbers for the last *days* days."""
        scans = self.scans_since(days)
        detections = self.detections_since(days)
        by_severity: dict[str, int] = {}
        by_verdict: dict[str, int] = {}
        by_action: dict[str, int] = {}
        for det in detections:
            if det.severity:
                by_severity[det.severity] = by_severity.get(det.severity, 0) + 1
            if det.verdict:
                by_verdict[det.verdict] = by_verdict.get(det.verdict, 0) + 1
            by_action[det.action_taken] = by_action.get(det.action_taken, 0) + 1
        return {
            "days": days,
            "scans": len(scans),
            "on_demand_scans": sum(1 for s in scans if s.kind == "ondemand"),
            "realtime_events": sum(1 for s in scans if s.kind == "realtime"),
            "files_scanned": sum(s.files_scanned for s in scans),
            "files_skipped": sum(s.files_skipped for s in scans),
            "files_excluded": sum(s.files_excluded for s in scans),
            "bytes_scanned": sum(s.bytes_scanned for s in scans),
            "detections": len(detections),
            "by_severity": by_severity,
            "by_verdict": by_verdict,
            "by_action": by_action,
        }

    @staticmethod
    def _detection_from_row(row: sqlite3.Row) -> StoredDetection:
        return StoredDetection(
            id=row["id"],
            scan_id=row["scan_id"],
            recorded_at=row["recorded_at"],
            path=row["path"],
            verdict=row["verdict"],
            severity=row["severity"],
            score=row["score"],
            name=row["name"],
            reasons=json.loads(row["reasons"] or "[]"),
            sha256=row["sha256"],
            action_taken=row["action_taken"],
        )


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------
_ACTION_PHRASES = {
    "none": "no action was taken — the file is still where it was",
    "pending": "waiting in the actions queue for your decision",
    "quarantined": "moved into the quarantine vault (reversible)",
    "deleted": "permanently deleted",
    "allowed": "you vouched for it — Argus restored it and will leave it alone",
    "ignored": "you chose to leave it as it is",
}


def report_dict(history: History, days: int = 7) -> dict:
    """The report as data (JSON-exportable)."""
    return {
        "product": "ARGUS.EXE",
        "vendor": "Sentinel Safeguard LLC",
        "generated_at": _utcnow_iso(),
        "summary": history.summary(days),
        "detections": [d.to_dict() for d in history.detections_since(days)],
        "recent_scans": [s.to_dict() for s in history.scans_since(days)],
    }


def render_text_report(history: History, days: int = 7) -> str:
    """The report in plain language."""
    summary = history.summary(days)
    detections = history.detections_since(days)
    lines: list[str] = []
    lines.append(f"ARGUS report — the last {days} day(s)")
    lines.append("=" * 60)
    lines.append(
        f"Scans run: {summary['scans']} "
        f"({summary['on_demand_scans']} manual, "
        f"{summary['realtime_events']} real-time)"
    )
    lines.append(
        f"Files checked: {summary['files_scanned']} "
        f"({summary['bytes_scanned'] / (1024 * 1024):.1f} MB)"
    )
    if summary["files_excluded"]:
        lines.append(
            f"Files left alone by your exclusions: {summary['files_excluded']}"
        )
    if summary["files_skipped"]:
        lines.append(
            f"Files that could not be read: {summary['files_skipped']}"
        )
    lines.append("")
    if not detections:
        lines.append(
            "Nothing was flagged. Everything Argus checked in this "
            "period came back clean."
        )
        return "\n".join(lines)

    lines.append(f"Flagged files: {len(detections)}")
    by_severity = summary["by_severity"]
    if by_severity:
        parts = ", ".join(
            f"{count} {severity}"
            for severity, count in sorted(
                by_severity.items(),
                key=lambda kv: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(kv[0], 4),
            )
        )
        lines.append(f"By severity: {parts}")
    for det in detections:
        verdict = (det.verdict or "Flagged").upper()
        severity = (det.severity or "unknown").capitalize()
        lines.append("")
        lines.append(f"[{verdict} — {severity}] {det.path}")
        if det.name:
            lines.append(f"  What: {det.name}")
        for reason in det.reasons:
            lines.append(f"  Why: {reason}")
        if det.score:
            lines.append(f"  Heuristic risk score: {det.score}")
        phrase = _ACTION_PHRASES.get(det.action_taken, det.action_taken)
        lines.append(f"  What happened: {phrase}.")
        if det.sha256:
            lines.append(f"  SHA-256: {det.sha256}")
    return "\n".join(lines)
