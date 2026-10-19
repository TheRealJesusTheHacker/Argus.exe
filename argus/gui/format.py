"""Plain-language formatting for the GUI — deliberately Qt-free.

Everything here is testable without a display: how protection status
becomes a headline a person understands, how sizes and counts read,
and how an engine result becomes the row the Scan page shows.
"""

from __future__ import annotations

from pathlib import Path


def protection_headline(status: dict | None) -> tuple[str, str, str]:
    """Turn a service status dict into (headline, detail, tone).

    Tone is one of "protected" | "paused" | "attention" | "off" so
    the caller can pick colors without parsing the text."""
    if not status or not status.get("running"):
        return (
            "Protection is off",
            "Real-time protection is not running. Files landing on this "
            "computer are not being checked as they arrive. Turn "
            "protection on to fix that.",
            "off",
        )
    if status.get("paused"):
        return (
            "Protection is paused",
            "Argus is loaded but not scanning right now. Resume "
            "protection to keep watching for threats.",
            "paused",
        )
    errors = status.get("last_error")
    if status.get("state") == "error" or errors:
        # The engine's own error text is a technical record (it is
        # in the status file and the log for support) — the person
        # at the screen gets plain language and a next step, never
        # a raw exception string.
        return (
            "Protection needs attention",
            "Something went wrong while protection was running. "
            "Turn protection off and back on — if it keeps "
            "happening, contact Sentinel Safeguard and mention "
            "what time it happened.",
            "attention",
        )
    watch_dirs = status.get("watch_dirs") or []
    pending = status.get("pending_actions") or 0
    detail = (
        f"Real-time protection is on and watching {len(watch_dirs)} "
        "folder(s). New and changed files are checked as they appear."
    )
    if pending:
        detail += (
            f" {pending} detection(s) are waiting for your decision — "
            "see Pending Actions."
        )
    return ("You're protected", detail, "protected")


def human_bytes(size: int | None) -> str:
    if size is None:
        return "—"
    value = float(size)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:,.0f} {unit}" if unit == "bytes" else f"{value:,.1f} {unit}"
        value /= 1024
    return f"{value:,.1f} TB"  # pragma: no cover


def scan_result_row(scanned) -> dict:
    """Flatten a ScannedFile into the dict the Scan page renders."""
    result = scanned.result
    assessment = scanned.assessment
    worst = None
    reasons: list[str] = []
    for det in assessment.detections:
        reasons.append(f"{det.name} — {det.reason}")
        if worst is None:
            worst = det.severity
    for sig in assessment.signals:
        reasons.append(f"{sig.name}: {sig.explanation} (+{sig.points})")
    return {
        "path": str(result.path),
        "name": Path(result.path).name,
        "size": result.size,
        "sha256": result.sha256,
        "verdict": scanned.verdict.value,
        "score": assessment.score,
        "severity": worst or _severity_for_score(assessment),
        "reasons": reasons,
        "error": result.error,
        "excluded": scanned.excluded,
        "scanned": scanned,
    }


def _severity_for_score(assessment) -> str | None:
    if assessment.max_severity:
        return assessment.max_severity
    if assessment.signals:
        return assessment.signals[0].severity
    return None


def policy_plain_language(policy: str) -> str:
    return {
        "ask": (
            "Ask me every time — Argus stops and waits for your "
            "decision before touching a suspicious file. Safest if "
            "you like being in control."
        ),
        "auto-quarantine-critical": (
            "Handle the worst automatically — Critical threats are "
            "quarantined on sight; anything less serious still asks "
            "you first."
        ),
        "log-only": (
            "Hands off — Argus records what it found but never moves "
            "or blocks a file. Best for testing and experts."
        ),
    }.get(policy, policy)


def score_band(score: int) -> str:
    if score >= 60:
        return "Malicious territory"
    if score >= 25:
        return "Suspicious territory"
    if score > 0:
        return "Some weak signals"
    return "Nothing suspicious seen"
