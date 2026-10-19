"""The ARGUS.EXE action layer: detections → responses.

Phase 3's engine could only *ask* for things to happen. This module is
where asking becomes doing — carefully. The rules are absolute:

- **Never silent.** Quarantine, delete, and allow are destructive or
  trust-changing operations. Every one of them requires an explicit
  confirmation from the caller: a human saying yes at a prompt, a
  queued action a human approved, or a real-time policy the user
  themselves configured. Library code never prompts and never
  assumes — without ``confirmed=True`` it raises
  :class:`ConfirmationRequired` and touches nothing.
- **Delete is never automatic.** Even under the most aggressive
  real-time policy, permanent deletion waits for a human. The most a
  policy may do unattended is *quarantine* a Critical file —
  quarantine is reversible, deletion is not.
- **Quarantine-first.** Deleting a file "for real" routes it through
  the vault first (so the vault index keeps the audit record) unless
  the caller explicitly asks for a direct delete.

Real-time integration: :meth:`ActionEngine.handle_realtime_event`
consumes the engine's events under ``config.realtime_default``:

- ``ask`` (default) — action requests become pending actions in the
  vault queue; a human approves or rejects them later;
- ``auto-quarantine-critical`` — Critical quarantine requests execute
  immediately (the user's configured policy *is* the confirmation);
  everything else, and every delete request, goes to the queue;
- ``log-only`` — requests are recorded in history and nothing else
  happens (simulation mode).

Every executed action is written to scan history so reports can say
what happened to each flagged file.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .config import ArgusConfig
from .quarantine import PendingAction, QuarantineEntry, Vault
from .reporting import DetectionRecord, History
from .scanner import hash_file

if TYPE_CHECKING:  # runtime import would be circular
    from .realtime import RealtimeEvent
    from .scanner import ScannedFile

log = logging.getLogger("argus.actions")

QUARANTINE = "quarantine"
DELETE = "delete"
ALLOW = "allow"
IGNORE = "ignore"
RESTORE = "restore"

#: Cap on remembered real-time detection contexts (see
#: :attr:`ActionEngine._rt_context`). Contexts exist only so a
#: following action event can borrow its detection's richer reasons;
#: a bounded FIFO keeps a busy watch folder from growing the map
#: without limit when detections never produce action events.
_RT_CONTEXT_LIMIT = 512


class ActionError(Exception):
    """An action could not be carried out."""


class ConfirmationRequired(ActionError):
    """A destructive action was attempted without explicit confirmation.

    This is the never-silent rule enforcing itself: catching this and
    retrying with ``confirmed=True`` without an actual human/policy
    decision behind it would defeat the point.
    """


def _require_confirmed(confirmed: bool, what: str) -> None:
    if not confirmed:
        raise ConfirmationRequired(
            f"{what} needs explicit confirmation — Argus never does "
            "this silently. A human decision (prompt, approved queued "
            "action, or the user's configured policy) must set "
            "confirmed=True."
        )


@dataclass
class DetectionInfo:
    """The facts about a flagged file that actions and the vault need."""

    name: str
    severity: str | None = None
    verdict: str | None = None
    reasons: list[str] | None = None
    sha256: str | None = None

    @classmethod
    def from_scanned(cls, scanned: "ScannedFile") -> "DetectionInfo":
        assessment = scanned.assessment
        if assessment.detections:
            name = assessment.detections[0].name
        elif assessment.signals:
            name = assessment.signals[0].name
        else:
            name = "Heuristic detection"
        reasons = [d.reason for d in assessment.detections]
        reasons += [s.explanation for s in assessment.signals]
        return cls(
            name=name,
            severity=assessment.max_severity,
            verdict=scanned.verdict.value,
            reasons=reasons,
            sha256=scanned.result.sha256,
        )


@dataclass
class ActionOutcome:
    """What an action (or a policy decision) actually did."""

    action: str
    path: str
    done: bool
    message: str
    entry_id: str | None = None
    pending_id: str | None = None
    restored_path: str | None = None


class ActionEngine:
    """Executes (or queues) responses to detections, with history."""

    def __init__(
        self,
        vault: Vault,
        config: ArgusConfig | None = None,
        *,
        config_path: Path | str | None = None,
        history: History | None = None,
    ) -> None:
        self.vault = vault
        self.config = config or ArgusConfig()
        self.config_path = Path(config_path) if config_path else None
        self.history = history
        #: Latest real-time detection event per path, so an action
        #: event (which follows its detection) can borrow its reasons.
        self._rt_context: dict[str, "RealtimeEvent"] = {}

    # ------------------------------------------------------------------
    # Direct actions (all require confirmation)
    # ------------------------------------------------------------------
    def quarantine(
        self,
        path: Path | str,
        info: DetectionInfo,
        *,
        confirmed: bool = False,
    ) -> ActionOutcome:
        """Move *path* into the quarantine vault."""
        _require_confirmed(confirmed, f"Quarantining {path}")
        entry = self.vault.quarantine_file(
            path,
            detection_name=info.name,
            severity=info.severity,
            verdict=info.verdict,
            reasons=info.reasons or [],
            sha256=info.sha256,
        )
        self._record_action(info, str(path), "quarantined", entry.sha256)
        return ActionOutcome(
            action=QUARANTINE,
            path=str(path),
            done=True,
            entry_id=entry.id,
            message=(
                f"{Path(path).name} is now in the quarantine vault. "
                "It cannot run from there, and you can restore it any "
                "time with: argus quarantine list / restore."
            ),
        )

    def delete(
        self,
        path: Path | str,
        info: DetectionInfo,
        *,
        confirmed: bool = False,
        direct: bool = False,
    ) -> ActionOutcome:
        """Permanently delete *path*.

        Default route goes through the vault first, so the vault
        index keeps an audit record of what was destroyed and why.
        ``direct=True`` skips the vault (the file is removed where it
        stands) — only history remembers it. Either way this needs
        explicit confirmation; there is no automatic delete anywhere
        in Argus.
        """
        _require_confirmed(confirmed, f"Permanently deleting {path}")
        target = Path(path)
        if not target.is_file():
            raise ActionError(f"nothing to delete at {target}")
        sha256 = info.sha256
        if sha256 is None:
            sha256, _ = hash_file(target)
        if direct:
            target.unlink()
            entry_id = None
        else:
            entry = self.vault.quarantine_file(
                target,
                detection_name=info.name,
                severity=info.severity,
                verdict=info.verdict,
                reasons=info.reasons or [],
                sha256=sha256,
            )
            self.vault.delete_permanent(entry.id)
            entry_id = entry.id
        self._record_action(info, str(target), "deleted", sha256)
        return ActionOutcome(
            action=DELETE,
            path=str(target),
            done=True,
            entry_id=entry_id,
            message=f"{target.name} has been permanently deleted.",
        )

    def allow_entry(
        self, entry_id: str, *, confirmed: bool = False
    ) -> ActionOutcome:
        """Vouch for a quarantined file: restore it, add its
        fingerprint to the exclusions, and mark it allowed — Argus
        will leave that exact file alone from now on."""
        _require_confirmed(confirmed, "Allowing a quarantined file")
        entry = self.vault.get_entry(entry_id)
        if entry is None:
            raise ActionError(f"no vault entry with id {entry_id}")
        restored = self.vault.restore(entry_id, final_status="allowed")
        self._exclude_hash(entry.sha256)
        if self.history is not None:
            self.history.update_detection_action(
                sha256=entry.sha256, path=entry.original_path,
                action_taken="allowed",
            )
        return ActionOutcome(
            action=ALLOW,
            path=entry.original_path,
            done=True,
            entry_id=entry.id,
            restored_path=str(restored),
            message=(
                f"{restored.name} has been restored to {restored} and "
                "its fingerprint added to your exclusions. Argus will "
                "leave this exact file alone from now on. (If the file "
                "changes, it becomes a different file and will be "
                "checked again.)"
            ),
        )

    def restore_entry(
        self, entry_id: str, *, confirmed: bool = False
    ) -> ActionOutcome:
        """Put a quarantined file back where it lived (the vault
        never overwrites a file that has since taken its place)."""
        _require_confirmed(confirmed, "Restoring a quarantined file")
        entry = self.vault.get_entry(entry_id)
        if entry is None:
            raise ActionError(f"no vault entry with id {entry_id}")
        restored = self.vault.restore(entry_id)
        return ActionOutcome(
            action=RESTORE,
            path=entry.original_path,
            done=True,
            entry_id=entry.id,
            restored_path=str(restored),
            message=f"{restored.name} has been restored to {restored}.",
        )

    def delete_entry(
        self, entry_id: str, *, confirmed: bool = False
    ) -> ActionOutcome:
        """Permanently destroy a quarantined file. The vault index
        row stays as the audit record."""
        _require_confirmed(confirmed, "Permanently deleting a quarantined file")
        entry = self.vault.get_entry(entry_id)
        if entry is None:
            raise ActionError(f"no vault entry with id {entry_id}")
        self.vault.delete_permanent(entry_id)
        if self.history is not None:
            self.history.update_detection_action(
                sha256=entry.sha256, path=entry.original_path,
                action_taken="deleted",
            )
        return ActionOutcome(
            action=DELETE,
            path=entry.original_path,
            done=True,
            entry_id=entry.id,
            message=(
                f"{Path(entry.original_path).name} has been "
                "permanently deleted from the quarantine vault."
            ),
        )

    def allow_file(
        self, path: Path | str, *, confirmed: bool = False
    ) -> ActionOutcome:
        """Vouch for a file that is still on disk (not quarantined):
        fingerprint it and add the fingerprint to the exclusions."""
        _require_confirmed(confirmed, f"Allowing {path}")
        target = Path(path)
        if not target.is_file():
            raise ActionError(f"nothing to allow at {target}")
        sha256, _ = hash_file(target)
        self._exclude_hash(sha256)
        return ActionOutcome(
            action=ALLOW,
            path=str(target),
            done=True,
            message=(
                f"Argus will leave {target.name} (and any identical "
                "copy of it) alone from now on."
            ),
        )

    def ignore(
        self, path: Path | str, info: DetectionInfo | None = None
    ) -> ActionOutcome:
        """Record a deliberate 'leave it' decision. Not destructive —
        no confirmation needed, and nothing about the file changes."""
        if info is not None:
            self._record_action(info, str(path), "ignored", info.sha256)
        log.info("user chose to ignore %s", path)
        return ActionOutcome(
            action=IGNORE,
            path=str(path),
            done=True,
            message=f"{Path(path).name} left as it is, at your decision.",
        )

    # ------------------------------------------------------------------
    # Pending queue: approve / reject
    # ------------------------------------------------------------------
    def enqueue(
        self,
        *,
        source: str,
        path: Path | str,
        action: str,
        info: DetectionInfo,
    ) -> PendingAction:
        """Queue an action request for a human decision."""
        return self.vault.add_pending(
            source=source,
            path=path,
            action=action,
            sha256=info.sha256,
            severity=info.severity,
            verdict=info.verdict,
            detection_name=info.name,
            reasons=info.reasons or [],
        )

    def list_pending(self) -> list[PendingAction]:
        return self.vault.list_pending("pending")

    def approve(self, pending_id: str) -> ActionOutcome:
        """Carry out a queued action. Approving IS the confirmation —
        a human reviewed this exact file and said yes."""
        pending = self._require_pending(pending_id)
        info = DetectionInfo(
            name=pending.detection_name or "Detection",
            severity=pending.severity,
            verdict=pending.verdict,
            reasons=list(pending.reasons),
            sha256=pending.sha256,
        )
        try:
            if pending.action == QUARANTINE:
                outcome = self.quarantine(pending.path, info, confirmed=True)
            elif pending.action == DELETE:
                outcome = self.delete(pending.path, info, confirmed=True)
            else:
                raise ActionError(
                    f"queued action {pending.action!r} cannot be approved"
                )
        except Exception as exc:
            self.vault.update_pending(pending_id, status="failed", error=str(exc))
            raise
        self.vault.update_pending(
            pending_id, status="done", entry_id=outcome.entry_id
        )
        if self.history is not None and pending.sha256:
            self.history.update_detection_action(
                sha256=pending.sha256,
                path=pending.path,
                action_taken=(
                    "quarantined" if pending.action == QUARANTINE else "deleted"
                ),
            )
        outcome.pending_id = pending_id
        return outcome

    def reject(self, pending_id: str) -> PendingAction:
        """Decline a queued action: the file is left exactly as it is."""
        pending = self._require_pending(pending_id)
        self.vault.update_pending(pending_id, status="rejected")
        if self.history is not None and pending.sha256:
            self.history.update_detection_action(
                sha256=pending.sha256, path=pending.path, action_taken="ignored"
            )
        decided = self.vault.get_pending(pending_id)
        assert decided is not None  # it existed a moment ago
        return decided

    def _require_pending(self, pending_id: str) -> PendingAction:
        pending = self.vault.get_pending(pending_id)
        if pending is None:
            raise ActionError(f"no pending action with id {pending_id}")
        if pending.status != "pending":
            raise ActionError(
                f"pending action {pending_id} was already {pending.status}"
            )
        return pending

    # ------------------------------------------------------------------
    # Real-time routing
    # ------------------------------------------------------------------
    def handle_realtime_event(self, event: "RealtimeEvent") -> ActionOutcome | None:
        """Route one real-time engine event under the configured policy.

        Detection events are recorded in history immediately (so
        alert/log severities, which never raise an action request,
        are still on the record) and remembered as context. Action
        events become a queue entry, an immediate Critical
        quarantine, or a history annotation — per
        ``config.realtime_default`` — and the history row is updated
        with the outcome. DELETE requests are never executed here,
        under any policy.
        """
        if event.kind == "detection" and event.path:
            # Remember the detection as context ONLY when its
            # severity's configured action can actually produce a
            # following action event — and keep the map bounded
            # (FIFO) either way. Detections are recorded in history
            # regardless; the context is purely an optimisation for
            # richer action reasons, so dropping the oldest is safe.
            if self.config.action_for(event.severity) in (QUARANTINE, DELETE):
                self._rt_context[event.path] = event
                while len(self._rt_context) > _RT_CONTEXT_LIMIT:
                    self._rt_context.pop(next(iter(self._rt_context)))
            if self.history is not None:
                self.history.record_realtime_detection(
                    path=event.path,
                    verdict=event.verdict,
                    severity=event.severity,
                    name="Real-time detection",
                    reasons=[event.message],
                    sha256=event.sha256,
                    action_taken="none",
                )
            return None
        if event.kind != "action" or not event.path or not event.action:
            return None

        context = self._rt_context.pop(event.path, None)
        reasons = [context.message] if context is not None else [event.message]
        info = DetectionInfo(
            name=_rt_detection_name(context, event),
            severity=event.severity,
            verdict=event.verdict,
            reasons=reasons,
            sha256=event.sha256,
        )
        policy = self.config.realtime_default

        if policy == "log-only":
            return ActionOutcome(
                action=event.action, path=event.path, done=False,
                message=(
                    "Real-time policy is 'log-only': the request was "
                    "written to history and nothing was queued or moved."
                ),
            )

        if (
            policy == "auto-quarantine-critical"
            and event.action == QUARANTINE
            and (event.severity or "").lower() == "critical"
        ):
            # The user's own configured policy is the confirmation.
            outcome = self.quarantine(event.path, info, confirmed=True)
            outcome.message = (
                "Your real-time policy quarantines Critical threats "
                "automatically. " + outcome.message
            )
            self._annotate_realtime(event, "quarantined")
            return outcome

        pending = self.enqueue(
            source="realtime", path=event.path, action=event.action, info=info
        )
        self._annotate_realtime(event, "pending")
        return ActionOutcome(
            action=event.action,
            path=event.path,
            done=False,
            pending_id=pending.id,
            message=(
                f"Queued for your decision (pending action {pending.id}). "
                "Argus has not touched the file. Review it with: "
                "argus pending list"
            ),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _annotate_realtime(self, event: "RealtimeEvent", action_taken: str) -> None:
        """Update the history row written when the detection arrived."""
        if self.history is None or not event.path:
            return
        self.history.update_detection_action(
            sha256=event.sha256, path=event.path, action_taken=action_taken
        )

    def _record_action(
        self, info: DetectionInfo, path: str, action_taken: str, sha256: str | None
    ) -> None:
        """Best-effort history note for direct (CLI-driven) actions:
        annotates the matching scan detection when there is one."""
        if self.history is None:
            return
        self.history.update_detection_action(
            sha256=sha256 or info.sha256, path=path, action_taken=action_taken
        )

    def _exclude_hash(self, sha256: str) -> None:
        self.config.add_hash_exclusion(sha256)
        if self.config_path is not None:
            try:
                self.config.save(self.config_path)
            except OSError as exc:
                raise ActionError(
                    f"the file was vouched for, but the exclusion could "
                    f"not be saved to {self.config_path}: {exc}. It will "
                    "be allowed until Argus restarts; add the fingerprint "
                    "to your config by hand to keep it permanent."
                ) from exc
        else:
            log.warning(
                "exclusion for %s is in-memory only (no config file to "
                "save it to)",
                sha256,
            )


def _rt_detection_name(
    context: "RealtimeEvent | None", event: "RealtimeEvent"
) -> str:
    """Best available name for a real-time detection. The detection
    event's message leads with the plain-language finding; the vault
    gets a short label plus that message as the reason."""
    if context is not None and context.verdict:
        return f"Real-time detection ({context.verdict})"
    return "Real-time detection"


def entry_info(entry: QuarantineEntry) -> DetectionInfo:
    """DetectionInfo rebuilt from a vault entry (for re-actions)."""
    return DetectionInfo(
        name=entry.detection_name,
        severity=entry.severity,
        verdict=entry.verdict,
        reasons=list(entry.reasons),
        sha256=entry.sha256,
    )
