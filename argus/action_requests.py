"""The service action-request channel (v1.0.4 trust split).

Under the installed layout, the quarantine vault lives in the
trusted data root: the LocalSystem service can act on it, but a
standard user's GUI/CLI process cannot even read it. Vault actions a
human asks for (restore / delete / allow / approve / reject) still
have to work from the GUI — so when the direct route is not
available to the calling process, the request is handed to the
service, which executes it against ITS OWN records and reports the
outcome back.

Protocol (plain JSON files in the shared directory):

- The caller writes ``shared/requests/<id>.json``::
      {id, kind, entry_id|pending_id, sha256, requested_by}
  where ``sha256`` is the fingerprint the human saw when they
  confirmed — the service refuses if its own record disagrees.
- The service writes ``shared/results/<id>.json``::
      {id, ok, message, restored_path?}
- The caller polls for its result file (bounded wait).

The helpers here are the caller side only; the executing side lives
in :mod:`argus.service`. The direct route stays the default
everywhere it works (portable edition, elevated shells, dev trees):
this channel exists for the standard-user GUI on an installed
machine, and the "direct" probe is :func:`path_writable`.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .paths import requests_dir, results_dir, write_text_atomic

#: Request kinds the service will execute.
REQUEST_KINDS = (
    "restore",
    "delete",
    "allow",
    "approve-pending",
    "reject-pending",
)

DEFAULT_TIMEOUT_SECONDS = 30.0
_POLL_INTERVAL_SECONDS = 0.25


@dataclass(frozen=True)
class ActionRequestResult:
    """The service's answer to one action request."""

    ok: bool
    message: str
    restored_path: str | None = None


def path_writable(path: Path | str) -> bool:
    """Best-effort probe: can THIS process write at *path*?

    Used to choose between the direct vault route and the service
    request channel. A nonexistent path defers to its parent.
    """
    target = Path(path)
    probe = target if target.exists() else target.parent
    return os.access(probe, os.W_OK)


def new_request_id() -> str:
    return uuid.uuid4().hex


def submit_request(
    kind: str,
    *,
    entry_id: str | None = None,
    pending_id: str | None = None,
    sha256: str | None = None,
    requested_by: str | None = None,
    requests: Path | None = None,
    request_id: str | None = None,
) -> str:
    """Drop one action request for the service. Returns its id.

    The request names a record (vault entry or pending action) and
    the fingerprint the human saw — never a path to act on blindly:
    the service resolves everything against its own records.
    """
    if kind not in REQUEST_KINDS:
        raise ValueError(f"unknown action request kind: {kind!r}")
    rid = request_id or new_request_id()
    payload = {
        "id": rid,
        "kind": kind,
        "entry_id": entry_id,
        "pending_id": pending_id,
        "sha256": sha256,
        "requested_by": requested_by or _default_requester(),
    }
    folder = Path(requests) if requests is not None else requests_dir()
    write_text_atomic(folder / f"{rid}.json", json.dumps(payload, indent=2) + "\n")
    return rid


def await_result(
    request_id: str,
    *,
    results: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ActionRequestResult:
    """Wait (bounded) for the service's result for *request_id*.

    A timeout is a normal, reportable outcome — the service may be
    stopped — never a hang and never a silent assumption of success.
    """
    folder = Path(results) if results is not None else results_dir()
    result_path = folder / f"{request_id}.json"
    deadline = time.monotonic() + timeout
    while True:
        try:
            raw = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = None
        if isinstance(raw, dict) and raw.get("id") == request_id:
            return ActionRequestResult(
                ok=bool(raw.get("ok")),
                message=str(raw.get("message") or ""),
                restored_path=raw.get("restored_path"),
            )
        if time.monotonic() >= deadline:
            return ActionRequestResult(
                ok=False,
                message=(
                    "The Argus protection service did not answer in "
                    f"{timeout:.0f} seconds. The action was NOT carried "
                    "out by this window. If the service is stopped, "
                    "start it (or restart Windows) and try again."
                ),
            )
        time.sleep(_POLL_INTERVAL_SECONDS)


def submit_and_wait(
    kind: str,
    *,
    entry_id: str | None = None,
    pending_id: str | None = None,
    sha256: str | None = None,
    requested_by: str | None = None,
    requests: Path | None = None,
    results: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ActionRequestResult:
    """Submit one action request and wait for the service's answer."""
    rid = submit_request(
        kind,
        entry_id=entry_id,
        pending_id=pending_id,
        sha256=sha256,
        requested_by=requested_by,
        requests=requests,
    )
    return await_result(rid, results=results, timeout=timeout)


def _default_requester() -> str:
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
