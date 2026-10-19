"""The service action-request channel (v1.0.4 trust split).

Under the installed layout, the quarantine vault lives in the
trusted data root: the LocalSystem service can act on it, but a
standard user's GUI/CLI process cannot even read it. Vault actions a
human asks for (restore / delete / allow / approve / reject) still
have to work from the GUI — so when the direct route is not
available to the calling process, the request is handed to the
service, which executes it against ITS OWN records and reports the
outcome back.

Two transports, one discipline:

- **File channel** (plain JSON files in the shared directory) —
  the original protocol, still used by portable/dev layouts and
  anywhere caller and service share one user's trust domain:

  - The caller writes ``shared/requests/<id>.json``::
        {id, kind, entry_id|pending_id, sha256, requested_by, nonce}
    where ``sha256`` is the fingerprint the human saw when they
    confirmed — the service refuses if its own record disagrees —
    and ``nonce`` is a fresh uuid4 hex kept in this module's
    outstanding registry (protocol v2).
  - The service writes ``shared/results/<id>.json``::
        {id, ok, message, restored_path?, nonce}
    echoing the request's nonce. The caller accepts a result only
    when its id matches AND its nonce matches the outstanding
    registry entry (when one exists) — a planted result file with a
    wrong or absent nonce is ignored and the caller keeps waiting.

- **Verified pipe channel** (fix round 2, FIX 1) — on Windows in
  the installed layout, PRIVILEGED kinds travel over the local
  named pipe in :mod:`argus.pipe_channel` instead, and the
  service executes only when the calling PROCESS verifies as the
  genuine Argus program (canonical path + setup-recorded
  fingerprint). A fingerprint says WHICH file; it is public data
  (the service publishes it in its snapshots) and can never say
  WHO is asking — the pipe can. See :func:`pipe_channel_required`.
  Pipe failure is a designed error, never a silent fallback to
  the forgeable file drop.

The helpers here are the caller side only; the executing side lives
in :mod:`argus.service`. The direct route stays the default
everywhere it works (portable edition, elevated shells, dev trees):
this channel exists for the standard-user GUI on an installed
machine, and the "direct" probe is :func:`path_writable`.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import pipe_channel
from .paths import requests_dir, results_dir, write_text_atomic
from .pipe_channel import PipeUnavailableError

#: Request kinds the service will execute.
REQUEST_KINDS = (
    "restore",
    "delete",
    "allow",
    "approve-pending",
    "reject-pending",
)

#: Every current request kind is privileged: each one moves,
#: destroys, or vouches for a file as LocalSystem on a human's
#: say-so. In the installed Windows layout they ALL require the
#: verified pipe (fix round 2).
PRIVILEGED_KINDS = frozenset(REQUEST_KINDS)

DEFAULT_TIMEOUT_SECONDS = 30.0
_POLL_INTERVAL_SECONDS = 0.25

#: Outstanding request nonces, by request id (protocol v2). An entry
#: exists from submit_request until await_result accepts a result
#: (or times out); results are only trusted against this registry.
_outstanding_nonces: dict[str, str] = {}


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
    nonce = uuid.uuid4().hex
    _outstanding_nonces[rid] = nonce
    payload = {
        "id": rid,
        "kind": kind,
        "entry_id": entry_id,
        "pending_id": pending_id,
        "sha256": sha256,
        "requested_by": requested_by or _default_requester(),
        "nonce": nonce,
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
    expected_nonce = _outstanding_nonces.get(request_id)
    while True:
        try:
            raw = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = None
        if isinstance(raw, dict) and raw.get("id") == request_id:
            # Nonce gate (v2): when this process submitted the
            # request, only a result echoing its nonce counts. A
            # planted result with a wrong/absent nonce is ignored —
            # the caller keeps waiting until timeout.
            if expected_nonce is not None and raw.get("nonce") != expected_nonce:
                raw = None
            else:
                _outstanding_nonces.pop(request_id, None)
                return ActionRequestResult(
                    ok=bool(raw.get("ok")),
                    message=str(raw.get("message") or ""),
                    restored_path=raw.get("restored_path"),
                )
        if time.monotonic() >= deadline:
            _outstanding_nonces.pop(request_id, None)
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
    """Submit one action request and wait for the service's answer.

    Transport: a PRIVILEGED kind on an installed Windows layout
    goes over the verified pipe (fix round 2) — see
    :func:`pipe_channel_required`. An explicit *requests* folder
    (tests, embedded callers) always means the file channel.
    """
    if (
        requests is None
        and kind in PRIVILEGED_KINDS
        and pipe_channel_required()
    ):
        return _submit_via_pipe(
            kind,
            entry_id=entry_id,
            pending_id=pending_id,
            sha256=sha256,
            requested_by=requested_by,
            timeout=timeout,
        )
    rid = submit_request(
        kind,
        entry_id=entry_id,
        pending_id=pending_id,
        sha256=sha256,
        requested_by=requested_by,
        requests=requests,
    )
    return await_result(rid, results=results, timeout=timeout)


# ----------------------------------------------------------------------
# Verified pipe transport (fix round 2, FIX 1)
# ----------------------------------------------------------------------
def pipe_channel_required() -> bool:
    """True when privileged actions must use the verified pipe:
    Windows, the INSTALLED layout (not portable — no
    ``ARGUS_DATA_DIR``), and a completed setup (the canonical
    program file exists AND setup recorded its fingerprint).
    Anywhere else, caller and service share one user's trust
    domain and the file channel stands (see the module
    docstring and docs/ROADMAP.md)."""
    if sys.platform != "win32":
        return False
    if os.environ.get("ARGUS_DATA_DIR"):
        return False
    try:
        from .selftrust import load_recorded_exe_sha256
        from .setup_engine import canonical_exe_path

        return canonical_exe_path().is_file() and bool(
            load_recorded_exe_sha256()
        )
    except Exception:
        return False


_PIPE_CONNECT_MESSAGE = (
    "Argus couldn't reach its protection service, so this action "
    "was NOT carried out. The service may be stopped — restart "
    "Windows (or start the Argus service) and try again."
)

_PIPE_LOST_MESSAGE = (
    "Argus reached its protection service, but the service stopped "
    "answering, so this action was NOT carried out. Nothing was "
    "changed — try again, and if it keeps happening, restart Argus."
)


def _submit_via_pipe(
    kind: str,
    *,
    entry_id: str | None,
    pending_id: str | None,
    sha256: str | None,
    requested_by: str | None,
    timeout: float,
) -> ActionRequestResult:
    rid = new_request_id()
    nonce = uuid.uuid4().hex
    _outstanding_nonces[rid] = nonce
    payload = {
        "id": rid,
        "kind": kind,
        "entry_id": entry_id,
        "pending_id": pending_id,
        "sha256": sha256,
        "requested_by": requested_by or _default_requester(),
        "nonce": nonce,
    }
    try:
        response = pipe_channel.pipe_roundtrip(payload, timeout=timeout)
    except PipeUnavailableError as exc:
        _outstanding_nonces.pop(rid, None)
        message = (
            _PIPE_CONNECT_MESSAGE
            if exc.stage == "connect"
            else _PIPE_LOST_MESSAGE
        )
        return ActionRequestResult(ok=False, message=message)
    _outstanding_nonces.pop(rid, None)
    if response.get("id") != rid or response.get("nonce") != nonce:
        # The answer does not carry this request's identity stamp:
        # treat the action as NOT carried out, whatever it claims.
        return ActionRequestResult(
            ok=False,
            message=(
                "The protection service's answer could not be "
                "verified (its identity stamp did not match this "
                "request), so Argus treats the action as NOT "
                "carried out. Nothing was assumed — check the "
                "quarantine and pending pages for the real state."
            ),
        )
    return ActionRequestResult(
        ok=bool(response.get("ok")),
        message=str(response.get("message") or ""),
        restored_path=response.get("restored_path"),
    )


class ServiceDetailsError(Exception):
    """The protection service answered a details query with a
    refusal (the record is gone, or failed its integrity check).
    Carries the service's own plain-language message."""


def pipe_failure_message(exc: PipeUnavailableError) -> str:
    """The designed error text for a pipe transport failure —
    connect failures and mid-exchange failures read differently,
    because the next step they suggest differs."""
    return (
        _PIPE_CONNECT_MESSAGE
        if exc.stage == "connect"
        else _PIPE_LOST_MESSAGE
    )


def _fetch_details(kind: str, key: str, record_id: str) -> dict | None:
    """Ask the service for its OWN record of one entry/pending
    row (the authoritative-confirmation query).

    Returns None when the pipe is not required here — the caller
    already holds authoritative local data. Raises
    :class:`PipeUnavailableError` on transport failure and
    :class:`ServiceDetailsError` when the service refuses: in
    the installed layout a confirmation must NEVER be built from
    an unsigned snapshot when the service cannot be asked.
    """
    if not pipe_channel_required():
        return None
    rid = new_request_id()
    nonce = uuid.uuid4().hex
    payload = {"id": rid, "kind": kind, key: record_id, "nonce": nonce}
    response = pipe_channel.pipe_roundtrip(payload, timeout=DEFAULT_TIMEOUT_SECONDS)
    if response.get("id") != rid or response.get("nonce") != nonce:
        raise ServiceDetailsError(
            "the protection service's answer could not be verified, "
            "so Argus will not act on it"
        )
    if not response.get("ok"):
        raise ServiceDetailsError(
            str(response.get("message") or "the service refused the query")
        )
    details = response.get("details")
    if not isinstance(details, dict):
        raise ServiceDetailsError(
            "the protection service sent no details for that record"
        )
    return details


def fetch_entry_details(entry_id: str) -> dict | None:
    """The service's own vault-entry record for *entry_id* —
    what quarantine confirmations must display in the installed
    layout. None when the pipe is not required (local data is
    already authoritative)."""
    return _fetch_details("entry-details", "entry_id", entry_id)


def fetch_pending_details(pending_id: str) -> dict | None:
    """The service's own pending-queue record for *pending_id* —
    what pending confirmations must display in the installed
    layout. None when the pipe is not required."""
    return _fetch_details("pending-details", "pending_id", pending_id)


def _default_requester() -> str:
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
