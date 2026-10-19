"""The process-identity-verified pipe channel (v1.1.0 fix round 2).

Why this exists
---------------
The file request channel (:mod:`argus.action_requests`) carries
*data*, not *credentials*: entry ids and SHA-256 fingerprints are
published in the service's own snapshots, so any standard-user
process can write a perfectly-formed request file and the service
cannot tell it apart from the genuine GUI's request. For
PRIVILEGED actions — restoring, allowing, or deleting vault
entries, approving or rejecting queued actions — that is not good
enough: a fingerprint proves WHICH file, never WHO is asking.

On Windows in the installed layout, privileged actions therefore
travel over a local named pipe, and the service executes a
request only when the process on the other end of the pipe is
verified to be the genuine Argus program:

1. the client PID is taken from the pipe itself
   (``GetNamedPipeClientProcessId`` — the client cannot claim
   another process's identity),
2. the PID's image path must resolve to the canonical install
   path of ``Argus.exe``,
3. that file's SHA-256 must equal the fingerprint the setup
   engine recorded in the trusted data root at install time
   (:mod:`argus.selftrust`) — a replaced binary fails here even
   though it sits at the right address, and with no recorded
   fingerprint privileged requests are refused outright.

The verification logic is factored behind an injectable
identity-provider seam so it is fully testable off-Windows; the
pywin32 transport lives in :class:`WindowsPipeServer` and
:func:`pipe_roundtrip` and is only touched on Windows.

Non-Windows and portable/dev layouts keep the file channel:
there the caller and the service share one user's trust domain,
and there is no LocalSystem boundary to cross. That limitation
is stated plainly in docs/ROADMAP.md — the pipe is what the
installed product's privilege boundary stands on.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("argus.pipe_channel")

#: The pipe privileged action requests travel over (Windows).
PIPE_NAME = r"\\.\pipe\ArgusProtectionActions"

#: Query kinds the pipe answers from the service's OWN records —
#: the authoritative-confirmation channel. These are never file
#: requests and are never privileged actions; they exist so a
#: human's confirmation dialog shows what the SERVICE holds, not
#: what an unsigned snapshot file claims.
QUERY_KINDS = ("entry-details", "pending-details")

#: One pipe message, generous against the file channel's 64 KB.
_MAX_MESSAGE_BYTES = 256 * 1024

#: ERROR_ACCESS_DENIED — what CreateNamedPipe reports when the
#: pipe name is already owned by another process.
_ERROR_ACCESS_DENIED = 5

#: FILE_FLAG_FIRST_PIPE_INSTANCE (winbase.h): the create fails
#: instead of queueing behind an existing pipe of the same name.
_FIRST_PIPE_INSTANCE = 0x00080000

#: How long one pipe session may live before the service drops
#: it (fix round 3): a client that connects and then says
#: nothing must not hold its session hostage.
_SESSION_TIMEOUT_SECONDS = 10.0


def _first_pipe_instance_flag() -> int:
    """Resolve FILE_FLAG_FIRST_PIPE_INSTANCE from whichever
    pywin32 module carries it; the winbase value is the fallback
    (the constant is stable ABI, not a guess)."""
    for module_name in ("win32con", "win32pipe", "win32file"):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        flag = getattr(module, "FILE_FLAG_FIRST_PIPE_INSTANCE", None)
        if flag:
            return int(flag)
    return _FIRST_PIPE_INSTANCE

#: The user-facing refusal when caller verification fails. Plain
#: language, no internals: the dialog that shows it belongs to
#: whoever was refused, genuine or not.
CALLER_REFUSAL_MESSAGE = (
    "Argus could not verify that this request came from the "
    "Argus program itself, so it was refused. Nothing was done. "
    "If you asked for this from the Argus window, close Argus and "
    "open it again; if it keeps happening, reinstall Argus."
)


class PipeUnavailableError(Exception):
    """The pipe channel could not be used. ``stage`` says where:
    ``"connect"`` (the service could not be reached at all),
    ``"write"`` / ``"read"`` (the service was reached but the
    exchange failed). Callers map the stage to distinct designed
    error text — and NEVER fall back to the file channel."""

    def __init__(self, stage: str, detail: str = ""):
        super().__init__(f"pipe {stage} failed: {detail}")
        self.stage = stage
        self.detail = detail


@dataclass(frozen=True)
class ClientIdentity:
    """Who the pipe's client process verifiably is."""

    image_path: Path
    sha256: str


@dataclass(frozen=True)
class CallerVerdict:
    ok: bool
    reason: str = ""


class ClientIdentityProvider:
    """Seam: answer "which program is process *pid*, and what is
    its fingerprint?" Implementations must return None when the
    question cannot be answered — never a guess."""

    def identify(self, pid: int) -> ClientIdentity | None:
        raise NotImplementedError


class WindowsClientIdentityProvider(ClientIdentityProvider):
    """The production provider (pywin32): open the client
    process with query rights, read its image path, hash the
    file. Every failure is None (unidentifiable ⇒ unverifiable
    ⇒ refused downstream)."""

    def identify(self, pid: int) -> ClientIdentity | None:
        try:
            import win32api  # type: ignore[import-not-found]
            import win32con  # type: ignore[import-not-found]
            import win32process  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
        except Exception:
            return None
        try:
            try:
                image = win32process.QueryFullProcessImageName(handle, 0)
            except Exception:
                return None
        finally:
            win32api.CloseHandle(handle)
        if not image:
            return None
        image_path = Path(image)
        try:
            digest = hashlib.sha256()
            with open(image_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return None
        return ClientIdentity(
            image_path=image_path, sha256=digest.hexdigest()
        )


def _norm_path(path: Path | str) -> str:
    import os

    return os.path.normcase(os.path.realpath(str(path)))


def verify_pipe_client(
    pid: int,
    *,
    identity_provider: ClientIdentityProvider,
    canonical_exe: Path | str,
    recorded_sha256: str | None,
) -> CallerVerdict:
    """Decide whether the process at the other end of the pipe
    is the genuine Argus program. ALL of:

    - the identity provider can identify the process;
    - a setup-recorded fingerprint EXISTS (without one there is
      nothing trustworthy to match — setup always writes it, so
      its absence means this install never completed properly);
    - the process image resolves to the canonical install path;
    - the image's SHA-256 equals the recorded fingerprint.
    """
    if not recorded_sha256:
        return CallerVerdict(
            False,
            "no program fingerprint was recorded at setup, so no "
            "caller can be verified",
        )
    try:
        identity = identity_provider.identify(pid)
    except Exception:
        log.exception("client identity provider failed for pid %s", pid)
        return CallerVerdict(False, "the caller could not be identified")
    if identity is None:
        return CallerVerdict(False, "the caller could not be identified")
    if _norm_path(identity.image_path) != _norm_path(canonical_exe):
        return CallerVerdict(
            False,
            f"the caller runs from {identity.image_path}, not the "
            f"installed Argus program at {canonical_exe}",
        )
    if identity.sha256.lower() != recorded_sha256.lower():
        return CallerVerdict(
            False,
            "the caller's program file does not match the "
            "fingerprint recorded at setup (possible replacement)",
        )
    return CallerVerdict(True)


def serve_pipe_stream(
    stream,
    *,
    client_pid: int,
    identity_provider: ClientIdentityProvider,
    canonical_exe: Path | str,
    recorded_sha256: str | None,
    execute,
) -> dict | None:
    """Run one pipe session over an abstract message stream.

    ``stream`` provides ``read_message() -> dict | None`` (None
    on EOF/garbage) and ``write_message(dict)``. ``execute`` is
    the service's request handler, invoked ONLY after the caller
    verifies. Returns the response written (None when the client
    sent nothing usable, in which case a refusal is written so
    the genuine client never hangs on a half-open pipe).
    """
    try:
        request = stream.read_message()
    except Exception:
        log.exception("pipe: could not read the request")
        return None
    if not isinstance(request, dict):
        try:
            stream.write_message(
                {"ok": False, "message": CALLER_REFUSAL_MESSAGE}
            )
        except Exception:
            pass
        return None
    verdict = verify_pipe_client(
        client_pid,
        identity_provider=identity_provider,
        canonical_exe=canonical_exe,
        recorded_sha256=recorded_sha256,
    )
    if not verdict.ok:
        log.warning(
            "pipe: refusing privileged request kind=%r from pid %s: %s",
            request.get("kind"), client_pid, verdict.reason,
        )
        response = {
            "id": request.get("id"),
            "ok": False,
            "message": CALLER_REFUSAL_MESSAGE,
            "nonce": request.get("nonce"),
        }
        try:
            stream.write_message(response)
        except Exception:
            log.exception("pipe: could not write the refusal")
        return response
    response = execute(request)
    if isinstance(response, dict):
        response.setdefault("id", request.get("id"))
        if "nonce" in request:
            response.setdefault("nonce", request.get("nonce"))
    try:
        stream.write_message(response)
    except Exception:
        log.exception("pipe: could not write the response")
    return response


# ----------------------------------------------------------------------
# Windows transport (pywin32) — client + server
# ----------------------------------------------------------------------
class _Win32PipeStream:
    """Message-stream adapter over one connected pipe handle."""

    def __init__(self, handle) -> None:
        self._handle = handle

    def read_message(self) -> dict | None:
        import win32file  # type: ignore[import-not-found]

        _hr, data = win32file.ReadFile(self._handle, _MAX_MESSAGE_BYTES)
        if not data:
            return None
        try:
            text = bytes(data).decode("utf-8").strip()
            parsed = json.loads(text) if text else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def write_message(self, payload: dict) -> None:
        import win32file  # type: ignore[import-not-found]

        data = (json.dumps(payload) + "\n").encode("utf-8")
        win32file.WriteFile(self._handle, data)


class WindowsPipeServer:
    """The service-side pipe listener (message mode).

    The listener thread creates one pipe instance per
    connection and hands each connected session to its OWN
    thread (fix round 3): a client that connects and then says
    nothing can no longer starve every later request — its
    session thread is dropped by a watchdog after
    ``session_timeout`` seconds while the others are served.

    The pipe is created with FILE_FLAG_FIRST_PIPE_INSTANCE:
    if another process already owns the pipe name (a squatter
    that grabbed it before the service started, or a second
    service instance), creation FAILS instead of quietly
    queueing behind the impostor — the listener logs loudly,
    sets :attr:`name_taken`, and does not serve. A squatter can
    field connections and lie to a client about an action's
    outcome, but it can never make THIS service execute
    anything; failing loudly is what keeps that lie from
    wearing the service's silence as endorsement.

    Each connection is served through
    :func:`serve_pipe_stream` by the *session handler* the
    service registered: ``callable(stream, client_pid)`` — the
    service wires it to its identity provider, canonical exe,
    recorded fingerprint, and request dispatcher, so the exact
    code tested off-Windows is the code that runs here.

    The pipe's DACL (SDDL) admits LocalSystem, administrators,
    and interactive users *to connect* — connecting buys
    nothing: every session still has to pass process
    verification before anything executes.
    """

    _SDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

    def __init__(
        self,
        session_handler,
        *,
        pipe_name: str = PIPE_NAME,
        session_timeout: float = _SESSION_TIMEOUT_SECONDS,
    ) -> None:
        """*session_handler* is ``callable(stream, client_pid)``
        — see :func:`serve_pipe_stream`."""
        self._session_handler = session_handler
        self._pipe_name = pipe_name
        self._session_timeout = session_timeout
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        #: True when the pipe name was already owned at startup
        #: and this listener therefore refused to serve (see the
        #: class docstring). Protection is unaffected; privileged
        #: actions surface the designed unreachable error.
        self.name_taken = False

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="argus-pipe", daemon=True
        )
        self._thread.start()
        log.info("privileged-action pipe listening on %s", self._pipe_name)

    def stop(self) -> None:
        self._stop.set()
        # ConnectNamedPipe blocks: wake it with a throwaway client
        # connection so the loop can notice the stop flag.
        try:
            import win32file  # type: ignore[import-not-found]

            handle = win32file.CreateFile(
                self._pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
            win32file.CloseHandle(handle)
        except Exception:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _security_attributes(self):
        import win32security  # type: ignore[import-not-found]

        descriptor = (
            win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                self._SDDL, win32security.SDDL_REVISION_1
            )
        )
        attrs = win32security.SECURITY_ATTRIBUTES()
        attrs.SECURITY_DESCRIPTOR = descriptor
        attrs.bInheritHandle = False
        return attrs

    def _run(self) -> None:
        import pywintypes  # type: ignore[import-not-found]
        import win32file  # type: ignore[import-not-found]
        import win32pipe  # type: ignore[import-not-found]

        while not self._stop.is_set():
            handle = None
            try:
                handle = win32pipe.CreateNamedPipe(
                    self._pipe_name,
                    (
                        win32pipe.PIPE_ACCESS_DUPLEX
                        | _first_pipe_instance_flag()
                    ),
                    (
                        win32pipe.PIPE_TYPE_MESSAGE
                        | win32pipe.PIPE_READMODE_MESSAGE
                        | win32pipe.PIPE_WAIT
                    ),
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    _MAX_MESSAGE_BYTES,
                    _MAX_MESSAGE_BYTES,
                    0,
                    self._security_attributes(),
                )
            except pywintypes.error as exc:
                if (
                    getattr(exc, "winerror", None)
                    == _ERROR_ACCESS_DENIED
                    and not self._stop.is_set()
                ):
                    # FIRST_PIPE_INSTANCE refused: the name is
                    # already owned — a squatter grabbed it first
                    # or another instance is serving. Do NOT
                    # serve (and do not retry: the owner is not
                    # going away). Protection itself is
                    # unaffected; privileged actions get the
                    # designed unreachable error instead of a
                    # silently impostor-served channel.
                    self.name_taken = True
                    log.error(
                        "the privileged-action pipe name %s is "
                        "already owned by another process — the "
                        "pipe listener will NOT serve. Privileged "
                        "actions are unavailable until the service "
                        "is restarted; real-time protection is "
                        "unaffected.",
                        self._pipe_name,
                    )
                    return
                if not self._stop.is_set():
                    log.warning("pipe server error: %s", exc)
                    self._stop.wait(0.1)
                continue
            try:
                win32pipe.ConnectNamedPipe(handle, None)
                if self._stop.is_set():
                    break
                try:
                    pid = win32pipe.GetNamedPipeClientProcessId(handle)
                except Exception:
                    pid = -1
                # The session runs on its OWN thread; this loop
                # goes straight back to listening, so one silent
                # or slow client can never starve the channel.
                worker = threading.Thread(
                    target=self._serve_session,
                    args=(handle, pid),
                    name="argus-pipe-session",
                    daemon=True,
                )
                worker.start()
                handle = None  # the session thread owns it now
            except pywintypes.error as exc:
                if not self._stop.is_set():
                    log.warning("pipe server error: %s", exc)
            except Exception:
                if not self._stop.is_set():
                    log.exception("pipe server failed")
            finally:
                if handle is not None:
                    try:
                        win32pipe.DisconnectNamedPipe(handle)
                    except Exception:
                        pass
                    try:
                        win32file.CloseHandle(handle)
                    except Exception:
                        pass

    def _serve_session(self, handle, pid: int) -> None:
        """Serve one connected pipe session on its own thread.

        A watchdog drops the session after ``session_timeout``
        seconds by closing its handle out from under it —
        closing unblocks a stuck ReadFile with an error, which
        the session machinery treats as "client sent nothing
        usable" (fail closed). The watchdog and the normal
        cleanup race to close the handle EXACTLY once.
        """
        import win32file  # type: ignore[import-not-found]
        import win32pipe  # type: ignore[import-not-found]

        lock = threading.Lock()
        state = {"closed": False}

        def _close_once(*, disconnect: bool) -> None:
            with lock:
                if state["closed"]:
                    return
                state["closed"] = True
            if disconnect:
                try:
                    win32pipe.DisconnectNamedPipe(handle)
                except Exception:
                    pass
            try:
                win32file.CloseHandle(handle)
            except Exception:
                pass

        watchdog = threading.Timer(
            self._session_timeout, _close_once, kwargs={"disconnect": False}
        )
        watchdog.daemon = True
        watchdog.start()
        try:
            self._session_handler(_Win32PipeStream(handle), pid)
        except Exception:
            log.exception("pipe session failed")
        finally:
            watchdog.cancel()
            _close_once(disconnect=True)


def pipe_roundtrip(
    payload: dict, *, timeout: float = 30.0, pipe_name: str = PIPE_NAME
) -> dict:
    """Send one request over the pipe and return the response.

    Windows only. Raises :class:`PipeUnavailableError` with the
    stage that failed — connect (service unreachable), write, or
    read (service stopped answering) — so callers can phrase the
    designed error precisely and never fall back silently.
    """
    if sys.platform != "win32":
        raise PipeUnavailableError("connect", "named pipes are Windows-only")
    import pywintypes  # type: ignore[import-not-found]
    import win32file  # type: ignore[import-not-found]
    import win32pipe  # type: ignore[import-not-found]

    try:
        win32pipe.WaitNamedPipe(pipe_name, int(timeout * 1000))
    except pywintypes.error as exc:
        raise PipeUnavailableError("connect", str(exc)) from exc
    try:
        handle = win32file.CreateFile(
            pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None,
        )
    except pywintypes.error as exc:
        raise PipeUnavailableError("connect", str(exc)) from exc

    outcome: dict = {}

    def _io() -> None:
        try:
            win32file.WriteFile(
                handle, (json.dumps(payload) + "\n").encode("utf-8")
            )
        except Exception as exc:  # pywintypes.error and friends
            outcome["error"] = PipeUnavailableError("write", str(exc))
            return
        try:
            _hr, data = win32file.ReadFile(handle, _MAX_MESSAGE_BYTES)
            outcome["response"] = json.loads(
                bytes(data).decode("utf-8").strip()
            )
        except Exception as exc:
            outcome["error"] = PipeUnavailableError("read", str(exc))

    worker = threading.Thread(target=_io, name="argus-pipe-client", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        # Timed out mid-exchange: closing the handle unblocks the
        # worker's ReadFile with an error.
        try:
            win32file.CloseHandle(handle)
        except Exception:
            pass
        raise PipeUnavailableError(
            "read", f"the service did not answer within {timeout:.0f} seconds"
        )
    try:
        win32file.CloseHandle(handle)
    except Exception:
        pass
    if "error" in outcome:
        raise outcome["error"]
    response = outcome.get("response")
    if not isinstance(response, dict):
        raise PipeUnavailableError("read", "the service sent no usable answer")
    return response
