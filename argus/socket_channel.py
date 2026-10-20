"""The process-identity-verified Unix socket channel (v1.2.0).

The Linux sibling of :mod:`argus.pipe_channel`, built for the
same reason and to the same standard: the file request channel
carries *data*, not *credentials* — entry ids and fingerprints
are published in the service's own snapshots, so any
standard-user process can drop a perfectly-formed request file.
For PRIVILEGED actions (restore / delete / allow a vault entry,
approve / reject a queued action) the service must know WHO is
asking, not just WHAT is asked.

On Linux in the installed (.deb) layout, privileged actions
therefore travel over a Unix domain socket, and the service
executes a request only when the process on the other end is
verified to be the genuine Argus program:

1. the peer's credentials are taken from the kernel itself
   (``SO_PEERCRED`` — the client cannot claim another process's
   pid or uid, exactly as ``GetNamedPipeClientProcessId`` cannot
   be spoofed on Windows);
2. a peer running as **root** is admitted on that credential
   alone: root already owns the machine, the vault included, so
   demanding more theatre from it would prove nothing. Every
   other peer must pass the full identity proof;
3. the peer's image path (``/proc/<pid>/exe``, resolved) must be
   the canonical installed program ``/usr/lib/argus/argus``;
4. that file's SHA-256 must equal the fingerprint recorded in
   the trusted data root at install time
   (:mod:`argus.selftrust`) — a replaced binary fails here even
   though it sits at the right address, and with no recorded
   fingerprint non-root callers are refused outright.

The session core is shared, not re-implemented:
:func:`argus.pipe_channel.serve_pipe_stream` runs the exchange,
with this module's :func:`verify_socket_client` supplying the
verdict computed from the richer kernel credentials (the pid
proof, plus the root rule only a uid can express).

Squatter discipline mirrors the Windows pipe's
FILE_FLAG_FIRST_PIPE_INSTANCE: if the socket path already has a
LIVE listener when the service starts, this server refuses to
serve — it logs loudly and sets :attr:`UnixSocketServer.name_taken`
— because a squatter that grabbed the path first could field
connections and lie to clients about an action's outcome. A
stale socket file nobody answers on is unlinked and replaced
(that is crash recovery, not squatting).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import struct
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from . import paths, pipe_channel
from .pipe_channel import (
    CALLER_REFUSAL_MESSAGE,
    CallerVerdict,
    ClientIdentity,
    ClientIdentityProvider,
    PipeUnavailableError,
)

log = logging.getLogger("argus.socket_channel")

#: The socket's file name inside its directory.
SOCKET_NAME = "argus.sock"

#: One message, the same generous bound as the pipe channel's.
_MAX_MESSAGE_BYTES = 256 * 1024

#: How long one session may live before the service drops it —
#: the same 10-second watchdog as the pipe channel (fix round 3
#: there): a client that connects and then says nothing must not
#: hold its session hostage.
_SESSION_TIMEOUT_SECONDS = 10.0

#: Concurrent sessions the listener will serve at once. Each
#: session is a thread in a root-owned daemon, and the socket is
#: connectable by any local user (verification gates execution,
#: not connection) — without a cap, a local process could open
#: connections in a loop and grow the protection service's
#: thread count without bound (hunt #2). The genuine client
#: holds at most a couple of sessions at a time; connections
#: past the cap are closed on arrival, never queued.
_MAX_CONCURRENT_SESSIONS = 64

_SO_PEERCRED = 17  # asm-generic/socket.h — stable Linux ABI
_PEERCRED_STRUCT = struct.Struct("iII")  # pid, uid, gid


@dataclass(frozen=True)
class PeerCredentials:
    """What the kernel vouches for about a socket's peer."""

    pid: int
    uid: int
    gid: int


def socket_dir() -> Path:
    """Where the socket lives: the systemd-managed runtime
    directory when it EXISTS (the installed service's
    RuntimeDirectory — systemd creates it before the service
    starts, and the GUI resolves the same answer), else the
    shared data folder (dev / portable runs, where caller and
    service share one user's trust domain anyway). Both sides
    resolve through this one function, so they cannot disagree
    about the address."""
    env = os.environ.get("ARGUS_SOCKET_DIR")
    if env:
        return Path(env)
    runtime = paths.LINUX_RUNTIME_DIR
    try:
        if runtime.is_dir():
            return runtime
    except OSError:
        pass
    return paths.shared_dir()


def socket_path() -> Path:
    env = os.environ.get("ARGUS_SOCKET_PATH")
    if env:
        return Path(env)
    return socket_dir() / SOCKET_NAME


# ----------------------------------------------------------------------
# Caller verification (the SO_PEERCRED analog of pipe verification)
# ----------------------------------------------------------------------
class LinuxClientIdentityProvider(ClientIdentityProvider):
    """The production provider: resolve ``/proc/<pid>/exe`` (the
    kernel's own record of what the process runs) and hash the
    file. Every failure is None — unidentifiable ⇒ unverifiable
    ⇒ refused downstream."""

    def identify(self, pid: int) -> ClientIdentity | None:
        if pid <= 0:
            return None
        try:
            image = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None
        # A deleted-but-running binary shows a " (deleted)" suffix.
        if image.endswith(" (deleted)"):
            image = image[: -len(" (deleted)")]
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


def peer_credentials(conn: socket.socket) -> PeerCredentials | None:
    """The kernel-stamped credentials of *conn*'s peer, or None
    when the question cannot be answered (never a guess)."""
    try:
        raw = conn.getsockopt(
            socket.SOL_SOCKET, _SO_PEERCRED, _PEERCRED_STRUCT.size
        )
        pid, uid, gid = _PEERCRED_STRUCT.unpack(raw)
    except (OSError, struct.error):
        return None
    if pid <= 0:
        return None
    return PeerCredentials(pid=int(pid), uid=int(uid), gid=int(gid))


def verify_socket_client(
    creds: PeerCredentials,
    *,
    identity_provider: ClientIdentityProvider,
    canonical_exe: Path | str,
    recorded_sha256: str | None,
    allow_root: bool = True,
) -> CallerVerdict:
    """Decide whether the process at the other end of the socket
    may ask for privileged actions.

    Root peers are admitted on the kernel credential alone when
    *allow_root* (the production rule — root owns the machine
    already). Every other peer must pass EXACTLY the pipe
    channel's proof: identifiable, a recorded fingerprint
    exists, the image resolves to the canonical installed
    program, and its SHA-256 equals the recorded fingerprint."""
    if allow_root and creds.uid == 0:
        return CallerVerdict(
            True, "the caller runs as root, which owns this machine"
        )
    return pipe_channel.verify_pipe_client(
        creds.pid,
        identity_provider=identity_provider,
        canonical_exe=canonical_exe,
        recorded_sha256=recorded_sha256,
    )


# ----------------------------------------------------------------------
# Message stream over one connected socket
# ----------------------------------------------------------------------
class _UnixStream:
    """Newline-delimited JSON message stream over one socket —
    the same framing discipline as the pipe channel's messages,
    adapted to a byte stream."""

    def __init__(self, conn: socket.socket) -> None:
        self._conn = conn
        self._buffer = b""

    def read_message(self) -> dict | None:
        while b"\n" not in self._buffer:
            if len(self._buffer) > _MAX_MESSAGE_BYTES:
                return None
            try:
                chunk = self._conn.recv(64 * 1024)
            except OSError:
                return None
            if not chunk:
                return None
            self._buffer += chunk
        line, _, rest = self._buffer.partition(b"\n")
        # Consume the message: bytes past the newline belong to
        # the NEXT message. The protocol exchanges one message
        # per connection today, but a stream that re-reads its
        # first line forever (or grows its buffer unboundedly)
        # is a bug waiting for a second message to matter
        # (hunt #2).
        self._buffer = rest
        try:
            parsed = json.loads(line.decode("utf-8").strip())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def write_message(self, payload: dict) -> None:
        data = (json.dumps(payload) + "\n").encode("utf-8")
        self._conn.sendall(data)


# ----------------------------------------------------------------------
# Server
# ----------------------------------------------------------------------
class UnixSocketServer:
    """The service-side socket listener.

    One accept thread; each connection is served on its OWN
    thread under a watchdog (the pipe server's fix-round-3
    shape): a client that connects and then says nothing is
    dropped after ``session_timeout`` seconds without starving
    anyone else.

    The session handler is ``callable(stream, creds)`` — the
    service wires it to :func:`verify_socket_client` and its
    request dispatcher, so the code tested off-systemd is the
    code that runs under it. A connection whose credentials the
    kernel cannot vouch for (``creds is None``) is served with
    an impossible pid/uid, which verification refuses.

    The socket file is mode 0666 — any local user may CONNECT.
    Connecting buys nothing: every session still has to pass
    verification before anything executes, exactly like the
    Windows pipe's connect-friendly DACL.
    """

    def __init__(
        self,
        session_handler,
        *,
        path: Path | str | None = None,
        session_timeout: float = _SESSION_TIMEOUT_SECONDS,
    ) -> None:
        self._session_handler = session_handler
        self._path = Path(path) if path is not None else socket_path()
        self._session_timeout = session_timeout
        self._session_slots = threading.BoundedSemaphore(
            _MAX_CONCURRENT_SESSIONS
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._listener: socket.socket | None = None
        self._bound = False
        #: True when a LIVE listener already owned the socket
        #: path at startup and this server therefore refused to
        #: serve (see the module docstring). Protection is
        #: unaffected; privileged actions surface the designed
        #: unreachable error.
        self.name_taken = False

    @property
    def path(self) -> Path:
        return self._path

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._listener = self._bind()
        if self._listener is None:
            return  # name taken — logged loudly in _bind
        self._thread = threading.Thread(
            target=self._run, name="argus-socket", daemon=True
        )
        self._thread.start()
        log.info("privileged-action socket listening on %s", self._path)

    def stop(self) -> None:
        self._stop.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
            # Wake the accept loop with a throwaway connection.
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                probe.settimeout(0.5)
                probe.connect(str(self._path))
                probe.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        # Only the server that BOUND the path may unlink it: a
        # server that found the name taken must never delete the
        # live owner's socket file on its way out.
        if self._bound:
            self._bound = False
            try:
                self._path.unlink(missing_ok=True)
            except OSError:
                pass

    def _bind(self) -> socket.socket | None:
        path = self._path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.error(
                "could not create the socket folder %s: %s — the "
                "verified-action channel will not serve",
                path.parent, exc,
            )
            self.name_taken = True
            return None
        if path.exists():
            # Something is at the address. If a live listener
            # answers, it is a squatter (or another service
            # instance): refuse to serve, like the pipe's
            # FIRST_PIPE_INSTANCE. If nobody answers, the file is
            # a crash leftover — unlinking it is recovery.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.5)
            try:
                probe.connect(str(path))
            except OSError:
                live = False
            else:
                live = True
            finally:
                probe.close()
            if live:
                self.name_taken = True
                log.error(
                    "the privileged-action socket %s is already "
                    "served by another process — this listener "
                    "will NOT serve. Privileged actions are "
                    "unavailable until the service is restarted; "
                    "real-time protection is unaffected.",
                    path,
                )
                return None
            try:
                path.unlink()
            except OSError as exc:
                log.error(
                    "could not clear the stale socket %s: %s", path, exc
                )
                self.name_taken = True
                return None
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(path))
            os.chmod(path, 0o666)
            listener.listen(16)
            listener.settimeout(0.5)
        except OSError as exc:
            log.error("could not bind the socket %s: %s", path, exc)
            listener.close()
            self.name_taken = True
            return None
        self._bound = True
        return listener

    def _run(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                log.exception("socket accept failed")
                continue
            if not self._session_slots.acquire(blocking=False):
                # Every session slot is busy: refuse the excess
                # connection outright rather than queueing a
                # thread for it (see _MAX_CONCURRENT_SESSIONS).
                log.warning(
                    "socket: refusing a connection — all %d "
                    "session slots are busy",
                    _MAX_CONCURRENT_SESSIONS,
                )
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            worker = threading.Thread(
                target=self._serve_session,
                args=(conn,),
                name="argus-socket-session",
                daemon=True,
            )
            worker.start()

    def _serve_session(self, conn: socket.socket) -> None:
        """Serve one connection on its own thread, under the
        watchdog: after ``session_timeout`` seconds the socket is
        shut down out from under the session, which the session
        machinery treats as "client sent nothing usable" (fail
        closed). Shutdown/close happens exactly once."""
        lock = threading.Lock()
        state = {"closed": False}

        def _close_once() -> None:
            with lock:
                if state["closed"]:
                    return
                state["closed"] = True
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        watchdog = threading.Timer(self._session_timeout, _close_once)
        watchdog.daemon = True
        watchdog.start()
        try:
            creds = peer_credentials(conn)
            if creds is None:
                # The kernel would not vouch for this peer: hand
                # the handler an impossible identity, which the
                # verification refuses (fail closed).
                creds = PeerCredentials(pid=-1, uid=2**31 - 1, gid=-1)
            self._session_handler(_UnixStream(conn), creds)
        except Exception:
            log.exception("socket session failed")
        finally:
            watchdog.cancel()
            _close_once()
            self._session_slots.release()


# ----------------------------------------------------------------------
# Client
# ----------------------------------------------------------------------
def socket_roundtrip(
    payload: dict, *, timeout: float = 30.0, path: Path | str | None = None
) -> dict:
    """Send one request over the socket and return the response.

    Linux mirror of :func:`argus.pipe_channel.pipe_roundtrip`:
    raises :class:`PipeUnavailableError` with the stage that
    failed — connect (service unreachable), write, or read
    (service stopped answering) — so callers phrase the designed
    error precisely and never fall back silently."""
    if not sys.platform.startswith("linux"):
        raise PipeUnavailableError("connect", "Unix sockets are Linux here")
    target = Path(path) if path is not None else socket_path()
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        try:
            conn.connect(str(target))
        except OSError as exc:
            raise PipeUnavailableError("connect", str(exc)) from exc
        stream = _UnixStream(conn)
        try:
            stream.write_message(payload)
        except OSError as exc:
            raise PipeUnavailableError("write", str(exc)) from exc
        try:
            response = stream.read_message()
        except OSError as exc:
            raise PipeUnavailableError("read", str(exc)) from exc
        if not isinstance(response, dict):
            raise PipeUnavailableError(
                "read", "the service sent no usable answer"
            )
        return response
    finally:
        try:
            conn.close()
        except OSError:
            pass


__all__ = [
    "CALLER_REFUSAL_MESSAGE",
    "LinuxClientIdentityProvider",
    "PeerCredentials",
    "UnixSocketServer",
    "peer_credentials",
    "socket_dir",
    "socket_path",
    "socket_roundtrip",
    "verify_socket_client",
]
