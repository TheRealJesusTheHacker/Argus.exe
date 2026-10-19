"""Windows service host for ARGUS.EXE real-time protection (Phase 5).

Phase 3 built the protection engine as a service-shaped core
(:class:`argus.service.ArgusService`: start / stop / pause / resume /
status heartbeat). This module is the thin Windows wrapper that lets
the Service Control Manager own that core, so protection:

- starts at boot, before anyone logs in;
- restarts if it ever stops unexpectedly (configured at install);
- shows up in the Windows Services console under its own name.

The pywin32 pieces (``win32serviceutil.ServiceFramework``) are
imported lazily and the service class is only defined when pywin32 is
present, so this module **imports cleanly on any platform**. Off
Windows — or without pywin32 — the management functions raise
:class:`ServiceUnavailable` with a plain-language reason instead of
an ImportError traceback.

Command routing lives in :func:`route_service_command` (pure logic,
unit-tested everywhere); the management commands are delegated to
pywin32's ``HandleCommandLine``, the documented management pattern.
The SCM launch itself is NOT a management command: when Windows
starts the service it launches this executable with the
``--service`` marker, and :func:`run_service_dispatcher` hosts the
service through ``servicemanager``'s dispatcher — the only path
that actually connects a process to the Service Control Manager.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .service import read_status_file

#: Service identity in the Windows Services console.
SERVICE_NAME = "ArgusProtection"
SERVICE_DISPLAY_NAME = "ARGUS.EXE — Real-Time Protection"
SERVICE_DESCRIPTION = (
    "Sentinel Safeguard LLC ARGUS.EXE: watches the folders threats "
    "land in, scans new and changed files, and applies your response "
    "policy. Part of the ARGUS.EXE antivirus."
)

#: Commands the management CLI understands.
SERVICE_COMMANDS = (
    "install", "uninstall", "start", "stop", "restart", "status", "run",
    "register", "unregister",
)

#: Marker argument the SCM registration carries: Windows launches
#: the one Argus executable with this word when it wants the
#: service hosted (a launch without it is the GUI). InstallService
#: appends the service class's ``_exe_args_`` to the registered
#: command line; the constant is the single source of that value.
SERVICE_EXE_ARGS = "--service"

#: pywin32 spells one command differently; map ours to theirs.
#: ("run" is deliberately absent: it is not a pywin32 command at
#: all — it is handled by the servicemanager dispatcher below.)
_PYWIN_COMMANDS = {"uninstall": "remove"}


class ServiceUnavailable(RuntimeError):
    """The Windows service layer cannot run here."""


def route_service_command(argv: list[str]) -> str:
    """Resolve the management command from CLI words.

    *argv* is what follows ``argus service``. Returns the canonical
    command name; raises :class:`ValueError` with usage text for
    anything unrecognized (including no command at all).
    """
    if not argv:
        raise ValueError(_usage("no command given"))
    command = argv[0].lower()
    aliases = {"remove": "uninstall", "delete": "uninstall"}
    command = aliases.get(command, command)
    if command not in SERVICE_COMMANDS:
        raise ValueError(_usage(f"unknown command {argv[0]!r}"))
    return command


def _usage(problem: str) -> str:
    return (
        f"argus service: {problem}. Usage: argus service "
        f"<{' | '.join(SERVICE_COMMANDS)}>"
    )


def require_windows(feature: str) -> None:
    """Raise :class:`ServiceUnavailable` unless this is Windows."""
    if sys.platform != "win32":
        raise ServiceUnavailable(
            f"{feature} needs Windows — this machine reports platform "
            f"'{sys.platform}'. The Argus service is a Windows service; "
            "on this platform use 'argus watch' for the same protection "
            "in the foreground."
        )


def _load_pywin():
    """Import the pywin32 service modules, or explain why not."""
    require_windows("The Argus Windows service")
    try:
        import win32event  # type: ignore[import-not-found]
        import win32service  # type: ignore[import-not-found]
        import win32serviceutil  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ServiceUnavailable(
            "pywin32 is not installed — Argus needs it to run as a "
            "Windows service. The packaged ARGUS.EXE includes it."
        ) from exc
    return win32serviceutil, win32service, win32event


#: Service Control Manager state names, by numeric code
#: (win32service.SERVICE_* constants), for query_service_state().
_SCM_STATE_NAMES = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "running",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}


def _query_service_status(name: str):
    """The raw SCM status query (a seam: tests replace this).

    Returns pywin32's status tuple; raises whatever pywin32 raises
    when the query fails — callers interpret the failure.
    """
    import win32serviceutil  # type: ignore[import-not-found]

    return win32serviceutil.QueryServiceStatus(name)


#: Win32 error the SCM returns for a service that is not installed.
ERROR_SERVICE_DOES_NOT_EXIST = 1060


def query_service_state(name: str = SERVICE_NAME) -> str | bool:
    """Ask the Service Control Manager for a service's state.

    Returns the state name (``"running"``, ``"stopped"``, …) when
    the SCM answered. Returns ``False`` when the state cannot be
    determined — not Windows, no pywin32, or the query failed —
    so callers treat the heartbeat file as unverified rather than
    trusting it. A heartbeat can be forged by anything that can
    write the status file; the SCM cannot.
    """
    if sys.platform != "win32":
        return False
    try:
        status = _query_service_status(name)
    except Exception:
        return False
    try:
        code = status[1]
    except (TypeError, IndexError):
        return False
    return _SCM_STATE_NAMES.get(code, f"unknown ({code})")


def query_service_state_detailed(name: str = SERVICE_NAME) -> str:
    """Like :func:`query_service_state`, but never ambiguous about
    *absence*: returns ``"not-installed"`` when the SCM says the
    service does not exist (error 1060), the state name when it
    does, and ``"unknown"`` when the question cannot be answered
    at all (not Windows, no pywin32, query failed another way).

    Setup decisions depend on the difference: "stopped" means
    *start it*, "not-installed" means *set it up first*.
    """
    if sys.platform != "win32":
        return "unknown"
    try:
        status = _query_service_status(name)
    except Exception as exc:
        if getattr(exc, "winerror", None) == ERROR_SERVICE_DOES_NOT_EXIST:
            return "not-installed"
        return "unknown"
    try:
        code = status[1]
    except (TypeError, IndexError):
        return "unknown"
    return _SCM_STATE_NAMES.get(code, "unknown")


def query_service_image_path(name: str = SERVICE_NAME) -> str | None:
    """The ImagePath the SCM has registered for the service, or
    None when it cannot be read (not Windows, no pywin32, service
    absent, query failed). Setup uses this to tell "registered
    exactly right" apart from "registered wrong / not at all" —
    the difference between skipping a step and redoing it."""
    if sys.platform != "win32":
        return None
    try:
        import win32service  # type: ignore[import-not-found]

        scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CONNECT
        )
        try:
            handle = win32service.OpenService(
                scm, name, win32service.SERVICE_QUERY_CONFIG
            )
            try:
                config = win32service.QueryServiceConfig(handle)
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception:
        return None
    # QueryServiceConfig returns a tuple whose path field is the
    # registered binary path (index 3 in pywin32's layout).
    try:
        return str(config[3])
    except (TypeError, IndexError):
        return None


#: A heartbeat younger than this counts as fresh evidence the
#: writer is alive (the service heartbeats every few seconds).
HEARTBEAT_FRESH_SECONDS = 45.0


def assess_service_status(
    status: dict | None,
    scm_state,
    *,
    now=None,
    fresh_seconds: float = HEARTBEAT_FRESH_SECONDS,
) -> tuple[str, str]:
    """Combine a heartbeat dict and the SCM's word into one verdict.

    Returns ``(verdict, note)`` with verdict ``"running"`` or
    ``"stopped"``. The gates (P2 CLI/GUI parity):

    - The SCM says the service is running → RUNNING, even when the
      heartbeat is stale — the heartbeat supplies details, not the
      verdict; a stale one only earns a "details may be out of
      date" note.
    - The SCM says the service is stopped / absent (any answered
      state that is not running) → STOPPED, however fresh the
      heartbeat claims to be (the status file is user-writable and
      can lie; the SCM cannot be written by a standard user).
    - The SCM cannot be asked (``scm_state`` is False — off
      Windows, no pywin32, foreground ``argus watch``) → the
      heartbeat decides, but only while it is FRESH: a stale or
      timestamp-less heartbeat under a "running" claim is a writer
      that died, reported as stopped.
    """
    from datetime import datetime, timezone

    if not status:
        return "stopped", "no status heartbeat was found"
    heartbeat_at = status.get("heartbeat_at")
    age: float | None = None
    if heartbeat_at:
        try:
            stamp = datetime.fromisoformat(str(heartbeat_at))
        except ValueError:
            stamp = None
        if stamp is not None:
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            moment = now or datetime.now(timezone.utc)
            age = (moment - stamp).total_seconds()
    fresh = age is not None and -60.0 <= age <= fresh_seconds

    if scm_state == "running":
        if status.get("running") and fresh:
            return "running", ""
        if not fresh:
            return (
                "running",
                "the service is running (confirmed by Windows), "
                "but its status details are stale — details syncing",
            )
        return "running", "the service is running (confirmed by Windows)"

    if isinstance(scm_state, str):
        # The SCM answered and it did not say "running".
        return (
            "stopped",
            f"Windows reports the ArgusProtection service is "
            f"{scm_state.replace('_', ' ')}",
        )

    # SCM unanswerable: the heartbeat is all there is.
    if status.get("running") and fresh:
        return "running", ""
    if status.get("running"):
        return (
            "stopped",
            "the last status heartbeat is stale — the writer does "
            "not appear to be running anymore",
        )
    return "stopped", ""


def service_exe_path() -> Path:
    """The executable the SCM should launch. In the packaged
    product there is exactly one Argus executable (``sys.executable``
    under PyInstaller) — it is the GUI, the service host, and the
    setup engine in one file; in a source checkout it is the Python
    interpreter (development only — the service then also needs the
    module path, which the packaged build exists to avoid)."""
    return Path(sys.executable)


def service_image_path(exe_path: Path | str) -> str:
    """The exact command line registered with the SCM as the
    service's ImagePath: the canonical executable, quoted, plus the
    ``--service`` marker — so a launch by Windows is told apart
    from a person double-clicking the same file (which opens the
    GUI)."""
    return f'"{exe_path}" {SERVICE_EXE_ARGS}'


# ----------------------------------------------------------------------
# Direct SCM operations (used by the self-install engine)
#
# These bypass pywin32's HandleCommandLine on purpose: setup must
# control the registered ImagePath exactly (canonical exe + marker)
# and must see every failure — a parse quirk in a command-line
# dispatcher must never be able to turn an install into a silent
# no-op again (the v1.0.5 lesson).
# ----------------------------------------------------------------------
def install_service(exe_path: Path | str, *, name: str = SERVICE_NAME) -> None:
    """Create the ArgusProtection service registration.

    Automatic start, LocalSystem account, ImagePath =
    :func:`service_image_path`. Raises whatever the SCM raises —
    the caller (setup) turns it into a designed failure. Windows +
    pywin32 + elevation required.
    """
    _win32serviceutil, win32service, _win32event = _load_pywin()
    scm = win32service.OpenSCManager(
        None, None, win32service.SC_MANAGER_ALL_ACCESS
    )
    try:
        handle = win32service.CreateService(
            scm,
            name,
            SERVICE_DISPLAY_NAME,
            win32service.SERVICE_ALL_ACCESS,
            win32service.SERVICE_WIN32_OWN_PROCESS,
            win32service.SERVICE_AUTO_START,
            win32service.SERVICE_ERROR_NORMAL,
            service_image_path(exe_path),
            None,  # load-order group
            0,  # no tag
            None,  # no dependencies
            None,  # LocalSystem account
            None,  # no password (LocalSystem)
        )
        try:
            try:
                win32service.ChangeServiceConfig2(
                    handle,
                    win32service.SERVICE_CONFIG_DESCRIPTION,
                    SERVICE_DESCRIPTION,
                )
            except Exception:
                pass  # the description is cosmetic; registration is not
        finally:
            win32service.CloseServiceHandle(handle)
    finally:
        win32service.CloseServiceHandle(scm)


def uninstall_service(name: str = SERVICE_NAME) -> None:
    """Remove the service registration. Raises on SCM failure."""
    _win32serviceutil, win32service, _win32event = _load_pywin()
    win32serviceutil = _win32serviceutil
    win32serviceutil.RemoveService(name)


def start_service(name: str = SERVICE_NAME) -> None:
    """Ask the SCM to start the service. Raises on SCM failure."""
    _win32serviceutil, _win32service, _win32event = _load_pywin()
    _win32serviceutil.StartService(name)


def stop_service(name: str = SERVICE_NAME) -> None:
    """Ask the SCM to stop the service. Raises on SCM failure."""
    _win32serviceutil, _win32service, _win32event = _load_pywin()
    _win32serviceutil.StopService(name)


def run_service_dispatcher(service_class=None) -> int:
    """Host the service for the Service Control Manager.

    This — and only this — is what runs when Windows launches the
    executable with the ``--service`` marker. pywin32's management
    dispatcher (``HandleCommandLine``) has no service-hosting path
    at all; hosting goes through ``servicemanager``:
    initialize, prepare to host the single service class, and hand
    the process to the SCM dispatcher, which calls the class's
    ``SvcDoRun`` when Windows starts the service.
    """
    require_windows("The Argus Windows service")
    if not HAS_PYWIN32 or ArgusWindowsService is None:
        raise ServiceUnavailable(
            "pywin32 is not installed — Argus needs it to run as a "
            "Windows service. The packaged ARGUS.EXE includes it."
        )
    import servicemanager  # type: ignore[import-not-found]

    cls = service_class if service_class is not None else ArgusWindowsService
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(cls)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def default_service_config_path() -> Path | None:
    """Where the installed service looks for its config.

    Argus's shared state lives machine-wide under
    ``%PROGRAMDATA%\\Argus`` (see :mod:`argus.paths`), so the
    service, the GUI, and the CLI all read the same
    ``argus-config.json`` there. Returns that path when the file
    exists, else None (Argus defaults)."""
    program_data = os.environ.get("ProgramData")
    if not program_data:
        return None
    candidate = Path(program_data) / "Argus" / "argus-config.json"
    return candidate if candidate.is_file() else None


# ----------------------------------------------------------------------
# The pywin32 service class (only defined when pywin32 is available)
# ----------------------------------------------------------------------
try:  # pragma: no cover - exercised only on Windows with pywin32
    _win32serviceutil, _win32service, _win32event = _load_pywin()
    HAS_PYWIN32 = True
except ServiceUnavailable:
    _win32serviceutil = _win32service = _win32event = None  # type: ignore[assignment]
    HAS_PYWIN32 = False


if HAS_PYWIN32:  # pragma: no cover - exercised only on Windows
    import servicemanager  # type: ignore[import-not-found]

    from .service import ArgusService as _ArgusService

    class ArgusWindowsService(_win32serviceutil.ServiceFramework):
        """SCM-facing wrapper around :class:`ArgusService`.

        The Service Control Manager calls :meth:`SvcDoRun` to start
        protection and :meth:`SvcStop` to end it; pause/continue map
        onto the engine's pause/resume.
        """

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION
        #: Appended to the registered ImagePath when the service is
        #: installed through pywin32's management path: the launched
        #: copy of the one Argus executable must know it is being
        #: run AS the service (see SERVICE_EXE_ARGS).
        _exe_args_ = SERVICE_EXE_ARGS
        #: Optional path to the service config file (set by main()).
        config_path: str | None = None

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = _win32event.CreateEvent(None, 0, 0, None)
            self._core = None

        def SvcStop(self):
            self.ReportServiceStatus(_win32service.SERVICE_STOP_PENDING)
            _win32event.SetEvent(self._stop_event)
            if self._core is not None:
                self._core.stop()

        def SvcPause(self):
            if self._core is not None:
                self._core.pause()

        def SvcContinue(self):
            if self._core is not None:
                self._core.resume()

        def SvcDoRun(self):
            servicemanager.LogInfoMsg(
                "ARGUS.EXE real-time protection service starting"
            )
            # Config resolution: an explicit path set by main()
            # wins; otherwise the shared machine config under
            # %PROGRAMDATA%\Argus when one exists; otherwise that
            # same standard location is named anyway (ArgusConfig
            # tolerates a missing file and uses defaults), so the
            # service and the GUI agree on where settings live.
            config_path = self.config_path
            if config_path is None:
                found = default_service_config_path()
                if found is not None:
                    config_path = str(found)
                else:
                    from .config import DEFAULT_CONFIG_NAME
                    from .paths import data_dir

                    config_path = str(data_dir() / DEFAULT_CONFIG_NAME)
            core = _ArgusService(config_path=config_path)
            self._core = core
            try:
                core.start()
            except Exception:
                servicemanager.LogErrorMsg(
                    "ARGUS.EXE protection could not start — see the "
                    "Argus status file and logs."
                )
                raise
            self.ReportServiceStatus(_win32service.SERVICE_RUNNING)
            # Block until SvcStop signals; the core runs its own
            # threads meanwhile.
            _win32event.WaitForSingleObject(
                self._stop_event, _win32event.INFINITE
            )
            core.stop()
            self._core = None

else:
    ArgusWindowsService = None  # type: ignore[assignment]


# ----------------------------------------------------------------------
# Management commands
# ----------------------------------------------------------------------
def perform_service_command(
    command: str,
    *,
    config_path: Path | str | None = None,
    handler=None,
    dispatcher=None,
) -> int:
    """Carry out a routed management command. Returns an exit code.

    *handler* performs the pywin32 ``HandleCommandLine`` call and is
    injectable for tests; the default lazily builds the real one.
    *dispatcher* hosts the service for the SCM (the "run" command)
    and is likewise injectable. "status" is answered from the
    service heartbeat file and works even when the service is
    stopped.
    """
    if command == "status":
        data = read_status_file(_status_file_for(config_path))
        if data is None:
            print(
                "Argus real-time protection: no status heartbeat found — "
                "the service does not appear to be running."
            )
            return 1
        # The same freshness + SCM gates the GUI applies: a stale
        # heartbeat under a stopped service must say so, and a
        # running service stays "running" even if its heartbeat
        # (the details channel) is stale.
        verdict, note = assess_service_status(
            data, query_service_state()
        )
        if verdict != "running":
            print(
                "Argus real-time protection is NOT RUNNING"
                + (f" — {note}." if note else ".")
            )
            return 1
        state = data.get("state", "unknown")
        print(
            f"Argus real-time protection is {state} "
            f"(version {data.get('version', '?')}, "
            f"started {data.get('started_at') or 'unknown'}, "
            f"{data.get('scans_completed', 0)} scans completed, "
            f"{data.get('detections', 0)} detections)."
        )
        if note:
            print(f"Note: {note}.")
        return 0

    if command in ("register", "unregister"):
        # Security Center registration lives next to service
        # management: installing protection includes telling Windows
        # Argus is the machine's antivirus.
        require_windows(f"Service command '{command}'")
        from . import winregister

        if command == "register":
            # One executable now: the same file is the product the
            # user opens and the reporter Windows Security talks to.
            exe = service_exe_path()
            product_exe = exe
            # Never tell Windows Security that a program which is
            # not actually on disk is the machine's antivirus.
            if not Path(product_exe).exists():
                print(
                    "argus service: cannot register ARGUS.EXE with "
                    f"Windows Security Center — {product_exe} was "
                    "not found on this machine. Reinstall ARGUS.EXE, "
                    "then run: argus service register"
                )
                return 1
            properties = winregister.antivirus_product_properties(
                product_exe=product_exe,
                reporting_exe=exe,
                instance_guid=winregister.INSTANCE_GUID,
            )
            winregister.register_antivirus(
                properties, require_existing_exe=True
            )
            print(
                "Registered ARGUS.EXE with Windows Security Center "
                "as this machine's antivirus provider."
            )
        else:
            removed = winregister.unregister_antivirus()
            print(
                f"Removed ARGUS.EXE from Windows Security Center "
                f"({removed} registration(s) removed)."
            )
        return 0

    if command == "run":
        # SCM launch: host the service. This must NEVER go through
        # HandleCommandLine — pywin32's command handler has no
        # hosting path (no StartServiceCtrlDispatcher call), so a
        # service "run" through it could never start.
        host = dispatcher or run_service_dispatcher
        return int(host() or 0)

    require_windows(f"Service command '{command}'")
    if not HAS_PYWIN32 or ArgusWindowsService is None:
        raise ServiceUnavailable(
            "pywin32 is not installed — Argus needs it to manage the "
            "Windows service. The packaged ARGUS.EXE includes it."
        )
    run = handler or _handle_command_line
    ArgusWindowsService.config_path = (  # type: ignore[union-attr]
        str(config_path) if config_path else None
    )
    argv = [str(service_exe_path())]
    if command == "install":
        # Protection starts with Windows, before anyone logs in.
        #
        # ORDER IS LOAD-BEARING: pywin32's HandleCommandLine parses
        # with POSIX getopt, which stops at the first non-option —
        # options placed AFTER the command word are never seen, the
        # leftover arguments fail its arity check, and it prints
        # usage and installs NOTHING (the v1.0.5 silent no-install).
        # Options therefore go BEFORE the command word.
        argv += ["--startup", "auto"]
    argv.append(_PYWIN_COMMANDS.get(command, command))
    try:
        run(ArgusWindowsService, argv=argv)
    except SystemExit as exc:  # HandleCommandLine exits when done
        return int(exc.code or 0)
    return 0


def _handle_command_line(service_class, *, argv: list[str]) -> None:  # pragma: no cover
    _win32serviceutil.HandleCommandLine(service_class, argv=argv)


def _status_file_for(config_path: Path | str | None) -> Path:
    from .config import ArgusConfig

    if config_path:
        return Path(ArgusConfig.load(config_path).status_file)
    return Path(ArgusConfig().status_file)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``argus service`` support commands.

    A launch with no words — or carrying the ``--service`` marker —
    is the Service Control Manager starting the service: host it
    through the servicemanager dispatcher, never the management
    command handler. Anything else is a management command word.
    """
    words = list(sys.argv[1:] if argv is None else argv)
    if not words or SERVICE_EXE_ARGS in words:
        try:
            return run_service_dispatcher()
        except ServiceUnavailable as exc:
            print(f"argus service: {exc}")
            return 2
    try:
        command = route_service_command(words)
    except ValueError as exc:
        print(str(exc))
        return 2
    try:
        return perform_service_command(command)
    except ServiceUnavailable as exc:
        print(f"argus service: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
