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
unit-tested everywhere); the actual SCM calls are delegated to
pywin32's ``HandleCommandLine``, the documented management pattern.
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

#: pywin32 spells two commands differently; map ours to theirs.
_PYWIN_COMMANDS = {"uninstall": "remove", "run": "run"}


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
            "Windows service. The packaged ArgusService.exe includes it."
        ) from exc
    return win32serviceutil, win32service, win32event


def service_exe_path() -> Path:
    """The executable the SCM should launch. In the packaged product
    this is ArgusService.exe (``sys.executable`` under PyInstaller);
    in a source checkout it is the Python interpreter (development
    only — the service then also needs the module path, which the
    packaged build exists to avoid)."""
    return Path(sys.executable)


def default_service_config_path() -> Path | None:
    """Where the installed service looks for its config:
    ``%PROGRAMDATA%\\Argus\\argus-config.json`` when it exists (the
    per-machine location a LocalSystem service can always read), else
    None (Argus defaults)."""
    program_data = os.environ.get("PROGRAMDATA")
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
            core = _ArgusService(config_path=self.config_path)
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
) -> int:
    """Carry out a routed management command. Returns an exit code.

    *handler* performs the pywin32 ``HandleCommandLine`` call and is
    injectable for tests; the default lazily builds the real one.
    "status" is answered from the service heartbeat file and works
    even when the service is stopped.
    """
    if command == "status":
        data = read_status_file(_status_file_for(config_path))
        if data is None:
            print(
                "Argus real-time protection: no status heartbeat found — "
                "the service does not appear to be running."
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
        return 0 if data.get("running") else 1

    if command in ("register", "unregister"):
        # Security Center registration lives next to service
        # management: installing protection includes telling Windows
        # Argus is the machine's antivirus.
        require_windows(f"Service command '{command}'")
        from . import winregister

        if command == "register":
            exe = service_exe_path()
            properties = winregister.antivirus_product_properties(
                product_exe=exe.with_name("Argus.exe"),
                reporting_exe=exe,
                instance_guid=winregister.INSTANCE_GUID,
            )
            winregister.register_antivirus(properties)
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

    require_windows(f"Service command '{command}'")
    if not HAS_PYWIN32 or ArgusWindowsService is None:
        raise ServiceUnavailable(
            "pywin32 is not installed — Argus needs it to manage the "
            "Windows service. The packaged ArgusService.exe includes it."
        )
    run = handler or _handle_command_line
    ArgusWindowsService.config_path = (  # type: ignore[union-attr]
        str(config_path) if config_path else None
    )
    if command == "run":
        # How the Service Control Manager launches the exe: no command
        # word at all, and pywin32 dispatches to the service.
        argv = [str(service_exe_path())]
    else:
        argv = [str(service_exe_path()), _PYWIN_COMMANDS.get(command, command)]
        if command == "install":
            # Protection starts with Windows, before anyone logs in.
            argv += ["--startup", "auto"]
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
    """Entry point for the packaged ArgusService.exe and
    ``argus service``: route and perform one management command.
    When the SCM launches the exe with no arguments, pywin32 expects
    a bare start dispatch — handled by "run"."""
    words = list(sys.argv[1:] if argv is None else argv)
    if not words:
        # Launched by the Service Control Manager: dispatch as a run.
        words = ["run"]
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
