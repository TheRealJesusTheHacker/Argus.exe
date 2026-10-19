"""systemd service host for ARGUS.EXE real-time protection (v1.2.0).

The Linux sibling of :mod:`argus.winservice`. Phase 3 built the
protection engine as a service-shaped core
(:class:`argus.service.ArgusService`: start / stop / pause /
resume / status heartbeat); Windows wraps that core in the SCM.
This module wraps the SAME core in **systemd**, so on Kali and
Parrot (and any Debian-based system) protection:

- starts at boot, before anyone logs in (``WantedBy=
  multi-user.target``, the ``SERVICE_AUTO_START`` analog);
- restarts if it ever stops unexpectedly (``Restart=on-failure``
  — the analog of the ``sc.exe failure`` restart policy the
  Windows setup engine configures);
- shows up in ``systemctl`` under its own name.

The mapping to the Windows host is deliberate and one-to-one:

============================  ==================================
Windows (winservice)          Linux (this module)
============================  ==================================
SCM service ``ArgusProtection``  systemd unit ``argus-protection``
ImagePath ``"Argus.exe" --service``  ``ExecStart=/usr/lib/argus/argus --service``
``servicemanager`` dispatcher  :func:`run_daemon` (foreground,
                              signal-driven, ``Type=simple``)
LocalSystem account           root (the unit's ``User`` default)
``%ProgramData%\\Argus``        ``/var/lib/argus`` (Environment=
                              ARGUS_DATA_DIR in the unit)
named pipe + GetNamedPipe-    Unix socket + SO_PEERCRED
ClientProcessId               (:mod:`argus.socket_channel`)
Security Center registration  — (no Linux analog exists; the
                              desktop entry is the system's
                              record that Argus is installed)
============================  ==================================

systemd is driven through its CLI (``systemctl``) behind an
injectable runner seam, exactly as the Windows host's SCM queries
sit behind a seam — everything here is unit-testable off a live
systemd, and every query fails closed (an unanswerable question
is "unknown", never "running").
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

from . import paths
from .service import read_status_file

#: Service identity in systemd (``systemctl status argus-protection``).
SERVICE_NAME = "argus-protection"
UNIT_NAME = "argus-protection.service"
#: Where the .deb registers Argus in the desktop's app menus.
DESKTOP_ENTRY_PATH = Path("/usr/share/applications/argus.desktop")
SERVICE_DISPLAY_NAME = "ARGUS.EXE — Real-Time Protection"
SERVICE_DESCRIPTION = (
    "Sentinel Safeguard LLC ARGUS.EXE: watches the folders threats "
    "land in, scans new and changed files, and applies your response "
    "policy. Part of the ARGUS.EXE antivirus."
)

#: Marker argument the unit's ExecStart carries — the same word
#: the Windows SCM registration uses: a launch carrying it is the
#: service host; a launch without it is the GUI.
SERVICE_EXE_ARGS = "--service"

#: Commands the management CLI understands on Linux (the Windows
#: set, translated: install/uninstall are the package manager's
#: job here, and say so).
SERVICE_COMMANDS = (
    "install", "uninstall", "start", "stop", "restart", "status", "run",
)


class ServiceUnavailable(RuntimeError):
    """The Linux service layer cannot run here."""


def canonical_exe_path() -> Path:
    """The installed program's canonical FHS address."""
    return paths.LINUX_PROGRAM_PATH


def canonical_install_dir() -> Path:
    return paths.LINUX_INSTALL_DIR


def preferred_config_path() -> Path:
    """Where the installed service (and the GUI) read config.

    The FHS config home wins when an admin has placed a config
    there (``/etc/argus/argus-config.json``); otherwise the shared
    data root's config — the same file every platform's data-dir
    logic names. One helper for the daemon and the GUI, so the
    two can never silently read different configs."""
    if paths.linux_installed_layout() and paths.LINUX_CONFIG_PATH.is_file():
        return paths.LINUX_CONFIG_PATH
    return paths.data_dir() / "argus-config.json"


# ----------------------------------------------------------------------
# The systemd unit (generated here; the packaged copy in
# packaging/linux/argus-protection.service must match render_unit()
# byte-for-byte — a test pins that, so the shipped unit can never
# drift from this source).
# ----------------------------------------------------------------------
def render_unit() -> str:
    """The argus-protection unit file, exactly as packaged.

    Type=simple matches how the service core actually starts:
    :func:`run_daemon` runs the engine in the foreground and
    systemd considers the service up once the process is exec'd —
    the product's own readiness proof is its heartbeat file, the
    same one Windows setup verifies after SCM start.
    RuntimeDirectory gives the service its root-owned /run/argus
    (the verified-action socket's home), recreated on every start.
    """
    exe = canonical_exe_path()
    return (
        "[Unit]\n"
        f"Description={SERVICE_DISPLAY_NAME}\n"
        "Documentation=https://github.com/TheRealJesusTheHacker/Argus.exe\n"
        "After=network.target\n"
        "Wants=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exe} {SERVICE_EXE_ARGS}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        f"Environment=ARGUS_DATA_DIR={paths.LINUX_DATA_DIR}\n"
        "RuntimeDirectory=argus\n"
        "RuntimeDirectoryMode=0755\n"
        "UMask=0022\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def unit_file_path() -> Path | None:
    """The unit file systemd would load, in its own precedence
    order (/etc overrides /run overrides /usr/lib), or None."""
    for candidate in paths.LINUX_UNIT_PATHS:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def systemd_registered_exe(
    unit_path: Path | str | None = None,
) -> Path | None:
    """The executable the unit's ExecStart names — a LOCATOR,
    never an identity proof (the same rule as the SCM ImagePath
    on Windows): it tells Argus where the canonical program file
    is expected to live. Identity is proven only by the recorded
    fingerprint (:mod:`argus.selftrust`)."""
    target = (
        Path(unit_path) if unit_path is not None else unit_file_path()
    )
    if target is None:
        return None
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("ExecStart="):
            continue
        command = line[len("ExecStart="):].strip()
        if not command:
            continue
        # ExecStart prefixes (-, @, +, !) precede the path; the
        # packaged unit carries none, but parse honestly anyway.
        first = command.split()[0].lstrip("-@+!").strip('"')
        if first:
            return Path(first)
    return None


# ----------------------------------------------------------------------
# systemctl queries (injectable runner seam — cf. winservice)
# ----------------------------------------------------------------------
def _default_runner(argv: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(
        argv, capture_output=True, text=True, timeout=15
    )
    return completed.returncode, completed.stdout, completed.stderr


#: systemctl is-active words → the SCM-shaped state names the
#: setup engine's mapping already understands.
_SYSTEMD_STATE_MAP = {
    "active": "running",
    "activating": "start_pending",
    "deactivating": "stop_pending",
    "reloading": "running",
    "inactive": "stopped",
    "failed": "stopped",
}


def query_service_state_detailed(
    name: str = UNIT_NAME, *, runner=None
) -> str:
    """Ask systemd for the unit's state, in SCM vocabulary:
    ``"running"``, ``"stopped"``, the pending states,
    ``"not-installed"`` when systemd says the unit does not
    exist, and ``"unknown"`` when the question cannot be answered
    at all (not Linux, no systemctl). Setup decisions depend on
    the difference between stopped and absent — see the Windows
    twin of this function."""
    if not sys.platform.startswith("linux"):
        return "unknown"
    run = runner or _default_runner
    try:
        _rc, stdout, _stderr = run(["systemctl", "is-active", name])
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    word = stdout.strip().splitlines()[0].strip() if stdout.strip() else ""
    if word in _SYSTEMD_STATE_MAP:
        return _SYSTEMD_STATE_MAP[word]
    # "unknown" from is-active, or an empty answer: distinguish
    # "no such unit" from "cannot tell" via the load state.
    try:
        _rc, stdout, _stderr = run(
            ["systemctl", "show", "-p", "LoadState", "--value", name]
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if stdout.strip() == "not-found":
        return "not-installed"
    return "unknown"


def query_service_state(name: str = UNIT_NAME, *, runner=None):
    """The state name when systemd answered; False when it could
    not be asked (mirrors the Windows twin's contract, so the
    heartbeat gates in winservice.assess_service_status apply
    unchanged)."""
    state = query_service_state_detailed(name, runner=runner)
    if state == "unknown":
        return False
    return state


# ----------------------------------------------------------------------
# Setup-state detection (the Linux branch of setup_engine)
# ----------------------------------------------------------------------
def detect_state(*, runner=None):
    """Classify this machine for the GUI's setup states, from the
    .deb layout's own evidence:

    - the canonical program file (``/usr/lib/argus/argus``),
    - the systemd unit's state,
    - the install's completeness proofs: the fingerprint the
      package recorded at install time, and the desktop entry
      (the system's record that Argus is installed — the closest
      Linux analog of the Windows registration probes).

    A service that exists while a proof is *provably* missing is
    INSTALLED_INCOMPLETE — a partial install the package manager
    heals by reinstalling. Unanswerable probes never demote a
    healthy install (the Windows rule, kept)."""
    from .setup_engine import SetupState

    exe = canonical_exe_path()
    unit_state = query_service_state_detailed(runner=runner)
    if not exe.is_file():
        if unit_state == "not-installed":
            return SetupState.NOT_INSTALLED
        if unit_state == "unknown":
            return SetupState.NOT_INSTALLED
        # A unit without its program is a broken partial install.
        return SetupState.INSTALLED_INCOMPLETE
    if unit_state == "not-installed":
        return SetupState.INSTALLED_INCOMPLETE
    if unit_state == "unknown":
        # systemd cannot be asked (not booted, container): the
        # program is installed; claim nothing about protection.
        return SetupState.INSTALLED_STOPPED
    try:
        from . import selftrust

        identity_recorded = (
            selftrust.load_recorded_exe_sha256() is not None
        )
    except Exception:
        identity_recorded = True  # unanswerable ≠ missing
    try:
        desktop_present = DESKTOP_ENTRY_PATH.is_file()
    except OSError:
        desktop_present = True  # unanswerable ≠ missing
    if not identity_recorded or not desktop_present:
        return SetupState.INSTALLED_INCOMPLETE
    if unit_state == "running":
        return SetupState.RUNNING
    return SetupState.INSTALLED_STOPPED


# ----------------------------------------------------------------------
# The daemon host (the systemd launch)
# ----------------------------------------------------------------------
def _refresh_identity_record() -> None:
    """Re-record the installed program's fingerprint when THIS
    process provably is the canonical installed program (its
    resolved /proc/self/exe IS the canonical path): the .deb's
    postinst records it at install time, and the daemon — the
    one process systemd launches from that exact address —
    refreshes it at start, so a package upgrade (new bytes at
    the same address, recorded by the new postinst) and a manual
    repair converge on the truth. Best-effort and root-only in
    practice: the trusted data root is root-owned, so anyone
    else's attempt simply fails and is logged."""
    try:
        running = Path(os.path.realpath("/proc/self/exe"))
        canonical = canonical_exe_path()
        if running != canonical or not canonical.is_file():
            return
        from . import __version__, selftrust

        selftrust.record_exe_identity(
            canonical, version=__version__
        )
    except Exception:
        # Never fatal: a missing record refuses privileged
        # socket callers (fail closed), it does not stop
        # protection.
        import logging

        logging.getLogger("argus.linuxservice").exception(
            "could not refresh the self-identity record"
        )


def run_daemon(config_path: Path | str | None = None) -> int:
    """Host the protection service for systemd.

    This — and only this — is what runs when systemd launches
    the program with the ``--service`` marker. Foreground by
    design (``Type=simple``): the core runs its own threads, and
    SIGTERM/SIGINT (systemd's stop, a terminal's Ctrl-C) shut it
    down cleanly through the same stop path the Windows host
    uses."""
    if not sys.platform.startswith("linux"):
        raise ServiceUnavailable(
            "the systemd service host is Linux-only; this machine "
            f"reports platform '{sys.platform}'"
        )
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
    )
    log = logging.getLogger("argus.linuxservice")
    from .service import ArgusService

    resolved = (
        Path(config_path)
        if config_path is not None
        else preferred_config_path()
    )
    _refresh_identity_record()
    core = ArgusService(config_path=resolved)
    stop_event = threading.Event()

    def _ask_stop(signum, _frame):
        log.info("signal %s received — stopping", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _ask_stop)
    signal.signal(signal.SIGINT, _ask_stop)
    try:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except (ValueError, OSError):
        pass
    log.info("ARGUS.EXE real-time protection service starting (systemd)")
    core.run_forever(stop_event)
    log.info("ARGUS.EXE real-time protection service stopped")
    return 0


# ----------------------------------------------------------------------
# Management commands (systemctl is the operator's tool; Argus's
# own words route to it, and answer status from the same gates
# the Windows CLI uses)
# ----------------------------------------------------------------------
def route_service_command(argv: list[str]) -> str:
    """Resolve the management command (pure; mirrors the Windows
    twin, including its usage error)."""
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


def perform_service_command(
    command: str,
    *,
    config_path: Path | str | None = None,
    runner=None,
) -> int:
    """Carry out a routed management command. Returns an exit code."""
    if command == "run":
        return run_daemon(config_path)
    if command == "status":
        cfg = Path(config_path) if config_path else preferred_config_path()
        from .config import ArgusConfig

        status_file = Path(ArgusConfig.load(cfg).status_file)
        data = read_status_file(status_file)
        if data is None:
            print(
                "Argus real-time protection: no status heartbeat "
                "found — the service does not appear to be running."
            )
            return 1
        verdict, note = _assess_status(data, runner=runner)
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
    if command in ("install", "uninstall"):
        # On Linux the package manager owns installation — the
        # honest answer is the designed direction, not a
        # half-built imitation of dpkg.
        if command == "install":
            print(
                "On Linux, Argus installs with its package: "
                "sudo apt install ./Argus.deb — the package sets "
                "up and starts the protection service for you."
            )
        else:
            print(
                "On Linux, Argus is removed by its package "
                "manager: sudo apt remove argus (your quarantine "
                "vault and history are kept) or sudo apt purge "
                "argus (everything is removed)."
            )
        return 0
    # start / stop / restart: systemd's call, through its own CLI.
    run = runner or _default_runner
    try:
        returncode, _out, stderr = run(
            ["systemctl", command, UNIT_NAME]
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"argus service: could not ask systemd to {command} "
              f"the protection service: {exc}")
        return 2
    if returncode != 0:
        print(
            f"argus service: systemd could not {command} the "
            f"protection service. {stderr.strip()}".strip()
        )
        return 1
    print(f"Argus protection service: {command} requested.")
    return 0


def _assess_status(
    status: dict, *, runner=None
) -> tuple[str, str]:
    """Combine a heartbeat dict and systemd's word into one
    verdict — the SAME gates as the Windows CLI's
    :func:`argus.winservice.assess_service_status` (the manager's
    word outranks the user-writable heartbeat; an unanswerable
    manager leaves the verdict to heartbeat freshness), with
    Linux wording:

    - systemd says running → RUNNING, even when the heartbeat is
      stale (details may lag; protection is on).
    - systemd answered anything else → STOPPED, however fresh
      the heartbeat claims to be.
    - systemd cannot be asked → a FRESH heartbeat decides.
    """
    from datetime import datetime, timezone

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
            age = (datetime.now(timezone.utc) - stamp).total_seconds()
    fresh = age is not None and -60.0 <= age <= 45.0

    systemd_state = query_service_state(runner=runner)
    if systemd_state == "running":
        if status.get("running") and fresh:
            return "running", ""
        if not fresh:
            return (
                "running",
                "the service is running (confirmed by systemd), "
                "but its status details are stale — details syncing",
            )
        return "running", "the service is running (confirmed by systemd)"
    if isinstance(systemd_state, str):
        return (
            "stopped",
            f"systemd reports the argus-protection service is "
            f"{systemd_state.replace('_', ' ')}",
        )
    if status.get("running") and fresh:
        return "running", ""
    if status.get("running"):
        return (
            "stopped",
            "the last status heartbeat is stale — the writer does "
            "not appear to be running anymore",
        )
    return "stopped", ""


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``argus service`` support commands on Linux.

    A launch with no words — or carrying the ``--service``
    marker — is systemd starting the service: host it in the
    foreground, never the management handler."""
    words = list(sys.argv[1:] if argv is None else argv)
    if not words or SERVICE_EXE_ARGS in words:
        try:
            return run_daemon()
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
