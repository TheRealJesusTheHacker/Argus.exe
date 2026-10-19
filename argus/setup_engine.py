"""Self-install engine: the one Argus executable sets itself up.

Since v1.1.0 there is no separate installer and no separate service
executable. The single ``Argus.exe`` a person downloads contains the
GUI, the protection service host, and this engine. When protection
is not set up yet, the GUI offers one button — "Set up protection" —
which relaunches this same file elevated with ``--run-setup``; the
engine then:

1. places the executable at its canonical home
   (``C:\\Program Files\\Sentinel Safeguard\\Argus\\Argus.exe``),
   verifying the copy byte-for-byte;
2. creates the machine data tree and applies the trust-split ACLs
   (v1.0.4 design, previously applied by the retired Inno script —
   the commands moved here verbatim, now with checked exit codes),
   and records the placed program's SHA-256 fingerprint in that
   trusted root — the scanner later exempts Argus's own program
   only when the file at its address still matches a recorded
   identity proof (see :mod:`argus.selftrust`);
3. installs the ``ArgusProtection`` service (automatic start,
   LocalSystem, ImagePath = canonical exe + ``--service``);
4. sets the service's crash-recovery policy to restart;
5. registers Argus with Windows Security Center;
6. writes the Add/Remove Programs entry (its UninstallString runs
   this same exe with ``--uninstall``);
7. starts the service; and
8. VERIFIES — SCM reports running AND a fresh heartbeat lands in
   the shared status file — before calling setup done.

Every step is checked and every failure raises :class:`SetupError`
carrying a plain-language ``user_message`` (the only text a user
ever sees) plus a technical ``detail`` for logs and support. No
step's failure is swallowed: the v1.0.5 install silently no-opped
inside a hidden installer step and Argus shipped "installed" with
no service at all. That failure mode is designed out here.

All machine-touching operations are injectable seams (keyword
arguments), so the whole engine is unit-tested off Windows.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from . import __version__ as ARGUS_VERSION
from . import paths, winservice
from .service import read_status_file

IS_WINDOWS = sys.platform == "win32"

#: Where the one executable lives once installed.
INSTALL_FOLDER_PARTS = ("Sentinel Safeguard", "Argus")
EXE_NAME = "Argus.exe"

#: Add/Remove Programs registry key (HKLM) for the installed product.
UNINSTALL_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\ARGUS.EXE"
)
UNINSTALL_DISPLAY_NAME = "ARGUS.EXE — Sentinel Safeguard"
UNINSTALL_PUBLISHER = "Sentinel Safeguard LLC"

#: The setup result the elevated helper leaves for the GUI.
SETUP_RESULT_NAME = "setup-result.json"

#: How long verification waits for the service + heartbeat.
VERIFY_TIMEOUT_SECONDS = 30.0
_VERIFY_POLL_SECONDS = 0.5

#: Progress step keys, in order. The setup window maps these to
#: plain-language lines; the engine never invents others.
STEP_PLACING = "placing"
STEP_SECURING = "securing"
STEP_INSTALLING = "installing"
STEP_REGISTERING = "registering"
STEP_STARTING = "starting"
STEP_VERIFYING = "verifying"


class SetupState(Enum):
    """What setup can know about this machine."""

    NOT_INSTALLED = "not_installed"
    INSTALLED_STOPPED = "installed_stopped"
    INSTALLED_INCOMPLETE = "installed_incomplete"
    RUNNING = "running"
    PORTABLE = "portable"


class SetupError(RuntimeError):
    """A setup step failed, in two voices.

    ``user_message`` is plain language, safe to show a non-technical
    person, and always ends in something they can do. ``detail`` is
    the technical record (command, exit code, exception) for logs
    and support — it is never shown in the GUI.
    """

    def __init__(self, user_message: str, detail: str = ""):
        super().__init__(user_message)
        self.user_message = user_message
        self.detail = detail


# ----------------------------------------------------------------------
# Locations & state
# ----------------------------------------------------------------------
def is_portable() -> bool:
    """Portable mode: data lives beside the exe (ARGUS_DATA_DIR set).
    Portable Argus NEVER self-installs — protection runs in-process
    while the window is open, by design."""
    return bool(os.environ.get("ARGUS_DATA_DIR"))


def canonical_install_dir() -> Path:
    program_files = os.environ.get("ProgramFiles") or r"C:\Program Files"
    return Path(program_files).joinpath(*INSTALL_FOLDER_PARTS)


def canonical_exe_path() -> Path:
    return canonical_install_dir() / EXE_NAME


def _running_exe() -> Path | None:
    """The file currently running, when it is a packaged exe.
    Source checkouts (python.exe) return None — there is nothing
    to self-place."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    return None


def detect_state(
    *,
    scm_state: str | None = None,
    portable: bool | None = None,
    av_registered: bool | None = None,
    arp_present: bool | None = None,
) -> SetupState:
    """Classify this machine for the GUI's setup states.

    *scm_state* may be injected (tests); otherwise the SCM is asked
    via :func:`argus.winservice.query_service_state_detailed`, which
    distinguishes "not-installed" (error 1060) from a stopped
    service — the difference between "set up" and "turn on".

    A machine whose service exists but whose Security Center
    registration or Add/Remove Programs entry is *provably* missing
    is :attr:`SetupState.INSTALLED_INCOMPLETE` — a partial install
    (an interrupted or older setup) that re-running setup heals.
    "Provably" matters: when a registration probe cannot answer,
    it reports present, so an unanswerable probe never demotes a
    healthy install.
    """
    if is_portable() if portable is None else portable:
        return SetupState.PORTABLE
    if (
        scm_state is None
        and sys.platform.startswith("linux")
        and (paths.linux_installed_layout() or _linux_unit_present())
    ):
        # The .deb edition (v1.2.0): systemd is the service
        # manager here, and its states — plus the package
        # layout's own proofs — classify the machine. Injected
        # probes (tests, support tooling) keep the historical
        # SCM-shaped path below on every platform, unchanged.
        from . import linuxservice

        return linuxservice.detect_state()
    state = (
        scm_state
        if scm_state is not None
        else winservice.query_service_state_detailed()
    )
    if state == "not-installed":
        return SetupState.NOT_INSTALLED
    if state not in (
        "running", "stopped", "paused", "start_pending",
        "stop_pending", "continue_pending", "pause_pending",
    ):
        # "unknown": the SCM could not be asked (not Windows / no
        # pywin32). Nothing can be proven to exist, so the honest
        # classification is the one that offers setup, not the one
        # that claims protection.
        return SetupState.NOT_INSTALLED
    if av_registered is None or arp_present is None:
        probed_av, probed_arp = _registration_probe()
        if av_registered is None:
            av_registered = probed_av
        if arp_present is None:
            arp_present = probed_arp
    if not av_registered or not arp_present:
        return SetupState.INSTALLED_INCOMPLETE
    if state == "running":
        return SetupState.RUNNING
    return SetupState.INSTALLED_STOPPED


def _linux_unit_present() -> bool:
    """True when a systemd unit file for Argus exists at any of
    the standard locations (the .deb installs one even before
    its first start)."""
    try:
        return any(p.is_file() for p in paths.LINUX_UNIT_PATHS)
    except OSError:
        return False


# ----------------------------------------------------------------------
# Registration probes (is each install outcome verifiably in place?)
# ----------------------------------------------------------------------
_registration_probe_cache: tuple[float, bool, bool] | None = None
_REGISTRATION_PROBE_TTL_SECONDS = 60.0


def _registration_probe() -> tuple[bool, bool]:
    """``(av_registered, arp_present)`` for this machine, cached
    briefly (the dashboard polls state every few seconds and the
    Security Center query is not free). A probe that cannot answer
    reports True — see :func:`detect_state`."""
    global _registration_probe_cache
    now = time.monotonic()
    if (
        _registration_probe_cache is not None
        and now - _registration_probe_cache[0]
        < _REGISTRATION_PROBE_TTL_SECONDS
    ):
        return _registration_probe_cache[1], _registration_probe_cache[2]
    result = (_av_registration_present(), _arp_entry_present())
    _registration_probe_cache = (now, result[0], result[1])
    return result


def _av_registration_present() -> bool:
    """True when Windows Security Center lists an Argus product —
    or when the question cannot be answered here (off Windows the
    SCM state already classified the machine before this runs)."""
    if not IS_WINDOWS:
        return True
    try:
        import win32com.client  # type: ignore[import-not-found]

        wmi = win32com.client.GetObject(
            r"winmgmts:\\.\root\SecurityCenter2"
        )
        products = wmi.ExecQuery(
            "SELECT displayName FROM AntiVirusProduct"
        )
        return any(
            "ARGUS" in str(product.displayName).upper()
            for product in products
        )
    except Exception:
        return True  # unanswerable ≠ missing


def _arp_entry_present() -> bool:
    """True when the Add/Remove Programs entry exists — or when
    the question cannot be answered here."""
    if not IS_WINDOWS:
        return True
    try:
        import winreg  # type: ignore[import-not-found]

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_READ
        ):
            return True
    except FileNotFoundError:
        return False  # provably missing
    except Exception:
        return True  # unanswerable ≠ missing


def _av_registration_verified() -> bool:
    """Strict variant for install(): True only when the Security
    Center registration is POSITIVELY seen. Anything unanswerable
    counts as not-done — re-registering is idempotent, skipping
    on a guess is how partial installs stay partial."""
    if not IS_WINDOWS:
        return False
    try:
        import win32com.client  # type: ignore[import-not-found]

        wmi = win32com.client.GetObject(
            r"winmgmts:\\.\root\SecurityCenter2"
        )
        products = wmi.ExecQuery(
            "SELECT displayName FROM AntiVirusProduct"
        )
        return any(
            "ARGUS" in str(product.displayName).upper()
            for product in products
        )
    except Exception:
        return False


def _arp_entry_verified() -> bool:
    """Strict variant for install(): True only when the ARP entry
    is POSITIVELY present."""
    if not IS_WINDOWS:
        return False
    try:
        import winreg  # type: ignore[import-not-found]

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_READ
        ):
            return True
    except Exception:
        return False


def _registered_image_path() -> str | None:
    """The service's registered ImagePath, when it can be read."""
    return winservice.query_service_image_path()


def _image_path_is_canonical(canonical: Path) -> bool | None:
    """True/False when the registered ImagePath provably is / is
    not exactly the canonical registration; None when unreadable."""
    registered = _registered_image_path()
    if registered is None:
        return None
    expected = winservice.service_image_path(canonical)
    return registered.strip().lower() == expected.strip().lower()


# ----------------------------------------------------------------------
# Elevation
# ----------------------------------------------------------------------
def is_elevated() -> bool:
    """True when this process runs with an administrator token."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def relaunch_as_admin(
    arguments: list[str], *, exe: Path | str | None = None
) -> bool:
    """Relaunch an Argus executable elevated (the one familiar UAC
    prompt). Returns True when Windows accepted the launch; False
    when the user declined or the launch failed — the caller shows
    the designed "needs your permission" state either way."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        target = str(exe) if exe is not None else sys.executable
        params = " ".join(
            f'"{arg}"' if any(c in arg for c in " \t") else arg
            for arg in arguments
        )
        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", target, params, None, 1
        )
        return int(result) > 32
    except Exception:
        return False


def start_service_elevated() -> bool:
    """Ask Windows (via one UAC prompt) to start the installed
    protection service: the canonical exe relaunches elevated with
    the ``start`` management word. Used by the GUI's "Turn
    protection on" when the service exists but is stopped — the GUI
    itself never touches the service, and never starts a second
    engine against the installed layout."""
    return relaunch_as_admin(["start"], exe=canonical_exe_path())


# ----------------------------------------------------------------------
# Setup result hand-off (elevated helper → GUI)
# ----------------------------------------------------------------------
def setup_result_path() -> Path:
    return paths.shared_dir() / SETUP_RESULT_NAME


def write_setup_result(result: dict) -> Path:
    payload = dict(result)
    payload.setdefault("at", time.time())
    return paths.write_text_atomic(
        setup_result_path(), json.dumps(payload, indent=2)
    )


def read_setup_result(*, max_age_seconds: float = 600.0) -> dict | None:
    """The last setup outcome, when one was left recently."""
    try:
        raw = json.loads(setup_result_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    at = raw.get("at")
    if isinstance(at, (int, float)) and time.time() - at > max_age_seconds:
        return None
    return raw


# ----------------------------------------------------------------------
# Install
# ----------------------------------------------------------------------
@dataclass
class InstallResult:
    state: SetupState
    exe: Path
    steps: list[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _default_run_command(argv: list[str]):
    return subprocess.run(argv, capture_output=True, text=True)


def _run_checked(run_command, argv: list[str], user_message: str) -> None:
    """Run one external command; any failure is a SetupError with
    the command and its output in the detail — never silent."""
    try:
        completed = run_command(argv)
    except Exception as exc:
        raise SetupError(user_message, detail=f"{argv!r} raised {exc!r}") from exc
    if getattr(completed, "returncode", 1) != 0:
        detail = (
            f"{argv!r} exited {completed.returncode}: "
            f"{(getattr(completed, 'stdout', '') or '').strip()} "
            f"{(getattr(completed, 'stderr', '') or '').strip()}"
        ).strip()
        raise SetupError(user_message, detail=detail)


def _heartbeat_fresh(heartbeat: dict | None, *, max_age: float = 45.0) -> bool:
    if not heartbeat or not heartbeat.get("running"):
        return False
    stamp_raw = heartbeat.get("heartbeat_at")
    if not stamp_raw:
        return False
    try:
        stamp = datetime.fromisoformat(str(stamp_raw))
    except ValueError:
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    return -60.0 <= age <= max_age


def _copy_failure_message(exc: BaseException) -> str:
    """Name the real cause class of a self-placement failure.

    "Free up some disk space" for a file that is simply *in use*
    sends the person chasing the wrong fix (P1-7): the message
    distinguishes the causes a person can act on — the old Argus
    service still holding the file, a permission Windows denied,
    the source file gone, the disk actually full.
    """
    winerror = getattr(exc, "winerror", None)
    if isinstance(exc, FileNotFoundError):
        return (
            "Argus couldn't put its program in place — the file "
            "it was started from could not be found. Download "
            "Argus.exe again and run the fresh copy."
        )
    if winerror in (32, 33) or (
        isinstance(exc, PermissionError) and winerror is not None
    ):
        return (
            "Argus couldn't replace its program file — it is in "
            "use, most likely by the Argus protection service "
            "from an earlier setup. Restart this PC, then choose "
            "“Set up protection” again."
        )
    if isinstance(exc, PermissionError):
        return (
            "Argus couldn't put its program in place — Windows "
            "denied access to the install folder. Make sure you "
            "allowed the administrator prompt, then try setting "
            "up again."
        )
    if isinstance(exc, OSError) and exc.errno == 28:  # ENOSPC
        return (
            "Argus couldn't put its program in place — this PC "
            "is out of disk space. Free up some space and try "
            "setting up again."
        )
    return (
        "Argus couldn't put its program in place. Try setting "
        "up again; if it keeps failing, contact Sentinel Safeguard."
    )


def _configured_status_path(root: Path) -> Path:
    """The status-file path verification must watch: the one the
    machine's CONFIG names (``config.status_file``), never a
    hardcoded default — a configured location is where the
    service will actually heartbeat."""
    from .config import DEFAULT_CONFIG_NAME, ArgusConfig

    config = ArgusConfig.load(root / DEFAULT_CONFIG_NAME)
    return Path(config.status_file)


def _read_configured_heartbeat(root: Path) -> dict | None:
    return read_status_file(_configured_status_path(root))


#: Start Menu location (machine-wide, under ProgramData).
START_MENU_PARTS = (
    "Microsoft", "Windows", "Start Menu", "Programs", "Sentinel Safeguard",
)


def start_menu_folder() -> Path:
    program_data = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(program_data).joinpath(*START_MENU_PARTS)


def _create_start_menu_shortcuts(exe: Path, run_command) -> None:
    """Create the Start Menu shortcuts the product promises:
    ``ARGUS.EXE`` (opens the app) and ``ARGUS.EXE Dev Toolkit``
    (opens it on the Dev Toolkit page — :mod:`argus.gui.app`
    routes ``--page devtoolkit``). Windows creates shortcuts
    through the shell; PowerShell's WScript.Shell COM is the
    scriptable route, exit-code-checked like every other step."""
    folder = start_menu_folder()
    script = "; ".join(
        [
            f"New-Item -ItemType Directory -Force '{folder}' "
            "| Out-Null",
            "$ws = New-Object -ComObject WScript.Shell",
            *(
                (
                    f"$s = $ws.CreateShortcut('{link}'); "
                    f"$s.TargetPath = '{exe}'; "
                    + (f"$s.Arguments = '{args}'; " if args else "")
                    + "$s.Save()"
                )
                for link, args in (
                    (str(folder / "ARGUS.EXE.lnk"), ""),
                    (str(folder / "ARGUS.EXE Dev Toolkit.lnk"),
                     "--page devtoolkit"),
                )
            ),
        ]
    )
    _run_checked(
        run_command,
        [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-Command", script,
        ],
        "Argus couldn't create its Start Menu shortcut. Try "
        "setting up again.",
    )


def _remove_start_menu_shortcuts() -> None:
    """Remove the Start Menu shortcut folder (uninstall)."""
    folder = start_menu_folder()
    try:
        shutil.rmtree(folder)
    except FileNotFoundError:
        pass
    try:
        folder.parent.rmdir()  # the Programs folder — only if empty
    except OSError:
        pass


def install(
    *,
    progress=None,
    source_exe: Path | None = None,
    copy_file=shutil.copyfile,
    run_command=None,
    install_service_fn=None,
    remove_service_fn=None,
    stop_service_fn=None,
    register_av_fn=None,
    write_uninstall_entry_fn=None,
    start_service_fn=None,
    scm_state_fn=None,
    read_heartbeat_fn=None,
    data_root: Path | None = None,
    sleep=time.sleep,
    monotonic=time.monotonic,
    verify_timeout: float = VERIFY_TIMEOUT_SECONDS,
    av_registered_fn=None,
    arp_present_fn=None,
    service_image_ok_fn=None,
    create_shortcuts_fn=None,
    acls_in_place_fn=None,
) -> InstallResult:
    """Set Argus up on this machine, verifying every step.

    Runs elevated (the GUI arranges that via ``--run-setup``).
    Resumable and idempotent (P1-6): every step first checks
    whether its outcome is already verifiably in place — the exe
    already home with the right bytes, the service already
    registered with the canonical ImagePath, the AV registration
    and Add/Remove Programs entry already present, the ACLs
    already applied — and skips the work when it is. A partial
    install (setup interrupted, an older build's leftovers) is
    therefore healed by simply running setup again, and a
    complete one converges without churn. Raises
    :class:`SetupError` at the first step that genuinely fails —
    later steps do not run.
    """
    if is_portable():
        raise SetupError(
            "This is the portable edition of Argus, and portable "
            "Argus never installs itself. Protection runs while "
            "the Argus window is open.",
            detail="install() called with ARGUS_DATA_DIR set",
        )
    run_command = run_command or _default_run_command
    install_service_fn = install_service_fn or winservice.install_service
    remove_service_fn = remove_service_fn or winservice.uninstall_service
    stop_service_fn = stop_service_fn or winservice.stop_service
    register_av_fn = register_av_fn or _register_av_default
    write_uninstall_entry_fn = (
        write_uninstall_entry_fn or _write_uninstall_entry
    )
    start_service_fn = start_service_fn or winservice.start_service
    scm_state_fn = scm_state_fn or winservice.query_service_state_detailed
    root = Path(data_root) if data_root is not None else paths.data_dir()
    read_heartbeat_fn = read_heartbeat_fn or (
        lambda: _read_configured_heartbeat(root)
    )
    av_registered_fn = av_registered_fn or _av_registration_verified
    arp_present_fn = arp_present_fn or _arp_entry_verified
    service_image_ok_fn = service_image_ok_fn or _image_path_is_canonical
    if create_shortcuts_fn is None:
        create_shortcuts_fn = (
            lambda exe: _create_start_menu_shortcuts(exe, run_command)
        )
    canonical = canonical_exe_path()
    steps: list[str] = []

    def note(step: str) -> None:
        steps.append(step)
        if progress is not None:
            progress(step)

    # -- 0. clear the old service out of the way FIRST (P1-7) -------
    # An existing ArgusProtection service is stopped before
    # anything touches the exe: a RUNNING old service holds the
    # canonical file open, and the self-placement copy then fails
    # for a reason the old code reported as a generic copy error.
    # The registration itself is removed only when it is not
    # already exactly canonical (P1-6 resumability) — an
    # unreadable ImagePath counts as "not proven right", so it is
    # rebuilt.
    service_present = scm_state_fn() != "not-installed"
    registration_kept = False
    if service_present:
        try:
            stop_service_fn()
        except Exception:
            pass  # not running is fine — unlocking is the point
        if service_image_ok_fn(canonical) is True:
            registration_kept = True
        else:
            try:
                remove_service_fn()
            except Exception as exc:
                raise SetupError(
                    "Argus couldn't remove the earlier protection "
                    "service registration. Restart this PC and try "
                    "setting up again.",
                    detail=f"pre-place service removal: {exc!r}",
                ) from exc

    # -- 1. self-place ------------------------------------------------
    note(STEP_PLACING)
    source = source_exe if source_exe is not None else _running_exe()
    already_placed = False
    if source is not None and canonical.is_file():
        source_path = Path(source)
        if source_path.resolve() == canonical.resolve():
            already_placed = True
        else:
            try:
                already_placed = (
                    canonical.stat().st_size == source_path.stat().st_size
                    and _sha256(canonical) == _sha256(source_path)
                )
            except OSError:
                already_placed = False
    if source is not None and not already_placed:
        source = Path(source)
        try:
            canonical.parent.mkdir(parents=True, exist_ok=True)
            copy_file(source, canonical)
            if (
                canonical.stat().st_size != source.stat().st_size
                or _sha256(canonical) != _sha256(source)
            ):
                canonical.unlink(missing_ok=True)
                raise SetupError(
                    "Argus couldn't put its program in place — the "
                    "copy didn't check out. Free up some disk space "
                    "and try setting up again.",
                    detail=f"copy verification failed: {source} -> {canonical}",
                )
        except SetupError:
            raise
        except Exception as exc:
            raise SetupError(
                _copy_failure_message(exc),
                detail=f"self-place {source} -> {canonical}: {exc!r}",
            ) from exc

    # -- 2. data tree + trust-split ACLs ------------------------------
    note(STEP_SECURING)
    quarantine = root / "quarantine"
    shared = root / "shared"
    requests = shared / "requests"
    results = shared / "results"
    try:
        for folder in (root, quarantine, shared, requests, results):
            folder.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise SetupError(
            "Argus couldn't prepare its data folders. Try setting "
            "up again.",
            detail=f"data tree under {root}: {exc!r}",
        ) from exc
    acls_done = False
    if acls_in_place_fn is not None:
        try:
            acls_done = bool(acls_in_place_fn(root))
        except Exception:
            acls_done = False  # unproven → apply them
    if IS_WINDOWS and not acls_done:
        # The v1.0.4 trust split, formerly applied by the retired
        # installer script — same grants, now exit-code-checked,
        # with inheritance broken wherever the design intends a
        # FIXED ACL set (root, quarantine, shared, and both channel
        # folders): an inherited grant from a parent must never
        # quietly widen what the split decided.
        _run_checked(
            run_command,
            [
                "icacls.exe", str(root), "/inheritance:r",
                "/grant:r", "SYSTEM:(OI)(CI)F",
                "Administrators:(OI)(CI)F", "Users:(OI)(CI)RX",
            ],
            "Argus couldn't secure its data folders. Try setting "
            "up again.",
        )
        _run_checked(
            run_command,
            [
                "icacls.exe", str(quarantine), "/inheritance:r",
                "/grant:r", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F",
            ],
            "Argus couldn't lock down its threat vault. Try "
            "setting up again.",
        )
        _run_checked(
            run_command,
            [
                "icacls.exe", str(shared), "/inheritance:r",
                "/grant:r", "SYSTEM:(OI)(CI)F",
                "Administrators:(OI)(CI)F", "Users:(OI)(CI)M",
                "/T", "/Q",
            ],
            "Argus couldn't prepare its shared data folder. Try "
            "setting up again.",
        )
        # The action-request channel (P0-1): requests\ is a
        # WRITE-ONLY drop box for standard users — they can create
        # a request file (WD: write data / AD: append data, i.e.
        # create files and folders) but cannot read or list what
        # is in it (no RD/GR), so one user's process cannot
        # inspect or harvest another's requests. Only SYSTEM (the
        # service that executes them) and Administrators can read.
        _run_checked(
            run_command,
            [
                "icacls.exe", str(requests), "/inheritance:r",
                "/grant:r", "SYSTEM:(OI)(CI)F",
                "Administrators:(OI)(CI)F", "Users:(OI)(CI)(WD,AD)",
            ],
            "Argus couldn't secure its service request folder. "
            "Try setting up again.",
        )
        # results\ is the mirror: the service publishes outcomes
        # (SYSTEM modify — publishing is atomic rename + cleanup),
        # users may read them, never write.
        _run_checked(
            run_command,
            [
                "icacls.exe", str(results), "/inheritance:r",
                "/grant:r", "SYSTEM:(OI)(CI)M",
                "Administrators:(OI)(CI)F", "Users:(OI)(CI)RX",
            ],
            "Argus couldn't secure its service results folder. "
            "Try setting up again.",
        )

    # Record the installed program's fingerprint in the trusted
    # root, so the scanner can later PROVE the file at the
    # program's address is the file setup put there (see
    # argus.selftrust): Argus exempts its own program only with
    # an identity check, and this record is one of the proofs.
    # The root's ACL (users: read-only) is what keeps the record
    # itself out of a compromised user process's reach.
    if canonical.is_file():
        try:
            from . import selftrust

            selftrust.record_exe_identity(
                canonical, root, version=ARGUS_VERSION
            )
        except Exception as exc:
            raise SetupError(
                "Argus couldn't record its own fingerprint. Try "
                "setting up again.",
                detail=f"self-identity record for {canonical}: {exc!r}",
            ) from exc

    # -- 3. service registration --------------------------------------
    note(STEP_INSTALLING)
    if not registration_kept:
        try:
            install_service_fn(canonical)
        except SetupError:
            raise
        except Exception as exc:
            raise SetupError(
                "Argus couldn't set up always-on protection on this "
                "PC. Try setting up again; if it keeps failing, "
                "contact Sentinel Safeguard.",
                detail=f"service install: {exc!r}",
            ) from exc
    # Crash recovery: restart the service if it ever stops
    # unexpectedly (the retired installer's `sc failure` settings).
    # sc.exe parses each `name= value` pair as SEPARATE argv tokens
    # (P1-5): passing "reset= 86400" as one string hands sc.exe a
    # value with a leading space / an unparseable pair, and the
    # recovery policy silently never applies.
    _run_checked(
        run_command,
        [
            "sc.exe", "failure", winservice.SERVICE_NAME,
            "reset=", "86400",
            "actions=", "restart/60000/restart/60000/restart/60000",
        ],
        "Argus couldn't set up its automatic-restart safety net. "
        "Try setting up again.",
    )

    # -- 4. Windows Security Center + Add/Remove Programs + Start Menu
    note(STEP_REGISTERING)
    try:
        if not av_registered_fn():
            register_av_fn(canonical)
        if not arp_present_fn():
            write_uninstall_entry_fn(canonical)
        if IS_WINDOWS:
            create_shortcuts_fn(canonical)
    except SetupError:
        raise
    except Exception as exc:
        raise SetupError(
            "Argus couldn't finish registering with Windows. Try "
            "setting up again; if it keeps failing, contact "
            "Sentinel Safeguard.",
            detail=f"registration: {exc!r}",
        ) from exc

    # -- 5. start ------------------------------------------------------
    note(STEP_STARTING)
    if scm_state_fn() != "running":
        try:
            start_service_fn()
        except Exception as exc:
            raise SetupError(
                "Argus is set up, but protection didn't start. "
                "Restarting Windows usually fixes this — or try "
                "setting up again.",
                detail=f"service start: {exc!r}",
            ) from exc

    # -- 6. verify: SCM + a fresh heartbeat, or it didn't happen ------
    note(STEP_VERIFYING)
    deadline = monotonic() + verify_timeout
    while True:
        if scm_state_fn() == "running" and _heartbeat_fresh(read_heartbeat_fn()):
            return InstallResult(state=SetupState.RUNNING, exe=canonical,
                                 steps=steps)
        if monotonic() >= deadline:
            raise SetupError(
                "Argus finished setting up, but protection didn't "
                "confirm it's running. Restarting Windows usually "
                "fixes this.",
                detail=(
                    f"verification timed out after {verify_timeout}s: "
                    f"scm={scm_state_fn()!r} "
                    f"heartbeat={read_heartbeat_fn()!r}"
                ),
            )
        sleep(_VERIFY_POLL_SECONDS)


def _register_av_default(exe: Path) -> None:
    """Tell Windows Security Center the canonical exe is the
    machine's antivirus (product and reporter are the same file
    now). Raises on failure — the caller wraps it."""
    from . import winregister

    properties = winregister.antivirus_product_properties(
        product_exe=exe,
        reporting_exe=exe,
        instance_guid=winregister.INSTANCE_GUID,
    )
    winregister.register_antivirus(properties, require_existing_exe=True)


def _write_uninstall_entry(exe: Path) -> None:
    import winreg  # type: ignore[import-not-found]

    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_WRITE
    ) as key:
        winreg.SetValueEx(
            key, "DisplayName", 0, winreg.REG_SZ, UNINSTALL_DISPLAY_NAME
        )
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, ARGUS_VERSION)
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, UNINSTALL_PUBLISHER)
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(exe.parent))
        winreg.SetValueEx(
            key, "UninstallString", 0, winreg.REG_SZ, f'"{exe}" --uninstall'
        )
        winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, str(exe))
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)


def _remove_uninstall_entry() -> None:
    import winreg  # type: ignore[import-not-found]

    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY)
    except FileNotFoundError:
        pass  # already gone — the desired end state


# ----------------------------------------------------------------------
# Uninstall
# ----------------------------------------------------------------------
@dataclass
class UninstallResult:
    steps: list[str] = field(default_factory=list)
    removed_data: bool = False
    leftovers: list[str] = field(default_factory=list)


def uninstall(
    *,
    remove_data: bool = False,
    progress=None,
    stop_service_fn=None,
    remove_service_fn=None,
    unregister_av_fn=None,
    remove_uninstall_entry_fn=None,
    schedule_delete_on_reboot_fn=None,
    scm_state_fn=None,
    remove_shortcuts_fn=None,
    data_root: Path | None = None,
) -> UninstallResult:
    """Remove Argus from this machine.

    Removes the service, the Security Center registration, and the
    Add/Remove Programs entry. The program file itself is deleted
    when possible; when the running process IS that file (the usual
    case — uninstall starts from the installed exe), deletion is
    scheduled for the next restart instead, and reported in
    ``leftovers`` rather than hidden.

    Data (vault, history, settings) is KEPT unless *remove_data* —
    uninstalling by accident must not destroy the record of what
    Argus caught. Raises :class:`SetupError` if a removal step
    genuinely fails.
    """
    stop_service_fn = stop_service_fn or winservice.stop_service
    remove_service_fn = remove_service_fn or winservice.uninstall_service
    if unregister_av_fn is None:
        from . import winregister

        unregister_av_fn = winregister.unregister_antivirus
    remove_uninstall_entry_fn = (
        remove_uninstall_entry_fn or _remove_uninstall_entry
    )
    schedule_delete_on_reboot_fn = (
        schedule_delete_on_reboot_fn or _schedule_delete_on_reboot
    )
    scm_state_fn = scm_state_fn or winservice.query_service_state_detailed
    if remove_shortcuts_fn is None:
        remove_shortcuts_fn = (
            _remove_start_menu_shortcuts if IS_WINDOWS else (lambda: None)
        )
    result = UninstallResult()

    def note(step: str) -> None:
        result.steps.append(step)
        if progress is not None:
            progress(step)

    if scm_state_fn() != "not-installed":
        note("removing-service")
        try:
            try:
                stop_service_fn()
            except Exception:
                pass  # already stopped — removal is the point
            remove_service_fn()
        except Exception as exc:
            raise SetupError(
                "Argus couldn't remove its always-on protection. "
                "Try uninstalling again.",
                detail=f"service removal: {exc!r}",
            ) from exc
        # Verify the removal actually happened (P2): asking the
        # SCM to remove a service and having it still be there is
        # an honest failure, not a success with a footnote. An
        # unanswerable SCM ("unknown") is not proof of presence,
        # so it does not fail the uninstall.
        remaining = scm_state_fn()
        if remaining not in ("not-installed", "unknown"):
            raise SetupError(
                "Argus couldn't remove its always-on protection — "
                "Windows still lists the Argus service. Restart "
                "this PC and try uninstalling again.",
                detail=f"service still present after removal: {remaining}",
            )
    note("unregistering")
    try:
        unregister_av_fn()
        remove_uninstall_entry_fn()
        remove_shortcuts_fn()
    except SetupError:
        raise
    except Exception as exc:
        raise SetupError(
            "Argus couldn't finish unregistering with Windows. "
            "Try uninstalling again.",
            detail=f"unregistration: {exc!r}",
        ) from exc

    root = Path(data_root) if data_root is not None else paths.data_dir()
    if remove_data:
        note("removing-data")
        try:
            shutil.rmtree(root)
            result.removed_data = True
        except FileNotFoundError:
            result.removed_data = True
        except Exception:
            # Plain language only in leftovers — these lines are
            # shown in the success dialog verbatim; raw exception
            # text never belongs there.
            result.leftovers.append(
                f"Your Argus data folder ({root}) could not be "
                "removed — a file in it may still be in use. You "
                "can delete that folder by hand once Argus is closed"
            )

    note("removing-program")
    canonical = canonical_exe_path()
    try:
        canonical.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        # Almost certainly because this very process is running
        # from it. Schedule the deletion for the next restart and
        # say so — never pretend the file is gone when it isn't.
        try:
            schedule_delete_on_reboot_fn(canonical)
            result.leftovers.append(
                f"{canonical} will be removed when this PC restarts"
            )
        except Exception:
            result.leftovers.append(
                f"{canonical} could not be removed. You can delete "
                "it by hand after restarting this PC"
            )
    # Clean up the install folders themselves when they are left
    # empty — first Argus's own folder, then the Sentinel
    # Safeguard parent (rmdir only succeeds on an empty folder,
    # so anything still shared is never touched).
    for folder in (canonical.parent, canonical.parent.parent):
        try:
            folder.rmdir()
        except OSError:
            pass
    return result


def _schedule_delete_on_reboot(path: Path) -> None:
    import ctypes

    MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
    moved = ctypes.windll.kernel32.MoveFileExW(  # type: ignore[attr-defined]
        str(path), None, MOVEFILE_DELAY_UNTIL_REBOOT
    )
    if not moved:
        raise OSError(f"MoveFileExW failed for {path}")
