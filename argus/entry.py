"""The one entry point of the packaged ARGUS.EXE.

A single executable is the whole product; how it was launched
decides what it does:

- ``--service`` in argv → Windows is starting the protection
  service: host it through the servicemanager dispatcher
  (:func:`argus.winservice.run_service_dispatcher`). The service
  registration's ImagePath carries this marker.
- ``--run-setup`` → the elevated setup helper: run the self-install
  engine with a small progress window, leave a result file for the
  GUI, exit.
- ``--uninstall`` → the uninstaller flow (self-elevates, plain
  confirm dialog, progress, done).
- ``--self-check`` → the release pipeline's smoke test: import
  every lazily-loaded module the packaged build needs (the pywin32
  service stack and PySide6 above all — the modules static
  analysis is most likely to have missed), print the version, and
  exit 0 without opening any window. A module that fails to
  import is named, and the exit code is nonzero.
- ``--self-check-qt`` → the pipeline's GUI smoke test: importing
  PySide6 is not proof the interface can start — its platform
  plugin loads only when a QApplication is created. This mode
  creates the application (offscreen), applies the theme, builds
  the real main window AND the onboarding wizard (the first-run
  path), closes them, and exits 0; any failure exits nonzero
  with a plain message. The pipeline runs it next to
  ``--self-check`` so a build whose GUI would die on launch fails
  in CI, not on a user's machine.
- ``scan`` (or ``--scan``) as the first word → a real headless
  scan through the same command-line engine ``python -m argus``
  uses (:func:`argus.cli.main` with the ``scan`` subcommand):
  the packaged executable can scan a file or folder from a
  terminal or a script and reports the scan's own exit code
  (0 clean, 1 detections, 2 error). Added in v1.2.7 — before
  that, the packaged executable had no scan entry point at all,
  so a frozen build could never demonstrate a scan of itself.
- a management word (``install`` / ``start`` / ``stop`` /
  ``status`` / ``register`` / …) → the service support commands.
  Plumbing for the GUI's own helpers and for support — never a
  user surface.
- anything else (including no arguments, and the GUI's ``--page``)
  → the graphical interface: what a person double-clicking the
  file gets.

Routing is pure and unit-tested; the heavy halves (Qt, pywin32)
are imported only on the branch that needs them.
"""

from __future__ import annotations

import importlib
import sys

from . import __version__
from .winservice import SERVICE_COMMANDS, SERVICE_EXE_ARGS

#: First words that mean "service support command, not the GUI".
_MANAGEMENT_WORDS = frozenset(SERVICE_COMMANDS) | {"service"}

#: The import census for ``--self-check``: every module the
#: packaged executable loads lazily at runtime. PyInstaller's
#: static analysis follows imports it can SEE; the service stack
#: and the Qt layer are imported inside functions by design, so
#: they are exactly what a build can silently ship without. The
#: release workflow runs the built exe with ``--self-check`` and
#: fails the release if any name here cannot be imported.
SELF_CHECK_MODULES = (
    # Windows service stack (argus.winservice / setup engine)
    "win32service",
    "win32serviceutil",
    "win32event",
    "servicemanager",
    "pywintypes",
    "pythoncom",
    "win32com",
    "win32com.client",
    # GUI stack
    "PySide6",
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    # Argus's own lazy halves
    "argus.winservice",
    "argus.winregister",
    "argus.setup_engine",
    "argus.service",
    "argus.pipe_channel",
    "argus.platform_authenticode",
    "argus.cli",
    "argus.gui.backend",
    "argus.gui.setup_app",
    "argus.gui.app",
    "argus.gui.onboarding",
)

#: The import census for the LINUX build (v1.2.0): the modules
#: the packaged Linux program loads lazily — the systemd service
#: host, the Unix-socket verified channel, the dpkg trust, the
#: inotify watcher — in place of the pywin32 stack, which does
#: not exist there. :func:`main` selects it on Linux; the Windows
#: census above stays the default everywhere (existing callers
#: and tests are untouched).
SELF_CHECK_MODULES_LINUX = (
    # GUI stack
    "PySide6",
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    # Argus's own lazy halves (Linux platform layer)
    "argus.linuxservice",
    "argus.socket_channel",
    "argus.platform_dpkg",
    "argus.inotify_watcher",
    "argus.setup_engine",
    "argus.service",
    "argus.pipe_channel",
    "argus.cli",
    "argus.gui.backend",
    "argus.gui.setup_app",
    "argus.gui.app",
    "argus.gui.onboarding",
)


def run_self_check(import_module=None, modules=None) -> int:
    """Import every module in the census (*modules*, default
    :data:`SELF_CHECK_MODULES` — the Windows census; the Linux
    build passes :data:`SELF_CHECK_MODULES_LINUX`).

    Prints the product version and the census result. Returns 0
    when everything imports; returns 1 and names each failing
    module (on stderr) otherwise. Opens no window and starts
    nothing — importing ``argus.gui.*`` modules does not create a
    QApplication; only running the GUI does that.
    """
    census = tuple(modules) if modules is not None else SELF_CHECK_MODULES
    importer = import_module or importlib.import_module
    failures: list[tuple[str, BaseException]] = []
    for name in census:
        try:
            importer(name)
        except BaseException as exc:  # named, counted — never hidden
            failures.append((name, exc))
    if failures:
        for name, exc in failures:
            print(
                f"argus self-check: FAILED to import {name}: {exc!r}",
                file=sys.stderr,
            )
        print(
            f"ARGUS.EXE {__version__} self-check FAILED: "
            f"{len(failures)} of {len(census)} modules "
            "could not be imported.",
            file=sys.stderr,
        )
        return 1
    print(
        f"ARGUS.EXE {__version__} self-check OK: "
        f"{len(census)} modules imported."
    )
    return 0


def _default_qt_app():
    """Build the real QApplication for the Qt self-check.

    The platform defaults to offscreen when the caller set none —
    the check must run headless in the release pipeline, and the
    offscreen plugin is exactly the plugin whose absence this
    check exists to catch. Reuses a live instance if one exists
    (the test suite's convention), so the check is safe to run
    inside a process that already hosts the application.
    """
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication(
        [sys.argv[0] or "Argus.exe"]
    )


def _default_qt_window(app):
    """Theme *app* and build the real main window on it.

    Mirrors :func:`argus.gui.app.run_gui` minus the event loop:
    theme, icon, backend, MainWindow with every page. The
    first-run path is part of the smoke (fix round 3): the
    onboarding wizard is CONSTRUCTED too (never exec'd — being
    built is what proves its module and widget tree survived
    packaging), so a build whose wizard broke fails here, not
    on a customer's first launch. If the packaged GUI would
    die on launch, it dies here — in CI.
    """
    from .gui import theme
    from .gui.backend import GuiBackend
    from .gui.main_window import MainWindow
    from .gui.onboarding import OnboardingWizard
    from .gui.widgets import make_app_icon

    theme.apply_theme(app)
    app.setWindowIcon(make_app_icon())
    backend = GuiBackend()
    window = MainWindow(backend)
    wizard = OnboardingWizard(backend)
    wizard.close()
    return window


def run_self_check_qt(app_factory=None, window_factory=None) -> int:
    """Prove the packaged GUI can actually start, not just import.

    Creates the QApplication (which is when Qt loads its platform
    plugin — the piece a frozen build can silently ship without),
    applies the theme, constructs the real main window and the
    onboarding wizard, shows and closes the window. Returns 0 on
    success; returns 1 with a plain message naming the stage
    that failed otherwise.

    *app_factory* / *window_factory* are the injectable seam the
    tests use; production passes neither and gets the real stack.
    """
    make_app = app_factory or _default_qt_app
    build_window = window_factory or _default_qt_window

    try:
        app = make_app()
    except BaseException as exc:  # named, staged — never hidden
        print(
            "argus Qt self-check: FAILED to create the Qt "
            f"application: {exc!r}",
            file=sys.stderr,
        )
        print(
            f"ARGUS.EXE {__version__} Qt self-check FAILED: the "
            "interface could not start (the Qt platform plugin may "
            "be missing from this build).",
            file=sys.stderr,
        )
        return 1

    try:
        window = build_window(app)
        window.show()
        if hasattr(app, "processEvents"):
            app.processEvents()
        window.close()
        if hasattr(app, "processEvents"):
            app.processEvents()
    except BaseException as exc:  # named, staged — never hidden
        print(
            "argus Qt self-check: FAILED to build or show the "
            f"main window: {exc!r}",
            file=sys.stderr,
        )
        print(
            f"ARGUS.EXE {__version__} Qt self-check FAILED: the "
            "application started but its main window could not be "
            "built.",
            file=sys.stderr,
        )
        return 1

    print(
        f"ARGUS.EXE {__version__} Qt self-check OK: application "
        "created, theme applied, main window and onboarding "
        "wizard built and closed."
    )
    return 0


def route_invocation(argv: list[str]) -> str:
    """Classify one launch. *argv* excludes the program name.

    Returns one of: ``"service"`` (host for the SCM), ``"setup"``,
    ``"uninstall"``, ``"manage"`` (support commands),
    ``"self-check"``, ``"self-check-qt"``, ``"scan"`` (headless
    scan through the CLI engine), ``"gui"``.
    """
    args = [str(a) for a in argv]
    if SERVICE_EXE_ARGS in args:
        return "service"
    if "--run-setup" in args:
        return "setup"
    if "--uninstall" in args:
        return "uninstall"
    if "--self-check-qt" in args:
        return "self-check-qt"
    if "--self-check" in args:
        return "self-check"
    if args and args[0].lower() in ("scan", "--scan"):
        return "scan"
    if args and args[0].lower() in _MANAGEMENT_WORDS:
        return "manage"
    return "gui"


def _attach_parent_console() -> None:
    """Give a frozen Windows scan a real console to print to.

    The Windows build is a windowed (no-console) executable, so a
    scan launched from a terminal would otherwise have nowhere
    for its results to go — the exit code would arrive but the
    report would not. When this process is frozen on Windows and
    has no usable standard streams, attach to the parent process's
    console and reopen stdout/stderr onto it. Everywhere else
    (source runs, the Linux build — which is a console build —
    and any process that already has streams) this is a no-op.
    Best-effort: a failure leaves the streams as they are and the
    scan still runs and still returns its exit code.
    """
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    if sys.stdout is not None and sys.stderr is not None:
        return
    try:
        import ctypes
        import io

        # ATTACH_PARENT_PROCESS = -1
        ctypes.windll.kernel32.AttachConsole(-1)
        if sys.stdout is None:
            sys.stdout = io.TextIOWrapper(
                open("CONOUT$", "wb"), encoding="utf-8", errors="replace"
            )
        if sys.stderr is None:
            sys.stderr = io.TextIOWrapper(
                open("CONOUT$", "wb"), encoding="utf-8", errors="replace"
            )
    except Exception:
        pass


def run_scan(args: list[str]) -> int:
    """Run one headless scan through the real CLI engine.

    *args* are the words after ``scan``/``--scan`` — a target path
    plus any of the scan subcommand's own options (``--json``,
    ``--db``, ``--quarantine``, …). This is the identical code
    path ``python -m argus scan`` runs: same engine, same exit
    codes (0 clean, 1 detections found, 2 error).
    """
    _attach_parent_console()
    from .cli import main as cli_main

    return cli_main(["scan", *args])


def main(argv: list[str] | None = None) -> int:
    """Dispatch one launch of the packaged executable."""
    args = list(sys.argv[1:] if argv is None else argv)
    route = route_invocation(args)

    if route == "service":
        if sys.platform.startswith("linux"):
            # systemd is starting the protection service: host it
            # in the foreground (argus.linuxservice.run_daemon).
            from .linuxservice import ServiceUnavailable, run_daemon

            try:
                return run_daemon()
            except ServiceUnavailable as exc:
                print(f"argus service: {exc}")
                return 2
        from .winservice import ServiceUnavailable, run_service_dispatcher

        try:
            return run_service_dispatcher()
        except ServiceUnavailable as exc:
            print(f"argus service: {exc}")
            return 2

    if route == "setup":
        from .gui.setup_app import run_setup

        return run_setup()

    if route == "uninstall":
        from .gui.setup_app import run_uninstall

        return run_uninstall()

    if route == "self-check-qt":
        return run_self_check_qt()

    if route == "self-check":
        if sys.platform.startswith("linux") and getattr(
            sys, "frozen", False
        ):
            # The packaged Linux build (PyInstaller-frozen): its
            # census is the Linux module set — the pywin32 names
            # in the default census do not exist there. A source
            # run keeps the historical default census on every
            # platform (that is the seam the test suite pins).
            return run_self_check(modules=SELF_CHECK_MODULES_LINUX)
        return run_self_check()

    if route == "scan":
        return run_scan(args[1:])

    if route == "manage":
        words = args[1:] if args and args[0].lower() == "service" else args
        if sys.platform.startswith("linux"):
            from .linuxservice import main as service_main

            return service_main(words)
        from .winservice import main as service_main

        return service_main(words)

    from . import gui

    return gui.main([sys.argv[0], *args])


if __name__ == "__main__":
    raise SystemExit(main())
