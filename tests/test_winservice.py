"""Tests for the Phase 5 Windows service layer (argus.winservice).

Covers the pure logic — command routing, the platform guard, status
reporting from a heartbeat file, and delegation to the pywin32
handler — with fakes, on any platform. The pywin32 class itself only
exists on Windows with pywin32 installed and is not exercised here.
"""

import json
import sys

import pytest

from argus import winservice
from argus.winservice import (
    SERVICE_NAME,
    ServiceUnavailable,
    main,
    perform_service_command,
    route_service_command,
)


# ----------------------------------------------------------------------
# Routing
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "words,expected",
    [
        (["install"], "install"),
        (["uninstall"], "uninstall"),
        (["remove"], "uninstall"),  # pywin32 spelling, accepted
        (["start"], "start"),
        (["STOP"], "stop"),  # case-insensitive
        (["restart"], "restart"),
        (["status"], "status"),
        (["run"], "run"),
        (["register"], "register"),
        (["unregister"], "unregister"),
    ],
)
def test_route_commands(words, expected):
    assert route_service_command(words) == expected


def test_route_rejects_unknown():
    with pytest.raises(ValueError) as excinfo:
        route_service_command(["frobnicate"])
    assert "argus service" in str(excinfo.value)


def test_route_rejects_empty():
    with pytest.raises(ValueError):
        route_service_command([])


def test_service_identity():
    assert SERVICE_NAME == "ArgusProtection"
    assert "ARGUS" in winservice.SERVICE_DISPLAY_NAME


# ----------------------------------------------------------------------
# Platform guard
# ----------------------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="guard test is for non-Windows")
def test_management_commands_refuse_off_windows():
    for command in (
        "install", "start", "stop", "uninstall", "run",
        "register", "unregister",
    ):
        with pytest.raises(ServiceUnavailable):
            perform_service_command(command)


def test_require_windows_message_is_plain_language():
    if sys.platform == "win32":
        pytest.skip("guard passes on Windows")
    with pytest.raises(ServiceUnavailable) as excinfo:
        winservice.require_windows("Testing")
    assert "Windows" in str(excinfo.value)


# ----------------------------------------------------------------------
# Status reporting (works everywhere, reads the heartbeat file)
# ----------------------------------------------------------------------
def test_status_command_reads_heartbeat(tmp_path, capsys, monkeypatch):
    status_file = tmp_path / "argus-status.json"
    # The status command now applies the freshness gate (P2): a
    # "running" claim needs a FRESH heartbeat when the SCM cannot
    # be asked — real services always write heartbeat_at.
    from datetime import datetime, timezone

    status_file.write_text(
        json.dumps(
            {
                "state": "running",
                "running": True,
                "version": "1.0.0",
                "started_at": "2026-01-01T00:00:00+00:00",
                "heartbeat_at": datetime.now(timezone.utc).isoformat(),
                "scans_completed": 42,
                "detections": 3,
            }
        )
    )
    config_path = tmp_path / "cfg.json"
    config_path.write_text(json.dumps({"status_file": str(status_file)}))
    code = perform_service_command("status", config_path=config_path)
    out = capsys.readouterr().out
    assert code == 0
    assert "running" in out
    assert "42" in out


def test_status_command_without_heartbeat(tmp_path, capsys):
    config_path = tmp_path / "cfg.json"
    config_path.write_text(
        json.dumps({"status_file": str(tmp_path / "missing.json")})
    )
    code = perform_service_command("status", config_path=config_path)
    assert code == 1
    assert "not" in capsys.readouterr().out.lower()


# ----------------------------------------------------------------------
# Delegation to the pywin32 handler (faked)
# ----------------------------------------------------------------------
def test_perform_delegates_with_mapped_command(monkeypatch):
    calls = []

    def fake_handler(service_class, *, argv):
        calls.append((service_class, argv))
        raise SystemExit(0)

    monkeypatch.setattr(winservice.sys, "platform", "win32")
    monkeypatch.setattr(winservice, "HAS_PYWIN32", True)
    monkeypatch.setattr(
        winservice, "ArgusWindowsService", type("FakeSvc", (), {})
    )

    code = perform_service_command("uninstall", handler=fake_handler)
    assert code == 0
    _, argv = calls[0]
    assert argv[-1] == "remove"  # uninstall maps to pywin32's "remove"


@pytest.mark.parametrize("command,word", [("start", "start"), ("stop", "stop")])
def test_start_stop_argv_carry_no_stray_args(monkeypatch, command, word):
    """start/stop reach the handler as exactly [exe, word] — no
    extra arguments pywin32's parser could trip over."""
    calls = []

    def fake_handler(service_class, *, argv):
        calls.append(argv)
        raise SystemExit(0)

    monkeypatch.setattr(winservice.sys, "platform", "win32")
    monkeypatch.setattr(winservice, "HAS_PYWIN32", True)
    monkeypatch.setattr(
        winservice, "ArgusWindowsService", type("FakeSvc", (), {})
    )
    assert perform_service_command(command, handler=fake_handler) == 0
    (argv,) = calls
    assert argv[1:] == [word]


def test_install_argv_options_before_command_word(monkeypatch):
    """REGRESSION (v1.0.5 silent no-install): pywin32's
    HandleCommandLine parses with POSIX getopt, which stops at the
    first non-option. The install argv was [exe, "install",
    "--startup", "auto"] — the options were never parsed, the
    arity check failed, usage printed, NOTHING was installed.
    The options must come BEFORE the command word."""
    calls = []

    def fake_handler(service_class, *, argv):
        calls.append(argv)
        raise SystemExit(0)

    monkeypatch.setattr(winservice.sys, "platform", "win32")
    monkeypatch.setattr(winservice, "HAS_PYWIN32", True)
    monkeypatch.setattr(
        winservice, "ArgusWindowsService", type("FakeSvc", (), {})
    )
    assert perform_service_command("install", handler=fake_handler) == 0
    (argv,) = calls
    assert argv[1:] == ["--startup", "auto", "install"]


def test_run_uses_servicemanager_dispatcher_never_handler(monkeypatch):
    """REGRESSION (v1.0.5 service could never start): the SCM
    launch was routed to HandleCommandLine as "run" — a command
    pywin32 does not have, in a handler that contains no
    StartServiceCtrlDispatcher call. Hosting must go through the
    servicemanager dispatcher seam, and the command handler must
    not be touched at all."""
    def bomb_handler(service_class, *, argv):  # pragma: no cover
        raise AssertionError("HandleCommandLine must not host the service")

    hosted = []

    def fake_dispatcher():
        hosted.append(True)
        return 0

    monkeypatch.setattr(winservice.sys, "platform", "win32")
    code = perform_service_command(
        "run", handler=bomb_handler, dispatcher=fake_dispatcher
    )
    assert code == 0
    assert hosted == [True]


def test_run_service_dispatcher_calls_servicemanager_in_order(monkeypatch):
    """The hosting sequence itself: Initialize →
    PrepareToHostSingle(cls) → StartServiceCtrlDispatcher."""
    import types

    calls = []
    fake_sm = types.ModuleType("servicemanager")
    fake_sm.Initialize = lambda: calls.append("Initialize")
    fake_sm.PrepareToHostSingle = lambda cls: calls.append(
        ("PrepareToHostSingle", cls)
    )
    fake_sm.StartServiceCtrlDispatcher = lambda: calls.append(
        "StartServiceCtrlDispatcher"
    )
    monkeypatch.setitem(sys.modules, "servicemanager", fake_sm)
    monkeypatch.setattr(winservice.sys, "platform", "win32")
    monkeypatch.setattr(winservice, "HAS_PYWIN32", True)
    sentinel_class = type("FakeSvc", (), {})
    monkeypatch.setattr(winservice, "ArgusWindowsService", sentinel_class)

    assert winservice.run_service_dispatcher() == 0
    assert calls == [
        "Initialize",
        ("PrepareToHostSingle", sentinel_class),
        "StartServiceCtrlDispatcher",
    ]


def test_service_image_path_carries_service_marker():
    """The registered ImagePath must launch the one exe WITH the
    --service marker, or Windows would open the GUI at boot
    instead of hosting protection."""
    image = winservice.service_image_path(
        r"C:\Program Files\Sentinel Safeguard\Argus\Argus.exe"
    )
    assert image == (
        r'"C:\Program Files\Sentinel Safeguard\Argus\Argus.exe" --service'
    )
    assert winservice.SERVICE_EXE_ARGS == "--service"


def test_detailed_state_distinguishes_not_installed(monkeypatch):
    """Error 1060 from the SCM means NOT INSTALLED — setup's
    difference between "set up" and "turn on". Other failures and
    other platforms stay honestly "unknown"."""
    class FakeScmError(Exception):
        def __init__(self, winerror):
            super().__init__("scm error")
            self.winerror = winerror

    monkeypatch.setattr(winservice.sys, "platform", "win32")

    def missing(name):
        raise FakeScmError(1060)

    monkeypatch.setattr(winservice, "_query_service_status", missing)
    assert winservice.query_service_state_detailed() == "not-installed"

    def other_failure(name):
        raise FakeScmError(5)

    monkeypatch.setattr(winservice, "_query_service_status", other_failure)
    assert winservice.query_service_state_detailed() == "unknown"

    def running(name):
        return (0, 4, 0, 0, 0, 0, 0)  # dwCurrentState = SERVICE_RUNNING

    monkeypatch.setattr(winservice, "_query_service_status", running)
    assert winservice.query_service_state_detailed() == "running"
    assert winservice.query_service_state() == "running"


def test_register_command_uses_service_paths(monkeypatch, capsys):
    from argus import winregister

    seen = {}

    def fake_register(properties, **kwargs):
        seen.update(properties)
        return properties

    monkeypatch.setattr(winservice.sys, "platform", "win32")
    monkeypatch.setattr(winregister, "register_antivirus", fake_register)
    from pathlib import Path, PureWindowsPath

    monkeypatch.setattr(
        winservice, "service_exe_path",
        lambda: PureWindowsPath(
            r"C:\Program Files\Sentinel Safeguard\Argus\Argus.exe"
        ),
    )
    # The register command verifies the product exe exists (fix
    # #27) before registering: on this (non-Windows) test host the
    # C:\ path cannot really exist, so existence of exactly that
    # file is faked — the refusal half is covered by the next test.
    real_exists = Path.exists
    monkeypatch.setattr(
        Path, "exists",
        lambda self: str(self).endswith("Argus.exe") or real_exists(self),
    )
    code = perform_service_command("register")
    assert code == 0
    # One executable (v1.1.0): product and reporter are the same file.
    assert seen["pathToSignedReportingExe"].endswith("Argus.exe")
    assert seen["pathToSignedProductExe"].endswith("Argus.exe")
    assert seen["instanceGuid"] == winregister.INSTANCE_GUID
    assert "Security Center" in capsys.readouterr().out


def test_register_command_refuses_missing_product_exe(monkeypatch, capsys):
    # Regression (fix #27): never tell Windows Security that a
    # program which is not on disk is the machine's antivirus.
    from argus import winregister

    called = []
    monkeypatch.setattr(winservice.sys, "platform", "win32")
    monkeypatch.setattr(
        winregister, "register_antivirus",
        lambda properties, **kw: called.append(properties),
    )
    from pathlib import Path, PureWindowsPath

    monkeypatch.setattr(
        winservice, "service_exe_path",
        lambda: PureWindowsPath(
            r"C:\Program Files\Sentinel Safeguard\Argus\Argus.exe"
        ),
    )
    monkeypatch.setattr(Path, "exists", lambda self: False)
    code = perform_service_command("register")
    assert code == 1
    assert called == []  # Security Center was never touched
    assert "not found" in capsys.readouterr().out


def test_main_routes_and_reports(monkeypatch, capsys):
    if sys.platform == "win32":
        pytest.skip("expects the non-Windows refusal path")
    assert main(["bogus"]) == 2
    assert main(["install"]) == 2  # refused off Windows, with a message
    out = capsys.readouterr().out
    assert "argus service" in out
