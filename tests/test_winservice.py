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
    status_file.write_text(
        json.dumps(
            {
                "state": "running",
                "running": True,
                "version": "1.0.0",
                "started_at": "2026-01-01T00:00:00+00:00",
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

    calls.clear()
    perform_service_command("run", handler=fake_handler)
    _, argv = calls[0]
    assert len(argv) == 1  # SCM launch: bare argv, no command word


def test_register_command_uses_service_paths(monkeypatch, capsys):
    from argus import winregister

    seen = {}

    def fake_register(properties, **kwargs):
        seen.update(properties)
        return properties

    monkeypatch.setattr(winservice.sys, "platform", "win32")
    monkeypatch.setattr(winregister, "register_antivirus", fake_register)
    from pathlib import PureWindowsPath

    monkeypatch.setattr(
        winservice, "service_exe_path",
        lambda: PureWindowsPath(
            r"C:\Program Files\Sentinel Safeguard\Argus\ArgusService.exe"
        ),
    )
    code = perform_service_command("register")
    assert code == 0
    assert seen["pathToSignedReportingExe"].endswith("ArgusService.exe")
    assert seen["pathToSignedProductExe"].endswith("Argus.exe")
    assert seen["instanceGuid"] == winregister.INSTANCE_GUID
    assert "Security Center" in capsys.readouterr().out


def test_main_routes_and_reports(monkeypatch, capsys):
    if sys.platform == "win32":
        pytest.skip("expects the non-Windows refusal path")
    assert main(["bogus"]) == 2
    assert main(["install"]) == 2  # refused off Windows, with a message
    out = capsys.readouterr().out
    assert "argus service" in out
