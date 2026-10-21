"""Tests for the packaged executable's headless scan route (v1.2.7).

Before v1.2.7 the packaged Argus.exe exposed no scan entry point:
``argus.entry.route_invocation`` sent a ``scan`` launch to the GUI,
so a frozen build could never demonstrate a scan. The route now
hands the launch to the REAL CLI engine (``argus.cli.main`` with
the ``scan`` subcommand) — same engine, same exit codes.
"""

import pytest

from argus import entry
from argus.cli import EXIT_CLEAN, EXIT_DETECTIONS
from argus.entry import main, route_invocation

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "C:\\somewhere"],
        ["--scan", "C:\\somewhere"],
        ["SCAN", "C:\\somewhere"],
        ["scan"],
    ],
)
def test_scan_routes_to_scan(argv):
    assert route_invocation(argv) == "scan"


@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], "gui"),
        (["--page", "scan"], "gui"),  # the GUI's own page option is not a scan launch
        (["--service", "scan"], "service"),  # the SCM marker still wins
        (["install"], "manage"),
        (["--self-check"], "self-check"),
    ],
)
def test_scan_route_does_not_steal_other_launches(argv, expected):
    assert route_invocation(argv) == expected


def test_scan_dispatch_passes_words_and_returns_exit_code(monkeypatch):
    seen = {}

    def fake_cli_main(argv):
        seen["argv"] = argv
        return 1

    monkeypatch.setattr("argus.cli.main", fake_cli_main)
    assert main(["scan", "target", "--json"]) == 1
    assert seen["argv"] == ["scan", "target", "--json"]
    assert main(["--scan", "target"]) == 1
    assert seen["argv"] == ["scan", "target"]


def test_scan_route_runs_the_real_engine(tmp_path, monkeypatch, capsys):
    """End-to-end through entry.main: a clean file scans clean and
    an EICAR control is flagged — the packaged route is the real
    engine, not a stub."""
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "readme.txt").write_text("perfectly ordinary document")

    assert main(["scan", str(tree)]) == EXIT_CLEAN
    assert "Detections: none" in capsys.readouterr().out

    (tree / "eicar.com").write_bytes(EICAR)
    assert main(["scan", str(tree)]) == EXIT_DETECTIONS
    out = capsys.readouterr().out
    assert "EICAR-Test-File" in out
    assert "MALICIOUS" in out


def test_attach_parent_console_is_noop_off_windows_frozen():
    # On this platform (and in every source run) the helper must
    # never touch the streams.
    entry._attach_parent_console()
