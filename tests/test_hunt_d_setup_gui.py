"""Hunt fix-pass tests — Package D (setup / CLI / GUI / CI / docs).

Named for the findings they pin. Pure-logic tests (setup state
machine with stubbed seams, CLI resolver + loose-pending source,
self-check census with an import fake, configured-status
verification) run on any Python; the Qt tests skip cleanly when
PySide6 is absent and run offscreen in the GUI venv.

The CROSS-PACKAGE FOLLOW-UP block at the end pins the vault/service
package's interface changes in Package D's files: the devtools
settings' new shared default, the service-published pending view,
the bench's exclusion parity, and the scan page's real-fingerprint
quarantine rule.
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from argus import cli, setup_engine
from argus.setup_engine import SetupState


# ----------------------------------------------------------------------
# P1-5 — sc.exe failure tokens are separate argv items
# ----------------------------------------------------------------------
class _TickingClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 1.0
        return self.now


class _FakeMachine:
    def __init__(self, tmp_path, *, scm_states=("not-installed",)):
        self.calls = []
        self.scm_states = list(scm_states)
        self.data_root = tmp_path / "ProgramData" / "Argus"
        self.heartbeat = {
            "running": True,
            "state": "running",
            "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        }

    def scm_state(self):
        if len(self.scm_states) > 1:
            return self.scm_states.pop(0)
        return self.scm_states[0]

    def run_command(self, argv):
        self.calls.append(("run", list(argv)))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def kwargs(self, **extra):
        base = dict(
            run_command=self.run_command,
            install_service_fn=lambda exe: self.calls.append("install_service"),
            remove_service_fn=lambda: self.calls.append("remove_service"),
            stop_service_fn=lambda: self.calls.append("stop_service"),
            register_av_fn=lambda exe: self.calls.append("register_av"),
            write_uninstall_entry_fn=lambda exe: self.calls.append("arp"),
            start_service_fn=lambda: self.calls.append("start_service"),
            scm_state_fn=self.scm_state,
            read_heartbeat_fn=lambda: self.heartbeat,
            data_root=self.data_root,
            sleep=lambda _s: None,
            monotonic=_TickingClock(),
            verify_timeout=5.0,
            create_shortcuts_fn=lambda exe: self.calls.append("shortcuts"),
        )
        base.update(extra)
        return base


@pytest.fixture(autouse=True)
def _windows(monkeypatch):
    monkeypatch.setattr(setup_engine, "IS_WINDOWS", True)


@pytest.fixture()
def canonical(tmp_path, monkeypatch):
    program_files = tmp_path / "Program Files"
    monkeypatch.setenv("ProgramFiles", str(program_files))
    return program_files / "Sentinel Safeguard" / "Argus" / "Argus.exe"


def test_hunt_p1_5_sc_failure_tokens_are_split(tmp_path, canonical):
    machine = _FakeMachine(
        tmp_path, scm_states=("not-installed", "stopped", "running")
    )
    setup_engine.install(**machine.kwargs())
    runs = [c[1] for c in machine.calls if isinstance(c, tuple)]
    recovery = next(a for a in runs if a[0] == "sc.exe")
    # Each `name=` and its value are SEPARATE argv tokens — no
    # token may carry an embedded space (the old form handed
    # sc.exe "reset= 86400" as one string and the policy silently
    # never applied).
    assert "reset=" in recovery and "86400" in recovery
    assert "actions=" in recovery
    assert "restart/60000/restart/60000/restart/60000" in recovery
    assert all(" " not in token for token in recovery)


# ----------------------------------------------------------------------
# P1-6 — partial installs: INSTALLED_INCOMPLETE + resumable install
# ----------------------------------------------------------------------
def test_hunt_p1_6_detect_state_installed_incomplete():
    assert (
        setup_engine.detect_state(
            scm_state="stopped", portable=False,
            av_registered=False, arp_present=True,
        )
        is SetupState.INSTALLED_INCOMPLETE
    )
    assert (
        setup_engine.detect_state(
            scm_state="running", portable=False,
            av_registered=True, arp_present=False,
        )
        is SetupState.INSTALLED_INCOMPLETE
    )
    # Complete registration keeps the classic states.
    assert (
        setup_engine.detect_state(
            scm_state="stopped", portable=False,
            av_registered=True, arp_present=True,
        )
        is SetupState.INSTALLED_STOPPED
    )
    assert (
        setup_engine.detect_state(
            scm_state="running", portable=False,
            av_registered=True, arp_present=True,
        )
        is SetupState.RUNNING
    )


def test_hunt_p1_6_install_skips_steps_already_in_place(tmp_path, canonical):
    """A heal run over a partial install: the AV registration and
    ARP entry already exist, the service registration is already
    canonical — none of those steps redo their work."""
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(b"already-home")
    machine = _FakeMachine(
        tmp_path, scm_states=("stopped", "stopped", "running")
    )
    result = setup_engine.install(
        source_exe=canonical,
        av_registered_fn=lambda: True,
        arp_present_fn=lambda: True,
        service_image_ok_fn=lambda exe: True,
        copy_file=lambda s, d: pytest.fail("copy must be skipped"),
        **machine.kwargs(),
    )
    assert result.state is SetupState.RUNNING
    assert "register_av" not in machine.calls
    assert "arp" not in machine.calls
    assert "install_service" not in machine.calls
    assert "remove_service" not in machine.calls
    # …but the service was stopped (unlock) and started again.
    assert "stop_service" in machine.calls
    assert "start_service" in machine.calls


def test_hunt_p1_7_old_service_removed_before_copy(tmp_path, canonical):
    """P1-7: with a WRONG old registration, stop+remove happen
    before the self-placement copy (a running old service locks
    the exe)."""
    source = tmp_path / "Downloads" / "Argus.exe"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"new-exe")
    machine = _FakeMachine(
        tmp_path, scm_states=("running", "stopped", "running")
    )
    copied = []

    def copy_file(src, dst):
        copied.append((Path(src), Path(dst)))
        machine.calls.append("copy")
        Path(dst).parent.mkdir(parents=True, exist_ok=True)
        Path(dst).write_bytes(Path(src).read_bytes())

    setup_engine.install(
        source_exe=source, copy_file=copy_file,
        service_image_ok_fn=lambda exe: False,
        **machine.kwargs(),
    )
    assert machine.calls.index("remove_service") < machine.calls.index("copy")
    assert machine.calls.index("copy") < machine.calls.index("install_service")


def test_hunt_p1_7_copy_failure_names_cause_class(tmp_path, canonical):
    source = tmp_path / "Downloads" / "Argus.exe"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"new-exe")
    machine = _FakeMachine(
        tmp_path, scm_states=("not-installed", "running")
    )

    def locked_copy(src, dst):
        raise PermissionError(13, "Access is denied")

    with pytest.raises(setup_engine.SetupError) as excinfo:
        setup_engine.install(
            source_exe=source, copy_file=locked_copy, **machine.kwargs()
        )
    message = excinfo.value.user_message.lower()
    assert "denied" in message or "in use" in message
    assert "disk space" not in message  # not the old generic line

    def missing_copy(src, dst):
        raise FileNotFoundError(2, "No such file")

    with pytest.raises(setup_engine.SetupError) as excinfo:
        setup_engine.install(
            source_exe=source, copy_file=missing_copy, **machine.kwargs()
        )
    assert "could not be found" in excinfo.value.user_message.lower()


# ----------------------------------------------------------------------
# P0-1 — channel ACLs: requests write-only, results read-only
# ----------------------------------------------------------------------
def test_hunt_p0_1_channel_acl_commands(tmp_path, canonical):
    machine = _FakeMachine(
        tmp_path, scm_states=("not-installed", "stopped", "running")
    )
    setup_engine.install(**machine.kwargs())
    runs = [c[1] for c in machine.calls if isinstance(c, tuple)]
    icacls = [a for a in runs if a[0] == "icacls.exe"]
    by_target = {a[1]: a for a in icacls}

    requests_acl = next(
        a for a in icacls if a[1].endswith(os.sep + "requests")
    )
    assert "/inheritance:r" in requests_acl
    users_grant = next(t for t in requests_acl if t.startswith("Users:"))
    assert "WD" in users_grant and "AD" in users_grant
    assert "RD" not in users_grant and "RX" not in users_grant
    assert "M" not in users_grant and "F" not in users_grant
    assert any(t.startswith("SYSTEM:") and "F" in t for t in requests_acl)

    results_acl = next(a for a in icacls if a[1].endswith(os.sep + "results"))
    assert "/inheritance:r" in results_acl
    users_grant = next(t for t in results_acl if t.startswith("Users:"))
    assert "RX" in users_grant and "M" not in users_grant

    # Root + shared break inheritance too (the fixed-ACL-set design).
    root_acl = by_target[str(machine.data_root)]
    shared_acl = next(
        a for a in icacls if a[1].endswith(os.sep + "shared")
    )
    assert "/inheritance:r" in root_acl
    assert "/inheritance:r" in shared_acl


# ----------------------------------------------------------------------
# P1-26 — entry self-check census (import-mock)
# ----------------------------------------------------------------------
def test_hunt_p1_26_self_check_census_and_failure_naming(capsys):
    from argus.entry import SELF_CHECK_MODULES, route_invocation, run_self_check

    assert route_invocation(["--self-check"]) == "self-check"
    for name in (
        "win32service", "win32serviceutil", "servicemanager",
        "pywintypes", "pythoncom", "PySide6",
    ):
        assert name in SELF_CHECK_MODULES

    imported = []
    assert run_self_check(
        import_module=lambda name: imported.append(name)
    ) == 0
    assert imported == list(SELF_CHECK_MODULES)
    out = capsys.readouterr().out
    assert "1.1.0" in out and "self-check OK" in out

    def failing(name):
        if name == "win32service":
            raise ImportError("No module named 'win32service'")
        return None

    assert run_self_check(import_module=failing) == 1
    err = capsys.readouterr().err
    assert "win32service" in err  # the failing module is NAMED


# ----------------------------------------------------------------------
# P1-15 — CLI config resolver: one resolver, no CWD defaults
# ----------------------------------------------------------------------
def test_hunt_p1_15_cli_resolver_defaults_to_machine_config(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    args = SimpleNamespace(config=None)
    assert cli.resolve_config_path(args) == (
        tmp_path / "argus-config.json"
    )
    explicit = SimpleNamespace(config="elsewhere.json")
    assert cli.resolve_config_path(explicit) == Path("elsewhere.json")


def test_hunt_p1_15_cli_parser_has_no_cwd_relative_defaults():
    parser = cli.build_parser()
    # Walk every subparser's defaults: no action may default to a
    # bare filename (the old watch/watch-status/quarantine-allow
    # CWD-relative defaults).
    bare = {"argus-config.json", "argus-status.json", "signatures.sigdb"}

    def walk(p):
        for action in p._actions:
            if isinstance(action.default, str):
                assert action.default not in bare, (
                    f"{action.dest} defaults to bare {action.default!r}"
                )
            if hasattr(action, "choices") and isinstance(
                action.choices, dict
            ):
                for sub in action.choices.values():
                    walk(sub)

    walk(parser)


def test_hunt_p2_cli_watch_status_scm_gates(tmp_path, monkeypatch, capsys):
    """watch-status: SCM stopped + stale heartbeat says NOT
    RUNNING; SCM running stays RUNNING with a stale heartbeat."""
    from argus import winservice

    status_path = tmp_path / "status.json"
    stale = {
        "running": True,
        "state": "running",
        "heartbeat_at": "2020-01-01T00:00:00+00:00",
        "watch_dirs": [],
    }
    status_path.write_text(json.dumps(stale))
    args = SimpleNamespace(
        config=None, status_file=str(status_path), json=False
    )
    monkeypatch.setattr(winservice, "query_service_state", lambda: "stopped")
    assert cli._cmd_watch_status(args) == cli.EXIT_ERROR
    assert "NOT RUNNING" in capsys.readouterr().out

    monkeypatch.setattr(winservice, "query_service_state", lambda: "running")
    assert cli._cmd_watch_status(args) == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "RUNNING" in out and "stale" in out


# ----------------------------------------------------------------------
# Item 12 confirmation — setup verifies the CONFIGURED status file
# ----------------------------------------------------------------------
def test_hunt_p2_setup_verification_uses_configured_status_file(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    custom_status = tmp_path / "elsewhere" / "my-status.json"
    (root / "argus-config.json").write_text(
        json.dumps({"status_file": str(custom_status)})
    )
    assert setup_engine._configured_status_path(root) == custom_status
    custom_status.parent.mkdir(parents=True)
    custom_status.write_text(json.dumps({"running": True}))
    assert setup_engine._read_configured_heartbeat(root) == {"running": True}


# ======================================================================
# Qt-dependent tests (skip without PySide6; run in the GUI venv)
# ======================================================================
try:
    from PySide6.QtWidgets import QApplication  # noqa: E402

    HAS_QT = True
except ImportError:  # pragma: no cover - system python has no Qt
    HAS_QT = False

requires_qt = pytest.mark.skipif(
    not HAS_QT, reason="PySide6 not installed — GUI tests skip"
)


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture()
def backend(tmp_path, monkeypatch):
    data_root = tmp_path / "argus-data"
    data_root.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    from argus.gui.backend import GuiBackend
    from argus.signatures import init_db

    config_path = tmp_path / "argus-config.json"
    db_path = tmp_path / "signatures.sigdb"
    init_db(db_path, seed=True)
    gui_backend = GuiBackend(
        config_path=config_path,
        devtools_path=tmp_path / "devtools.json",
    )
    gui_backend.config.signature_db = str(db_path)
    gui_backend.config.watch_dirs = [str(tmp_path)]
    gui_backend.config.vault_dir = str(tmp_path / "vault")
    gui_backend.config.history_db = str(tmp_path / "history.db")
    gui_backend.config.status_file = str(tmp_path / "status.json")
    gui_backend.save_config()
    yield gui_backend
    gui_backend.close()


# ----------------------------------------------------------------------
# FOLLOW-UP 2a — the GUI devtools default IS the engine's default
# ----------------------------------------------------------------------
@requires_qt
def test_hunt_followup_backend_devtools_default_is_shared_default(
    qapp, tmp_path, monkeypatch
):
    data_root = tmp_path / "argus-data"
    data_root.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    from argus import devtools
    from argus.gui.backend import GuiBackend

    gui_backend = GuiBackend(config_path=tmp_path / "cfg.json")
    try:
        assert gui_backend.devtools_path == devtools.default_devtools_path()
        assert gui_backend.devtools_path == (
            data_root / "shared" / "argus-devtools.json"
        )
        # The GUI toggle and the ActionEngine's act-time check read
        # the same persisted file: flipping the backend's settings
        # and saving moves simulation_mode_enabled() with it.
        assert devtools.simulation_mode_enabled() is False
        gui_backend.dev.simulation_mode = True
        gui_backend.save_dev()
        assert devtools.simulation_mode_enabled() is True
    finally:
        gui_backend.close()


# ----------------------------------------------------------------------
# FOLLOW-UP 2b — GUI pending display comes from the pending VIEW in
# the installed layout; the CLI loose read falls back the same way
# ----------------------------------------------------------------------
def _pending_view_rows(tmp_path):
    return [
        {
            "id": "pend-1",
            "created_at": "2026-10-19T00:00:00+00:00",
            "decided_at": None,
            "source": "realtime",
            "path": str(tmp_path / "evil.exe"),
            "sha256": "a" * 64,
            "action": "quarantine",
            "severity": "high",
            "verdict": "Malicious",
            "detection_name": "Test.Detection",
            "reasons": ["looked bad"],
            "status": "pending",
            "entry_id": None,
            "error": None,
        }
    ]


def _write_pending_view(base: Path, rows) -> Path:
    view = base / "shared" / "pending-view.json"
    view.parent.mkdir(parents=True, exist_ok=True)
    view.write_text(
        json.dumps({"generated_at": "now", "pending": rows})
    )
    return view


@requires_qt
def test_hunt_followup_backend_pending_loose_reads_view(
    qapp, backend, tmp_path, monkeypatch
):
    data_root = Path(os.environ["ARGUS_DATA_DIR"])
    _write_pending_view(data_root, _pending_view_rows(tmp_path))
    rows = backend.pending_actions_loose()
    assert [r.id for r in rows] == ["pend-1"]
    # Installed layout (this process does not own the store):
    # display comes from the view and decisions route via service.
    monkeypatch.setattr(backend, "owns_pending_store", lambda: False)
    display, via_service = backend.pending_display()
    assert via_service is True
    assert [r.id for r in display] == ["pend-1"]


def test_hunt_followup_cli_pending_loose_view_fallback(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "data"
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    _write_pending_view(data_root, _pending_view_rows(tmp_path))
    # The trusted DB path does not exist/readable here → the view
    # is the source.
    args = SimpleNamespace(config=None)
    config = cli.load_config(args)
    rows = cli._read_pending_loose(args, config)
    assert [r.id for r in rows] == ["pend-1"]

    # Direct route still works when the DB itself is readable
    # (elevated / dev): rows come from the real database.
    from argus.quarantine import Vault

    db_path = tmp_path / "pending.db"
    vault = Vault.open(tmp_path / "vault", db_path)
    try:
        vault.add_pending(
            source="realtime", path=str(tmp_path / "x.exe"),
            action="quarantine", sha256="b" * 64, severity="high",
            verdict="Malicious", detection_name="T", reasons=[],
        )
    finally:
        vault.close()
    monkeypatch.setattr(
        cli, "_resolve_pending_db", lambda a, c: db_path
    )
    rows = cli._read_pending_loose(args, config)
    assert len(rows) == 1 and rows[0].sha256 == "b" * 64


# ----------------------------------------------------------------------
# FOLLOW-UP 3 — BenchWorker passes the config's exclusions
# ----------------------------------------------------------------------
@requires_qt
def test_hunt_followup_benchworker_exclusion_parity(
    qapp, backend, tmp_path
):
    import hashlib

    from argus import devtools
    from argus.config import Exclusions
    from argus.gui.settings_pages import BenchWorker

    target = tmp_path / "eicar-test.txt"
    target.write_bytes(devtools.EICAR_BYTES)
    digest = hashlib.sha256(devtools.EICAR_BYTES).hexdigest()

    # Without the exclusion the bench calls it Malicious (EICAR).
    plain = BenchWorker(backend, str(target)).execute()
    assert plain.verdict == "Malicious"

    # With the file excluded in the config, the bench — fed the
    # config's exclusions by BenchWorker — leaves it alone,
    # exactly like a real scan would.
    backend.config.exclusions = Exclusions(hashes=frozenset({digest}))
    excluded = BenchWorker(backend, str(target)).execute()
    assert excluded.verdict == "Clean"


# ----------------------------------------------------------------------
# FOLLOW-UP 1 — scan-page quarantine needs a REAL fingerprint
# ----------------------------------------------------------------------
@requires_qt
def test_hunt_followup_scanpage_quarantine_hashes_missing_sha(
    qapp, backend, tmp_path, monkeypatch
):
    import hashlib

    from PySide6.QtWidgets import QMessageBox

    from argus.gui.scan_page import ScanPage

    target = tmp_path / "evil.exe"
    target.write_bytes(b"MZ pretend malware")
    page = ScanPage(backend)
    monkeypatch.setattr(
        QMessageBox, "question",
        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes),
    )
    infos = []
    monkeypatch.setattr(
        QMessageBox, "information",
        staticmethod(lambda *a, **k: infos.append(a)),
    )
    row = {
        "path": str(target), "name": "evil.exe",
        "verdict": "Malicious", "severity": "high",
        "sha256": None, "reasons": ["flagged"], "scanned": None,
    }
    page._act("quarantine", row)
    # The file was quarantined under its REAL hash — computed at
    # action time — not refused and not placeholdered.
    assert not target.exists()
    entries = backend.vault().list_entries()
    assert len(entries) == 1
    assert entries[0].sha256 == hashlib.sha256(
        b"MZ pretend malware"
    ).hexdigest()
    page.close()


@requires_qt
def test_hunt_followup_scanpage_quarantine_no_sha_honest_note(
    qapp, backend, tmp_path, monkeypatch
):
    from PySide6.QtWidgets import QMessageBox

    from argus.gui.scan_page import ScanPage

    page = ScanPage(backend)
    monkeypatch.setattr(
        QMessageBox, "question",
        staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes),
    )
    warnings = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda *a, **k: warnings.append(a)),
    )
    gone = tmp_path / "vanished.exe"  # never existed: no hash possible
    row = {
        "path": str(gone), "name": "vanished.exe",
        "verdict": "Malicious", "severity": "high",
        "sha256": None, "reasons": [], "scanned": None,
    }
    page._act("quarantine", row)
    # Honest note, no engine call, nothing quarantined.
    assert warnings and "fingerprint" in warnings[0][2]
    assert "no fingerprint" in page.result_label.text()
    assert backend.vault().list_entries() == []
    page.close()


# ----------------------------------------------------------------------
# P1-24 / P1-25 — badge tint hue + progress-bar contrast (render)
# ----------------------------------------------------------------------
@requires_qt
def test_hunt_p1_24_severity_badge_tint_hue_and_contrast(qapp):
    import colorsys

    from argus.gui import theme
    from argus.gui.widgets import SeverityBadge, badge_tint_composited

    def lum(hex_color):
        raw = hex_color.lstrip("#")
        ch = [int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        lin = [
            c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
            for c in ch
        ]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    for severity, color in theme.SEVERITY_COLORS.items():
        badge = SeverityBadge.for_severity(severity)
        # The stylesheet carries an rgba() tint — never an 8-digit
        # hex (which Qt would read as #AARRGGBB and shift the hue).
        assert "rgba(" in badge.styleSheet()
        import re

        assert not re.search(r"#[0-9a-fA-F]{8}\b", badge.styleSheet())
        tint = badge_tint_composited(color)
        # Rendered hue ≈ the severity color's hue.
        def hue(hex_color):
            raw = hex_color.lstrip("#")
            r, g, b = (int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4))
            return colorsys.rgb_to_hsv(r, g, b)[0] * 360

        assert abs(hue(tint) - hue(color)) < 25, (severity, tint, color)
        # Text (the severity color itself) on the rendered tint ≥ AA.
        ratio = (max(lum(color), lum(tint)) + 0.05) / (
            min(lum(color), lum(tint)) + 0.05
        )
        assert ratio >= 4.5, (severity, ratio)
        badge.close()


@requires_qt
def test_hunt_p1_25_progress_bar_at_50_percent(qapp):
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QProgressBar

    from argus.gui import theme

    theme.apply_theme(qapp)
    bar = QProgressBar()
    bar.setRange(0, 100)
    bar.setValue(50)
    bar.setFormat("%p%")
    bar.resize(300, 24)
    bar.show()
    qapp.processEvents()
    image = bar.grab().toImage().convertToFormat(
        QImage.Format.Format_RGB32
    )
    # Filled half renders GREEN_DEEP (under the centered text the
    # sample points keep clear of glyphs by hugging the edges of
    # each half); unfilled half renders PANEL.
    filled = image.pixelColor(12, 12)
    unfilled = image.pixelColor(image.width() - 12, 12)
    assert filled.name() == theme.GREEN_DEEP
    assert unfilled.name() == theme.PANEL
    bar.close()


# ======================================================================
# ALIGNMENT (Package B follow-up) — the GUI/bench scoring mirrors
# follow argus.scoring's semantics: the signed trim is EARNED by a
# DER-parsed signer (P1-20), and system-file trust zeroes only
# PE-content signals — protected signals keep FULL points (P0-3).
# ======================================================================
import sys as _sys

_sys.path.insert(0, str(Path(__file__).parent))


def _sig(name, points, severity="high"):
    from argus.heuristics.signals import Signal

    return Signal(name=name, severity=severity, points=points,
                  explanation="x")


def test_hunt_p0_3_evaluate_signals_trust_keeps_protected_points():
    """The bench's evaluator (devtools.evaluate_signals) must score
    a trusted file exactly as argus.scoring does: PE-content
    zeroed, protected signals — filename, tamper, oversize — at
    full points."""
    from argus.devtools import DevSettings, evaluate_signals

    signals = [
        _sig("process_injection_combo", 45, "critical"),  # PE content
        _sig("rtl_override_filename", 20),                # protected
        _sig("argus_program_file_replaced", 35),          # protected
        _sig("oversize_not_fully_analyzed", 25, "medium"),  # protected
    ]
    ev = evaluate_signals(signals, DevSettings(), trusted_system_file=True)
    assert ev.raw_score == 125
    assert ev.score == 20 + 35 + 25
    counted = {s.name: s.points for s in ev.counted_signals}
    assert counted["argus_program_file_replaced"] == 35
    assert counted["rtl_override_filename"] == 20
    # Pure PE content under trust still zeroes completely.
    pure = evaluate_signals(
        signals[:1], DevSettings(), trusted_system_file=True
    )
    assert pure.score == 0


def test_hunt_p1_20_evaluate_signals_trim_only_when_earned():
    """evaluate_signals' `signed` flag means trim-ELIGIBLE: the
    caller decides eligibility (DER signer or not); with it, the
    −15 applies; without it the score stands untouched."""
    from argus.devtools import DevSettings, evaluate_signals

    signals = [_sig("a", 45), _sig("b", 25)]  # 70 raw
    assert evaluate_signals(signals, DevSettings(), signed=False).score == 70
    assert evaluate_signals(signals, DevSettings(), signed=True).score == 55


def _discount_profile(*, cert: str) -> bytes:
    """Raw heuristic score 70 (injection combo 45 + RWX section
    25, no short-circuit) wearing the requested certificate —
    'junk' = valid cert-table header, unparseable payload;
    'claimed' = DER PKCS#7 with an extracted signer."""
    from pe_fixtures import PEBuilder, TEXT_CHARS, code_bytes

    builder = (
        PEBuilder()
        .add_section(".text", code_bytes(4096), TEXT_CHARS)
        .add_section(
            ".rwx", code_bytes(2048), TEXT_CHARS | 0x80000000
        )
        .set_imports(
            {
                "KERNEL32.dll": [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "ExitProcess",
                ]
            }
        )
        .set_entry(0)
    )
    if cert == "junk":
        builder.set_cert(0x1000)
    elif cert == "claimed":
        builder.set_cert_signer("FixtureSoft Ltd", "FixtureSoft")
    return builder.build()


@requires_qt
def test_hunt_p1_20_gui_and_bench_deny_trim_to_unparseable_cert(
    qapp, backend, tmp_path
):
    """GUI worker AND test bench: a structurally-signed file whose
    certificate payload does not DER-parse to a signer gets NO
    −15 trim (score 70, not 55); a DER-signed file earns it."""
    from argus.gui.backend import ScanWorker
    from argus.gui.settings_pages import BenchWorker
    from argus.heuristics.analyze import analyze_file
    from argus.scanner import scan_file
    from argus.signatures import SignatureDB

    junk = tmp_path / "junk.exe"
    junk.write_bytes(_discount_profile(cert="junk"))
    report = analyze_file(junk)
    assert report.signed is True  # structurally signed…
    assert report.signed_trim_eligible is False  # …but no signer

    bench = BenchWorker(backend, str(junk)).execute()
    assert bench.score == 70  # no trim on the bench path

    with SignatureDB.open(backend.config.signature_db) as db:
        scanned = scan_file(junk, db, [], heuristics=False)
    ScanWorker(backend)._apply_heuristics(scanned)
    assert scanned.assessment.score == 70  # no trim on the GUI path

    claimed = tmp_path / "claimed.exe"
    claimed.write_bytes(_discount_profile(cert="claimed"))
    assert analyze_file(claimed).signed_trim_eligible is True
    bench2 = BenchWorker(backend, str(claimed)).execute()
    assert bench2.score == 55  # 70 − 15: the trim, earned
    with SignatureDB.open(backend.config.signature_db) as db:
        scanned2 = scan_file(claimed, db, [], heuristics=False)
    ScanWorker(backend)._apply_heuristics(scanned2)
    assert scanned2.assessment.score == 55


@requires_qt
def test_hunt_p0_3_gui_worker_trusted_file_keeps_protected_signals(
    qapp, backend, tmp_path, monkeypatch
):
    """The GUI scan path on a trusted Microsoft binary wearing a
    double-extension name, with the scanner's tamper signal already
    on the assessment: BOTH protected signals survive the worker's
    re-scoring at full points (the old mirror dropped the tamper
    signal entirely and zeroed everything under trust)."""
    from test_hunt_b_detection import complete_microsoft_pe

    from argus.gui.backend import ScanWorker
    from argus.heuristics.analyze import analyze_file
    from argus.heuristics.signals import Signal
    from argus.scanner import scan_file
    from argus.signatures import SignatureDB

    root = tmp_path / "Windows"
    system32 = root / "System32"
    system32.mkdir(parents=True)
    monkeypatch.setattr(
        "argus.heuristics.analyze.windows_root", lambda: root
    )
    target = system32 / "driver.jpg.exe"  # double-extension masquerade
    target.write_bytes(complete_microsoft_pe())
    report = analyze_file(target)
    assert report.trusted_system_file is True

    with SignatureDB.open(backend.config.signature_db) as db:
        scanned = scan_file(target, db, [], heuristics=False)
    # The surface the scanner itself produces for a tamper suspect
    # (heuristics off): the tamper signal rides the assessment.
    scanned.assessment.signals.append(
        Signal(
            name="argus_program_file_replaced", severity="high",
            points=35, explanation="tamper indicator",
        )
    )
    ScanWorker(backend)._apply_heuristics(scanned)
    points = {s.name: s.points for s in scanned.assessment.signals}
    # Protected signals survive, at FULL points…
    assert points.get("argus_program_file_replaced") == 35
    assert points.get("double_extension") == 30
    # …and they alone make the score: PE content was zeroed.
    assert scanned.assessment.score == 65
