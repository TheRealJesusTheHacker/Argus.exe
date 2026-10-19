"""Tests for the Phase 5 Dev Toolkit engine (argus.devtools).

Pure stdlib tests — no Qt, no Windows needed: signal catalog integrity
(guarded against the signal library's own source), sensitivity
mapping, per-signal steering, the test bench, the EICAR self-test, and
simulation mode's core promise — it records intent and touches
nothing.
"""

import re
from pathlib import Path

import pytest

from argus import devtools
from argus.actions import ActionEngine, DetectionInfo
from argus.config import ArgusConfig
from argus.detections import Verdict
from argus.devtools import (
    SIGNAL_CATALOG,
    DevSettings,
    SignalOverride,
    SimulatedActionEngine,
    evaluate_signals,
    run_self_test,
    run_test_bench,
    thresholds_for_sensitivity,
)
from argus.heuristics.signals import Signal
from argus.quarantine import Vault
from argus.rules import BUILTIN_RULES
from argus.signatures import SignatureDB, init_db

SIGNAL_SOURCES = (
    Path("argus/heuristics/signals.py"),
    Path("argus/heuristics/analyze.py"),
)
_SIGNAL_LITERAL = re.compile(
    r'Signal\(\s*name="([^"]+)",\s*severity="([^"]+)",\s*points=(\d+)'
)


def _source_signals() -> dict[str, tuple[str, int]]:
    found: dict[str, tuple[str, int]] = {}
    for source in SIGNAL_SOURCES:
        for name, severity, points in _SIGNAL_LITERAL.findall(
            source.read_text(encoding="utf-8")
        ):
            found[name] = (severity, int(points))
    return found


def test_signal_catalog_matches_signal_library():
    """The toolkit catalog must mirror the engine's signals exactly —
    if a signal is added, renamed, re-weighted, or re-severitied in
    the library, this fails until the catalog (and so the editor)
    catches up."""
    source = _source_signals()
    catalog = {spec.name: (spec.severity, spec.points) for spec in SIGNAL_CATALOG}
    assert catalog == source


def test_catalog_summaries_are_plain_language():
    for spec in SIGNAL_CATALOG:
        assert spec.summary, spec.name
        assert spec.severity in ("low", "medium", "high", "critical")


# ----------------------------------------------------------------------
# Sensitivity
# ----------------------------------------------------------------------
def test_sensitivity_midpoint_is_engine_defaults():
    assert thresholds_for_sensitivity(50) == (25, 60)


def test_sensitivity_monotonic():
    pairs = [thresholds_for_sensitivity(s) for s in (0, 25, 50, 75, 100)]
    suspicious = [p[0] for p in pairs]
    malicious = [p[1] for p in pairs]
    assert suspicious == sorted(suspicious, reverse=True)
    assert malicious == sorted(malicious, reverse=True)
    for low, high in pairs:
        assert high > low >= 5


def test_sensitivity_clamped():
    assert thresholds_for_sensitivity(-10) == thresholds_for_sensitivity(0)
    assert thresholds_for_sensitivity(250) == thresholds_for_sensitivity(100)


# ----------------------------------------------------------------------
# Settings round-trip + steering
# ----------------------------------------------------------------------
def test_devsettings_round_trip(tmp_path):
    settings = DevSettings(sensitivity=80, simulation_mode=True)
    settings.set_override("double_extension", enabled=False, weight=1.0)
    settings.set_override("packer_section_name", enabled=True, weight=2.0)
    path = tmp_path / "devtools.json"
    settings.save(path)

    loaded = DevSettings.load(path)
    assert loaded.sensitivity == 80
    assert loaded.simulation_mode is True
    assert loaded.override_for("double_extension").enabled is False
    assert loaded.override_for("packer_section_name").weight == 2.0
    assert loaded.load_warnings == []


def test_devsettings_tolerates_garbage(tmp_path):
    path = tmp_path / "devtools.json"
    path.write_text('{"sensitivity": "very", "signal_overrides": {"x": 5}}')
    loaded = DevSettings.load(path)
    assert loaded.sensitivity == 50
    assert loaded.signal_overrides == {}
    assert loaded.load_warnings  # said so loudly, did not crash


def _signal(name: str, points: int, severity: str = "high") -> Signal:
    return Signal(name=name, severity=severity, points=points, explanation="x")


def test_evaluate_respects_disable_and_weight():
    settings = DevSettings()
    settings.set_override("off_signal", enabled=False, weight=1.0)
    settings.set_override("half_signal", enabled=True, weight=0.5)
    evaluation = evaluate_signals(
        [_signal("off_signal", 40), _signal("half_signal", 40)], settings
    )
    assert evaluation.raw_score == 20
    names = {e.signal.name: e for e in evaluation.entries}
    assert names["off_signal"].adjusted_points == 0
    assert names["half_signal"].adjusted_points == 20


def test_evaluate_thresholds_follow_sensitivity():
    signals = [_signal("a", 20), _signal("b", 10)]  # 30 points total
    relaxed = evaluate_signals(signals, DevSettings(sensitivity=0))
    strict = evaluate_signals(signals, DevSettings(sensitivity=100))
    # Relaxed thresholds are 38/90 -> 30 points is Clean there;
    # strict thresholds are 13/30 -> the same 30 points is Malicious.
    assert relaxed.verdict is Verdict.CLEAN
    assert strict.verdict is Verdict.MALICIOUS


def test_disabled_signal_cannot_complete_critical_combination():
    settings = DevSettings()
    settings.set_override("high_entropy_executable_section", enabled=False, weight=1.0)
    evaluation = evaluate_signals(
        [
            _signal("process_injection_combo", 45, "critical"),
            _signal("high_entropy_executable_section", 25),
        ],
        settings,
    )
    assert evaluation.short_circuit is False


# ----------------------------------------------------------------------
# Test bench
# ----------------------------------------------------------------------
@pytest.fixture()
def sigdb(tmp_path):
    path = tmp_path / "bench.sigdb"
    init_db(path, seed=True)
    with SignatureDB.open(path) as db:
        yield db


def test_bench_disassembles_eicar(tmp_path, sigdb):
    target = tmp_path / "eicar.txt"
    target.write_bytes(devtools.EICAR_BYTES)
    result = run_test_bench(target, sigdb, BUILTIN_RULES)
    assert result.error is None
    assert result.signature_name == "EICAR-Test-File"
    assert result.verdict == "Malicious"
    assert result.sha256 is not None and len(result.sha256) == 64


def test_bench_reports_script_signals(tmp_path, sigdb):
    payload = b"powershell -enc " + b"A" * 80 + b"\n"
    target = tmp_path / "dropper.ps1"
    target.write_bytes(payload)
    result = run_test_bench(target, sigdb, [])
    names = {s.name for s in result.signals}
    assert "encoded_powershell_command" in names
    entry = next(s for s in result.signals if s.name == "encoded_powershell_command")
    assert entry.base_points == 30
    assert entry.adjusted_points == 30
    assert result.verdict in ("Suspicious", "Malicious")


def test_bench_unreadable_file_reports_error(tmp_path, sigdb):
    result = run_test_bench(tmp_path / "missing.exe", sigdb, [])
    assert result.error is not None
    assert result.verdict == "Clean"


# ----------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------
def test_self_test_passes_and_cleans_up(tmp_path):
    scratch = tmp_path / "scratch"
    result = run_self_test(scratch)
    assert result.passed, result.summary()
    assert all(step.ok for step in result.steps)
    assert not scratch.exists()  # removed every trace


# ----------------------------------------------------------------------
# Simulation mode — records intent, touches nothing
# ----------------------------------------------------------------------
def test_simulation_records_intent_and_touches_nothing(tmp_path):
    target = tmp_path / "evil.exe"
    target.write_bytes(b"MZ pretend malware")
    before = target.read_bytes()

    engine = SimulatedActionEngine()
    info = DetectionInfo(name="Test", severity="critical", verdict="Malicious")
    outcome = engine.quarantine(target, info, confirmed=True)
    delete_outcome = engine.delete(target, info, confirmed=True)

    assert outcome.done is False
    assert delete_outcome.done is False
    assert "Simulation mode" in outcome.message
    assert [r.action for r in engine.records] == ["quarantine", "delete"]
    assert target.read_bytes() == before  # untouched, byte for byte


def test_simulation_contrasts_with_real_engine(tmp_path):
    """The same call on the real engine really moves the file — the
    simulation guarantee is meaningful only if the real thing isn't a
    no-op."""
    vault_dir = tmp_path / "vault"
    with Vault.open(vault_dir) as vault:
        engine = ActionEngine(vault, ArgusConfig())
        target = tmp_path / "evil2.exe"
        target.write_bytes(b"MZ pretend malware")
        info = DetectionInfo(name="Test", severity="high", verdict="Malicious")
        with pytest.raises(Exception):
            engine.quarantine(target, info)  # unconfirmed: refused
        assert target.exists()
        engine.quarantine(target, info, confirmed=True)
        assert not target.exists()  # confirmed: really quarantined


def test_signal_override_validation():
    assert SignalOverride.from_dict({"enabled": True, "weight": 99}).weight == 5.0
    assert SignalOverride.from_dict({"enabled": "yes"}) is None
    assert SignalOverride.from_dict("nope") is None
