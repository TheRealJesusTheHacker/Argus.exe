"""Tests for argus.realtime: engine detection events + policy actions,
exclusions, process monitoring (fake + real enumerator)."""

import subprocess
import sys
import time

import pytest

from argus.config import ArgusConfig
from argus.realtime import ProcessInfo, ProcessMonitor, RealtimeEngine
from argus.rules import BUILTIN_RULES
from argus.signatures import SignatureDB, init_db

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _wait_for(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def engine_env(tmp_path):
    """A watched folder, a seeded signature DB, and an event sink."""
    watched = tmp_path / "watched"
    watched.mkdir()
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    events: list = []
    config = ArgusConfig(
        watch_dirs=[watched],
        poll_interval=0.05,
        stable_polls=1,
        process_monitor_enabled=False,
        status_file=str(tmp_path / "status.json"),
    )
    db = SignatureDB.open(db_path)
    engine = RealtimeEngine(config, db, BUILTIN_RULES, on_event=events.append)
    yield watched, config, engine, events
    engine.stop()
    db.close()


def test_dropped_eicar_produces_detection_and_quarantine_action(engine_env):
    watched, _config, engine, events = engine_env
    engine.start()
    (watched / "eicar.com").write_bytes(EICAR)

    assert _wait_for(lambda: any(e.kind == "detection" for e in events))
    detection = next(e for e in events if e.kind == "detection")
    assert detection.verdict == "Malicious"
    assert detection.severity == "high"
    assert "EICAR-Test-File" in detection.message

    # High severity maps to a quarantine *request* — and the file must
    # still be sitting there untouched (Phase 3 never moves files).
    assert _wait_for(lambda: any(e.kind == "action" for e in events))
    action = next(e for e in events if e.kind == "action")
    assert action.action == "quarantine"
    assert (watched / "eicar.com").exists()
    # (Counts are >=: a poll may catch the file mid-write and scan it
    # once as a partial before the finished file is scanned for real.)
    assert engine.stats.detections >= 1
    assert engine.stats.scans_completed >= 1


def test_clean_file_is_scanned_quietly(engine_env):
    watched, _config, engine, events = engine_env
    engine.start()
    (watched / "notes.txt").write_text("perfectly ordinary")
    assert _wait_for(lambda: engine.stats.scans_completed >= 1)
    time.sleep(0.3)
    assert [e for e in events if e.kind == "detection"] == []


def test_modified_file_is_rescanned(engine_env):
    watched, _config, engine, events = engine_env
    engine.start()
    target = watched / "payload.bin"
    target.write_bytes(b"harmless at first")
    assert _wait_for(lambda: engine.stats.scans_completed >= 1)

    target.write_bytes(EICAR)  # same name, now malicious
    assert _wait_for(lambda: any(e.kind == "detection" for e in events))
    assert engine.stats.scans_completed >= 2


def test_excluded_path_is_never_flagged(engine_env, tmp_path):
    watched, config, engine, events = engine_env
    from argus.config import Exclusions
    import os

    safe_dir = watched / "safe"
    safe_dir.mkdir()
    config.exclusions = Exclusions(
        paths=(os.path.normcase(os.path.abspath(str(safe_dir))),)
    )
    engine.start()
    (safe_dir / "eicar.com").write_bytes(EICAR)
    (watched / "other.txt").write_text("bait so we know scanning ran")
    assert _wait_for(lambda: engine.stats.scans_completed >= 1)
    time.sleep(0.3)
    assert [e for e in events if e.kind == "detection"] == []
    assert engine.stats.files_excluded >= 1


def test_oversized_file_is_flagged_and_deferred_scanned(engine_env):
    # v1.0.4: oversize is detection-grade (not info-only) AND the
    # file still gets a full deferred scan — being big is not a way
    # to dodge the scanner.
    watched, config, engine, events = engine_env
    config.max_realtime_file_size = 10  # bytes — everything is oversized
    # Written *before* start so no poll can catch a mid-write state.
    (watched / "big.bin").write_bytes(b"x" * 100)
    engine.start()
    assert _wait_for(
        lambda: any(
            e.kind == "detection" and e.verdict == "Suspicious" for e in events
        )
    )
    assert _wait_for(lambda: engine.stats.scans_completed >= 1)
    assert engine.stats.files_oversized == 1


# ----------------------------------------------------------------------
# Process monitor
# ----------------------------------------------------------------------
def test_process_monitor_fake_enumerator_detects_launch(tmp_path):
    image = tmp_path / "app.exe"
    image.write_bytes(b"MZ fake")
    launched: list = []
    state = {"procs": []}
    monitor = ProcessMonitor(
        on_launch=launched.append, enumerator=lambda: list(state["procs"])
    )
    assert monitor.poll_once() == []  # baseline is silent
    state["procs"] = [ProcessInfo(pid=42, name="app.exe", image_path=image)]
    found = monitor.poll_once()
    assert found and found[0].pid == 42
    assert launched and launched[0].name == "app.exe"
    assert monitor.poll_once() == []  # not reported twice


def test_process_monitor_detects_real_spawned_process():
    """Spawn a real sleeper and watch the real enumerator notice it."""
    if sys.platform != "linux":
        pytest.skip("real-enumerator test uses /proc")
    monitor = ProcessMonitor()
    monitor.poll_once()  # baseline
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(4)"]
    )
    try:
        found = _wait_for(
            lambda: any(p.pid == proc.pid for p in monitor.poll_once()),
            timeout=6.0,
        )
        assert found, "monitor never noticed the spawned process"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_engine_scans_launched_process_image(engine_env, tmp_path):
    """A 'launched' EICAR image (via the process path) is flagged."""
    _watched, _config, engine, events = engine_env
    engine.config.process_monitor_enabled = False
    engine.start()
    image = tmp_path / "evil.exe"
    image.write_bytes(EICAR)
    proc = ProcessInfo(pid=999, name="evil.exe", image_path=image)
    engine._on_process_launch(proc)  # what the monitor calls on launch
    assert _wait_for(lambda: any(e.kind == "detection" for e in events))
    process_events = [e for e in events if e.kind == "process"]
    assert process_events and process_events[0].verdict == "Malicious"
    assert engine.stats.processes_seen == 1
