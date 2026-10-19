"""Tests for argus.service: lifecycle, heartbeat status file, pause /
resume, config reload, and the watch-status CLI."""

import json
import time

from argus.cli import EXIT_CLEAN, EXIT_ERROR, main
from argus.config import ArgusConfig
from argus.service import ArgusService, read_status_file
from argus.signatures import init_db


def _wait_for(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _make_service(tmp_path, **overrides):
    watched = tmp_path / "watched"
    watched.mkdir(exist_ok=True)
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    config = ArgusConfig(
        watch_dirs=[watched],
        poll_interval=0.05,
        stable_polls=1,
        process_monitor_enabled=False,
        signature_db=str(db_path),
        status_file=str(tmp_path / "status.json"),
        heartbeat_interval=0.5,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return ArgusService(config=config), watched, tmp_path / "status.json"


def test_start_writes_running_status_and_stop_updates_it(tmp_path):
    service, _watched, status_path = _make_service(tmp_path)
    service.start()
    try:
        assert service.state == "running"
        assert _wait_for(lambda: status_path.is_file())
        data = read_status_file(status_path)
        assert data is not None
        assert data["running"] is True
        assert data["state"] == "running"
        assert data["started_at"]
        assert data["version"]
        assert data["scans_completed"] == 0
    finally:
        service.stop()
    assert service.state == "stopped"
    data = read_status_file(status_path)
    assert data["running"] is False
    assert data["state"] == "stopped"


def test_heartbeat_keeps_status_fresh(tmp_path):
    service, _watched, status_path = _make_service(tmp_path)
    service.start()
    try:
        assert _wait_for(lambda: status_path.is_file())
        first = read_status_file(status_path)["heartbeat_at"]
        assert _wait_for(
            lambda: read_status_file(status_path)["heartbeat_at"] != first,
            timeout=5.0,
        )
    finally:
        service.stop()


def test_pause_and_resume(tmp_path):
    service, _watched, status_path = _make_service(tmp_path)
    service.start()
    try:
        service.pause()
        assert service.state == "paused"
        assert service.engine.paused is True
        data = read_status_file(status_path)
        assert data["paused"] is True
        service.resume()
        assert service.state == "running"
        assert service.engine.paused is False
    finally:
        service.stop()


def test_status_counts_scans(tmp_path):
    service, watched, _status = _make_service(tmp_path)
    service.start()
    try:
        (watched / "hello.txt").write_text("hello")
        assert _wait_for(lambda: service.status()["scans_completed"] >= 1)
        status = service.status()
        assert status["files_watched"] >= 1
    finally:
        service.stop()


def test_reload_config_applies_new_watch_dirs(tmp_path):
    config_path = tmp_path / "argus-config.json"
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    payload = {
        "watch_dirs": [str(dir_a)],
        "poll_interval_seconds": 0.05,
        "process_monitor_enabled": False,
        "signature_db": str(db_path),
        "status_file": str(tmp_path / "status.json"),
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    service = ArgusService(config_path=config_path)
    service.start()
    try:
        assert service.config.watch_dirs == [dir_a]
        payload["watch_dirs"] = [str(dir_b)]
        config_path.write_text(json.dumps(payload), encoding="utf-8")
        service.reload_config()
        assert service.state == "running"
        assert service.config.watch_dirs == [dir_b]
    finally:
        service.stop()


def test_start_with_missing_db_raises(tmp_path):
    config = ArgusConfig(
        signature_db=str(tmp_path / "nope.sigdb"),
        status_file=str(tmp_path / "status.json"),
    )
    service = ArgusService(config=config)
    import pytest
    from argus.signatures import SignatureError

    with pytest.raises(SignatureError):
        service.start()
    assert service.state == "stopped"


def test_read_status_file_missing_or_garbage(tmp_path):
    assert read_status_file(tmp_path / "absent.json") is None
    garbage = tmp_path / "status.json"
    garbage.write_text("not json at all", encoding="utf-8")
    assert read_status_file(garbage) is None


def test_watch_status_cli(tmp_path, capsys):
    service, _watched, status_path = _make_service(tmp_path)
    service.start()
    try:
        assert main(["watch-status", "--status-file", str(status_path)]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "RUNNING" in out
        assert main(
            ["watch-status", "--status-file", str(status_path), "--json"]
        ) == EXIT_CLEAN
        payload = json.loads(capsys.readouterr().out)
        assert payload["state"] == "running"
    finally:
        service.stop()


def test_watch_status_cli_not_running(tmp_path, capsys):
    missing = tmp_path / "no-status.json"
    assert main(["watch-status", "--status-file", str(missing)]) == EXIT_ERROR
    assert "NOT RUNNING" in capsys.readouterr().out
