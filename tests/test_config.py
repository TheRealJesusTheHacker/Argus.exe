"""Tests for argus.config: defaults, tolerant loading, exclusions."""

import hashlib
import json

from argus.config import ArgusConfig, Exclusions


def _write_config(tmp_path, payload) -> "object":
    path = tmp_path / "argus-config.json"
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_defaults_without_file():
    config = ArgusConfig.load(None)
    assert config.load_warnings == []
    assert config.watch_dirs  # Downloads/Desktop/Documents/temp
    assert config.poll_interval > 0
    assert config.process_monitor_enabled is True
    assert config.action_for("critical") == "quarantine"
    assert config.action_for("high") == "quarantine"
    assert config.action_for("medium") == "alert"
    assert config.action_for("low") == "log"
    assert config.exclusions.empty


def test_missing_file_is_defaults_plus_warning(tmp_path):
    config = ArgusConfig.load(tmp_path / "absent.json")
    assert config.load_warnings  # loud, not silent
    assert config.action_for("critical") == "quarantine"  # defaults intact


def test_corrupt_json_falls_back_with_warning(tmp_path):
    path = _write_config(tmp_path, "{ this is not json")
    config = ArgusConfig.load(path)
    assert config.load_warnings
    assert config.poll_interval > 0  # defaults intact


def test_non_object_json_falls_back(tmp_path):
    path = _write_config(tmp_path, "[1, 2, 3]")
    config = ArgusConfig.load(path)
    assert config.load_warnings


def test_valid_config_overrides(tmp_path):
    path = _write_config(tmp_path, {
        "watch_dirs": [str(tmp_path / "inbox")],
        "poll_interval_seconds": 0.25,
        "stable_polls": 3,
        "process_monitor_enabled": False,
        "severity_actions": {"low": "alert", "critical": "delete"},
        "max_realtime_file_size_mb": 10,
    })
    config = ArgusConfig.load(path)
    assert config.load_warnings == []
    assert config.watch_dirs == [tmp_path / "inbox"]
    assert config.poll_interval == 0.25
    assert config.stable_polls == 3
    assert config.process_monitor_enabled is False
    assert config.action_for("low") == "alert"
    assert config.action_for("critical") == "delete"
    assert config.action_for("high") == "quarantine"  # untouched default
    assert config.max_realtime_file_size == 10 * 1024 * 1024


def test_wrong_typed_values_warn_and_keep_defaults(tmp_path):
    path = _write_config(tmp_path, {
        "watch_dirs": "not-a-list",
        "poll_interval_seconds": "fast",
        "severity_actions": {"critical": "explode"},
        "stable_polls": -5,
    })
    config = ArgusConfig.load(path)
    assert len(config.load_warnings) >= 4
    assert config.action_for("critical") == "quarantine"
    assert config.stable_polls >= 1


def test_exclusions_from_config(tmp_path):
    digest = hashlib.sha256(b"known good installer").hexdigest()
    path = _write_config(tmp_path, {
        "exclusions": {
            "paths": [str(tmp_path / "trusted")],
            "hashes": [digest.upper()],  # case-insensitive on load
        },
    })
    config = ArgusConfig.load(path)
    assert config.load_warnings == []
    assert config.is_excluded(tmp_path / "trusted" / "anything.exe")
    assert config.is_excluded(tmp_path / "trusted")
    assert not config.is_excluded(tmp_path / "elsewhere" / "file.exe")
    assert config.is_excluded(tmp_path / "anywhere.exe", digest)
    assert not config.is_excluded(tmp_path / "anywhere.exe", "0" * 64)


def test_exclusions_object_matching(tmp_path):
    excl = Exclusions(paths=(), hashes=frozenset({"ab" * 32}))
    assert excl.is_hash_excluded("AB" * 32)
    assert not excl.is_hash_excluded(None)
    assert not excl.is_path_excluded(tmp_path / "x")
    assert Exclusions().empty


def test_bad_exclusion_entries_warn(tmp_path):
    path = _write_config(tmp_path, {
        "exclusions": {"paths": [123], "hashes": ["not-a-hash"]},
    })
    config = ArgusConfig.load(path)
    assert len(config.load_warnings) == 2
    assert config.exclusions.empty
