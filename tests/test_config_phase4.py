"""Tests for the Phase 4 config surface: realtime_default policy,
vault/history locations, and save()/load() round-tripping (the
mechanism Allow uses to persist exclusions)."""

from argus.config import ArgusConfig


def test_realtime_default_validation(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text('{"realtime_default": "auto-quarantine-critical"}')
    config = ArgusConfig.load(path)
    assert config.realtime_default == "auto-quarantine-critical"
    assert config.load_warnings == []

    path.write_text('{"realtime_default": "yolo-mode"}')
    config = ArgusConfig.load(path)
    assert config.realtime_default == "ask"  # safe default kept
    assert any("realtime_default" in w for w in config.load_warnings)


def test_save_load_round_trip(tmp_path):
    config = ArgusConfig()
    config.realtime_default = "log-only"
    config.vault_dir = "/somewhere/vault"
    config.history_db = "/somewhere/history.db"
    config.add_hash_exclusion("A" * 64)
    config.severity_actions["low"] = "ignore"

    path = tmp_path / "saved.json"
    config.save(path)

    loaded = ArgusConfig.load(path)
    assert loaded.realtime_default == "log-only"
    assert loaded.vault_dir == "/somewhere/vault"
    assert loaded.history_db == "/somewhere/history.db"
    assert "a" * 64 in loaded.exclusions.hashes
    assert loaded.severity_actions["low"] == "ignore"
    assert loaded.load_warnings == []


def test_vault_and_history_locations_load(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text('{"vault_dir": "/v", "history_db": "/h.db"}')
    config = ArgusConfig.load(path)
    assert config.vault_dir == "/v"
    assert config.history_db == "/h.db"
