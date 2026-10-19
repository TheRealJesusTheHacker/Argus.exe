"""Tests for the Phase 4 CLI: scan actions + flags, quarantine
commands, pending queue, report and history commands."""

import json

import pytest

from argus.cli import EXIT_CLEAN, EXIT_DETECTIONS, EXIT_ERROR, main
from argus.quarantine import Vault
from argus.signatures import init_db

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_dir))
    target_dir = tmp_path / "stuff"
    target_dir.mkdir()
    (target_dir / "eicar.com").write_bytes(EICAR)
    (target_dir / "notes.txt").write_text("perfectly ordinary")
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    return {
        "root": tmp_path, "target": target_dir, "db": db_path,
        "vault_dir": data_dir / "quarantine",
        "history_db": data_dir / "history.db",
    }


def _scan(cli_env, *extra):
    return main([
        "scan", str(cli_env["target"]), "--db", str(cli_env["db"]), *extra,
    ])


def test_scan_without_flags_takes_no_action(cli_env, capsys):
    code = _scan(cli_env)
    assert code == EXIT_DETECTIONS
    # Non-interactive + no flags: report only, file untouched.
    assert (cli_env["target"] / "eicar.com").exists()
    vault = Vault.open(cli_env["vault_dir"])
    try:
        assert vault.count() == 0
    finally:
        vault.close()
    out = capsys.readouterr().out
    assert "EICAR" in out


def test_scan_quarantine_flag(cli_env):
    code = _scan(cli_env, "--quarantine")
    assert code == EXIT_DETECTIONS
    assert not (cli_env["target"] / "eicar.com").exists()
    vault = Vault.open(cli_env["vault_dir"])
    try:
        assert vault.count("quarantined") == 1
        entry = vault.list_entries()[0]
        assert entry.detection_name == "EICAR-Test-File"
    finally:
        vault.close()


def test_scan_delete_flag(cli_env):
    code = _scan(cli_env, "--delete")
    assert code == EXIT_DETECTIONS
    assert not (cli_env["target"] / "eicar.com").exists()
    vault = Vault.open(cli_env["vault_dir"])
    try:
        entries = vault.list_entries()
        assert len(entries) == 1
        assert entries[0].status == "deleted"  # audit record remains
    finally:
        vault.close()


def test_scan_conflicting_flags_rejected(cli_env):
    assert _scan(cli_env, "--quarantine", "--delete") == EXIT_ERROR
    assert (cli_env["target"] / "eicar.com").exists()


def test_scan_records_history(cli_env):
    _scan(cli_env)
    from argus.reporting import History
    history = History.open(cli_env["history_db"])
    try:
        summary = history.summary(days=1)
        assert summary["scans"] == 1
        assert summary["detections"] == 1
        assert summary["by_action"] == {"none": 1}
    finally:
        history.close()


def test_quarantine_list_and_restore_via_cli(cli_env, capsys):
    _scan(cli_env, "--quarantine")
    code = main(["quarantine", "list"])
    assert code == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "eicar.com" in out

    vault = Vault.open(cli_env["vault_dir"])
    entry_id = vault.list_entries()[0].id
    vault.close()

    # Prefix ids work, like a human copying from the list.
    code = main(["quarantine", "restore", entry_id[:12]])
    assert code == EXIT_CLEAN
    assert (cli_env["target"] / "eicar.com").read_bytes() == EICAR


def test_quarantine_delete_via_cli_requires_yes_when_not_tty(cli_env):
    _scan(cli_env, "--quarantine")
    vault = Vault.open(cli_env["vault_dir"])
    entry_id = vault.list_entries()[0].id
    vault.close()

    # No --yes and no TTY (pytest): refused, entry still live.
    code = main(["quarantine", "delete", entry_id])
    assert code == EXIT_CLEAN
    vault = Vault.open(cli_env["vault_dir"])
    try:
        assert vault.get_entry(entry_id).status == "quarantined"
    finally:
        vault.close()

    code = main(["quarantine", "delete", entry_id, "--yes"])
    assert code == EXIT_CLEAN
    vault = Vault.open(cli_env["vault_dir"])
    try:
        assert vault.get_entry(entry_id).status == "deleted"
    finally:
        vault.close()


def test_quarantine_allow_via_cli(cli_env, tmp_path):
    _scan(cli_env, "--quarantine")
    vault = Vault.open(cli_env["vault_dir"])
    entry_id = vault.list_entries()[0].id
    vault.close()

    config_path = tmp_path / "argus-config.json"
    code = main([
        "quarantine", "allow", entry_id, "--yes",
        "--config", str(config_path),
    ])
    assert code == EXIT_CLEAN
    # File restored…
    assert (cli_env["target"] / "eicar.com").read_bytes() == EICAR
    # …entry marked allowed…
    vault = Vault.open(cli_env["vault_dir"])
    try:
        assert vault.get_entry(entry_id).status == "allowed"
    finally:
        vault.close()
    # …and the exclusion saved, so a rescan with that config skips it.
    code = main([
        "scan", str(cli_env["target"]), "--db", str(cli_env["db"]),
        "--config", str(config_path),
    ])
    assert code == EXIT_CLEAN


def test_pending_flow_via_cli(cli_env, capsys):
    # Simulate a queued real-time request in the same vault.
    from argus.actions import ActionEngine, DetectionInfo
    from argus.config import ArgusConfig
    vault = Vault.open(cli_env["vault_dir"])
    engine = ActionEngine(vault, ArgusConfig())
    target = cli_env["target"] / "eicar.com"
    pending = engine.enqueue(
        source="realtime", path=target, action="quarantine",
        info=DetectionInfo(name="EICAR-Test-File", severity="high",
                           verdict="Malicious", reasons=["test"],
                           sha256=None),
    )
    vault.close()

    code = main(["pending", "list"])
    assert code == EXIT_CLEAN
    assert "eicar.com" in capsys.readouterr().out

    code = main(["pending", "approve", pending.id[:12]])
    assert code == EXIT_CLEAN
    assert not target.exists()
    vault = Vault.open(cli_env["vault_dir"])
    try:
        assert vault.count("quarantined") == 1
        assert vault.get_pending(pending.id).status == "done"
    finally:
        vault.close()


def test_report_and_history_commands(cli_env, capsys):
    _scan(cli_env, "--quarantine")
    capsys.readouterr()

    code = main(["report", "--days", "7"])
    assert code == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "ARGUS report" in out
    assert "eicar.com" in out
    assert "quarantine vault" in out  # action taken, in plain language

    code = main(["report", "--days", "7", "--json"])
    assert code == EXIT_CLEAN
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["detections"] == 1

    code = main(["history"])
    assert code == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Recent scans" in out
    assert "Recent detections" in out


def test_quarantine_list_empty(cli_env, capsys):
    code = main(["quarantine", "list"])
    assert code == EXIT_CLEAN
    assert "empty" in capsys.readouterr().out


def test_unknown_entry_id_errors(cli_env):
    assert main(["quarantine", "restore", "zzzz-not-an-id"]) == EXIT_ERROR
    assert main(["pending", "approve", "zzzz-not-an-id"]) == EXIT_ERROR
