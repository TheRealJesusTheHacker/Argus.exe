"""Tests for argus.actions: the never-silent rule, quarantine /
delete / allow flows, the pending queue, and the real-time policy
modes (ask / auto-quarantine-critical / log-only) end-to-end through
the real-time engine with EICAR and critical-rule fixtures."""

import hashlib
import time

import pytest

from argus.actions import (
    ActionEngine,
    ActionError,
    ConfirmationRequired,
    DetectionInfo,
)
from argus.config import ArgusConfig
from argus.quarantine import Vault
from argus.realtime import RealtimeEngine
from argus.reporting import History
from argus.rules import BUILTIN_RULES
from argus.scanner import scan_file
from argus.signatures import SignatureDB, init_db

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
MIMIKATZ_MARKER = b"run sekurlsa::logonpasswords now"  # critical rule


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
@pytest.fixture()
def env(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    history = History.open(tmp_path / "history.db")
    config_path = tmp_path / "argus-config.json"
    config = ArgusConfig()
    engine = ActionEngine(
        vault, config, config_path=config_path, history=history
    )
    yield {
        "vault": vault, "history": history, "config": config,
        "config_path": config_path, "engine": engine, "root": tmp_path,
    }
    history.close()
    vault.close()


def _info(name="Test.Detection", severity="high", verdict="Malicious", sha256=None):
    return DetectionInfo(
        name=name, severity=severity, verdict=verdict,
        reasons=["Flagged by a test."], sha256=sha256,
    )


def _drop(root, name, data):
    path = root / name
    path.write_bytes(data)
    return path


# ----------------------------------------------------------------------
# The never-silent rule
# ----------------------------------------------------------------------
def test_destructive_actions_require_confirmation(env):
    target = _drop(env["root"], "evil.exe", b"bad-bytes")
    info = _info()
    with pytest.raises(ConfirmationRequired):
        env["engine"].quarantine(target, info)
    with pytest.raises(ConfirmationRequired):
        env["engine"].delete(target, info)
    with pytest.raises(ConfirmationRequired):
        env["engine"].allow_file(target)
    # Nothing was touched and nothing was recorded as taken.
    assert target.read_bytes() == b"bad-bytes"
    assert env["vault"].count() == 0


def test_quarantine_action(env):
    target = _drop(env["root"], "evil.exe", EICAR)
    outcome = env["engine"].quarantine(
        target, _info(sha256=hashlib.sha256(EICAR).hexdigest()), confirmed=True
    )
    assert outcome.done
    assert outcome.entry_id
    assert not target.exists()
    assert env["vault"].count("quarantined") == 1


def test_delete_action_goes_through_vault(env):
    target = _drop(env["root"], "evil.exe", EICAR)
    outcome = env["engine"].delete(target, _info(), confirmed=True)
    assert outcome.done
    assert not target.exists()
    # The vault index keeps the audit record even though the file is gone.
    entries = env["vault"].list_entries()
    assert len(entries) == 1
    assert entries[0].status == "deleted"


def test_delete_direct(env):
    # v1.1.0 (P2): the direct-delete route was removed — delete
    # always goes through the vault, and passing direct= is an error.
    target = _drop(env["root"], "evil.exe", EICAR)
    with pytest.raises(TypeError):
        env["engine"].delete(target, _info(), confirmed=True, direct=True)
    assert target.exists()
    env["engine"].delete(target, _info(), confirmed=True)
    assert not target.exists()
    assert env["vault"].count() == 1  # the audit record


def test_allow_entry_restores_excludes_and_scanner_stands_down(env, tmp_path):
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    target = _drop(env["root"], "eicar.com", EICAR)
    engine = env["engine"]
    outcome = engine.quarantine(
        target,
        _info(name="EICAR-Test-File", sha256=hashlib.sha256(EICAR).hexdigest()),
        confirmed=True,
    )
    entry_id = outcome.entry_id

    allowed = engine.allow_entry(entry_id, confirmed=True)
    assert allowed.done
    # File is back, byte-identical.
    assert target.read_bytes() == EICAR
    # Entry marked allowed.
    assert env["vault"].get_entry(entry_id).status == "allowed"
    # Exclusion persisted to the config file.
    reloaded = ArgusConfig.load(env["config_path"])
    sha = hashlib.sha256(EICAR).hexdigest()
    assert sha in reloaded.exclusions.hashes
    # And the scanner now leaves it alone.
    db = SignatureDB.open(db_path)
    try:
        scanned = scan_file(target, db, BUILTIN_RULES,
                            exclusions=reloaded.exclusions)
    finally:
        db.close()
    assert scanned.excluded


def test_ignore_is_safe_without_confirmation(env):
    target = _drop(env["root"], "meh.exe", b"whatever")
    outcome = env["engine"].ignore(target, _info())
    assert outcome.done
    assert target.exists()


# ----------------------------------------------------------------------
# Pending queue
# ----------------------------------------------------------------------
def test_pending_approve_quarantine(env):
    target = _drop(env["root"], "evil.exe", EICAR)
    engine = env["engine"]
    # A real queued action always carries the file's fingerprint —
    # approval verifies against it (v1.0.4 approval safety).
    pending = engine.enqueue(
        source="realtime", path=target, action="quarantine",
        info=_info(sha256=hashlib.sha256(EICAR).hexdigest()),
    )
    assert env["vault"].pending_count() == 1
    assert target.exists()  # queued != touched

    outcome = engine.approve(pending.id)
    assert outcome.done
    assert not target.exists()
    assert env["vault"].get_pending(pending.id).status == "done"
    assert env["vault"].count("quarantined") == 1


def test_pending_approve_delete(env):
    target = _drop(env["root"], "evil.exe", EICAR)
    engine = env["engine"]
    pending = engine.enqueue(
        source="realtime", path=target, action="delete",
        info=_info(sha256=hashlib.sha256(EICAR).hexdigest()),
    )
    engine.approve(pending.id)
    assert not target.exists()
    assert env["vault"].list_entries()[0].status == "deleted"


def test_pending_reject_leaves_file(env):
    target = _drop(env["root"], "evil.exe", EICAR)
    engine = env["engine"]
    pending = engine.enqueue(
        source="scan", path=target, action="delete", info=_info()
    )
    engine.reject(pending.id)
    assert target.read_bytes() == EICAR
    assert env["vault"].get_pending(pending.id).status == "rejected"
    assert env["vault"].count() == 0


def test_pending_double_decision_refused(env):
    engine = env["engine"]
    target = _drop(env["root"], "evil.exe", EICAR)
    pending = engine.enqueue(
        source="scan", path=target, action="quarantine", info=_info()
    )
    engine.reject(pending.id)
    with pytest.raises(ActionError):
        engine.approve(pending.id)
    with pytest.raises(ActionError):
        engine.reject(pending.id)


def test_approve_missing_file_marks_failed(env):
    engine = env["engine"]
    target = _drop(env["root"], "ghost.exe", EICAR)
    pending = engine.enqueue(
        source="realtime", path=target, action="quarantine", info=_info()
    )
    target.unlink()  # the file vanished before the human decided
    with pytest.raises(Exception):
        engine.approve(pending.id)
    assert env["vault"].get_pending(pending.id).status == "failed"


# ----------------------------------------------------------------------
# Real-time policy modes (through the real engine)
# ----------------------------------------------------------------------
def _wait_for(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def rt_env(tmp_path):
    """Watched folder + vault + history + action engine + realtime engine."""
    watched = tmp_path / "watched"
    watched.mkdir()
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    vault = Vault.open(tmp_path / "vault")
    history = History.open(tmp_path / "history.db")
    state = {"engines": []}

    def build(policy: str, severity_actions=None):
        config = ArgusConfig(
            watch_dirs=[watched],
            poll_interval=0.05,
            stable_polls=1,
            process_monitor_enabled=False,
            status_file=str(tmp_path / "status.json"),
            realtime_default=policy,
        )
        if severity_actions:
            config.severity_actions.update(severity_actions)
        actions = ActionEngine(
            vault, config, config_path=tmp_path / "cfg.json", history=history
        )
        db = SignatureDB.open(db_path)
        rt = RealtimeEngine(
            config, db, BUILTIN_RULES, on_event=actions.handle_realtime_event
        )
        state["engines"].append((rt, db))
        return rt, actions

    yield watched, vault, history, build
    for rt, db in state["engines"]:
        rt.stop()
        db.close()
    history.close()
    vault.close()


def test_rt_policy_ask_queues_and_leaves_file(rt_env):
    watched, vault, history, build = rt_env
    rt, _actions = build("ask")
    rt.start()
    target = watched / "eicar.com"
    target.write_bytes(EICAR)

    assert _wait_for(lambda: vault.pending_count() == 1)
    assert target.exists()  # ask = Argus does not touch it
    assert vault.count("quarantined") == 0
    pending = vault.list_pending()[0]
    assert pending.action == "quarantine"
    assert pending.source == "realtime"
    # And history knows about it.
    assert _wait_for(lambda: history.summary(days=1)["detections"] >= 1)
    det = history.recent_detections()[0]
    assert det.action_taken == "pending"


def test_rt_policy_auto_quarantine_critical(rt_env):
    watched, vault, history, build = rt_env
    rt, _actions = build("auto-quarantine-critical")
    rt.start()
    target = watched / "creds.txt"
    target.write_bytes(MIMIKATZ_MARKER)  # critical-severity rule

    assert _wait_for(lambda: vault.count("quarantined") == 1)
    assert _wait_for(lambda: not target.exists())
    assert vault.pending_count() == 0
    entry = vault.list_entries("quarantined")[0]
    assert entry.severity == "critical"


def test_rt_policy_auto_leaves_noncritical_queued(rt_env):
    watched, vault, history, build = rt_env
    rt, _actions = build("auto-quarantine-critical")
    rt.start()
    target = watched / "eicar.com"  # severity high, not critical
    target.write_bytes(EICAR)

    assert _wait_for(lambda: vault.pending_count() == 1)
    assert target.exists()
    assert vault.count("quarantined") == 0


def test_rt_policy_auto_never_deletes(rt_env):
    """Even with policy set to delete Criticals, real-time never
    deletes: a Critical delete request goes to the human queue."""
    watched, vault, history, build = rt_env
    rt, _actions = build(
        "auto-quarantine-critical", severity_actions={"critical": "delete"}
    )
    rt.start()
    target = watched / "creds.txt"
    target.write_bytes(MIMIKATZ_MARKER)

    assert _wait_for(lambda: vault.pending_count() == 1)
    assert target.exists()  # NOT deleted
    assert vault.list_pending()[0].action == "delete"


def test_rt_policy_log_only(rt_env):
    watched, vault, history, build = rt_env
    rt, _actions = build("log-only")
    rt.start()
    target = watched / "eicar.com"
    target.write_bytes(EICAR)

    assert _wait_for(lambda: history.summary(days=1)["detections"] >= 1)
    time.sleep(0.3)
    assert vault.pending_count() == 0
    assert vault.count() == 0
    assert target.exists()
    det = history.recent_detections()[0]
    assert det.action_taken == "none"
