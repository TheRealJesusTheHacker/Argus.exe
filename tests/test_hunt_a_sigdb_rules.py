"""Hunt fix-pass tests — Package A (v1.1.0).

Findings covered:

- P1-1/P1-2/P1-3 — sigdb auth: no re-signing, tamper matrix,
  row-field HMAC coverage, ``require_auth`` enforcement, key
  location in installed vs portable layout.
- P1-14 — rules budget polled inside pattern matching, patterns
  per rule cap, rules-file size cap, honest ``finish()`` surface
  for a single-rule matcher.
- P1-21 — tail pass over the last 8 MiB after budget death.
- P1-18 — watcher sampled content hash (timestomp swap).
- P2 — realtime ADS on the process path; locked-file retry
  list pruning/bounding.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

import argus.realtime as realtime
import argus.signatures as signatures
from argus import paths
from argus.config import ArgusConfig
from argus.realtime import (
    MAX_LOCKED_RETRIES,
    ProcessInfo,
    RealtimeEngine,
    _WorkItem,
)
from argus.rules import (
    MAX_PATTERNS_PER_RULE,
    MAX_RULES_FILE_SIZE,
    Rule,
    RuleError,
    RuleMatcher,
    evaluate_stream,
    load_rules,
)
from argus.signatures import (
    SignatureDB,
    SignatureError,
    bootstrap_signature_db,
    ensure_signature_db,
    init_db,
    key_path_for,
)
from argus.watcher import DirectoryWatcher, sampled_content_hash

AUTH_KEY = "auth_hmac"


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _meta(db_path: Path) -> dict:
    conn = sqlite3.connect(db_path)
    try:
        return dict(conn.execute("SELECT key, value FROM meta"))
    finally:
        conn.close()


def _exec(db_path: Path, sql: str, params=()) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _make_db(tmp_path: Path, name: str = "sigs.sigdb") -> Path:
    db_path = tmp_path / name
    init_db(db_path)
    return db_path


def _rule(name: str, *texts: str, condition: str = "any") -> Rule:
    return Rule.from_dict(
        {
            "name": name,
            "description": "test",
            "severity": "high",
            "condition": condition,
            "patterns": [{"text": t} for t in texts],
        }
    )


class _ManualClock:
    """Time stands still until the test advances it."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ======================================================================
# P1-1 — bootstrap/ensure NEVER re-signs an existing database
# ======================================================================
def test_hunt_p1_1_no_resign_helper_remains():
    assert not hasattr(signatures, "_try_refresh_auth")


def test_hunt_p1_1_ensure_does_not_resign_missing_tag(tmp_path):
    db_path = _make_db(tmp_path)
    key_file = key_path_for(db_path)
    key_bytes_before = key_file.read_bytes()
    _exec(db_path, "DELETE FROM meta WHERE key = ?", (AUTH_KEY,))
    stamp = db_path.stat().st_mtime_ns
    with pytest.raises(SignatureError):
        ensure_signature_db(db_path)
    # Nothing was written back: the tag is still absent, the key
    # is untouched, and the file itself was not modified.
    assert AUTH_KEY not in _meta(db_path)
    assert key_file.read_bytes() == key_bytes_before
    assert db_path.stat().st_mtime_ns == stamp


def test_hunt_p1_1_bootstrap_does_not_resign_wrong_tag(tmp_path):
    db_path = _make_db(tmp_path)
    _exec(
        db_path,
        "UPDATE meta SET value = ? WHERE key = ?",
        ("f" * 64, AUTH_KEY),
    )
    with pytest.raises(SignatureError):
        bootstrap_signature_db(db_path)
    # The wrong tag is still there — bootstrap refused, it did
    # not "refresh" the tag over the (possibly tampered) rows.
    assert _meta(db_path)[AUTH_KEY] == "f" * 64


def test_hunt_p1_1_ensure_valid_db_is_readonly_noop(tmp_path):
    db_path = _make_db(tmp_path)
    stamp = db_path.stat().st_mtime_ns
    assert ensure_signature_db(db_path) is None
    assert db_path.stat().st_mtime_ns == stamp


# ======================================================================
# P1-2 — tamper matrix for ensure + open
# ======================================================================
def test_hunt_p1_2_wrong_tag_rejected_everywhere(tmp_path):
    db_path = _make_db(tmp_path)
    _exec(
        db_path,
        "UPDATE meta SET value = ? WHERE key = ?",
        ("0" * 64, AUTH_KEY),
    )
    with pytest.raises(SignatureError):
        ensure_signature_db(db_path)
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path)
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path, require_auth=True)


def test_hunt_p1_2_missing_tag_with_key_is_tamper(tmp_path):
    db_path = _make_db(tmp_path)
    assert key_path_for(db_path).is_file()  # key exists
    _exec(db_path, "DELETE FROM meta WHERE key = ?", (AUTH_KEY,))
    with pytest.raises(SignatureError):
        ensure_signature_db(db_path)
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path, require_auth=True)
    # Reporting mode still opens and flags it instead of hiding it.
    with SignatureDB.open(db_path) as db:
        assert db.info.auth_missing is True
        assert db.info.auth_verified is False


def test_hunt_p1_2_missing_tag_and_no_key_is_unauthenticatable(tmp_path):
    db_path = _make_db(tmp_path)
    _exec(db_path, "DELETE FROM meta WHERE key = ?", (AUTH_KEY,))
    key_path_for(db_path).unlink()
    with pytest.raises(SignatureError):
        ensure_signature_db(db_path)
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path, require_auth=True)


def test_hunt_p1_2_missing_key_with_tag_enforced_under_require_auth(tmp_path):
    db_path = _make_db(tmp_path)
    key_path_for(db_path).unlink()
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path, require_auth=True)
    with pytest.raises(SignatureError):
        ensure_signature_db(db_path)
    # ...but reporting mode (require_auth=False) still only reports.
    with SignatureDB.open(db_path) as db:
        assert db.info.auth_missing is True


def test_hunt_p1_2_require_auth_enforcement_and_success(tmp_path):
    db_path = _make_db(tmp_path)
    with SignatureDB.open(db_path, require_auth=True) as db:
        assert db.info.auth_verified is True
        assert db.info.auth_missing is False


# ======================================================================
# P1-3 — HMAC covers name / severity / family, not just the digest
# ======================================================================
@pytest.mark.parametrize("field", ["name", "severity", "family"])
def test_hunt_p1_3_row_field_tamper_detected(tmp_path, field):
    sub = tmp_path / field
    sub.mkdir()
    db_path = _make_db(sub)
    new_value = "critical" if field == "severity" else "Forged-Value"
    _exec(db_path, f"UPDATE hashes SET {field} = ?", (new_value,))
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path)
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path, require_auth=True)
    with pytest.raises(SignatureError):
        ensure_signature_db(db_path)


def test_hunt_p1_3_digest_tamper_still_detected(tmp_path):
    db_path = _make_db(tmp_path)
    _exec(db_path, "UPDATE hashes SET sha256 = ?", ("a" * 64,))
    # Keep meta.count truthful so ONLY the HMAC can catch this.
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path)


# ======================================================================
# P1-1/2/3 — key location: installed layout vs portable/custom
# ======================================================================
def test_hunt_p1_1_key_lives_in_vault_for_default_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    db_path = signatures.default_signature_db_path()
    expected = paths.default_vault_dir() / (db_path.name + ".key")
    assert key_path_for(db_path) == expected
    init_db(db_path)
    assert expected.is_file()
    assert not (db_path.parent / (db_path.name + ".key")).exists()
    if sys.platform != "win32":
        assert oct(expected.stat().st_mode & 0o777) == "0o600"
    with SignatureDB.open(db_path, require_auth=True) as db:
        assert db.info.auth_verified is True


def test_hunt_p1_1_key_beside_custom_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    db_path = tmp_path / "custom" / "my.sigdb"
    expected = db_path.parent / "my.sigdb.key"
    assert key_path_for(db_path) == expected
    init_db(db_path)
    assert expected.is_file()
    with SignatureDB.open(db_path, require_auth=True) as db:
        assert db.info.auth_verified is True


# ======================================================================
# P1-14 — budget polled inside pattern matching; caps; honest finish
# ======================================================================
class _JumpClock:
    """Returns 0 for the first few reads, then jumps far ahead —
    the budget dies deterministically in the middle of a scan."""

    def __init__(self, calm_reads: int = 3) -> None:
        self.calls = 0
        self.calm_reads = calm_reads

    def __call__(self) -> float:
        self.calls += 1
        return 0.0 if self.calls <= self.calm_reads else 1000.0


def test_hunt_p1_14_budget_trips_mid_pattern_single_rule():
    rule = _rule("MidPattern", "NEEDLE-AT-THE-END")
    matcher = RuleMatcher([rule], time_budget=2.0)
    matcher._clock = _JumpClock(calm_reads=3)
    data = b"x" * (512 * 1024) + b"NEEDLE-AT-THE-END"
    matcher.feed(data)
    # The trip happened DURING this one feed's single pattern
    # scan — no second feed, no second rule was needed to notice.
    assert matcher.budget_exceeded is True


def test_hunt_p1_14_finish_reports_budget_for_single_rule_matcher():
    rule = _rule("Single", "needle")
    clock = _ManualClock()
    matcher = RuleMatcher([rule], time_budget=2.0)
    matcher._clock = clock
    matcher.feed(b"a needle in a small file")
    assert matcher.budget_exceeded is False
    clock.advance(60.0)  # budget dies after the (only) feed
    hits = matcher.finish()
    assert matcher.budget_exceeded is True  # finish() is honest
    assert any(h.name == "Single" for h in hits)  # match kept


def test_hunt_p1_14_pattern_count_cap():
    with pytest.raises(RuleError):
        _rule("TooMany", *[f"pat-{i}" for i in range(MAX_PATTERNS_PER_RULE + 1)])
    ok = _rule("AtCap", *[f"pat-{i}" for i in range(MAX_PATTERNS_PER_RULE)])
    assert len(ok.patterns) == MAX_PATTERNS_PER_RULE


def test_hunt_p1_14_pattern_cap_rejects_rule_at_load(tmp_path):
    specs = [
        {
            "name": "TooManyPatterns",
            "description": "test",
            "severity": "high",
            "condition": "any",
            "patterns": [{"text": f"p{i}"} for i in range(MAX_PATTERNS_PER_RULE + 5)],
        },
        {
            "name": "Good",
            "description": "test",
            "severity": "low",
            "condition": "any",
            "patterns": [{"text": "fine"}],
        },
    ]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(specs), encoding="utf-8")
    assert [r.name for r in load_rules(path)] == ["Good"]


def test_hunt_p1_14_rules_file_size_cap(tmp_path):
    path = tmp_path / "huge-rules.json"
    # Invalid JSON *and* over the cap: the cap error must win,
    # proving the size is refused before parsing.
    path.write_bytes(b"[" + b" " * (MAX_RULES_FILE_SIZE + 1))
    assert path.stat().st_size > MAX_RULES_FILE_SIZE
    with pytest.raises(RuleError, match="cap"):
        load_rules(path)


def test_hunt_p1_14_rules_file_under_cap_still_loads(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "Small",
                    "description": "test",
                    "severity": "low",
                    "condition": "any",
                    "patterns": [{"text": "hello"}],
                }
            ]
        ),
        encoding="utf-8",
    )
    assert [r.name for r in load_rules(path)] == ["Small"]


# ======================================================================
# P1-21 — tail pass catches an EOF payload after budget death
# ======================================================================
def test_hunt_p1_21_tail_pass_catches_eof_payload_after_budget_death():
    rule = _rule("TailPayload", "EOFPAYLOADMARKER")
    clock = _ManualClock()
    matcher = RuleMatcher([rule], time_budget=2.0)
    matcher._clock = clock
    chunk = b"x" * (1024 * 1024)
    matcher.feed(chunk)  # primary pass starts healthy
    clock.advance(60.0)  # budget dies long before EOF
    for _ in range(7):
        matcher.feed(chunk)  # captured for the tail, never matched
    matcher.feed(chunk + b"EOFPAYLOADMARKER")  # EOF chunk
    assert matcher.budget_exceeded is True
    hits = matcher.finish()
    assert any(h.name == "TailPayload" for h in hits)
    assert matcher.tail_pass_ran is True
    assert matcher.budget_exceeded is True  # still honestly partial
    assert matcher.partial_coverage is True
    note = matcher.coverage_note or ""
    assert "both passes ran" in note
    assert "tail pass" in note
    assert "primary" in note


def test_hunt_p1_21_no_tail_pass_when_budget_healthy():
    rule = _rule("Healthy", "needle")
    matcher = RuleMatcher([rule], time_budget=60.0)
    matcher.feed(b"a needle here")
    hits = matcher.finish()
    assert any(h.name == "Healthy" for h in hits)
    assert matcher.tail_pass_ran is False
    assert matcher.coverage_note is None
    assert matcher.budget_exceeded is False


def test_hunt_p1_21_evaluate_stream_surfaces_tail_state():
    rule = _rule("Streamed", "spanningneedle")
    hits, matcher = evaluate_stream(
        [b"spann", b"ingneedle here"], [rule]
    )
    assert any(h.name == "Streamed" for h in hits)
    assert matcher.budget_exceeded is False


# ======================================================================
# P1-18 — watcher rescan on same-size, same-mtime content swap
# ======================================================================
def test_hunt_p1_18_sampled_hash_covers_head_and_tail(tmp_path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * 200_000)
    before = sampled_content_hash(target, target.stat().st_size)
    # Change ONLY the last KiB (inside the tail sample).
    with open(target, "r+b") as fh:
        fh.seek(199_000)
        fh.write(b"B" * 1000)
    after_tail = sampled_content_hash(target, target.stat().st_size)
    assert after_tail != before
    # Change ONLY the first KiB (inside the head sample).
    with open(target, "r+b") as fh:
        fh.seek(0)
        fh.write(b"C" * 1000)
    assert sampled_content_hash(target, target.stat().st_size) != after_tail


def test_hunt_p1_18_timestomped_same_size_swap_rescans(tmp_path):
    ready: list = []
    watcher = DirectoryWatcher(
        [tmp_path], poll_interval=0.05, stable_polls=2,
        on_ready=ready.append,
    )
    target = tmp_path / "payload.bin"
    target.write_bytes(b"A" * 4096)
    assert watcher.poll_once() == []
    assert watcher.poll_once() == [target]  # stable: scanned

    st = target.stat()
    target.write_bytes(b"B" * 4096)  # same size, new content
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))  # timestomp
    now = target.stat()
    assert now.st_size == st.st_size
    assert now.st_mtime_ns == st.st_mtime_ns

    # The old (size, mtime)-only signature would call this file
    # "already scanned" forever. The sampled hash sees the swap:
    # the file re-enters the stability wait and is reported again.
    assert watcher.poll_once() == []
    assert watcher.poll_once() == [target]
    assert ready == [target, target]


# ======================================================================
# P2 — realtime: ADS on the process path + retry list pruning
# ======================================================================
@pytest.fixture()
def rt_engine(tmp_path):
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
    engine = RealtimeEngine(config, db, [], on_event=events.append)
    yield engine, events, tmp_path
    engine.stop()
    db.close()


def test_hunt_p2_ads_hook_runs_on_process_path(rt_engine, monkeypatch):
    engine, _events, tmp_path = rt_engine
    calls: list = []

    def fake_scan_named_streams(path, db, rules, **kwargs):
        calls.append((Path(path), kwargs))
        return []

    monkeypatch.setattr(realtime, "scan_named_streams", fake_scan_named_streams)
    target = tmp_path / "launched.exe"
    target.write_bytes(b"MZ ordinary clean image")
    proc = ProcessInfo(pid=4242, name="launched.exe", image_path=target)
    engine._process(
        _WorkItem(path=target, source="process", process=proc)
    )
    assert calls and calls[0][0] == target  # ADS ran for a process launch

    calls.clear()
    watched_file = tmp_path / "dropped.bin"
    watched_file.write_bytes(b"ordinary too")
    engine._process(_WorkItem(path=watched_file, source="watch"))
    assert calls and calls[0][0] == watched_file  # watch path kept it


def test_hunt_p2_retry_pruning_drops_vanished_files(rt_engine):
    engine, _events, tmp_path = rt_engine
    ghost = tmp_path / "never-existed.bin"  # locked, then vanished
    engine._handle_locked(_WorkItem(path=ghost, source="watch"))
    assert len(engine._retry_timers) == 1
    timer = engine._retry_timers[0]
    dropped = engine._prune_retry_timers()
    assert dropped >= 1
    assert engine._retry_timers == []
    assert timer.finished.is_set()  # cancelled, not left pending


def test_hunt_p2_retry_pruning_drops_finished_timers(rt_engine):
    engine, _events, tmp_path = rt_engine
    done = threading.Timer(0.01, lambda: None)
    done.start()
    deadline = time.time() + 5
    while not done.finished.is_set() and time.time() < deadline:
        time.sleep(0.01)
    assert done.finished.is_set()
    engine._retry_timers.append(done)
    assert engine._prune_retry_timers() >= 1
    assert engine._retry_timers == []


def test_hunt_p2_retry_exhaustion_prunes_pending_for_file(rt_engine):
    engine, events, tmp_path = rt_engine
    target = tmp_path / "locked.bin"
    target.write_bytes(b"locked content")
    engine._handle_locked(_WorkItem(path=target, source="watch", attempts=0))
    assert len(engine._retry_timers) == 1
    # The final attempt fails too: NotScanned is reported and no
    # pending retry entry for the file is left behind.
    engine._handle_locked(
        _WorkItem(path=target, source="watch", attempts=MAX_LOCKED_RETRIES)
    )
    assert engine._retry_timers == []
    assert any(
        e.kind == "detection" and e.verdict == "NotScanned" for e in events
    )


def test_hunt_p2_retry_list_is_bounded(rt_engine, monkeypatch):
    engine, _events, tmp_path = rt_engine
    monkeypatch.setattr(realtime, "MAX_PENDING_RETRY_TIMERS", 3)
    for i in range(6):
        f = tmp_path / f"locked-{i}.bin"
        f.write_bytes(b"x")
        engine._handle_locked(_WorkItem(path=f, source="watch", attempts=0))
    assert len(engine._retry_timers) <= 3


def test_hunt_p2_requeue_drops_vanished_file(rt_engine):
    engine, _events, tmp_path = rt_engine
    ghost = tmp_path / "gone.bin"
    engine._requeue(_WorkItem(path=ghost, source="watch", attempts=1))
    assert engine._queue.empty()
