"""Hunt fix-pass tests — Package C (vault / service / channel).

Names carry finding ids: P0-1 service-owned pending queue, channel
hardening (nonce / isolation / ordering), P1-4 vault row MAC,
P1-9 simulation seam + devtools relocation, P1-10 no raw errors,
P2 batch (restore claim, delete ordering, malformed rows, bench
through scan_file).
"""

import hashlib
import json
import sqlite3
import threading

import pytest

from argus import action_requests
from argus.actions import ActionEngine, ActionError, DetectionInfo
from argus.config import ArgusConfig, Exclusions
from argus.devtools import run_test_bench, simulation_mode_enabled
from argus.paths import (
    default_pending_db,
    default_vault_dir,
    legacy_shared_pending_db,
    pending_view_path,
    shared_dir,
)
from argus.quarantine import QuarantineError, Vault, read_pending_db, read_pending_view
from argus.rules import BUILTIN_RULES, Rule
from argus.rules import Pattern
from argus.scanner import scan_file
from argus.service import ArgusService
from argus.signatures import SignatureError, init_db

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _info(data: bytes, name="Test.Detection"):
    return DetectionInfo(
        name=name, severity="high", verdict="Malicious",
        reasons=["test"], sha256=_sha(data),
    )


@pytest.fixture()
def svc_env(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    req = shared / "requests"
    res = shared / "results"
    req.mkdir(parents=True)
    res.mkdir(parents=True)
    monkeypatch.setattr("argus.service.requests_dir", lambda: req)
    monkeypatch.setattr("argus.service.results_dir", lambda: res)
    monkeypatch.setattr(
        "argus.service.vault_view_path", lambda: shared / "vault-view.json"
    )
    monkeypatch.setattr(
        "argus.service.pending_view_path", lambda: shared / "pending-view.json"
    )
    config = ArgusConfig(status_file=str(tmp_path / "status.json"))
    vault = Vault.open(tmp_path / "vault", tmp_path / "trusted" / "pending.db")
    engine = ActionEngine(vault, config, config_path=tmp_path / "cfg.json")
    svc = ArgusService(config=config)
    svc.vault = vault
    svc.actions = engine
    svc.state = "running"
    yield {
        "svc": svc, "vault": vault, "engine": engine, "config": config,
        "root": tmp_path, "shared": shared, "req": req, "res": res,
    }
    vault.close()


def _drop_request(env, rid, payload):
    payload = {"id": rid, **payload}
    (env["req"] / f"{rid}.json").write_text(json.dumps(payload), encoding="utf-8")
    return payload


def _result(env, rid):
    return json.loads((env["res"] / f"{rid}.json").read_text(encoding="utf-8"))


# ----------------------------------------------------------------------
# P0-1 — paths, pending view, legacy migration
# ----------------------------------------------------------------------
def test_hunt_p0_1_pending_db_is_trusted_and_view_is_shared(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    assert default_pending_db() == default_vault_dir() / "pending.db"
    assert default_pending_db() == tmp_path / "data" / "quarantine" / "pending.db"
    assert legacy_shared_pending_db() == shared_dir() / "pending.db"
    assert pending_view_path() == shared_dir() / "pending-view.json"


def test_hunt_p0_1_pending_view_roundtrip_and_corrupt(tmp_path):
    view = tmp_path / "pending-view.json"
    assert read_pending_view(view) == []  # missing
    view.write_text("{not json", encoding="utf-8")
    assert read_pending_view(view) == []  # corrupt
    vault = Vault.open(tmp_path / "vault", tmp_path / "p.db")
    try:
        row = vault.add_pending(
            source="realtime", path="/tmp/x.exe", action="quarantine",
            sha256="a" * 64,
        )
        view.write_text(
            json.dumps({"generated_at": "t", "pending": [row.to_dict()]}),
            encoding="utf-8",
        )
        rows = read_pending_view(view)
        assert [r.id for r in rows] == [row.id]
        assert rows[0].action == "quarantine"
    finally:
        vault.close()


def test_hunt_p0_1_service_publishes_pending_view(svc_env):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = env["engine"].enqueue(
        source="realtime", path=target, action="quarantine", info=_info(EICAR)
    )
    env["svc"]._publish_pending_view(force=True)
    rows = read_pending_view(env["shared"] / "pending-view.json")
    assert [r.id for r in rows] == [pending.id]


def test_hunt_p0_1_forged_legacy_row_cannot_drive_approval_or_exclusion(
    svc_env, monkeypatch, tmp_path
):
    """A forged row planted in the legacy SHARED pending DB — its
    fingerprint does not match the live file and it names no real
    vault entry — is dropped at migration. An approve request for
    its id is then refused, the file is untouched, and no exclusion
    is created."""
    env = svc_env
    target = tmp_path / "victim.exe"
    target.write_bytes(b"innocent contents")
    legacy = tmp_path / "shared-legacy" / "pending.db"
    legacy_vault = Vault.open(tmp_path / "legacy-vault", legacy)
    try:
        forged = legacy_vault.add_pending(
            source="realtime", path=target, action="quarantine",
            sha256=_sha(b"totally different bytes"),  # does NOT match live file
            detection_name="Forged.Detection",
        )
        forged_id = forged.id
    finally:
        legacy_vault.close()
    monkeypatch.setattr("argus.service.legacy_shared_pending_db", lambda: legacy)
    env["svc"]._migrate_legacy_pending(env["vault"])
    # Dropped, not migrated; legacy evidence renamed away.
    assert env["vault"].get_pending(forged_id) is None
    assert not legacy.exists()
    assert (legacy.parent / "pending.db.migrated").exists()
    # An approval request for the forged id is refused.
    result = env["svc"]._execute_request(
        {"id": "r1", "kind": "approve-pending", "pending_id": forged_id,
         "sha256": _sha(b"totally different bytes")}
    )
    assert result["ok"] is False
    assert target.read_bytes() == b"innocent contents"
    # And no exclusion was produced by any of it.
    assert env["config"].exclusions.hashes == frozenset()
    allow = env["svc"]._execute_request(
        {"id": "r2", "kind": "allow", "entry_id": forged_id,
         "sha256": _sha(b"totally different bytes")}
    )
    assert allow["ok"] is False
    assert env["config"].exclusions.hashes == frozenset()


def test_hunt_p0_1_verified_legacy_row_migrates(svc_env, monkeypatch, tmp_path):
    """UPDATED in fix round 2 (FIX 2 — disclosed in the round-2
    report): round 1 migrated a row whose LIVE FILE hashed to
    the row's sha256. That leg proved nothing — anyone can hash
    any file — so round 2 migrates ONLY entry-bound rows (the
    referenced vault entry's blob must decrypt under the vault
    key to exactly the row's sha256). Both halves are pinned
    here now: an entry-bound row migrates; a live-hash-only row
    is DROPPED and counted."""
    env = svc_env
    vault = env["vault"]

    # The anchor: a real entry in the TRUSTED vault.
    entry_target = tmp_path / "bound.exe"
    entry_target.write_bytes(EICAR)
    entry = vault.quarantine_file(entry_target, detection_name="Bound")

    # A live file whose hash a legacy row can match WITHOUT any
    # vault entry — round 1 kept this row; round 2 drops it.
    orphan_target = tmp_path / "orphan.exe"
    orphan_target.write_bytes(b"orphan-bytes")

    legacy = tmp_path / "legacy" / "pending.db"
    lv = Vault.open(tmp_path / "lv", legacy)
    try:
        bound = lv.add_pending(
            source="realtime", path=entry_target, action="quarantine",
            sha256=_sha(EICAR),
        )
        lv.update_pending(bound.id, status="pending", entry_id=entry.id)
        orphan = lv.add_pending(
            source="realtime", path=orphan_target, action="delete",
            sha256=_sha(b"orphan-bytes"),
        )
        bound_id, orphan_id = bound.id, orphan.id
    finally:
        lv.close()
    monkeypatch.setattr("argus.service.legacy_shared_pending_db", lambda: legacy)
    env["svc"]._migrate_legacy_pending(env["vault"])
    assert env["vault"].get_pending(bound_id) is not None
    assert env["vault"].get_pending(orphan_id) is None
    assert env["svc"]._legacy_pending_dropped == 1
    assert (legacy.parent / "pending.db.migrated").exists()


def test_hunt_p0_1_approve_missing_sha_refused(svc_env):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = env["engine"].enqueue(
        source="realtime", path=target, action="quarantine", info=_info(EICAR)
    )
    result = env["svc"]._execute_request(
        {"id": "r", "kind": "approve-pending", "pending_id": pending.id}
    )
    assert result["ok"] is False
    assert "fingerprint" in result["message"]
    # Nothing marked, nothing moved.
    assert env["vault"].get_pending(pending.id).status == "pending"
    assert target.exists()


def test_hunt_p0_1_restore_missing_sha_refused(svc_env):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    entry = env["vault"].quarantine_file(target, detection_name="T")
    result = env["svc"]._execute_request(
        {"id": "r", "kind": "restore", "entry_id": entry.id}
    )
    assert result["ok"] is False
    assert env["vault"].get_entry(entry.id).status == "quarantined"


def test_hunt_p0_1_approve_live_hash_mismatch_refused_and_unmarked(svc_env):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = env["engine"].enqueue(
        source="realtime", path=target, action="quarantine", info=_info(EICAR)
    )
    target.write_bytes(b"swapped after queueing")
    result = env["svc"]._execute_request(
        {"id": "r", "kind": "approve-pending", "pending_id": pending.id,
         "sha256": _sha(EICAR)}  # matches the ROW, not the live file
    )
    assert result["ok"] is False
    # Refusal marks nothing: the row is still pending (not failed).
    assert env["vault"].get_pending(pending.id).status == "pending"
    assert target.read_bytes() == b"swapped after queueing"


# ----------------------------------------------------------------------
# Channel hardening — nonce, isolation, ordering, restart
# ----------------------------------------------------------------------
def test_hunt_channel_nonce_mismatch_result_ignored(tmp_path):
    req = tmp_path / "requests"
    res = tmp_path / "results"
    res.mkdir(parents=True)
    rid = action_requests.submit_request(
        "restore", entry_id="e1", sha256="a" * 64, requests=req
    )
    payload = json.loads((req / f"{rid}.json").read_text(encoding="utf-8"))
    assert payload["nonce"]  # v2: request carries a nonce
    # A planted result with the WRONG nonce is ignored: the caller
    # keeps waiting and times out instead of believing it.
    (res / f"{rid}.json").write_text(
        json.dumps({"id": rid, "ok": True, "message": "planted", "nonce": "0" * 32}),
        encoding="utf-8",
    )
    timed_out = action_requests.await_result(rid, results=res, timeout=0.6)
    assert timed_out.ok is False
    assert "did not answer" in timed_out.message
    # A result with NO nonce is ignored too.
    rid2 = action_requests.submit_request(
        "restore", entry_id="e2", sha256="b" * 64, requests=req
    )
    (res / f"{rid2}.json").write_text(
        json.dumps({"id": rid2, "ok": True, "message": "planted"}),
        encoding="utf-8",
    )
    timed_out2 = action_requests.await_result(rid2, results=res, timeout=0.6)
    assert timed_out2.ok is False


def test_hunt_channel_nonce_matching_result_accepted(tmp_path):
    req = tmp_path / "requests"
    res = tmp_path / "results"
    res.mkdir(parents=True)
    rid = action_requests.submit_request(
        "restore", entry_id="e1", sha256="a" * 64, requests=req
    )
    nonce = json.loads((req / f"{rid}.json").read_text(encoding="utf-8"))["nonce"]
    (res / f"{rid}.json").write_text(
        json.dumps({"id": rid, "ok": True, "message": "done", "nonce": nonce}),
        encoding="utf-8",
    )
    got = action_requests.await_result(rid, results=res, timeout=2.0)
    assert got.ok is True and got.message == "done"


def test_hunt_channel_directory_named_json_does_not_starve_batch(svc_env):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = env["engine"].enqueue(
        source="realtime", path=target, action="quarantine", info=_info(EICAR)
    )
    (env["req"] / "0000dir.json").mkdir()  # a DIRECTORY named *.json
    rid = "b" * 32
    _drop_request(
        env, rid,
        {"kind": "reject-pending", "pending_id": pending.id, "sha256": _sha(EICAR)},
    )
    processed = env["svc"].process_requests_once()
    assert processed == 1
    assert _result(env, rid)["ok"] is True
    assert env["vault"].get_pending(pending.id).status == "rejected"
    assert (env["req"] / "rejected" / "0000dir.json").is_dir()


def test_hunt_channel_oversized_request_rejected(svc_env):
    env = svc_env
    rid = "c" * 32
    (env["req"] / f"{rid}.json").write_bytes(b"x" * (64 * 1024 + 1))
    good_id = "d" * 32
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = env["engine"].enqueue(
        source="realtime", path=target, action="quarantine", info=_info(EICAR)
    )
    _drop_request(
        env, good_id,
        {"kind": "reject-pending", "pending_id": pending.id, "sha256": _sha(EICAR)},
    )
    env["svc"].process_requests_once()
    assert (env["req"] / "rejected" / f"{rid}.json").exists()
    assert not (env["res"] / f"{rid}.json").exists()
    assert _result(env, good_id)["ok"] is True  # batch not starved


def test_hunt_channel_unknown_kind_and_id_mismatch_rejected(svc_env):
    env = svc_env
    rid = "e" * 32
    _drop_request(env, rid, {"kind": "nuke-everything", "sha256": "a" * 64})
    rid2 = "f" * 32
    (env["req"] / f"{rid2}.json").write_text(
        json.dumps({"id": "someone-else", "kind": "restore"}), encoding="utf-8"
    )
    env["svc"].process_requests_once()
    assert (env["req"] / "rejected" / f"{rid}.json").exists()
    assert (env["req"] / "rejected" / f"{rid2}.json").exists()


def test_hunt_channel_result_exists_on_restart_no_reexecution(svc_env, monkeypatch):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = env["engine"].enqueue(
        source="realtime", path=target, action="quarantine", info=_info(EICAR)
    )
    calls = []
    real_impl = env["svc"]._execute_request_impl

    def counting(request):
        calls.append(request)
        return real_impl(request)

    monkeypatch.setattr(env["svc"], "_execute_request_impl", counting)
    rid = "1" * 32
    _drop_request(
        env, rid,
        {"kind": "approve-pending", "pending_id": pending.id, "sha256": _sha(EICAR)},
    )
    # The result already exists (written before a restart).
    (env["res"] / f"{rid}.json").write_text(
        json.dumps({"id": rid, "ok": True, "message": "already done"}),
        encoding="utf-8",
    )
    env["svc"].process_requests_once()
    assert calls == []  # NO re-execution
    assert not (env["req"] / f"{rid}.json").exists()  # request removed
    assert env["vault"].get_pending(pending.id).status == "pending"
    assert target.exists()


def test_hunt_channel_service_echoes_nonce(svc_env):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = env["engine"].enqueue(
        source="realtime", path=target, action="quarantine", info=_info(EICAR)
    )
    rid = "2" * 32
    _drop_request(
        env, rid,
        {"kind": "reject-pending", "pending_id": pending.id,
         "sha256": _sha(EICAR), "nonce": "n0nce-value"},
    )
    env["svc"].process_requests_once()
    assert _result(env, rid)["nonce"] == "n0nce-value"


# ----------------------------------------------------------------------
# P1-4 — vault row MAC + blob traversal
# ----------------------------------------------------------------------
def _tamper(vault, entry_id, **fields):
    with vault._lock:
        assignments = ", ".join(f"{k} = ?" for k in fields)
        vault._conn.execute(
            f"UPDATE entries SET {assignments} WHERE id = ?",
            (*fields.values(), entry_id),
        )
        vault._conn.commit()


def test_hunt_p1_4_tampered_vault_row_refused_on_restore_and_delete(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    try:
        target = tmp_path / "evil.exe"
        target.write_bytes(EICAR)
        entry = vault.quarantine_file(target, detection_name="T")
        _tamper(vault, entry.id, sha256="0" * 64)  # hand edit, no key
        with pytest.raises(QuarantineError, match="tamper"):
            vault.restore(entry.id)
        with pytest.raises(QuarantineError, match="tamper"):
            vault.delete_permanent(entry.id)
        assert vault.get_entry(entry.id).status == "quarantined"
    finally:
        vault.close()


def test_hunt_p1_4_blob_name_traversal_refused(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    try:
        target = tmp_path / "evil.exe"
        target.write_bytes(EICAR)
        entry = vault.quarantine_file(target, detection_name="T")
        # Even with a MAC recomputed for the tampered name (attacker
        # somehow seals it), the blob-name format/traversal guard
        # refuses on its own.
        evil_name = "../../escape.blob"
        mac = vault._entry_mac(
            entry_id=entry.id, original_path=entry.original_path,
            blob_name=evil_name, sha256=entry.sha256,
        )
        _tamper(vault, entry.id, blob_name=evil_name, row_mac=mac)
        with pytest.raises(QuarantineError):
            vault.restore(entry.id)
        with pytest.raises(QuarantineError):
            vault.delete_permanent(entry.id)
    finally:
        vault.close()


def test_hunt_p1_4_legacy_row_adopted_only_after_revalidation(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    target = tmp_path / "evil.exe"
    target.write_bytes(EICAR)
    entry = vault.quarantine_file(target, detection_name="T")
    vault.close()
    # Strip the MAC: the row looks legacy. Its blob still verifies,
    # so reopening adopts a fresh MAC and restore works.
    conn = sqlite3.connect(tmp_path / "vault" / "vault.db")
    conn.execute("UPDATE entries SET row_mac = NULL WHERE id = ?", (entry.id,))
    conn.commit()
    conn.close()
    reopened = Vault.open(tmp_path / "vault")
    try:
        assert reopened.get_entry(entry.id).row_mac
        assert reopened.restore(entry.id) == target
    finally:
        reopened.close()


def test_hunt_p1_4_legacy_row_failing_revalidation_refused(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    target = tmp_path / "evil.exe"
    target.write_bytes(EICAR)
    entry = vault.quarantine_file(target, detection_name="T")
    vault.close()
    # Legacy-looking row whose recorded sha does NOT match its blob:
    # re-validation at open must fail, and execution must refuse.
    conn = sqlite3.connect(tmp_path / "vault" / "vault.db")
    conn.execute(
        "UPDATE entries SET row_mac = NULL, sha256 = ? WHERE id = ?",
        ("0" * 64, entry.id),
    )
    conn.commit()
    conn.close()
    reopened = Vault.open(tmp_path / "vault")
    try:
        with pytest.raises(QuarantineError, match="tamper"):
            reopened.restore(entry.id)
    finally:
        reopened.close()


# ----------------------------------------------------------------------
# P1-9 — simulation seam + devtools default location
# ----------------------------------------------------------------------
def _write_sim_settings(tmp_path, monkeypatch, on=True):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    shared = tmp_path / "data" / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    (shared / "argus-devtools.json").write_text(
        json.dumps({"simulation_mode": on}), encoding="utf-8"
    )


def test_hunt_p1_9_devtools_default_location_is_shared(tmp_path, monkeypatch):
    from argus.devtools import default_devtools_path

    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    assert default_devtools_path() == shared_dir() / "argus-devtools.json"
    _write_sim_settings(tmp_path, monkeypatch, on=True)
    assert simulation_mode_enabled() is True
    _write_sim_settings(tmp_path, monkeypatch, on=False)
    assert simulation_mode_enabled() is False


def test_hunt_p1_9_sim_mode_blocks_real_delete_no_explicit_flag(
    tmp_path, monkeypatch
):
    _write_sim_settings(tmp_path, monkeypatch, on=True)
    vault = Vault.open(tmp_path / "vault")
    try:
        engine = ActionEngine(vault, ArgusConfig())
        target = tmp_path / "evil.exe"
        target.write_bytes(EICAR)
        # No explicit simulation flag passed — the persisted flag,
        # consulted at act time, blocks it.
        outcome = engine.delete(target, _info(EICAR), confirmed=True)
        assert outcome.done is False
        assert "Simulation mode" in outcome.message
        assert target.read_bytes() == EICAR
        assert vault.count() == 0
        q = engine.quarantine(target, _info(EICAR), confirmed=True)
        assert q.done is False and target.exists()
    finally:
        vault.close()


def test_hunt_p1_9_explicit_override_beats_persisted_flag(tmp_path, monkeypatch):
    _write_sim_settings(tmp_path, monkeypatch, on=True)
    vault = Vault.open(tmp_path / "vault")
    try:
        engine = ActionEngine(vault, ArgusConfig())
        target = tmp_path / "evil.exe"
        target.write_bytes(EICAR)
        outcome = engine.delete(
            target, _info(EICAR), confirmed=True, simulation=False
        )
        assert outcome.done is True
        assert not target.exists()
    finally:
        vault.close()


def test_hunt_p1_9_quarantine_without_fingerprint_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    vault = Vault.open(tmp_path / "vault")
    try:
        engine = ActionEngine(vault, ArgusConfig())
        target = tmp_path / "evil.exe"
        target.write_bytes(EICAR)
        info = DetectionInfo(name="T", severity="high", verdict="Malicious")
        with pytest.raises(ActionError, match="fingerprint"):
            engine.quarantine(target, info, confirmed=True)
        assert target.exists() and vault.count() == 0
    finally:
        vault.close()


# ----------------------------------------------------------------------
# P1-10 — no raw errors via the channel
# ----------------------------------------------------------------------
def test_hunt_p1_10_raw_errors_mapped_to_plain_language(svc_env, monkeypatch):
    env = svc_env
    target = env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    entry = env["vault"].quarantine_file(target, detection_name="T")

    def boom(exc):
        def _raise(*a, **k):
            raise exc
        return _raise

    cases = [
        (SignatureError("SECRET-DETAIL-SIG"), "signature database"),
        (PermissionError("SECRET-DETAIL-PERM"), "could not access"),
        (RuntimeError("SECRET-DETAIL-BOOM"), "could not be carried out"),
    ]
    for exc, expect in cases:
        monkeypatch.setattr(env["engine"], "restore_entry", boom(exc))
        result = env["svc"]._execute_request(
            {"id": "r", "kind": "restore", "entry_id": entry.id,
             "sha256": entry.sha256}
        )
        assert result["ok"] is False
        assert expect in result["message"]
        assert "SECRET-DETAIL" not in result["message"], result["message"]
        assert "the action failed:" not in result["message"]


# ----------------------------------------------------------------------
# P2 — restore claim, malformed pending rows, bench seam
# ----------------------------------------------------------------------
def test_hunt_p2_concurrent_restore_claim(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    try:
        target = tmp_path / "evil.exe"
        target.write_bytes(EICAR * 200)
        entry = vault.quarantine_file(target, detection_name="T")
        barrier = threading.Barrier(2)
        outcomes = []

        def attempt():
            barrier.wait(timeout=5)
            try:
                outcomes.append(("ok", vault.restore(entry.id)))
            except QuarantineError as exc:
                outcomes.append(("err", str(exc)))

        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        oks = [o for o in outcomes if o[0] == "ok"]
        errs = [o for o in outcomes if o[0] == "err"]
        assert len(oks) == 1 and len(errs) == 1, outcomes
        assert target.read_bytes() == EICAR * 200
        assert vault.get_entry(entry.id).status == "restored"
    finally:
        vault.close()


def test_hunt_p2_malformed_pending_row_isolated(tmp_path):
    vault = Vault.open(tmp_path / "vault", tmp_path / "pending.db")
    try:
        good = vault.add_pending(
            source="s", path="/tmp/good.exe", action="quarantine",
            sha256="a" * 64, reasons=["fine"],
        )
        bad = vault.add_pending(
            source="s", path="/tmp/bad.exe", action="quarantine",
            sha256="b" * 64,
        )
        with vault._lock:
            vault._pending_conn.execute(
                "UPDATE pending_actions SET reasons = 'not-json' WHERE id = ?",
                (bad.id,),
            )
            vault._pending_conn.commit()
        listed = vault.list_pending(None)
        assert [p.id for p in listed] == [good.id]
        assert vault.get_pending(bad.id) is None
        loose = read_pending_db(tmp_path / "pending.db")
        assert [p.id for p in loose] == [good.id]
    finally:
        vault.close()


def test_hunt_p2_delete_permanent_bookkeeping_before_shred(tmp_path, monkeypatch):
    vault = Vault.open(tmp_path / "vault")
    try:
        target = tmp_path / "evil.exe"
        target.write_bytes(EICAR)
        entry = vault.quarantine_file(target, detection_name="T")
        blob = vault.blobs_dir / entry.blob_name

        def failing_update(entry_id, **fields):
            raise QuarantineError("index unavailable (test)")

        monkeypatch.setattr(vault, "_update_entry", failing_update)
        with pytest.raises(QuarantineError):
            vault.delete_permanent(entry.id)
        # The update failed, so the blob must still be there.
        assert blob.exists()
    finally:
        vault.close()


def test_hunt_p2_bench_excluded_file_matches_scan_file(tmp_path):
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path, seed=True)
    target = tmp_path / "eicar.txt"
    target.write_bytes(EICAR)
    exclusions = Exclusions(hashes=frozenset({_sha(EICAR)}))
    with _open_db(db_path) as db:
        scanned = scan_file(target, db, BUILTIN_RULES, exclusions=exclusions)
        bench = run_test_bench(target, db, BUILTIN_RULES, exclusions=exclusions)
    assert scanned.excluded is True
    assert bench.verdict == scanned.verdict.value == "Clean"
    assert bench.signature_name is None


def test_hunt_p2_bench_oversize_file_matches_scan_file(tmp_path):
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path, seed=True)
    rule = Rule(
        name="Oversize_Test_Rule", description="test", severity="critical",
        patterns=(Pattern.from_text("evil-string"),),
    )
    target = tmp_path / "big.bin"
    with open(target, "wb") as fh:
        fh.write(b"evil-string at the head")
        fh.truncate(64 * 1024 * 1024 + 1024)  # over the rule cap, non-exec
    with _open_db(db_path) as db:
        scanned = scan_file(target, db, [rule])
        bench = run_test_bench(target, db, [rule])
    # Real scan skips pattern rules for oversize bulk; the old bench
    # fed the whole file to its own matcher and cried Malicious.
    assert scanned.verdict.value == "Clean"
    assert bench.verdict == scanned.verdict.value
    assert bench.rule_hits == []


def _open_db(path):
    from argus.signatures import SignatureDB

    return SignatureDB.open(path)
