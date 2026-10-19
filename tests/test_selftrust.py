"""Self-exclusion: Argus never scans itself — and the exemption
cannot be claimed by an impostor.

The set is consulted inside scan_file, before any read:
- (hunt P0-2) only the quarantine vault subtree and the
  signature-DB file + key are out of scope — the shared folder,
  config, history, status and install-dir support files scan
  normally;
- the program file is out of scope ONLY with an identity proof
  (hunt P1-8: the fingerprint recorded at setup decides when a
  record exists; the running exe is the fallback proof; an SCM
  registration alone is a locator, never a proof) — never by name;
- a file at the program's own address that CONTRADICTS the
  recorded fingerprint is scanned in full and reported as a
  tamper indicator; with no record, it is just scanned.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from pe_fixtures import clean_pe  # noqa: E402

from argus import selftrust, setup_engine  # noqa: E402
from argus.detections import Verdict  # noqa: E402
from argus.scanner import scan_file, scan_path  # noqa: E402
from argus.selftrust import SelfExclusions  # noqa: E402
from argus.signatures import SignatureDB, init_db  # noqa: E402

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------------
# The data tree: skipped pre-read
# ----------------------------------------------------------------------
def test_data_tree_file_skipped_before_any_read(db, tmp_path):
    data_root = tmp_path / "ProgramData" / "Argus"
    blob = data_root / "quarantine" / "blobs" / "sample.bin"
    blob.parent.mkdir(parents=True)
    blob.write_bytes(EICAR)  # even carrying the test virus string
    exclusions = SelfExclusions(data_roots=(data_root,))

    scanned = scan_file(blob, db, [], self_exclusions=exclusions)

    assert scanned.excluded is True
    assert scanned.exclusion_source == selftrust.SOURCE_VAULT
    # Pre-read proof: the file was never hashed or signature-checked.
    assert scanned.result.sha256 is None
    assert scanned.result.size == len(EICAR)  # stat only
    assert scanned.verdict is Verdict.CLEAN
    assert scanned.assessment.detections == []
    assert any(
        "does not scan its own files" in note
        for note in scanned.assessment.notes
    )


def test_scan_path_reports_self_files_as_excluded(db, tmp_path):
    # Hunt P0-2: the exclusion scope is the vault subtree + the
    # signature DB files — shared\history.db scans normally now.
    data_root = tmp_path / "data"
    (data_root / "shared").mkdir(parents=True)
    (data_root / "shared" / "history.db").write_bytes(b"argus state")
    (data_root / "quarantine").mkdir(parents=True)
    (data_root / "quarantine" / "blob.bin").write_bytes(b"neutralised")
    outsider = tmp_path / "outside.txt"
    outsider.write_text("ordinary")
    exclusions = SelfExclusions(data_roots=(data_root,))

    report = scan_path(tmp_path, db, [], self_exclusions=exclusions)

    by_name = {f.path.name: f for f in report.files}
    assert by_name["blob.bin"].excluded is True
    assert by_name["blob.bin"].exclusion_source is not None
    assert by_name["history.db"].excluded is False
    assert by_name["outside.txt"].excluded is False
    assert report.stats.files_excluded == 1


# ----------------------------------------------------------------------
# Abuse resistance: a NAME earns nothing
# ----------------------------------------------------------------------
def test_eicar_named_argus_exe_in_random_folder_is_detected(db, tmp_path):
    impostor = tmp_path / "Downloads" / "Argus.exe"
    impostor.parent.mkdir()
    impostor.write_bytes(EICAR)
    # Even with a full self-exclusion set for a DIFFERENT install,
    # this file is a stranger and gets scanned.
    exclusions = SelfExclusions(
        data_roots=(tmp_path / "elsewhere-data",),
        install_dir=tmp_path / "elsewhere-install",
        own_exe=tmp_path / "elsewhere-install" / "Argus.exe",
    )

    scanned = scan_file(impostor, db, [], self_exclusions=exclusions)

    assert scanned.excluded is False
    assert scanned.exclusion_source is None
    assert scanned.verdict is Verdict.MALICIOUS
    assert scanned.assessment.detections[0].name == "EICAR-Test-File"


def test_check_tamper_suspect_when_identity_proofs_absent(tmp_path):
    # Hunt P1-8: with NO recorded fingerprint, absence of proofs
    # is not tamper evidence — the file is simply a stranger's
    # (scanned normally, no signal). Tamper requires a record
    # that the file contradicts.
    exe = tmp_path / "Program Files" / "Argus" / "Argus.exe"
    exclusions = SelfExclusions(own_exe=exe)  # no proofs at all
    outcome = exclusions.check(exe)
    assert outcome.excluded is False
    assert outcome.tamper_suspect is False


# ----------------------------------------------------------------------
# The program file: identity decides
# ----------------------------------------------------------------------
def test_exe_excluded_by_recorded_fingerprint(db, tmp_path):
    exe = tmp_path / "install" / "Argus.exe"
    exe.parent.mkdir(parents=True)
    payload = clean_pe()
    exe.write_bytes(payload)
    exclusions = SelfExclusions(
        own_exe=exe, recorded_exe_sha256=_sha(payload)
    )
    scanned = scan_file(exe, db, [], self_exclusions=exclusions)
    assert scanned.excluded is True
    assert scanned.exclusion_source == selftrust.SOURCE_RECORDED_EXE
    assert scanned.result.sha256 is None  # skipped pre-read


def test_exe_excluded_as_the_running_program(db, tmp_path):
    exe = tmp_path / "install" / "Argus.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(clean_pe())
    exclusions = SelfExclusions(own_exe=exe, running_exe=exe)
    scanned = scan_file(exe, db, [], self_exclusions=exclusions)
    assert scanned.excluded is True
    assert scanned.exclusion_source == selftrust.SOURCE_RUNNING_EXE


def test_exe_excluded_as_the_scm_registered_program(db, tmp_path):
    # Hunt P1-8: an SCM registration is a LOCATOR, not an identity
    # proof — with no recorded fingerprint it exempts nothing
    # (and accuses nothing: the file is scanned, no tamper flag).
    exe = tmp_path / "install" / "Argus.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(clean_pe())
    exclusions = SelfExclusions(own_exe=exe, scm_exe=exe)
    scanned = scan_file(exe, db, [], self_exclusions=exclusions)
    assert scanned.excluded is False
    assert scanned.exclusion_source is None
    assert not any(
        sig.name == "argus_program_file_replaced"
        for sig in scanned.assessment.signals
    )


def test_exe_with_wrong_fingerprint_is_scanned_and_flagged(db, tmp_path):
    """The tamper case: the file at the program's address is not
    the program setup installed. No exclusion, full scan, and a
    tamper signal on top of whatever the content earns."""
    exe = tmp_path / "install" / "Argus.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(clean_pe())  # innocuous content, wrong identity
    exclusions = SelfExclusions(
        own_exe=exe, recorded_exe_sha256=_sha(b"the-real-argus")
    )

    scanned = scan_file(exe, db, [], self_exclusions=exclusions)

    assert scanned.excluded is False
    assert scanned.result.sha256 == _sha(clean_pe())  # really read
    names = {sig.name for sig in scanned.assessment.signals}
    assert "argus_program_file_replaced" in names
    assert scanned.verdict is Verdict.SUSPICIOUS
    assert any(
        "tamper indicator" in note for note in scanned.assessment.notes
    )


def test_install_dir_support_file_excluded(db, tmp_path):
    # Hunt P0-2: the blanket install-tree exclusion is gone — in
    # the install dir ONLY the identity-proven exe is exempt;
    # support files scan normally (this one is detected).
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    support = install_dir / "readme.txt"
    support.write_bytes(EICAR)
    exclusions = SelfExclusions(
        install_dir=install_dir, own_exe=install_dir / "Argus.exe"
    )
    scanned = scan_file(support, db, [], self_exclusions=exclusions)
    assert scanned.excluded is False
    assert scanned.exclusion_source is None
    assert scanned.verdict is Verdict.MALICIOUS


# ----------------------------------------------------------------------
# The default set, built from the machine (env-driven)
# ----------------------------------------------------------------------
def test_default_set_skips_the_live_data_tree(db, tmp_path, monkeypatch):
    data_root = tmp_path / "live-data"
    blob = data_root / "quarantine" / "blobs" / "x.bin"
    blob.parent.mkdir(parents=True)
    blob.write_bytes(EICAR)
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
    selftrust.reset_default_cache()

    scanned = scan_file(blob, db, [])  # no explicit set: the default

    assert scanned.excluded is True
    assert scanned.exclusion_source == selftrust.SOURCE_VAULT
    selftrust.reset_default_cache()


def test_realtime_engine_drops_own_files(tmp_path, monkeypatch):
    """Watcher events for Argus's own tree die in the engine's
    exclusion path: counted as excluded, never a detection."""
    from argus.config import ArgusConfig
    from argus.realtime import RealtimeEngine
    from argus.rules import BUILTIN_RULES

    watched = tmp_path / "argus-data"
    watched.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(watched))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
    selftrust.reset_default_cache()

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
    db_handle = SignatureDB.open(db_path)
    engine = RealtimeEngine(config, db_handle, BUILTIN_RULES,
                            on_event=events.append)
    try:
        engine.start()
        # Hunt P0-2: only the vault subtree of the data root is
        # self-excluded now — the test file lives there (a file at
        # the data root itself would scan normally and detect).
        (watched / "quarantine").mkdir(exist_ok=True)
        (watched / "quarantine" / "eicar.com").write_bytes(EICAR)
        deadline = time.time() + 8.0
        while time.time() < deadline and engine.stats.files_excluded < 1:
            time.sleep(0.05)
        assert engine.stats.files_excluded >= 1
        time.sleep(0.3)
        assert [e for e in events if e.kind == "detection"] == []
    finally:
        engine.stop()
        db_handle.close()
        selftrust.reset_default_cache()


# ----------------------------------------------------------------------
# Setup records the fingerprint the scanner later trusts
# ----------------------------------------------------------------------
def test_record_and_load_roundtrip(tmp_path):
    exe = tmp_path / "Argus.exe"
    exe.write_bytes(b"program-bytes")
    target = selftrust.record_exe_identity(exe, tmp_path, version="1.1.0")
    assert target.name == selftrust.SELF_IDENTITY_NAME
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["exe_sha256"] == _sha(b"program-bytes")
    assert payload["exe_path"] == str(exe)
    assert selftrust.load_recorded_exe_sha256(tmp_path) == _sha(b"program-bytes")
    assert selftrust.load_recorded_exe_sha256(tmp_path / "missing") is None


def test_install_records_program_fingerprint(tmp_path, monkeypatch):
    program_files = tmp_path / "Program Files"
    monkeypatch.setenv("ProgramFiles", str(program_files))
    monkeypatch.delenv("ARGUS_DATA_DIR", raising=False)
    canonical = setup_engine.canonical_exe_path()
    data_root = tmp_path / "ProgramData" / "Argus"
    source = tmp_path / "Downloads" / "Argus.exe"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"the-real-program")

    states = iter(["not-installed", "running"])
    result = setup_engine.install(
        source_exe=source,
        run_command=lambda argv: __import__("subprocess").CompletedProcess(
            argv, 0, "", ""
        ),
        install_service_fn=lambda exe: None,
        remove_service_fn=lambda: None,
        stop_service_fn=lambda: None,
        register_av_fn=lambda exe: None,
        write_uninstall_entry_fn=lambda exe: None,
        start_service_fn=lambda: None,
        scm_state_fn=lambda: next(states, "running"),
        read_heartbeat_fn=lambda: {
            "running": True,
            "heartbeat_at": datetime.now(timezone.utc).isoformat(),
        },
        data_root=data_root,
        sleep=lambda _s: None,
        monotonic=lambda: 0.0,
        verify_timeout=5.0,
    )
    assert result.state is setup_engine.SetupState.RUNNING

    recorded = selftrust.load_recorded_exe_sha256(data_root)
    assert recorded == _sha(b"the-real-program")

    # And the recorded proof actually exempts the placed program.
    exclusions = SelfExclusions(
        own_exe=canonical, recorded_exe_sha256=recorded
    )
    outcome = exclusions.check(canonical)
    assert outcome.excluded is True
    assert outcome.source == selftrust.SOURCE_RECORDED_EXE
