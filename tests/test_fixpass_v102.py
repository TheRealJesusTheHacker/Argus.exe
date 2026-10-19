"""Regression tests for the v1.0.2 fix pass (bug-hunt findings
P0 #1/#2, P1 #3/#4, P2 #9–#20). GUI-side findings live in
tests/test_gui_smoke.py; service findings in tests/test_service.py;
Windows-registration findings in tests/test_winservice.py /
tests/test_winregister.py."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from argus import paths
from argus.actions import ActionEngine, ConfirmationRequired
from argus.config import ArgusConfig
from argus.devtools import SimulatedActionEngine
from argus.quarantine import QuarantineError, Vault
from argus.realtime import RealtimeEvent, _declare_toolhelp_prototypes
from argus.reporting import History
from argus.scanner import ScanStats, iter_files
from argus.signatures import (
    SignatureDB,
    ensure_signature_db,
    init_db,
)


# ----------------------------------------------------------------------
# P0 #1 / #2 — signature DB bootstrap + shared data location
# ----------------------------------------------------------------------

def test_signature_and_status_defaults_are_absolute_under_data_dir(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    config = ArgusConfig()
    for value in (config.signature_db, config.status_file):
        path = Path(value)
        assert path.is_absolute()
        assert path.parent == tmp_path / "data"


def test_data_dir_windows_uses_programdata(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("ARGUS_DATA_DIR", raising=False)
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    assert paths.data_dir() == Path(r"C:\ProgramData") / "Argus"
    monkeypatch.delenv("ProgramData")
    assert paths.data_dir() == Path(r"C:\ProgramData") / "Argus"


def test_data_dir_override_still_wins_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "portable"))
    assert paths.data_dir() == tmp_path / "portable"


def test_ensure_signature_db_creates_seeded_then_noops(tmp_path):
    db_path = tmp_path / "sub" / "signatures.sigdb"
    assert ensure_signature_db(db_path) is not None  # created
    assert db_path.is_file()
    info = SignatureDB.open(db_path).info
    assert info.count >= 1  # EICAR seed present
    # A second call changes nothing — an existing DB is never
    # re-seeded or overwritten.
    stamp = db_path.stat().st_mtime_ns
    assert ensure_signature_db(db_path) is None  # no-op
    assert db_path.stat().st_mtime_ns == stamp


def test_cli_scan_bootstraps_default_db(tmp_path, monkeypatch):
    # Regression (P0 #1): `argus scan` with no --db on a fresh
    # install must create + seed the DB under the data folder
    # instead of erroring out.
    from argus.cli import EXIT_CLEAN, main

    data_dir = tmp_path / "data"
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_dir))
    monkeypatch.chdir(tmp_path)  # nowhere near the data folder
    clean = tmp_path / "clean.txt"
    clean.write_text("perfectly ordinary text", encoding="utf-8")
    assert main(["scan", str(clean)]) == EXIT_CLEAN
    assert (data_dir / "signatures.sigdb").is_file()


# ----------------------------------------------------------------------
# P1 #3 / P2 #9 — signature DB init + open
# ----------------------------------------------------------------------

def test_init_db_reinit_keeps_count_truthful(tmp_path):
    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path, seed=True)
    assert SignatureDB.open(db_path).info.count >= 1
    # Re-init unseeded ("create a new database" contract): the old
    # rows must be gone AND the stored count must say so — the old
    # bug left the seeded count in meta with an empty table, and
    # open() then refused the DB as corrupt.
    init_db(db_path, seed=False)
    info = SignatureDB.open(db_path).info
    assert info.count == 0


def test_signature_db_path_with_uri_characters(tmp_path):
    # Regression (fix #9): #, %, and spaces in a path must not break
    # the read-only SQLite URI open() builds. ('?' would be the other
    # classic URI breaker, but it is illegal in Windows filenames, so
    # the fixture sticks to characters every OS allows.)
    weird = tmp_path / "we#ird dir%"
    weird.mkdir()
    db_path = weird / "sigs.sigdb"
    init_db(db_path, seed=True)
    db = SignatureDB.open(db_path)
    assert db.info.count >= 1
    db.close()


# ----------------------------------------------------------------------
# P1 #4 / P2 #11 — restore publishing
# ----------------------------------------------------------------------

def _vault_with_file(tmp_path, vault, name="evil.exe", data=b"x" * 5000):
    target = tmp_path / "downloads" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    entry = vault.quarantine_file(
        target, detection_name="Test.Detection", severity="high"
    )
    return target, entry


def test_restore_never_overwrites_existing_file(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    try:
        target, entry = _vault_with_file(tmp_path, vault)
        target.write_bytes(b"a different, innocent file")
        restored = vault.restore(entry.id)
        assert target.read_bytes() == b"a different, innocent file"
        assert restored.name == "evil (restored by Argus).exe"
        assert restored.read_bytes() == b"x" * 5000
    finally:
        vault.close()


def test_restore_works_when_hardlinks_unavailable(tmp_path, monkeypatch):
    # Regression (fix #4/#11): the publish step must not depend on
    # os.replace across volumes or on hard links — when os.link
    # fails, the name is claimed with an exclusive create instead.
    vault = Vault.open(tmp_path / "vault")
    try:
        _target, entry = _vault_with_file(tmp_path, vault)

        def no_links(src, dst):
            raise OSError("cross-device link")

        monkeypatch.setattr(os, "link", no_links)
        restored = vault.restore(entry.id)
        assert restored.read_bytes() == b"x" * 5000
    finally:
        vault.close()


# ----------------------------------------------------------------------
# P1 #7 — engine-level vault entry points (real + simulated)
# ----------------------------------------------------------------------

def test_action_engine_restore_and_delete_entry(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    history = History.open(tmp_path / "history.db")
    engine = ActionEngine(vault, history=history)
    try:
        _target, entry = _vault_with_file(tmp_path, vault)
        # The never-silent rule: entry actions need confirmation too.
        with pytest.raises(ConfirmationRequired):
            engine.restore_entry(entry.id)
        outcome = engine.restore_entry(entry.id, confirmed=True)
        assert outcome.done and outcome.restored_path
        assert Path(outcome.restored_path).read_bytes() == b"x" * 5000

        _t2, entry2 = _vault_with_file(tmp_path, vault, name="evil2.exe")
        outcome = engine.delete_entry(entry2.id, confirmed=True)
        assert outcome.done
        assert vault.get_entry(entry2.id).status == "deleted"
    finally:
        vault.close()
        history.close()


def test_simulated_engine_records_vault_intent_without_touching(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    sim = SimulatedActionEngine()
    try:
        _target, entry = _vault_with_file(tmp_path, vault)
        outcome = sim.restore_entry(entry.id, confirmed=True)
        assert outcome.done is False
        assert "Simulation mode is on" in outcome.message
        assert vault.get_entry(entry.id).status == "quarantined"
        outcome = sim.delete_entry(entry.id, confirmed=True)
        assert outcome.done is False
        assert vault.get_entry(entry.id).status == "quarantined"
        assert [r.action for r in sim.records] == ["restore", "delete"]
    finally:
        vault.close()


# ----------------------------------------------------------------------
# P2 #13 — bounded real-time detection context
# ----------------------------------------------------------------------

def _detection_event(path: str, severity: str = "critical") -> RealtimeEvent:
    return RealtimeEvent(
        kind="detection", message="flagged as malicious",
        timestamp="2026-01-01T00:00:00+00:00",
        path=path, verdict="Malicious", severity=severity,
        sha256="0" * 64,
    )


def test_rt_context_only_stashed_for_actionable_severities(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    config = ArgusConfig()  # defaults: low -> alert only
    engine = ActionEngine(vault, config=config)
    try:
        engine.handle_realtime_event(_detection_event("/tmp/a", "low"))
        assert engine._rt_context == {}
        engine.handle_realtime_event(_detection_event("/tmp/b", "critical"))
        assert "/tmp/b" in engine._rt_context
    finally:
        vault.close()


def test_rt_context_is_bounded(tmp_path):
    from argus.actions import _RT_CONTEXT_LIMIT

    vault = Vault.open(tmp_path / "vault")
    engine = ActionEngine(vault, config=ArgusConfig())
    try:
        for i in range(_RT_CONTEXT_LIMIT + 25):
            engine.handle_realtime_event(_detection_event(f"/tmp/f{i}"))
        assert len(engine._rt_context) == _RT_CONTEXT_LIMIT
        assert "/tmp/f0" not in engine._rt_context  # oldest evicted
    finally:
        vault.close()


# ----------------------------------------------------------------------
# P2 #14 — Toolhelp32 prototypes
# ----------------------------------------------------------------------

def test_toolhelp_prototypes_use_pointer_sized_handles():
    import ctypes

    class FakeFunc:
        restype = None
        argtypes = None

    class FakeKernel32:
        CreateToolhelp32Snapshot = FakeFunc()
        Process32FirstW = FakeFunc()
        Process32NextW = FakeFunc()
        OpenProcess = FakeFunc()
        QueryFullProcessImageNameW = FakeFunc()
        CloseHandle = FakeFunc()

    class FakeEntry(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong)]

    _declare_toolhelp_prototypes(FakeKernel32, FakeEntry)
    # Handle producers must be declared c_void_p: the default int
    # restype truncates 64-bit handles and breaks the
    # INVALID_HANDLE_VALUE comparison.
    assert FakeKernel32.CreateToolhelp32Snapshot.restype is ctypes.c_void_p
    assert FakeKernel32.OpenProcess.restype is ctypes.c_void_p
    assert FakeKernel32.CreateToolhelp32Snapshot.argtypes is not None
    assert FakeKernel32.CloseHandle.argtypes is not None


# ----------------------------------------------------------------------
# P2 #15 — symlink-to-directory scan root
# ----------------------------------------------------------------------

def test_scan_root_symlink_to_directory_is_walked(tmp_path):
    real = tmp_path / "realdir"
    real.mkdir()
    (real / "inside.txt").write_text("content", encoding="utf-8")
    link = tmp_path / "linkdir"
    link.symlink_to(real, target_is_directory=True)
    found = [p.name for p in iter_files(link, ScanStats())]
    assert found == ["inside.txt"]


def test_inner_symlink_dirs_still_not_followed(tmp_path):
    real = tmp_path / "realdir"
    real.mkdir()
    (real / "inside.txt").write_text("content", encoding="utf-8")
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / "linkdir").symlink_to(real, target_is_directory=True)
    found = list(iter_files(outer, ScanStats()))
    assert found == []  # inside trees, links are still never chased


# ----------------------------------------------------------------------
# P2 #16 — entropy equivalence (bulk counting)
# ----------------------------------------------------------------------

def test_entropy_bulk_matches_reference():
    import math
    import random

    from argus.heuristics.entropy import EntropyAnalyzer, shannon_entropy

    def reference(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        total = len(data)
        return -sum(
            (c / total) * math.log2(c / total) for c in counts if c
        )

    rng = random.Random(7)
    for _ in range(40):
        data = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 5000)))
        assert shannon_entropy(data) == pytest.approx(reference(data))
        analyzer = EntropyAnalyzer(window_size=1024)
        for i in range(0, len(data), 333):
            analyzer.feed(data[i : i + 333])
        report = analyzer.finish()
        assert report.whole_entropy == pytest.approx(reference(data), abs=1e-9)


# ----------------------------------------------------------------------
# P2 #18 — WAL + busy timeout on vault and history
# ----------------------------------------------------------------------

def test_vault_and_history_use_wal(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    history = History.open(tmp_path / "history.db")
    try:
        for conn in (vault._conn, history._conn):
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
            assert mode.lower() == "wal"
            assert timeout >= 1000
    finally:
        vault.close()
        history.close()


# ----------------------------------------------------------------------
# P2 #19 — duplicate PE import descriptors merge
# ----------------------------------------------------------------------

def test_duplicate_import_descriptors_are_merged():
    # Regression (fix #19): real PEs can carry two descriptors for
    # the SAME DLL; the parser used to keep only the second one's
    # functions, silently discarding the first list. Built by hand
    # here because the shared PE builder keys imports by DLL name
    # (a dict cannot express the duplicate).
    import struct
    from types import SimpleNamespace

    from argus.heuristics.pe import _parse_imports

    blob = bytearray(0x2000)

    def put(rva: int, data: bytes) -> None:
        blob[rva - 0x1000 : rva - 0x1000 + len(data)] = data

    def descriptor(oft: int, name: int, ft: int) -> bytes:
        return struct.pack("<IIIII", oft, 0, 0, name, ft)

    def thunk_table(*name_rvas: int) -> bytes:
        return b"".join(struct.pack("<I", r) for r in name_rvas) + b"\x00" * 4

    def import_name(text: str) -> bytes:
        return b"\x00\x00" + text.encode() + b"\x00"

    # Two descriptors, both naming KERNEL32.dll, different thunks.
    put(0x1000, descriptor(0x1100, 0x1200, 0x1100))
    put(0x1014, descriptor(0x1150, 0x1200, 0x1150))
    put(0x1028, b"\x00" * 20)  # terminating null descriptor
    put(0x1100, thunk_table(0x1300))
    put(0x1150, thunk_table(0x1350))
    put(0x1200, b"KERNEL32.dll\x00")
    put(0x1300, import_name("CreateFileA"))
    put(0x1350, import_name("ExitProcess"))

    section = SimpleNamespace(
        virtual_address=0x1000, virtual_size=0x2000,
        size_of_raw_data=0x2000, pointer_to_raw_data=0,
    )

    class FakeReader:
        sections = [section]

        def read_at(self, offset, size):
            return bytes(blob[offset : offset + size]).ljust(size, b"\x00")

        def c_string(self, offset, max_len):
            end = blob.find(b"\x00", offset, offset + max_len)
            if end == -1:
                end = offset + max_len
            return bytes(blob[offset:end]).decode("ascii", "replace")

    imports = _parse_imports(FakeReader(), lambda rva: rva - 0x1000, 0x1000, False)
    assert imports == {"KERNEL32.dll": ["CreateFileA", "ExitProcess"]}


# ----------------------------------------------------------------------
# P2 #12 — atomic config save
# ----------------------------------------------------------------------

def test_config_save_is_atomic_and_round_trips(tmp_path):
    target = tmp_path / "cfg" / "argus-config.json"
    config = ArgusConfig(watch_dirs=[str(tmp_path)])
    config.save(target)
    assert target.is_file()
    assert not (tmp_path / "cfg" / "argus-config.json.tmp").exists()
    assert [str(p) for p in ArgusConfig.load(target).watch_dirs] == config.watch_dirs


def test_history_record_round_trip_after_wal(tmp_path):
    history = History.open(tmp_path / "history.db")
    try:
        history.record_realtime_detection(
            path="/tmp/x.exe", verdict="Malicious",
            severity="high", name="Test", reasons=["r"],
            sha256="a" * 64,
        )
        rows = history.recent_detections()
        assert rows and rows[0].path == "/tmp/x.exe"
    finally:
        history.close()
