"""Regression tests for the 2026-10-20 field failure (v1.2.4).

On a real Windows machine, the first-run wizard's EICAR self-test
failed at fingerprinting with "could not read file: Invalid
argument": the machine's resident security stack refused Argus's
read of the just-written test file with errno EINVAL — an error
no Argus code raises and no clean machine reproduces (verified on
Windows CI in source and frozen form, where every step passes).

Two product defects turned that environment event into a false
"Argus is broken" verdict:

1. ``scanner._is_scan_blocked`` recognised only a small allow-list
   of errnos (EACCES/EPERM/EAGAIN/EBUSY). Any other read failure
   fell through to a plain assessment whose verdict was Clean —
   a file Argus never read, waved through as clean, against the
   scanner's own documented rule ("NotScanned, never Clean").
   Every scan surface shared the hole: CLI tallies, the realtime
   retry decision, and folder scans all key off the verdict.

2. ``run_self_test`` reported the blocked read as an engine
   failure — summary "Do not rely on Argus until this is looked
   at", detection step claiming the verdict was "Clean".

These tests inject the field's exact failure at the exact
boundaries it crossed — the streamed read inside ``scan_file``
and the scan result inside ``run_self_test`` — and pin the
corrected behaviour. The classification tests fail on the
pre-fix code with verdict Clean.
"""

from __future__ import annotations

import builtins
import errno
import os
from pathlib import Path

import pytest

from argus import devtools
from argus.detections import FileAssessment, Verdict
from argus.scanner import FileResult, ScannedFile, _is_scan_blocked, scan_file
from argus.signatures import SignatureDB, init_db


# ----------------------------------------------------------------------
# The classifier itself
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "err",
    [
        errno.EACCES,
        errno.EPERM,
        errno.EAGAIN,
        errno.EBUSY,
        errno.EINVAL,  # the field failure, 2026-10-20
        errno.EIO,
        errno.ESTALE,
        errno.ETXTBSY,
        errno.EDEADLK,
    ],
)
def test_is_scan_blocked_any_unreadable_file(err):
    """A file that is there but cannot be read is blocked,
    whatever errno the OS or a filter driver chose to answer."""
    assert _is_scan_blocked(OSError(err, os.strerror(err))) is True


@pytest.mark.parametrize("err", [errno.ENOENT, errno.ENOTDIR])
def test_is_scan_blocked_not_there_stays_plain(err):
    """The documented boundary: a vanished file is a plain read
    error (still recorded on the result), not a blocked read —
    there is nothing to retry and nothing being withheld."""
    assert _is_scan_blocked(OSError(err, os.strerror(err))) is False


def test_is_scan_blocked_permission_error():
    assert _is_scan_blocked(PermissionError(errno.EACCES, "denied")) is True


# ----------------------------------------------------------------------
# scan_file with the read exploding mid-stream
# ----------------------------------------------------------------------
class _ExplodingReader:
    """Wraps a real binary file; every read raises *exc*.

    Models the field exactly: the file opens fine, the read is
    refused — the shape a filter driver's refusal takes by the
    time it reaches the scanner's streamed read.
    """

    def __init__(self, real, exc: OSError) -> None:
        self._real = real
        self._exc = exc

    def read(self, _size: int = -1) -> bytes:
        raise self._exc

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._real.close()
        return False

    def close(self) -> None:
        self._real.close()


def _scan_with_read_error(tmp_path, monkeypatch, err: int) -> ScannedFile:
    target = tmp_path / "payload.bin"
    target.write_bytes(b"field probe payload" * 4)
    db_path = tmp_path / "sigs.db"
    init_db(db_path, seed=True)
    real_open = builtins.open

    def guarded_open(file, mode="r", *args, **kwargs):
        fh = real_open(file, mode, *args, **kwargs)
        if Path(str(file)) == target and "rb" in mode:
            return _ExplodingReader(
                fh, OSError(err, os.strerror(err))
            )
        return fh

    monkeypatch.setattr(builtins, "open", guarded_open)
    with SignatureDB.open(db_path) as db:
        return scan_file(target, db, [], heuristics=False)


@pytest.mark.parametrize("err", [errno.EINVAL, errno.EIO, errno.EACCES])
def test_scan_file_unreadable_is_not_scanned_never_clean(
    tmp_path, monkeypatch, err
):
    """The field failure, end to end through the real scanner:
    the verdict must be NotScanned — never Clean — and the file
    must not be reported as fingerprinted."""
    scanned = _scan_with_read_error(tmp_path, monkeypatch, err)
    assert scanned.result.error is not None
    assert "could not read file" in scanned.result.error
    assert scanned.result.sha256 is None
    assert scanned.assessment.not_scanned is True
    assert scanned.verdict is Verdict.NOT_SCANNED


def test_scan_file_vanished_mid_read_stays_plain_error(
    tmp_path, monkeypatch
):
    """Boundary pin: a file that vanishes mid-read is a plain
    recorded error (the result still carries it), not NotScanned."""
    scanned = _scan_with_read_error(tmp_path, monkeypatch, errno.ENOENT)
    assert scanned.result.error is not None
    assert scanned.assessment.not_scanned is False


# ----------------------------------------------------------------------
# The self-test's designed interference outcome
# ----------------------------------------------------------------------
def _blocked_scan(_target, _db, _rules, **_kwargs) -> ScannedFile:
    """A scan result in the field's shape: read refused, no
    fingerprint, nothing detected."""
    result = FileResult(
        path=Path("eicar-test-file.txt"),
        error="could not read file: Invalid argument",
    )
    assessment = FileAssessment(not_scanned=True)
    return ScannedFile(result=result, assessment=assessment)


def _step(result, name: str):
    return next(s for s in result.steps if s.name == name)


def test_self_test_blocked_read_reports_interference_not_failure(
    tmp_path, monkeypatch
):
    """When another program stops the self-test reading its own
    test file — twice, after the retry — the outcome is the
    designed interference report: not passed, but NOT 'Argus is
    broken', and no step claims the file was judged Clean."""
    monkeypatch.setattr(devtools, "scan_file", _blocked_scan)
    monkeypatch.setattr(devtools, "_SELF_TEST_RETRY_PAUSE_SECONDS", 0)
    result = devtools.run_self_test(tmp_path / "scratch")
    assert result.passed is False
    assert result.blocked is True
    summary = result.summary()
    assert "could not be completed" in summary
    assert "other antivirus" in summary
    assert "Do not rely on Argus" not in summary
    fingerprint = _step(result, "fingerprinting")
    assert fingerprint.ok is False
    assert "could not read the test file" in fingerprint.detail
    detection = _step(result, "detection")
    assert detection.ok is False
    assert detection.detail.startswith("not checked")
    assert "Clean" not in detection.detail


def test_self_test_blocked_once_then_reads_passes(tmp_path, monkeypatch):
    """A brief hold must not fail the test: first read refused,
    retry (with a freshly written file) reads fine, and the pass
    is reported honestly as a second-try pass."""
    real_scan_file = devtools.scan_file  # argus.scanner.scan_file
    calls = {"n": 0}

    def flaky_scan(target, db, rules, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _blocked_scan(target, db, rules, **kwargs)
        return real_scan_file(target, db, rules, **kwargs)

    monkeypatch.setattr(devtools, "scan_file", flaky_scan)
    monkeypatch.setattr(devtools, "_SELF_TEST_RETRY_PAUSE_SECONDS", 0)
    result = devtools.run_self_test(tmp_path / "scratch")
    assert calls["n"] == 2
    assert result.passed is True
    assert result.blocked is False
    fingerprint = _step(result, "fingerprinting")
    assert fingerprint.ok is True
    assert "second try" in fingerprint.detail
    detection = _step(result, "detection")
    assert detection.ok is True
    assert "Malicious" in detection.detail
