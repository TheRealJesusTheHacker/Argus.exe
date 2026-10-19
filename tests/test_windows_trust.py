"""Microsoft-signed system-file trust: Argus recognises normal
Windows files — and the recognition can never be abused as a
whitewash.

Trust requires ALL THREE: a structurally valid certificate, a
Microsoft signer identity extracted from the PKCS#7 blob, and a
home under the Windows directory. It clears ONLY the heuristic
score: signature-database and pattern-rule detections stand.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from pe_fixtures import (  # noqa: E402
    PEBuilder,
    RDATA_CHARS,
    TEXT_CHARS,
    boring_windows_binary,
    code_bytes,
    microsoft_signed_injector,
)

from argus.detections import Verdict, assess  # noqa: E402
from argus.heuristics.analyze import analyze_file  # noqa: E402
from argus.heuristics.pe import parse_pe, signer_is_microsoft  # noqa: E402
from argus.heuristics.signals import Signal  # noqa: E402
from argus.rules import Pattern, Rule  # noqa: E402
from argus.scanner import scan_file  # noqa: E402
from argus.scoring import score_signals  # noqa: E402
from argus.signatures import SignatureDB, SignatureHit, init_db  # noqa: E402


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


@pytest.fixture()
def windows_tree(tmp_path):
    """A fake Windows installation tree + a Downloads folder."""
    root = tmp_path / "Windows"
    system32 = root / "System32"
    system32.mkdir(parents=True)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    return root, system32, downloads


# ----------------------------------------------------------------------
# Signer identity extraction (the DER walk)
# ----------------------------------------------------------------------
def test_signer_identity_extracted(tmp_path):
    # Hunt P0-3: the legacy fixture's PKCS#7 carries a certificate
    # CLAIMING Microsoft but NO SignerInfo at all — identity now
    # requires a structurally complete SignerInfo, so the claim
    # earns no identity (it is still an extracted signer for the
    # P1-20 trim bar). Complete-SignerInfo positives are pinned
    # in tests/test_hunt_b_detection.py.
    target = tmp_path / "boring.exe"
    target.write_bytes(boring_windows_binary())
    info = parse_pe(target)
    assert info.signed is True
    assert info.cert_malformed is False
    assert info.has_extracted_signer is True
    assert info.signer_info_complete is False
    assert info.signer_name is None
    assert info.signer_org is None
    assert not signer_is_microsoft(info)


def test_signer_identity_org_only(tmp_path):
    """Some Microsoft certs carry the name in the Organization."""
    data = (
        PEBuilder()
        .add_section(".text", code_bytes(1024), TEXT_CHARS)
        .set_cert_signer(None, "Microsoft Corporation")
        .set_entry(0)
        .build()
    )
    target = tmp_path / "org.exe"
    target.write_bytes(data)
    info = parse_pe(target)
    # Hunt P0-3: no SignerInfo in this fixture either — the org
    # claim alone grants no identity now.
    assert info.signer_name is None
    assert info.signer_org is None
    assert info.has_extracted_signer is True
    assert not signer_is_microsoft(info)


def test_signer_identity_non_microsoft(tmp_path):
    data = (
        PEBuilder()
        .add_section(".text", code_bytes(1024), TEXT_CHARS)
        .set_cert_signer("FixtureSoft Ltd", "FixtureSoft")
        .set_entry(0)
        .build()
    )
    target = tmp_path / "other.exe"
    target.write_bytes(data)
    info = parse_pe(target)
    assert info.signed is True
    # Hunt P0-3: identity is withheld without a complete
    # SignerInfo, whoever the certificate claims to be.
    assert info.signer_name is None
    assert info.has_extracted_signer is True  # FixtureSoft was claimed
    assert not signer_is_microsoft(info)


def test_signer_identity_absent_for_payloadless_cert(tmp_path):
    """The legacy fixture (valid header, zero payload) is signed
    but claims no identity — and must gain none."""
    data = (
        PEBuilder()
        .add_section(".text", code_bytes(1024), TEXT_CHARS)
        .set_cert(0x800)
        .set_entry(0)
        .build()
    )
    target = tmp_path / "zeros.exe"
    target.write_bytes(data)
    info = parse_pe(target)
    assert info.signed is True
    assert info.signer_name is None
    assert info.signer_org is None
    assert not signer_is_microsoft(info)


def test_signer_identity_garbage_blob_no_crash_no_identity(tmp_path):
    """A structurally valid WIN_CERTIFICATE wrapping DER garbage:
    the walk fails safe to 'no identity' — never raises."""
    data = bytearray(
        PEBuilder()
        .add_section(".text", code_bytes(1024), TEXT_CHARS)
        .set_cert_signer("Microsoft Windows", "Microsoft Corporation")
        .set_entry(0)
        .build()
    )
    data[-48:] = b"\xff" * 48  # trash the tail of the PKCS#7 blob
    target = tmp_path / "garbage.exe"
    target.write_bytes(bytes(data))
    info = parse_pe(target)
    assert info.signer_name is None
    assert not signer_is_microsoft(info)


# ----------------------------------------------------------------------
# Scoring: the trusted flag
# ----------------------------------------------------------------------
def _signal(name, points, severity="high"):
    return Signal(
        name=name, severity=severity, points=points,
        explanation=f"fixture signal {name}",
    )


def test_score_signals_trusted_zeroes_score_and_combo():
    signals = [
        _signal("process_injection_combo", 45, "critical"),
        _signal("high_entropy_executable_section", 40, "critical"),
    ]
    untrusted = score_signals(signals, signed=True)
    assert untrusted.verdict is Verdict.MALICIOUS  # combo short-circuit

    trusted = score_signals(signals, signed=True, trusted_system_file=True)
    assert trusted.score == 0
    assert trusted.raw_score == 85  # the arithmetic is still shown
    assert trusted.short_circuit is False
    assert trusted.verdict is Verdict.CLEAN
    assert trusted.trusted_system_file is True
    assert trusted.signals == signals  # nothing hidden


def test_signature_detection_never_cleared_by_trust():
    """Composition pin: a signature hit decides MALICIOUS on its
    own, in a different channel from the heuristic score trust
    zeroes."""
    hit = SignatureHit(
        sha256="a" * 64, name="KnownBad", family="Test", severity="high"
    )
    assessment = assess(hit, [])
    scored = score_signals(
        [_signal("anything", 0, "low")], trusted_system_file=True
    )
    assessment.signals = scored.signals
    assessment.score = scored.score
    assessment.heuristic_verdict = scored.verdict
    assert assessment.heuristic_verdict is Verdict.CLEAN
    assert assessment.verdict is Verdict.MALICIOUS


# ----------------------------------------------------------------------
# analyze_file: the three-condition trust
# ----------------------------------------------------------------------
def test_boring_binary_trusted_in_system_location(windows_tree):
    # Hunt P0-3: this fixture's signature has no SignerInfo, so
    # even in a system location it earns NO trust now (the
    # complete-SignerInfo positive case is pinned in
    # tests/test_hunt_b_detection.py). The mundane profile must
    # still not reach Malicious on its own merits.
    root, system32, _downloads = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(boring_windows_binary())
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is False
    assert report.signer is None
    assert not any(
        "signed Windows system file" in note for note in report.notes
    )
    scored = score_signals(
        report.signals, signed=report.signed,
        trusted_system_file=report.trusted_system_file,
    )
    assert scored.verdict is not Verdict.MALICIOUS


def test_boring_binary_not_trusted_in_downloads(windows_tree):
    root, _system32, downloads = windows_tree
    target = downloads / "driverhost.exe"
    target.write_bytes(boring_windows_binary())
    report = analyze_file(target, windows_root_dir=root)
    assert report.signed is True
    # Hunt P0-3: no complete SignerInfo — no identity anywhere,
    # and certainly no trust in Downloads.
    assert report.signer is None
    assert report.trusted_system_file is False
    assert not any(
        "signed Windows system file" in note for note in report.notes
    )


def test_boring_binary_is_boring_even_untrusted(windows_tree):
    """The mundane profile (CreateService import, ordinal-heavy
    imports, deterministic timestamp) must not reach Malicious on
    its own merits either — trust is a guarantee, not a fig leaf
    over a hair trigger."""
    root, _system32, downloads = windows_tree
    target = downloads / "driverhost.exe"
    target.write_bytes(boring_windows_binary())
    report = analyze_file(target, windows_root_dir=root)
    scored = score_signals(report.signals, signed=report.signed)
    assert scored.verdict is not Verdict.MALICIOUS
    assert scored.score < 60


def test_injector_with_microsoft_cert_caught_in_downloads(windows_tree):
    """Same bytes, wrong neighbourhood: the critical combination
    rules — a signature is not a passport."""
    root, _system32, downloads = windows_tree
    target = downloads / "driverhost.exe"
    target.write_bytes(microsoft_signed_injector())
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is False
    scored = score_signals(
        report.signals, signed=report.signed,
        trusted_system_file=report.trusted_system_file,
    )
    assert scored.verdict is Verdict.MALICIOUS


def test_injector_trusted_in_system32_but_signals_stay_listed(windows_tree):
    # Hunt P0-3: the injector's Microsoft claim has no complete
    # SignerInfo, so System32 no longer saves it — the critical
    # combination rules, in every location. (A COMPLETE
    # SignerInfo in System32 still earns trust with signals
    # listed; see tests/test_hunt_b_detection.py.)
    root, system32, _downloads = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(microsoft_signed_injector())
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is False
    names = {sig.name for sig in report.signals}
    assert "process_injection_combo" in names  # listed, not hidden
    scored = score_signals(
        report.signals, signed=report.signed,
        trusted_system_file=report.trusted_system_file,
    )
    assert scored.verdict is Verdict.MALICIOUS


def test_malformed_cert_gets_no_trust(windows_tree):
    """A claimed certificate region whose first entry is not
    PKCS signed data (type flipped to 0x0001) fails structural
    validation: not signed, no identity, no trust — even in a
    system location on the injector profile."""
    import struct

    root, system32, _downloads = windows_tree
    data = bytearray(microsoft_signed_injector())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    cert_dir = pe_offset + 4 + 20 + 112 + 4 * 8
    cert_offset, _cert_size = struct.unpack_from("<II", data, cert_dir)
    # wCertificateType sits 6 bytes into the WIN_CERTIFICATE header.
    struct.pack_into("<H", data, cert_offset + 6, 0x0001)
    target = system32 / "driverhost.exe"
    target.write_bytes(bytes(data))
    info = parse_pe(target)
    assert info.signed is False
    assert info.cert_malformed is True
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is False


# ----------------------------------------------------------------------
# scan_file integration: trust end-to-end, detections never cleared
# ----------------------------------------------------------------------
def test_scan_trusted_system_file_clean(db, windows_tree, monkeypatch):
    # Hunt P0-3: end-to-end, the incomplete-SignerInfo injector
    # in System32 is Malicious now, not Clean — its certificate
    # claims Microsoft but carries no complete SignerInfo.
    root, system32, _downloads = windows_tree
    monkeypatch.setattr(
        "argus.heuristics.analyze.windows_root", lambda: root
    )
    target = system32 / "driverhost.exe"
    target.write_bytes(microsoft_signed_injector())
    scanned = scan_file(target, db, [])
    assert scanned.verdict is Verdict.MALICIOUS
    assert scanned.assessment.score > 0
    # The critical-combination signals are still on the record.
    names = {sig.name for sig in scanned.assessment.signals}
    assert "process_injection_combo" in names
    assert not any(
        "signed Windows system file" in note
        for note in scanned.assessment.notes
    )


def test_scan_rule_detection_never_cleared_by_trust(
    db, windows_tree, monkeypatch
):
    """A pattern-rule hit is a DETECTION (assess() channel), not
    heuristic suspicion — trust must not touch it, even in a
    system location with a Microsoft signature."""
    root, system32, _downloads = windows_tree
    monkeypatch.setattr(
        "argus.heuristics.analyze.windows_root", lambda: root
    )
    target = system32 / "driverhost.exe"
    target.write_bytes(boring_windows_binary())
    rules = [
        Rule(
            name="fixture-needle",
            description="fixture rule matched the file's contents",
            severity="critical",
            patterns=(Pattern.from_text("Operating System"),),
        )
    ]
    scanned = scan_file(target, db, rules)
    assert scanned.assessment.detections  # the rule hit stands
    assert scanned.verdict is Verdict.MALICIOUS


def test_scan_injector_in_downloads_still_malicious(
    db, windows_tree, monkeypatch
):
    root, _system32, downloads = windows_tree
    monkeypatch.setattr(
        "argus.heuristics.analyze.windows_root", lambda: root
    )
    target = downloads / "driverhost.exe"
    target.write_bytes(microsoft_signed_injector())
    scanned = scan_file(target, db, [])
    assert scanned.verdict is Verdict.MALICIOUS
    digest = hashlib.sha256(microsoft_signed_injector()).hexdigest()
    assert scanned.result.sha256 == digest
