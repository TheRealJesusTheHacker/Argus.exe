"""v1.2.5 — the calibration correction.

v1.2.4 shipped two fixes for the owner's first real bundle run:
verified-sibling trust and a scoring calibration. Both fixes
work — but the v1.2.4 report's per-file measurement table for
the calibration was WRONG. The table had been taken from
terminal output that late-arriving results contradicted; the
crew caught its own error after shipping and re-measured twice.
This file pins the TRUE measurements and the corrected aim.

THE TRUE MEASUREMENTS (Argus's own analyzer, run 2026-10-20 on
the REAL published Technician's Toolkit v0.2.0 binaries — the
exact files the owner ran — reproduced independently before
this fix was written):

* TechniciansToolkit.exe, Argus.exe, VectorZip.exe,
  Charon/Charon.exe — Malicious 70, on exactly:
  anti_debug_imports 15, vm_evasion_strings 15,
  string_extraction_truncated 10,
  high_entropy_outside_sections 15, huge_overlay 15.
* NitroCoreOptimizer.exe — Malicious 70, the same list with
  unsigned_elevation_request 15 in place of vm_evasion_strings.
* Beerus/Beerus.exe — Suspicious 55: the shared list minus
  vm_evasion_strings.

Not one of the six carries the import combination the v1.2.4
battery fixture was built around. The convicted traits are the
shape of ONE-FILE PACKAGING itself: the giant overlay that
carries the bundled program, the high-entropy data living
outside every declared section, the flooded string table,
virtual-machine names shipped inside the bundled runtimes, an
unsigned elevation manifest. v1.2.4's corroboration class —
aimed at the import-combination profile — never intersects
these lists, so unverified copies still convicted at 70.

v1.2.5 extends the class by those five traits. Expected, and
pinned below: all six siblings unverified land at Suspicious
(59 for the five 70s; Beerus unchanged at 55); verified
in-bundle they remain Clean at 0, exactly as v1.2.4 proved.
The packed-injector profile is NOT capped — its entropy signal
is the in-section one, alongside writable-executable sections
and the injection combination, all outside the class — and the
behavioural profiles (download-and-execute, credential access,
persistence, keylogging) and the critical combinations convict
exactly as before.

The end-to-end fixture below is rebuilt to the REAL profile:
it manufactures the measured trait family (debugger-check
import, VM-environment string, a string table past the
extraction cap, a packed overlay) instead of the import
combination the v1.2.4 fixture chased.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from argus import bundletrust, selftrust
from argus.detections import Verdict
from argus.scanner import scan_file
from argus.scoring import CORROBORATION_ONLY_SIGNAL_NAMES, score_signals
from argus.heuristics.analyze import analyze_file
from argus.heuristics.signals import Signal
from argus.signatures import SignatureDB, init_db

from tests.pe_fixtures import (
    PEBuilder,
    RDATA_CHARS,
    TEXT_CHARS,
    code_bytes,
    packed_bytes,
    packed_injector_pe,
)


# ----------------------------------------------------------------------
# The measured profiles, verbatim (name, points, severity) as the
# analyzer reported them on the real published binaries.
# ----------------------------------------------------------------------
_SET_A = [
    ("anti_debug_imports", 15, "medium"),
    ("vm_evasion_strings", 15, "medium"),
    ("string_extraction_truncated", 10, "low"),
    ("high_entropy_outside_sections", 15, "medium"),
    ("huge_overlay", 15, "medium"),
]
_NITROCORE = [
    ("anti_debug_imports", 15, "medium"),
    ("string_extraction_truncated", 10, "low"),
    ("high_entropy_outside_sections", 15, "medium"),
    ("huge_overlay", 15, "medium"),
    ("unsigned_elevation_request", 15, "medium"),
]
_BEERUS = [row for row in _SET_A if row[0] != "vm_evasion_strings"]

#: (bundle-relative name, measured signals, measured raw score,
#:  expected score after the v1.2.5 correction, unverified)
MEASURED_PROFILES = [
    ("TechniciansToolkit.exe", _SET_A, 70, 59),
    ("Argus.exe", _SET_A, 70, 59),
    ("VectorZip.exe", _SET_A, 70, 59),
    ("Charon/Charon.exe", _SET_A, 70, 59),
    ("NitroCoreOptimizer.exe", _NITROCORE, 70, 59),
    ("Beerus/Beerus.exe", _BEERUS, 55, 55),
]


def _signals(rows) -> list[Signal]:
    return [
        Signal(name=name, severity=sev, points=points, explanation="measured")
        for name, points, sev in rows
    ]


@pytest.mark.parametrize(
    "label,rows,raw,expected",
    MEASURED_PROFILES,
    ids=[p[0] for p in MEASURED_PROFILES],
)
def test_measured_profile_unverified_is_capped_not_convicted(label, rows, raw, expected):
    """The field data itself, pinned: each sibling's exact
    measured signal list, scored unverified, must land at
    Suspicious after the correction — flagged for a look, not
    convicted for its packaging."""
    scored = score_signals(_signals(rows))
    assert scored.raw_score == raw
    assert scored.score == expected
    assert scored.verdict is Verdict.SUSPICIOUS


@pytest.mark.parametrize(
    "label,rows,raw,expected",
    MEASURED_PROFILES,
    ids=[p[0] for p in MEASURED_PROFILES],
)
def test_measured_profile_names_are_all_in_the_corrected_class(label, rows, raw, expected):
    """The by-construction proof, locked: the cap reaches the
    real profiles because every measured trait is a member of
    the corroboration class — the intersection v1.2.4 missed."""
    names = {name for name, _, _ in rows}
    assert names <= CORROBORATION_ONLY_SIGNAL_NAMES


@pytest.mark.parametrize(
    "label,rows,raw,expected",
    MEASURED_PROFILES,
    ids=[p[0] for p in MEASURED_PROFILES],
)
def test_measured_profile_verified_stays_zero(label, rows, raw, expected):
    """Sibling trust on the REAL profiles (v1.2.4 proved it on a
    crafted one): hash-verified, the heuristic score is 0 and
    the verdict Clean, signals still listed."""
    scored = score_signals(_signals(rows), trusted_bundle_sibling=True)
    assert scored.score == 0
    assert scored.verdict is Verdict.CLEAN
    assert len(scored.signals) == len(rows)


# ----------------------------------------------------------------------
# The battery fixture rebuilt to the real profile
# ----------------------------------------------------------------------
def onefile_packaging_pe(*, vm_strings: bool, elevation: bool) -> bytes:
    """A one-file-packaged program the way the kit's tools are
    actually built: ordinary low-entropy code, a debugger-check
    import (the bootloader's), a resource section carrying more
    strings than the extractor's cap (the bundled runtime's),
    and a large packed overlay (the payload archive) — plus,
    per variant, a VM-environment name from the bundled runtime
    libraries, or an unsigned elevation manifest.

    Overlay seeds are pinned: the overlay is pseudo-random, and
    a stray VM needle in its junk strings would change the
    profile — seed 42 for the VM variant (needle comes from the
    resource string regardless), seed 1 for the elevation
    variant (verified to contribute no VM needle)."""
    rdata = b""
    if vm_strings:
        rdata += b"VMware Tools compatibility layer\x00"
    if elevation:
        rdata += (
            b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1">'
            b"<requestedExecutionLevel level=\"requireAdministrator\"/>"
            b"</assembly>\x00"
        )
    rdata += b"".join(
        b"bundled-resource-string-%05d\x00" % i for i in range(20_050)
    )
    return (
        PEBuilder()
        .add_section(".text", code_bytes(4096), TEXT_CHARS)
        .add_section(".rdata", rdata, RDATA_CHARS)
        .set_imports(
            {
                "KERNEL32.dll": [
                    "IsDebuggerPresent",
                    "GetModuleHandleA",
                    "ExitProcess",
                ]
            }
        )
        .set_entry(0)
        .set_overlay(packed_bytes(384 * 1024, seed=42 if vm_strings else 1))
        .build()
    )


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


def test_real_profile_fixture_end_to_end_unverified(db, tmp_path):
    """The full pipeline on the rebuilt fixture, OUTSIDE any
    bundle: exactly the measured set-A signal list, 70 raw,
    held at 59 — Suspicious, not the field's Malicious."""
    target = tmp_path / "some-tool.exe"
    target.write_bytes(onefile_packaging_pe(vm_strings=True, elevation=False))
    scanned = scan_file(target, db, [])
    got = {(sig.name, sig.points) for sig in scanned.assessment.signals}
    assert got == {(name, points) for name, points, _ in _SET_A}
    assert scanned.assessment.score == 59
    assert scanned.verdict is Verdict.SUSPICIOUS


def test_real_profile_fixture_elevation_variant_end_to_end(db, tmp_path):
    """The NitroCore-shaped variant: the unsigned elevation
    manifest replaces the VM strings; same arithmetic."""
    target = tmp_path / "other-tool.exe"
    target.write_bytes(onefile_packaging_pe(vm_strings=False, elevation=True))
    scanned = scan_file(target, db, [])
    got = {(sig.name, sig.points) for sig in scanned.assessment.signals}
    assert got == {(name, points) for name, points, _ in _NITROCORE}
    assert scanned.assessment.score == 59
    assert scanned.verdict is Verdict.SUSPICIOUS


@pytest.fixture()
def bundle(tmp_path, monkeypatch):
    """The v1.2.4 bundle stage, restaged for the real-profile
    fixture: a Toolkit tree with its own integrity record and
    ARGUS_DATA_DIR inside it, exactly as the launcher sets it."""
    root = tmp_path / "TechniciansToolkit"
    root.mkdir()
    (root / "ArgusData").mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(root / "ArgusData"))
    bundletrust.reset_default_cache()
    selftrust.reset_default_cache()

    def finalize() -> Path:
        sums = {}
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name not in (
                "SHA256SUMS.txt",
                "MANIFEST.json",
            ):
                rel = path.relative_to(root).as_posix()
                sums[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        (root / "SHA256SUMS.txt").write_text(
            "".join(f"{d}  {rel}\n" for rel, d in sorted(sums.items())),
            encoding="utf-8",
        )
        (root / "MANIFEST.json").write_text(
            json.dumps({"bundle": "Technician's Toolkit", "tools": [{"name": "Argus"}]}),
            encoding="utf-8",
        )
        bundletrust.reset_default_cache()
        return root

    yield root, finalize
    bundletrust.reset_default_cache()
    selftrust.reset_default_cache()


def test_real_profile_fixture_verified_in_bundle_is_clean(db, bundle):
    """Both directions on the rebuilt fixture: verified against
    the bundle's record, the real profile scores 0/Clean with
    its signals still listed — the owner's actual configuration."""
    root, finalize = bundle
    target = root / "TechniciansToolkit.exe"
    target.write_bytes(onefile_packaging_pe(vm_strings=True, elevation=False))
    finalize()
    scanned = scan_file(target, db, [])
    assert scanned.verdict is Verdict.CLEAN
    assert scanned.assessment.score == 0
    assert {sig.name for sig in scanned.assessment.signals} == {
        name for name, _, _ in _SET_A
    }


# ----------------------------------------------------------------------
# Safety invariants — the correction must not blunt real detections
# ----------------------------------------------------------------------
def test_packed_injector_profile_is_outside_the_class(db, tmp_path):
    """WHY the packed injector cannot be capped: measured on the
    fixture itself, its profile carries the injection
    combination + the IN-SECTION entropy signal + a writable
    executable section — none of them packaging traits — and the
    combination short-circuits regardless."""
    target = tmp_path / "injector.exe"
    target.write_bytes(packed_injector_pe())
    report = analyze_file(target)
    names = {sig.name for sig in report.signals}
    assert "process_injection_combo" in names
    assert "high_entropy_executable_section" in names
    assert "writable_executable_section" in names
    assert not names <= CORROBORATION_ONLY_SIGNAL_NAMES
    scored = score_signals(report.signals, signed=report.signed_trim_eligible)
    assert scored.short_circuit is True
    assert scored.verdict is Verdict.MALICIOUS
    scanned = scan_file(target, db, [])
    assert scanned.verdict is Verdict.MALICIOUS


def test_critical_combination_with_packaging_traits_still_convicts():
    """Packaging traits riding along cannot launder a critical
    combination: the cap is bypassed by the short-circuit."""
    scored = score_signals(
        _signals(
            [
                ("process_injection_combo", 45, "critical"),
                ("high_entropy_executable_section", 25, "high"),
                ("huge_overlay", 15, "medium"),
                ("anti_debug_imports", 15, "medium"),
            ]
        )
    )
    assert scored.short_circuit is True
    assert scored.score == 100
    assert scored.verdict is Verdict.MALICIOUS


@pytest.mark.parametrize(
    "behaviour,points",
    [
        ("download_and_execute", 35),
        ("credential_access", 35),
        ("persistence_mechanism", 30),
        ("keylogging_combo", 30),
    ],
)
def test_any_behaviour_signal_lifts_the_cap_on_the_real_profile(behaviour, points):
    """Set A plus ONE behavioural signal: full arithmetic, the
    packaging traits corroborate at full weight, Malicious."""
    rows = _SET_A + [(behaviour, points, "high")]
    scored = score_signals(_signals(rows))
    assert scored.raw_score == 70 + points
    assert scored.score == 70 + points
    assert scored.verdict is Verdict.MALICIOUS


def test_signed_trim_and_hot_pocket_floor_still_behave_on_the_real_profile():
    """The signed path over the measured profile: the trim
    applies (70 → 55), the hot-pocket floor cannot push it back
    over the line, and a larger packaging-only signed profile
    is still held at 59 — the cap is applied after the trim."""
    scored = score_signals(_signals(_SET_A), signed=True)
    assert scored.score == 55
    assert scored.verdict is Verdict.SUSPICIOUS

    bigger = _signals(
        _SET_A + [("process_injection_combo", 45, "critical")]
    )
    scored = score_signals(bigger, signed=True)
    assert scored.raw_score == 115
    assert scored.score == 59
    assert scored.verdict is Verdict.SUSPICIOUS
