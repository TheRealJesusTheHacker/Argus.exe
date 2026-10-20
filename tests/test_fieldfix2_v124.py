"""Field-fix round 2 for v1.2.4 — findings #2 and #3 from the
owner's first real bundle run (2026-10-20).

Finding #2: Argus flagged the Technician's Toolkit bundle's own
launcher (and, per the owner, "everything") as Malicious. Every
PyInstaller-built sibling carries the bootloader traits Argus
scores — the in-memory-loader import combination (45),
debugger-detection imports (15), packer section names (15). Two
fixes, both in this file's sights:

* **Verified-sibling trust** (argus.bundletrust): a file whose
  SHA-256 matches the bundle's own integrity record gets its
  heuristic score zeroed on the Microsoft-trust terms — signals
  listed, signature/rule detections untouched. A fingerprint
  mismatch on a recorded place is tamper evidence. A name earns
  nothing.
* **Signal calibration** (argus.scoring): a profile made ONLY of
  packaging traits corroborates but cannot convict — held at the
  top of Suspicious. Any behavioural/structural signal lifts the
  cap and full arithmetic (and the critical combinations) apply.

Finding #3: Argus flagged ITSELF in portable mode. The
running-process identity proof in argus.selftrust was gated on
the canonical install address; the portable program never sits
there, so the gate was never entered. The proof now applies at
the running file's own address, with the recorded fingerprint
still decisive wherever a record exists.

The sibling-profile fixture below reproduces the measured field
profile exactly (injection combo + anti-debug + packer section =
75 raw points on the pre-fix scoring).

CORRECTION (v1.2.5): the sentence above is the v1.2.4 crew's
measurement error, kept visible rather than rewritten away.
The REAL field profile — measured on the published bundle
binaries, pinned verbatim in tests/test_fieldfix_v125.py —
carries no import combination at all: it is the one-file
packaging family (huge overlay, high-entropy data outside the
sections, a flooded string table, VM names from the bundled
runtimes, an unsigned elevation manifest). The fixture below
models a different, also-real profile class — named-injection-
import PEs — and the tests here remain valid for what they
actually exercise: the trust mechanics, and the cap applied to
the import-combination family. The calibration's corrected aim
lives in the v1.2.5 file.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from argus import bundletrust, selftrust
from argus.config import ArgusConfig
from argus.detections import Verdict
from argus.realtime import RealtimeEngine
from argus.rules import BUILTIN_RULES
from argus.scanner import scan_file, scan_path
from argus.scoring import score_signals
from argus.selftrust import SelfExclusions
from argus.heuristics.signals import Signal
from argus.signatures import SignatureDB, init_db

from tests.pe_fixtures import (
    PEBuilder,
    TEXT_CHARS,
    clean_pe,
    code_bytes,
    packed_injector_pe,
)

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bootloader_profile_pe() -> bytes:
    """A PyInstaller-bootloader-shaped PE: the in-memory-loader
    import combination + debugger-detection imports + a packer
    section name, over ordinary low-entropy code. (v1.2.5
    correction: this is a crafted named-injection-import
    profile, a real class — NOT the bundle tools' measured
    profile, which is the one-file packaging family pinned in
    tests/test_fieldfix_v125.py.)"""
    return (
        PEBuilder()
        .add_section(".text", code_bytes(4096), TEXT_CHARS)
        .add_section("UPX1", code_bytes(2048), TEXT_CHARS)
        .set_imports(
            {
                "KERNEL32.dll": [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "IsDebuggerPresent",
                    "GetProcAddress",
                    "LoadLibraryA",
                    "ExitProcess",
                ],
                "USER32.dll": ["MessageBoxA"],
            }
        )
        .set_entry(0)
        .build()
    )


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


@pytest.fixture()
def bundle(tmp_path, monkeypatch):
    """A Technician's Toolkit bundle tree with a real integrity
    record, and Argus "running from it": ARGUS_DATA_DIR points at
    the bundle's ArgusData folder, exactly as the bundle
    launcher's manifest sets it."""
    root = tmp_path / "TechniciansToolkit"
    root.mkdir()
    (root / "ArgusData").mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(root / "ArgusData"))
    bundletrust.reset_default_cache()
    selftrust.reset_default_cache()

    def add(rel: str, data: bytes) -> Path:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def finalize(extra_sums: dict[str, bytes] | None = None) -> Path:
        sums = {}
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name not in (
                "SHA256SUMS.txt",
                "MANIFEST.json",
            ):
                rel = path.relative_to(root).as_posix()
                sums[rel] = _sha(path.read_bytes())
        for rel, data in (extra_sums or {}).items():
            sums[rel] = _sha(data)
        (root / "SHA256SUMS.txt").write_text(
            "".join(f"{digest}  {rel}\n" for rel, digest in sorted(sums.items())),
            encoding="utf-8",
        )
        (root / "MANIFEST.json").write_text(
            json.dumps(
                {
                    "bundle": "Technician's Toolkit",
                    "tools": [{"name": "Argus"}, {"name": "Charon"}],
                }
            ),
            encoding="utf-8",
        )
        bundletrust.reset_default_cache()
        return root

    yield root, add, finalize
    bundletrust.reset_default_cache()
    selftrust.reset_default_cache()


# ----------------------------------------------------------------------
# Finding #3 — self-trust under portable/bundle conditions
# ----------------------------------------------------------------------
def test_portable_running_exe_excluded_at_noncanonical_address(db, tmp_path):
    """THE field gap: the program runs from the bundle folder,
    nowhere near the canonical install address, and never went
    through setup (no fingerprint record). The running-process
    proof must still recognise it. (Pre-fix, the identity gate
    was only entered at the canonical address, so this file was
    scanned as a stranger — Argus flagging itself.)"""
    bundle_exe = tmp_path / "TechniciansToolkit" / "Argus.exe"
    bundle_exe.parent.mkdir(parents=True)
    bundle_exe.write_bytes(clean_pe())
    exclusions = SelfExclusions(
        own_exe=tmp_path / "Program Files" / "Argus" / "Argus.exe",
        running_exe=bundle_exe,
    )
    scanned = scan_file(bundle_exe, db, [], self_exclusions=exclusions)
    assert scanned.excluded is True
    assert scanned.exclusion_source == selftrust.SOURCE_RUNNING_EXE


def test_portable_recorded_fingerprint_still_decisive(db, tmp_path):
    """With a fingerprint record present, the record rules at the
    running file's address too: match exempts, mismatch is
    tamper — the portable layout does not demote the primary
    proof."""
    bundle_exe = tmp_path / "TechniciansToolkit" / "Argus.exe"
    bundle_exe.parent.mkdir(parents=True)
    bundle_exe.write_bytes(clean_pe())
    good = SelfExclusions(
        own_exe=tmp_path / "Program Files" / "Argus" / "Argus.exe",
        running_exe=bundle_exe,
        recorded_exe_sha256=_sha(clean_pe()),
    )
    scanned = scan_file(bundle_exe, db, [], self_exclusions=good)
    assert scanned.excluded is True
    assert scanned.exclusion_source == selftrust.SOURCE_RECORDED_EXE

    bad = SelfExclusions(
        own_exe=tmp_path / "Program Files" / "Argus" / "Argus.exe",
        running_exe=bundle_exe,
        recorded_exe_sha256=_sha(b"the-real-argus"),
    )
    outcome = bad.check(bundle_exe)
    assert outcome.excluded is False
    assert outcome.tamper_suspect is True


def test_canonical_at_rest_copy_without_proof_stays_a_stranger(db, tmp_path):
    """Doctrine pin: the canonical address alone earns nothing.
    An at-rest copy at the install address that Argus is not
    running, with no fingerprint record, is scanned normally —
    no exclusion, no tamper accusation."""
    canonical = tmp_path / "Program Files" / "Argus" / "Argus.exe"
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(clean_pe())
    exclusions = SelfExclusions(
        own_exe=canonical,
        running_exe=tmp_path / "TechniciansToolkit" / "Argus.exe",
    )
    scanned = scan_file(canonical, db, [], self_exclusions=exclusions)
    assert scanned.excluded is False
    assert not any(
        sig.name == "argus_program_file_replaced"
        for sig in scanned.assessment.signals
    )


# ----------------------------------------------------------------------
# Finding #2, part 1 — verified-sibling trust
# ----------------------------------------------------------------------
def test_verified_sibling_not_flagged_signals_still_listed(db, bundle):
    root, add, finalize = bundle
    launcher = add("TechniciansToolkit.exe", bootloader_profile_pe())
    finalize()
    scanned = scan_file(launcher, db, [])
    assert scanned.verdict is Verdict.CLEAN
    assert scanned.assessment.score == 0
    names = {sig.name for sig in scanned.assessment.signals}
    # Nothing is hidden: the bootloader traits stay on the record.
    assert names == {
        "process_injection_combo",
        "anti_debug_imports",
        "packer_section_name",
    }
    assert any(
        "verified Sentinel Safeguard tool" in note
        for note in scanned.assessment.notes
    )


def test_verified_sibling_via_scan_path_tree(db, bundle):
    """The on-demand tree scan (what a user pointing Argus at the
    bundle folder runs) applies the same trust."""
    root, add, finalize = bundle
    add("TechniciansToolkit.exe", bootloader_profile_pe())
    add("Charon/Charon.exe", bootloader_profile_pe())
    finalize()
    report = scan_path(root, db, [])
    by_name = {f.result.path.name: f for f in report.files}
    assert by_name["TechniciansToolkit.exe"].verdict is Verdict.CLEAN
    assert by_name["Charon.exe"].verdict is Verdict.CLEAN


def test_sibling_one_byte_flipped_is_tamper_and_convicted(db, bundle):
    root, add, finalize = bundle
    original = bootloader_profile_pe()
    add("TechniciansToolkit.exe", original)
    finalize()
    target = root / "TechniciansToolkit.exe"
    flipped = bytearray(target.read_bytes())
    flipped[len(flipped) // 2] ^= 0xFF
    target.write_bytes(bytes(flipped))
    scanned = scan_file(target, db, [])
    names = {sig.name for sig in scanned.assessment.signals}
    assert "bundle_tool_file_modified" in names
    assert scanned.verdict is Verdict.MALICIOUS
    assert any(
        "tamper indicator" in note for note in scanned.assessment.notes
    )


def test_same_name_same_bytes_outside_bundle_earns_no_trust(db, bundle, tmp_path):
    """Name earns nothing, and neither does content alone: the
    identical bytes in a stranger's folder (no bundle anchor) get
    no sibling trust — they are scored as the stranger they are
    (calibration holds them at Suspicious, not Clean-by-trust)."""
    root, add, finalize = bundle
    add("TechniciansToolkit.exe", bootloader_profile_pe())
    finalize()
    stranger = tmp_path / "Downloads" / "TechniciansToolkit.exe"
    stranger.parent.mkdir()
    stranger.write_bytes(bootloader_profile_pe())
    scanned = scan_file(stranger, db, [])
    assert scanned.verdict is Verdict.SUSPICIOUS
    assert not any(
        "verified Sentinel Safeguard tool" in note
        for note in scanned.assessment.notes
    )


def test_unrecorded_file_inside_bundle_earns_no_trust(db, bundle):
    """A stranger dropped INTO the bundle folder but absent from
    the integrity record: scanned normally, trusted not at all,
    accused of nothing."""
    root, add, finalize = bundle
    add("TechniciansToolkit.exe", bootloader_profile_pe())
    finalize()
    dropped = add("free-games.exe", bootloader_profile_pe())
    scanned = scan_file(dropped, db, [])
    assert scanned.verdict is Verdict.SUSPICIOUS
    assert not any(
        sig.name == "bundle_tool_file_modified"
        for sig in scanned.assessment.signals
    )


def test_signature_detection_on_verified_sibling_still_fires(db, bundle):
    """Trust zeroes heuristics ONLY: a sibling whose very bytes
    are a signature-database match (the record honestly vouches
    for those bytes) is still Malicious on the signature."""
    root, add, finalize = bundle
    target = add("NitroCoreOptimizer.exe", EICAR)
    finalize()
    scanned = scan_file(target, db, [])
    assert scanned.verdict is Verdict.MALICIOUS
    assert scanned.assessment.detections
    assert scanned.assessment.detections[0].name == "EICAR-Test-File"


def test_realtime_path_agrees_with_on_demand(db, bundle, tmp_path):
    """The photo came through the realtime watcher; the fix must
    hold there too. The engine drives the same scanner core —
    proven behaviourally: both paths return the SAME verdict for
    the verified sibling (heuristics zeroed by trust; the two
    generic pattern rules still speak, exactly as the trust
    doctrine prescribes — and crucially NOT the field's Malicious),
    and both convict its byte-flipped twin as Malicious."""
    root, add, finalize = bundle
    launcher = add("TechniciansToolkit.exe", bootloader_profile_pe())
    finalize()

    on_demand = scan_file(launcher, db, BUILTIN_RULES)
    assert on_demand.assessment.score == 0  # heuristics zeroed by trust
    assert on_demand.verdict is Verdict.SUSPICIOUS  # rules still fire
    assert {
        det.name for det in on_demand.assessment.detections if det.kind == "rule"
    } == {"Process_Injection_API_Combo", "UPX_Packer_Marker"}

    events: list = []
    config = ArgusConfig(
        watch_dirs=[root],
        poll_interval=0.05,
        stable_polls=1,
        process_monitor_enabled=False,
        status_file=str(tmp_path / "status.json"),
    )
    engine = RealtimeEngine(config, db, BUILTIN_RULES, on_event=events.append)
    try:
        engine.start()
        assert _wait_for(lambda: engine.stats.scans_completed >= 1)
        time.sleep(0.3)
        detections = [e for e in events if e.kind == "detection"]
        # The realtime path agrees with on-demand: at most the
        # rule-driven Suspicious — never the field's Malicious.
        assert all(e.verdict != "Malicious" for e in detections)
        assert all(
            e.verdict == on_demand.verdict.value for e in detections
        )

        target = root / "TechniciansToolkit.exe"
        flipped = bytearray(target.read_bytes())
        flipped[len(flipped) // 3] ^= 0xFF
        target.write_bytes(bytes(flipped))
        assert _wait_for(
            lambda: any(
                e.kind == "detection" and e.verdict == "Malicious"
                for e in events
            ),
            timeout=10.0,
        )
    finally:
        engine.stop()


def _wait_for(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ----------------------------------------------------------------------
# Finding #2, part 2 — signal calibration
# ----------------------------------------------------------------------
def _sig(name, points, severity="high"):
    return Signal(name=name, severity=severity, points=points, explanation="t")


def test_calibration_packaging_traits_alone_cannot_convict():
    """The launcher's exact field profile: 75 raw points of pure
    packaging traits. Pre-fix: Malicious. Calibrated: held at
    the top of Suspicious — flagged for a look, not convicted."""
    scored = score_signals(
        [
            _sig("process_injection_combo", 45, "critical"),
            _sig("anti_debug_imports", 15, "medium"),
            _sig("packer_section_name", 15, "medium"),
        ]
    )
    assert scored.raw_score == 75
    assert scored.score == 59
    assert scored.verdict is Verdict.SUSPICIOUS


def test_calibration_any_real_signal_lifts_the_cap():
    scored = score_signals(
        [
            _sig("process_injection_combo", 45, "critical"),
            _sig("anti_debug_imports", 15, "medium"),
            _sig("packer_section_name", 15, "medium"),
            _sig("persistence_mechanism", 30),
        ]
    )
    assert scored.score == 105
    assert scored.verdict is Verdict.MALICIOUS


def test_calibration_ordinal_shadow_is_also_corroboration_class():
    scored = score_signals(
        [
            _sig("ordinal_hidden_combo_suspect", 22, "medium"),
            _sig("anti_debug_imports", 15, "medium"),
            _sig("packer_section_name", 15, "medium"),
            _sig("vm_evasion_strings", 15, "medium"),
        ]
    )
    # v1.2.5 CORRECTION — this test originally asserted the
    # opposite: that vm_evasion_strings is NOT a packaging trait
    # and the profile convicts at 67. The real measurement (the
    # published kit's own binaries, pinned in
    # tests/test_fieldfix_v125.py) proved VM-environment names
    # ride inside the runtimes every one-file tool bundles —
    # they are packaging, and the corrected class includes them.
    # The profile is now corroboration-only: held at 59.
    assert scored.score == 59
    assert scored.verdict is Verdict.SUSPICIOUS
    # The shadow itself still corroborates at full weight the
    # moment behaviour joins it: same profile plus an AMSI-
    # bypass string convicts outright.
    scored = score_signals(
        [
            _sig("ordinal_hidden_combo_suspect", 22, "medium"),
            _sig("anti_debug_imports", 15, "medium"),
            _sig("packer_section_name", 15, "medium"),
            _sig("vm_evasion_strings", 15, "medium"),
            _sig("amsi_bypass_strings", 25, "high"),
        ]
    )
    assert scored.score == 92
    assert scored.verdict is Verdict.MALICIOUS


def test_calibration_critical_combination_untouched():
    scored = score_signals(
        [
            _sig("process_injection_combo", 45, "critical"),
            _sig("high_entropy_executable_section", 25),
        ]
    )
    assert scored.short_circuit is True
    assert scored.verdict is Verdict.MALICIOUS


def test_calibration_bootloader_profile_end_to_end(db, tmp_path):
    """The full pipeline on the fixture that reproduces the
    field profile, OUTSIDE any bundle: Suspicious, 59 points,
    exactly the three packaging signals — nothing invented,
    nothing hidden."""
    target = tmp_path / "some-tool.exe"
    target.write_bytes(bootloader_profile_pe())
    scanned = scan_file(target, db, [])
    names = {sig.name for sig in scanned.assessment.signals}
    assert names == {
        "process_injection_combo",
        "anti_debug_imports",
        "packer_section_name",
    }
    assert scanned.assessment.score == 59
    assert scanned.verdict is Verdict.SUSPICIOUS


def test_detection_corpus_unchanged_packed_injector_still_malicious(db, tmp_path):
    """The real-malware profile (packed injector: injection
    combination inside high-entropy RWX sections) convicts
    exactly as before — calibration is not neutering."""
    target = tmp_path / "injector.exe"
    target.write_bytes(packed_injector_pe())
    scanned = scan_file(target, db, [])
    assert scanned.verdict is Verdict.MALICIOUS
    assert scanned.assessment.score >= 60


def test_clean_control_stays_clean(db, tmp_path):
    target = tmp_path / "clean.exe"
    target.write_bytes(clean_pe())
    scanned = scan_file(target, db, [])
    assert scanned.verdict is Verdict.CLEAN
