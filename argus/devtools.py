"""The ARGUS.EXE Dev Toolkit engine (Phase 5).

The Dev Toolkit is where a technical user can see *how* Argus thinks
and steer it: how sensitive the scoring is, which heuristic signals
count and how much, whether Argus is in simulation mode (detect-only,
touch nothing), and a test bench that takes any file apart and shows
every fact and every point that went into its verdict.

This module is the engine half — pure standard library, no GUI
imports — so every behaviour here is unit-testable headlessly. The
GUI panel (``argus.gui``) is a thin face over it.

Honesty rules, same as everywhere in Argus:

- **Simulation mode never touches a file.** Actions taken while it is
  on are recorded as *intent* ("would quarantine") and nothing else.
  The real action engine is not called.
- **The self-test proves the pipeline with the industry-standard
  EICAR test file** — a harmless string every antivirus is expected
  to catch — in a throwaway folder that is removed afterwards.
- **Signal tuning is transparent.** The catalog below mirrors the
  signal library's own severities and points; a test guards the
  mirror so the editor can never quietly drift from the engine.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from .detections import Verdict
from .heuristics.analyze import analyze_file
from .heuristics.signals import Signal
from .paths import write_text_atomic
from .rules import Rule, RuleMatcher
from .scanner import hash_file, scan_file
from .scoring import CRITICAL_COMBINATIONS, SIGNED_DISCOUNT
from .signatures import EICAR_NAME, SignatureDB, init_db

if TYPE_CHECKING:  # runtime import would be circular via actions->scanner
    from .actions import ActionOutcome, DetectionInfo
    from .realtime import RealtimeEvent

log = logging.getLogger("argus.devtools")

#: The EICAR anti-malware test string (68 bytes). Harmless by design —
#: it is the industry-standard way to prove a scanner works.
EICAR_BYTES = (
    rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

#: Default file name for the Dev Toolkit settings JSON.
DEVTOOLS_FILENAME = "argus-devtools.json"


# ----------------------------------------------------------------------
# Signal catalog (mirror of heuristics/signals.py + analyze.py)
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class SignalSpec:
    """The catalog facts about one heuristic signal."""

    name: str
    severity: str
    points: int
    summary: str


#: Every signal the engine can raise, with the severity and points the
#: signal library assigns it. ``tests/test_devtools.py`` parses the
#: signal library's source and fails if this catalog drifts from it.
SIGNAL_CATALOG: tuple[SignalSpec, ...] = (
    SignalSpec("rtl_override_filename", "critical", 60,
               "Filename hides an invisible right-to-left override character."),
    SignalSpec("powershell_download_cradle", "critical", 50,
               "Script downloads code and executes it in memory (download cradle)."),
    SignalSpec("process_injection_combo", "critical", 45,
               "Imports the API trio used to inject code into other programs."),
    SignalSpec("credential_access", "high", 35,
               "Reaches for stored passwords or the LSASS process."),
    SignalSpec("download_and_execute", "high", 35,
               "Can download a file and launch programs — dropper behaviour."),
    SignalSpec("content_extension_mismatch", "high", 30,
               "File IS a Windows program but its name claims otherwise."),
    SignalSpec("double_extension", "high", 30,
               "Disguised by a double extension, e.g. photo.jpg.exe."),
    SignalSpec("encoded_powershell_command", "high", 30,
               "Runs a Base64-hidden PowerShell command."),
    SignalSpec("keylogging_combo", "high", 30,
               "Keyboard hook plus key-state polling — a keylogger's kit."),
    SignalSpec("persistence_mechanism", "high", 30,
               "Installs a way to relaunch itself at login or boot."),
    SignalSpec("amsi_bypass_strings", "high", 25,
               "References disabling Windows' script-scanning interface."),
    SignalSpec("certutil_download", "high", 25,
               "Abuses the certutil tool to download files."),
    SignalSpec("high_entropy_executable_section", "high", 25,
               "Executable code section with near-random (packed) contents."),
    SignalSpec("malformed_certificate", "high", 25,
               "Claims a signature, but the certificate region is structurally fake."),
    SignalSpec("mshta_remote_script", "high", 25,
               "Runs a remote script through the mshta tool."),
    SignalSpec("regsvr32_remote", "high", 25,
               "Pulls a remote scriptlet through regsvr32 (Squiblydoo)."),
    SignalSpec("rundll32_javascript", "high", 25,
               "Runs JavaScript through rundll32's URL handler."),
    SignalSpec("writable_executable_section", "high", 25,
               "A section that is both writable and executable (W+X)."),
    SignalSpec("oversize_not_fully_analyzed", "medium", 25,
               "Executable too large for full analysis — Suspicious floor."),
    SignalSpec("system_binary_masquerade", "medium", 15,
               "Named after a core Windows system program."),
    SignalSpec("anti_debug_imports", "medium", 15,
               "Imports debugger-detection APIs."),
    SignalSpec("entry_point_outside_sections", "medium", 15,
               "Starting address falls outside every declared section."),
    SignalSpec("entry_point_unusual", "medium", 15,
               "Starts running in an unusual section (packer hallmark)."),
    SignalSpec("high_entropy_outside_sections", "medium", 15,
               "Packed-looking data hidden outside every declared section."),
    SignalSpec("high_entropy_unparsed_executable", "medium", 15,
               "Claims to be a program, cannot be parsed, near-random contents."),
    SignalSpec("high_entropy_window_in_section", "medium", 15,
               "A packed pocket hidden inside an ordinary-looking section."),
    SignalSpec("ordinal_heavy_imports", "medium", 15,
               "Most imports referenced by number, hiding what it calls."),
    SignalSpec("packer_section_name", "medium", 15,
               "Has a section named after a known executable packer."),
    SignalSpec("script_extension_mismatch", "medium", 15,
               "File's contents are a script but its name claims otherwise."),
    SignalSpec("script_fetches_remote_content", "medium", 15,
               "Script fetches content from a web address."),
    SignalSpec("script_obfuscation", "medium", 15,
               "Script is densely obfuscated to hide from human readers."),
    SignalSpec("unsigned_elevation_request", "medium", 15,
               "Unsigned, yet asks to run with administrator rights."),
    SignalSpec("vm_evasion_strings", "medium", 15,
               "Names virtual-machine environments (analysis evasion)."),
    SignalSpec("zero_raw_code_section", "medium", 15,
               "Code section exists in memory but not in the file."),
    SignalSpec("huge_overlay", "medium", 15,
               "Large unexplained data appended after the last section."),
    SignalSpec("keylogging_api", "medium", 12,
               "Uses a keyboard-hooking or key-state API."),
    SignalSpec("imports_truncated", "medium", 10,
               "Import table hit a safety cap — too large to fully read."),
    SignalSpec("string_extraction_truncated", "low", 10,
               "More embedded strings than Argus extracts (flooding)."),
    SignalSpec("tls_callbacks_present", "medium", 10,
               "Code runs before the program's official starting point."),
    SignalSpec("unparseable_executable", "low", 10,
               "Presents as a program but its structure cannot be parsed."),
    SignalSpec("very_long_script_line", "medium", 10,
               "A single script line over 2,000 characters (smuggled payload)."),
    SignalSpec("minimal_imports", "low", 5,
               "Imports almost nothing — real APIs likely resolved secretly."),
    SignalSpec("timestamp_anomaly", "low", 5,
               "Build timestamp missing, future-dated, or implausibly old."),
)

_CATALOG_BY_NAME = {spec.name: spec for spec in SIGNAL_CATALOG}


def signal_spec(name: str) -> SignalSpec | None:
    """Catalog facts for a signal name, or None if uncatalogued."""
    return _CATALOG_BY_NAME.get(name)


# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
@dataclass
class SignalOverride:
    """A user's steering for one signal: on/off + weight multiplier."""

    enabled: bool = True
    weight: float = 1.0

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "weight": self.weight}

    @classmethod
    def from_dict(cls, raw: object) -> "SignalOverride | None":
        if not isinstance(raw, dict):
            return None
        enabled = raw.get("enabled", True)
        weight = raw.get("weight", 1.0)
        if not isinstance(enabled, bool):
            return None
        if not isinstance(weight, (int, float)) or isinstance(weight, bool):
            return None
        return cls(enabled=enabled, weight=max(0.0, min(5.0, float(weight))))


@dataclass
class DevSettings:
    """Everything the Dev Toolkit panel controls.

    Stored in its own JSON file (separate from the protection config)
    so toolkit experiments never corrupt the settings protection
    itself depends on. Loading is tolerant, like
    :class:`~argus.config.ArgusConfig`: bad values fall back per key
    and are reported in ``load_warnings``.
    """

    #: 0 (relaxed) .. 100 (paranoid); 50 = the engine's own thresholds.
    sensitivity: int = 50
    signal_overrides: dict[str, SignalOverride] = field(default_factory=dict)
    simulation_mode: bool = False
    verbose_logging: bool = False
    load_warnings: list[str] = field(default_factory=list)
    source_path: Path | None = None

    # ------------------------------------------------------------------
    def thresholds(self) -> tuple[int, int]:
        """(suspicious, malicious) score thresholds for the
        sensitivity slider. 50 reproduces the engine's 25 / 60."""
        return thresholds_for_sensitivity(self.sensitivity)

    def override_for(self, name: str) -> SignalOverride:
        return self.signal_overrides.get(name, SignalOverride())

    def set_override(self, name: str, *, enabled: bool, weight: float) -> None:
        self.signal_overrides[name] = SignalOverride(
            enabled=enabled, weight=max(0.0, min(5.0, float(weight)))
        )

    # ------------------------------------------------------------------
    def save(self, path: Path | str) -> None:
        data = {
            "sensitivity": self.sensitivity,
            "simulation_mode": self.simulation_mode,
            "verbose_logging": self.verbose_logging,
            "signal_overrides": {
                name: override.to_dict()
                for name, override in sorted(self.signal_overrides.items())
            },
        }
        target = Path(path)
        # Atomic, crash-safe write (unique temp file + fsync +
        # permission-preserving rename, the shared helper): never
        # leave a half-written settings file behind.
        write_text_atomic(target, json.dumps(data, indent=2) + "\n")
        self.source_path = target

    @classmethod
    def load(cls, path: Path | str | None) -> "DevSettings":
        settings = cls()
        if path is None:
            return settings
        settings_path = Path(path)
        settings.source_path = settings_path
        if not settings_path.is_file():
            settings.load_warnings.append(
                f"dev toolkit settings not found: {settings_path} — using defaults"
            )
            return settings
        try:
            raw = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            settings.load_warnings.append(
                f"could not read {settings_path}: {exc} — using defaults"
            )
            return settings
        if not isinstance(raw, dict):
            settings.load_warnings.append(
                f"{settings_path} is not a JSON object — using defaults"
            )
            return settings
        warn = settings.load_warnings.append

        sens = raw.get("sensitivity")
        if isinstance(sens, int) and not isinstance(sens, bool) and 0 <= sens <= 100:
            settings.sensitivity = sens
        elif sens is not None:
            warn("'sensitivity' must be an integer 0-100 — keeping 50")

        for key in ("simulation_mode", "verbose_logging"):
            value = raw.get(key)
            if isinstance(value, bool):
                setattr(settings, key, value)
            elif value is not None:
                warn(f"'{key}' must be true/false — keeping default")

        overrides = raw.get("signal_overrides")
        if isinstance(overrides, dict):
            for name, raw_override in overrides.items():
                parsed = SignalOverride.from_dict(raw_override)
                if parsed is None:
                    warn(f"signal override for {name!r} is malformed — ignored")
                else:
                    settings.signal_overrides[str(name)] = parsed
        elif overrides is not None:
            warn("'signal_overrides' must be an object — ignored")
        return settings


def thresholds_for_sensitivity(sensitivity: int) -> tuple[int, int]:
    """Map the 0-100 sensitivity slider to score thresholds.

    50 → the engine's own (25, 60). Lower sensitivity raises the bar
    (fewer, stronger findings flag a file); higher sensitivity lowers
    it (weaker findings add up to a flag sooner).
    """
    sensitivity = max(0, min(100, int(sensitivity)))
    factor = 1.5 - (sensitivity / 100.0)  # 1.5 at 0, 1.0 at 50, 0.5 at 100
    suspicious = max(5, round(25 * factor))
    malicious = max(suspicious + 5, round(60 * factor))
    return suspicious, malicious


# ----------------------------------------------------------------------
# Scoring under toolkit settings
# ----------------------------------------------------------------------
@dataclass
class EvaluatedSignal:
    """One signal after toolkit steering: what counted, and how much."""

    signal: Signal
    enabled: bool
    adjusted_points: int


@dataclass
class Evaluation:
    """A score computed under Dev Toolkit settings."""

    entries: list[EvaluatedSignal]
    raw_score: int
    score: int
    signed: bool
    short_circuit: bool
    suspicious_threshold: int
    malicious_threshold: int

    @property
    def verdict(self) -> Verdict:
        if self.short_circuit:
            return Verdict.MALICIOUS
        if self.score >= self.malicious_threshold:
            return Verdict.MALICIOUS
        if self.score >= self.suspicious_threshold:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    @property
    def counted_signals(self) -> list[Signal]:
        """Signals that actually contributed (enabled ones, points
        adjusted by their weights)."""
        return [
            replace(entry.signal, points=entry.adjusted_points)
            for entry in self.entries
            if entry.enabled
        ]


def evaluate_signals(
    signals: list[Signal], settings: DevSettings, *, signed: bool = False
) -> Evaluation:
    """Score *signals* under toolkit settings.

    Mirrors :func:`argus.scoring.score_signals` — same critical
    combinations, same signature discount that lowers but never
    erases — with the toolkit's per-signal on/off + weight steering
    and sensitivity thresholds applied. Disabled signals contribute
    nothing and cannot complete a critical combination.
    """
    entries: list[EvaluatedSignal] = []
    for sig in signals:
        override = settings.override_for(sig.name)
        adjusted = round(sig.points * override.weight) if override.enabled else 0
        entries.append(
            EvaluatedSignal(
                signal=sig, enabled=override.enabled, adjusted_points=adjusted
            )
        )
    counted_names = {e.signal.name for e in entries if e.enabled}
    short_circuit = any(combo <= counted_names for combo in CRITICAL_COMBINATIONS)
    raw = sum(e.adjusted_points for e in entries)
    score = raw
    suspicious, malicious = settings.thresholds()
    if signed and raw > 0:
        score = raw - SIGNED_DISCOUNT
        if raw >= malicious:
            score = max(score, suspicious)
        score = max(score, 0)
    return Evaluation(
        entries=entries,
        raw_score=raw,
        score=score,
        signed=signed,
        short_circuit=short_circuit,
        suspicious_threshold=suspicious,
        malicious_threshold=malicious,
    )


# ----------------------------------------------------------------------
# Rule test bench
# ----------------------------------------------------------------------
@dataclass
class SignalBreakdown:
    name: str
    severity: str
    base_points: int
    adjusted_points: int
    enabled: bool
    explanation: str


@dataclass
class TestBenchResult:
    """The full dissection of one file, for the test bench panel."""

    path: str
    size: int | None
    sha256: str | None
    kind: str  # "pe" | "script" | "file"
    signature_name: str | None
    signature_family: str | None
    signature_severity: str | None
    rule_hits: list[dict]
    signals: list[SignalBreakdown]
    entropy_whole: float | None
    entropy_max_window: float | None
    pe_facts: dict | None
    signed: bool
    raw_score: int
    score: int
    short_circuit: bool
    verdict: str
    notes: list[str]
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "kind": self.kind,
            "signature": (
                {
                    "name": self.signature_name,
                    "family": self.signature_family,
                    "severity": self.signature_severity,
                }
                if self.signature_name
                else None
            ),
            "rule_hits": list(self.rule_hits),
            "signals": [
                {
                    "name": s.name,
                    "severity": s.severity,
                    "base_points": s.base_points,
                    "adjusted_points": s.adjusted_points,
                    "enabled": s.enabled,
                    "explanation": s.explanation,
                }
                for s in self.signals
            ],
            "entropy": (
                {"whole": self.entropy_whole, "max_window": self.entropy_max_window}
                if self.entropy_whole is not None
                else None
            ),
            "pe": self.pe_facts,
            "signed": self.signed,
            "raw_score": self.raw_score,
            "score": self.score,
            "short_circuit": self.short_circuit,
            "verdict": self.verdict,
            "notes": list(self.notes),
            "error": self.error,
        }


def run_test_bench(
    path: Path | str,
    db: SignatureDB,
    rules: list[Rule],
    settings: DevSettings | None = None,
) -> TestBenchResult:
    """Dissect one file: every fact and every point behind its verdict.

    Runs the same pieces the scanner runs — fingerprint + signature
    lookup, pattern rules, heuristic analysis — then scores the
    signals under *settings* (engine defaults when omitted), so the
    bench shows both what the engine sees and what the user's tuning
    does with it.
    """
    settings = settings or DevSettings()
    target = Path(path)
    try:
        sha256, size = hash_file(target)
    except OSError as exc:
        return TestBenchResult(
            path=str(target), size=None, sha256=None, kind="file",
            signature_name=None, signature_family=None,
            signature_severity=None, rule_hits=[], signals=[],
            entropy_whole=None, entropy_max_window=None, pe_facts=None,
            signed=False, raw_score=0, score=0, short_circuit=False,
            verdict=Verdict.CLEAN.value, notes=[],
            error=f"could not read the file: {exc.strerror or exc}",
        )

    hit = db.lookup(sha256)

    matcher = RuleMatcher(rules)
    try:
        with open(target, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                matcher.feed(chunk)
        rule_hits = matcher.finish()
    except OSError:
        rule_hits = []
    rule_dicts = [
        {
            "name": h.rule.name,
            "severity": h.rule.severity,
            "description": h.rule.description,
        }
        for h in rule_hits
    ]

    report = analyze_file(target, size)
    evaluation = evaluate_signals(report.signals, settings, signed=report.signed)
    verdict = evaluation.verdict
    if hit is not None:
        verdict = Verdict.MALICIOUS
    elif any(h.rule.severity == "critical" for h in rule_hits):
        verdict = Verdict.MALICIOUS
    elif rule_hits and verdict is Verdict.CLEAN:
        verdict = Verdict.SUSPICIOUS

    pe_facts: dict | None = None
    if report.pe is not None:
        pe = report.pe
        pe_facts = {
            "machine": pe.machine,
            "is_64bit": pe.is_64bit,
            "is_dll": pe.is_dll,
            "signed": pe.signed,
            "has_tls_callbacks": pe.has_tls,
            "sections": [
                {
                    "name": s.name,
                    "entropy": s.entropy,
                    "executable": s.is_executable,
                    "writable": s.is_writable,
                }
                for s in pe.sections
            ],
            "imported_dlls": sorted(pe.imports.keys()),
            "imported_function_count": len(pe.imported_functions),
            "overlay_size": pe.overlay_size,
        }

    breakdown = [
        SignalBreakdown(
            name=entry.signal.name,
            severity=entry.signal.severity,
            base_points=entry.signal.points,
            adjusted_points=entry.adjusted_points,
            enabled=entry.enabled,
            explanation=entry.signal.explanation,
        )
        for entry in evaluation.entries
    ]
    return TestBenchResult(
        path=str(target),
        size=size,
        sha256=sha256,
        kind=report.kind,
        signature_name=hit.name if hit else None,
        signature_family=hit.family if hit else None,
        signature_severity=hit.severity if hit else None,
        rule_hits=rule_dicts,
        signals=breakdown,
        entropy_whole=(
            report.entropy.whole_entropy if report.entropy is not None else None
        ),
        entropy_max_window=(
            report.entropy.max_window_entropy
            if report.entropy is not None
            else None
        ),
        pe_facts=pe_facts,
        signed=report.signed,
        raw_score=evaluation.raw_score,
        score=evaluation.score,
        short_circuit=evaluation.short_circuit,
        verdict=verdict.value,
        notes=list(report.notes),
    )


# ----------------------------------------------------------------------
# EICAR self-test
# ----------------------------------------------------------------------
@dataclass
class SelfTestStep:
    name: str
    ok: bool
    detail: str


@dataclass
class SelfTestResult:
    passed: bool
    steps: list[SelfTestStep]

    def summary(self) -> str:
        if self.passed:
            return (
                "Self-test passed: Argus caught the industry-standard "
                "EICAR test file end to end. Detection is working."
            )
        failed = [s.name for s in self.steps if not s.ok]
        return (
            "Self-test FAILED at: " + ", ".join(failed) + ". "
            "Do not rely on Argus until this is looked at."
        )


def run_self_test(work_dir: Path | str | None = None) -> SelfTestResult:
    """Prove the whole detection pipeline with the EICAR test file.

    Builds a throwaway signature database, writes the EICAR test file
    into a throwaway folder, scans it, and confirms Argus flags it as
    the EICAR signature — then removes every trace.

    Scratch-space ownership is strict: with no *work_dir*, a fresh
    temp folder is created and removed afterwards. A caller-supplied
    *work_dir* is only ever USED, never owned: it must be empty (or
    not exist yet), Argus removes only the two files it put there,
    and the folder itself stays. A non-empty pre-existing folder is
    refused outright — the self-test will not tidy up after itself
    with a recursive delete of somebody else's directory.
    """
    steps: list[SelfTestStep] = []
    owns_dir = work_dir is None
    if owns_dir:
        scratch = Path(tempfile.mkdtemp(prefix="argus-selftest-"))
    else:
        scratch = Path(work_dir)
        if scratch.is_dir() and any(scratch.iterdir()):
            return SelfTestResult(
                passed=False,
                steps=[
                    SelfTestStep(
                        "scratch folder",
                        False,
                        f"{scratch} is not empty — the self-test only "
                        "runs in an empty folder it can leave exactly "
                        "as it found it.",
                    )
                ],
            )
    artifacts = [scratch / "selftest.sigdb", scratch / "eicar-test-file.txt"]
    # The signature DB's HMAC key file is created beside it (v1.0.4)
    # and is equally ours to clean up.
    from .signatures import key_path_for

    artifacts.append(key_path_for(artifacts[0]))
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        db_path = artifacts[0]
        info = init_db(db_path, seed=True)
        steps.append(
            SelfTestStep(
                "signature database",
                info.count >= 1,
                f"built a test database with {info.count} signature(s)",
            )
        )
        target = artifacts[1]
        target.write_bytes(EICAR_BYTES)
        steps.append(
            SelfTestStep(
                "test file written",
                target.is_file(),
                "the harmless EICAR test file was created in a scratch folder",
            )
        )
        with SignatureDB.open(db_path) as db:
            scanned = scan_file(target, db, [], heuristics=False)
        sha_ok = scanned.result.sha256 is not None
        steps.append(
            SelfTestStep(
                "fingerprinting",
                sha_ok,
                "Argus read and fingerprinted the file"
                if sha_ok
                else f"fingerprinting failed: {scanned.result.error}",
            )
        )
        names = [d.name for d in scanned.assessment.detections]
        caught = EICAR_NAME in names and scanned.verdict is Verdict.MALICIOUS
        steps.append(
            SelfTestStep(
                "detection",
                caught,
                f"flagged as {EICAR_NAME} with a Malicious verdict"
                if caught
                else f"expected a Malicious EICAR verdict, got "
                f"{scanned.verdict.value} ({names or 'no detections'})",
            )
        )
    except Exception as exc:  # the self-test must report, never crash
        steps.append(SelfTestStep("self-test run", False, f"error: {exc}"))
    finally:
        if owns_dir:
            shutil.rmtree(scratch, ignore_errors=True)
            removed = not scratch.exists()
            cleanup_detail = (
                "scratch folder removed"
                if removed
                else "scratch folder could not be fully removed"
            )
        else:
            # Caller-supplied folder: remove only what we put there.
            for artifact in artifacts:
                artifact.unlink(missing_ok=True)
            removed = not any(artifact.exists() for artifact in artifacts)
            cleanup_detail = (
                "self-test files removed; the folder itself was "
                "left in place"
                if removed
                else "self-test files could not be fully removed"
            )
    steps.append(SelfTestStep("cleanup", removed, cleanup_detail))
    return SelfTestResult(
        passed=all(step.ok for step in steps), steps=steps
    )


# ----------------------------------------------------------------------
# Simulation mode
# ----------------------------------------------------------------------
@dataclass
class SimulatedAction:
    """An action Argus *would* have taken in simulation mode."""

    action: str
    path: str
    detail: str

    def describe(self) -> str:
        return f"Simulation mode: {self.detail}"


class SimulatedActionEngine:
    """A stand-in for :class:`~argus.actions.ActionEngine` that
    records intent and touches nothing.

    Used when Dev Toolkit simulation mode is on: detections are
    analysed and reported exactly as usual, but quarantine / delete /
    allow requests are written down as "would …" records instead of
    being carried out. There is deliberately no reference to a real
    vault here — in simulation mode nothing can reach the files.
    """

    def __init__(self) -> None:
        self.records: list[SimulatedAction] = []

    # -- the ActionEngine surface the GUI/service wiring uses --------
    def _record(self, action: str, path: str, verb: str) -> "ActionOutcome":
        from .actions import ActionOutcome

        detail = f"would {verb} {Path(path).name} ({path}) — nothing was touched."
        self.records.append(
            SimulatedAction(action=action, path=str(path), detail=detail)
        )
        log.info("simulation: %s", detail)
        return ActionOutcome(
            action=action,
            path=str(path),
            done=False,
            message=f"Simulation mode is on: Argus {detail}",
        )

    def quarantine(
        self, path: Path | str, info: "DetectionInfo", *, confirmed: bool = False
    ) -> "ActionOutcome":
        return self._record("quarantine", str(path), "quarantine")

    def delete(
        self,
        path: Path | str,
        info: "DetectionInfo",
        *,
        confirmed: bool = False,
        direct: bool = False,
    ) -> "ActionOutcome":
        return self._record("delete", str(path), "permanently delete")

    def allow_file(
        self, path: Path | str, *, confirmed: bool = False
    ) -> "ActionOutcome":
        return self._record("allow", str(path), "allow (vouch for)")

    def allow_entry(
        self, entry_id: str, *, confirmed: bool = False
    ) -> "ActionOutcome":
        return self._record(
            "allow", f"vault entry {entry_id}", "restore and allow"
        )

    def restore_entry(
        self, entry_id: str, *, confirmed: bool = False
    ) -> "ActionOutcome":
        return self._record_entry("restore", entry_id, "restore")

    def delete_entry(
        self, entry_id: str, *, confirmed: bool = False
    ) -> "ActionOutcome":
        return self._record_entry("delete", entry_id, "permanently delete")

    def _record_entry(
        self, action: str, entry_id: str, verb: str
    ) -> "ActionOutcome":
        from .actions import ActionOutcome

        detail = (
            f"would {verb} the quarantined file held as vault entry "
            f"{entry_id} — nothing was touched."
        )
        self.records.append(
            SimulatedAction(
                action=action, path=f"vault entry {entry_id}", detail=detail
            )
        )
        log.info("simulation: %s", detail)
        return ActionOutcome(
            action=action,
            path=f"vault entry {entry_id}",
            done=False,
            entry_id=entry_id,
            message=f"Simulation mode is on: Argus {detail}",
        )

    def handle_realtime_event(self, event: "RealtimeEvent") -> "ActionOutcome | None":
        if event.kind != "action" or not event.path or not event.action:
            return None
        return self._record(event.action, event.path, event.action)

    def approve(self, pending_id: str) -> "ActionOutcome":
        """Simulated approval: records the intent, decides nothing.
        The real queue entry stays exactly as it is."""
        from .actions import ActionOutcome

        detail = (
            f"would approve queued action {pending_id} — the queue "
            "entry was NOT decided and no file was touched."
        )
        self.records.append(
            SimulatedAction(
                action="approve-pending",
                path=f"pending action {pending_id}",
                detail=detail,
            )
        )
        log.info("simulation: %s", detail)
        return ActionOutcome(
            action="approve-pending",
            path=f"pending action {pending_id}",
            done=False,
            pending_id=pending_id,
            message=f"Simulation mode is on: Argus {detail}",
        )

    def reject(self, pending_id: str) -> "ActionOutcome":
        """Simulated rejection: records the intent, decides nothing."""
        from .actions import ActionOutcome

        detail = (
            f"would reject queued action {pending_id} — the queue "
            "entry was NOT decided and no file was touched."
        )
        self.records.append(
            SimulatedAction(
                action="reject-pending",
                path=f"pending action {pending_id}",
                detail=detail,
            )
        )
        log.info("simulation: %s", detail)
        return ActionOutcome(
            action="reject-pending",
            path=f"pending action {pending_id}",
            done=False,
            pending_id=pending_id,
            message=f"Simulation mode is on: Argus {detail}",
        )


# ----------------------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------------------
class LogCapture(logging.Handler):
    """A bounded in-memory log handler for the Dev Toolkit log view."""

    def __init__(self, capacity: int = 500) -> None:
        super().__init__()
        self.capacity = capacity
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append(self.format(record))
            if len(self.records) > self.capacity:
                del self.records[: len(self.records) - self.capacity]
        except Exception:
            self.handleError(record)


def apply_logging(verbose: bool) -> None:
    """Apply the toolkit's verbose-logging toggle to the argus logger
    tree (DEBUG when on, INFO when off)."""
    logging.getLogger("argus").setLevel(
        logging.DEBUG if verbose else logging.INFO
    )
    log.debug("verbose logging %s", "enabled" if verbose else "disabled")
