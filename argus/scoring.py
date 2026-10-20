"""The risk scoring model for ARGUS.EXE heuristics.

Heuristic signals (see :mod:`argus.heuristics.signals`) each carry a
weight in points. This module adds the points up and turns them into a
verdict:

- **0–24 points → Clean.** Nothing found that resembles a known
  malicious technique. (A lone weak signal or two lands here — Argus
  does not cry wolf over trivia.)
- **25–59 points → Suspicious.** One strong technique indicator, or
  several weak ones adding up. Worth a closer look.
- **60+ points → Malicious.** Multiple strong indicators in
  combination — the profile of real malware.

Two adjustments keep the model honest:

- **Critical combinations short-circuit.** Some signal combinations
  are damning in a way raw addition understates — a process-injection
  import set inside a packed, high-entropy executable section is
  Malicious outright, whatever the arithmetic says.
- **A digital signature lowers, never erases.** Signed malware exists,
  so a certificate table trims points (signed software has an
  accountable publisher) but can never whitewash a file to Clean from
  a Malicious-level score, and never cancels a critical combination.
- **A recognised Windows system file is not scored for its PE
  content.** When a file is a structurally-valid signed Microsoft
  binary in its proper system location (see
  :mod:`argus.heuristics.analyze`), its PE-content heuristic
  signals are zeroed: normal operating-system files must not be
  flagged for having ordinary system-binary properties.
  Filename/masquerade signals and the oversize floor are not PE
  content and are NEVER zeroed. This clears ONLY (part of) the
  heuristic score — a signature-database match or a pattern-rule
  detection on the same file still decides the verdict on its
  own, and every signal stays listed on the report.
- **A hash-verified Sentinel sibling gets the same treatment.**
  Inside the Technician's Toolkit bundle, a file whose SHA-256
  matches the bundle's own integrity record (see
  :mod:`argus.bundletrust`) is family, proven by fingerprint —
  never by name: its PE-content heuristic score is zeroed
  exactly as a system file's is, with the same never-zeroed
  exceptions, and the same signature/rule independence.
- **Packaging traits corroborate; they cannot convict alone.**
  A family of signals describes how a program is PACKAGED, not
  what it DOES: the in-memory-loader import combination and its
  ordinal-hidden shadow, debugger-detection imports, packer
  section names — and the shape of one-file packaging itself:
  a giant overlay carrying the bundled program, high-entropy
  data outside every declared section, a flooded string table,
  virtual-machine names shipped inside common runtimes, and an
  unsigned request for administrator rights in the manifest.
  Measured on the real published binaries of the whole
  Technician's Toolkit (the measurement is pinned as tests in
  ``tests/test_fieldfix_v125.py``), the kit's own tools summed
  to 70 points of exactly these traits and nothing else — over
  the Malicious line for files whose only offence was how they
  were built. (v1.2.4's first calibration round covered only
  the import-combination family: it had been aimed at a crafted
  profile instead of the measured one. v1.2.5 corrects the
  aim.) When a file's ENTIRE profile is packaging traits, its
  score is held just below the Malicious line (Suspicious —
  "worth a closer look" is the honest verdict for a packed
  stranger). The moment ANY other signal is present —
  persistence, credential access, a high-entropy executable
  section, a download-and-execute pair, anything behavioural —
  full arithmetic applies and the same traits corroborate at
  full weight; the critical combinations short-circuit exactly
  as before.

Every point in a score traces back to a named signal with a
plain-language explanation. No opaque math, no scareware inflation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detections import Verdict
from .heuristics.signals import Signal

#: Points at which a file becomes Suspicious.
SUSPICIOUS_THRESHOLD = 25
#: Points at which a file becomes Malicious.
MALICIOUS_THRESHOLD = 60
#: Points trimmed when the file carries an Authenticode signature.
SIGNED_DISCOUNT = 15

#: Signal-name combinations that are Malicious on sight.
CRITICAL_COMBINATIONS: tuple[frozenset[str], ...] = (
    frozenset({"process_injection_combo", "high_entropy_executable_section"}),
)

#: Signals system-file trust can NEVER zero (v1.1.0 hunt P0-3 /
#: L7 P2). Trust is a statement about PE *content* heuristics —
#: that a genuine Windows binary's sections/imports/strings look
#: the way Windows binaries look. It says nothing about the
#: file's NAME (masquerade is a property of the name, not the
#: content, and a trusted binary wearing a lying name is still
#: lying), nothing about the oversize floor (a file too large to
#: fully analyse was, by definition, not cleared by analysis),
#: and nothing about Argus's own tamper indicator.
TRUST_PROTECTED_SIGNAL_NAMES = frozenset({
    "rtl_override_filename",
    "double_extension",
    "system_binary_masquerade",
    "oversize_not_fully_analyzed",
    "argus_program_file_replaced",
})

#: "Hot pocket" window signals (v1.1.0 hunt P2): a high-entropy
#: pocket found by the sliding windows. Their points carry a
#: FLOOR through the signed trim: the trim may reduce a score,
#: but it may not dilute a hot pocket's contribution to zero —
#: dilution (a small hot pocket inside a large signed file) is
#: exactly how pockets hide.
HOT_POCKET_SIGNAL_NAMES = frozenset({
    "high_entropy_window_in_section",
    "high_entropy_outside_sections",
})

#: Packaging-trait signals (calibration v1.2.4, corrected
#: v1.2.5): properties of a program's RUNTIME/packaging rather
#: than its behaviour. Each is honest evidence — worth points,
#: worth listing — but they are ubiquitous in legitimate
#: software. Two families:
#:
#: * the loader family — the in-memory-loader import combination
#:   and its ordinal-hidden shadow, debugger-detection imports,
#:   packer section names (every PyInstaller bootloader imports
#:   the combination and the debugger checks; packer names ship
#:   with whole toolchains);
#: * the one-file family — the traits of carrying a whole
#:   program inside one file: a huge overlay, high-entropy data
#:   outside the declared sections, a string table past the
#:   extraction cap, virtual-machine names bundled inside
#:   common runtimes, and an unsigned elevation manifest.
#:
#: The one-file family was measured on the REAL published
#: bundle binaries in v1.2.5 (the six signal lists are pinned
#: verbatim in tests/test_fieldfix_v125.py): five kit tools
#: scored 70 — Malicious — on these traits alone, the sixth 55.
#: v1.2.4's class covered only the loader family, so the cap
#: never intersected the real profiles; that is the error
#: v1.2.5 corrects. A profile consisting ONLY of these traits
#: corroborates suspicion; it cannot carry a file over the
#: Malicious line by itself. Any signal outside this set lifts
#: the cap and full arithmetic applies. Note
#: ``high_entropy_outside_sections`` keeps its hot-pocket
#: membership above: the pocket floor still guards the signed
#: trim, and the cap below is applied after it — the pocket
#: counts in full toward Suspicious either way, and
#: corroborates at full weight the moment any behavioural
#: signal is present.
CORROBORATION_ONLY_SIGNAL_NAMES = frozenset({
    "process_injection_combo",
    "ordinal_hidden_combo_suspect",
    "anti_debug_imports",
    "packer_section_name",
    "huge_overlay",
    "high_entropy_outside_sections",
    "string_extraction_truncated",
    "vm_evasion_strings",
    "unsigned_elevation_request",
})


@dataclass
class ScoredSignals:
    """The outcome of scoring one file's heuristic signals."""

    signals: list[Signal] = field(default_factory=list)
    raw_score: int = 0
    score: int = 0
    signed: bool = False
    short_circuit: bool = False
    #: True when the file was recognised as a signed Windows
    #: system file: the heuristic score was zeroed in full (raw
    #: score and signals are still recorded — nothing is hidden).
    trusted_system_file: bool = False
    #: True when the file was recognised as a hash-verified
    #: Sentinel sibling from the bundle's own integrity record:
    #: the heuristic score was zeroed on the same terms.
    trusted_bundle_sibling: bool = False

    @property
    def verdict(self) -> Verdict:
        if self.short_circuit:
            return Verdict.MALICIOUS
        if self.score >= MALICIOUS_THRESHOLD:
            return Verdict.MALICIOUS
        if self.score >= SUSPICIOUS_THRESHOLD:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    @property
    def max_severity(self) -> str | None:
        best: str | None = None
        best_rank = 0
        for sig in self.signals:
            rank = _SEVERITY_RANK.get(sig.severity, 0)
            if rank > best_rank:
                best, best_rank = sig.severity, rank
        return best


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def score_signals(
    signals: list[Signal],
    *,
    signed: bool = False,
    trusted_system_file: bool = False,
    trusted_bundle_sibling: bool = False,
) -> ScoredSignals:
    """Combine heuristic *signals* into a score and verdict.

    ``signed`` records that the signed score trim applies (see
    module docstring): it lowers but never erases, never below the
    Suspicious line when the raw score was at Malicious level, and
    never overrides a critical combination. Since
    the v1.1.0 hunt (P1-20) callers may only pass True when the
    certificate payload DER-parses as PKCS#7 SignedData WITH an
    extracted signer — a certificate region that is mere junk
    bytes earns no trim, however valid its table header looks.

    ``trusted_system_file`` records that the file was recognised
    as a signed Windows system file in a system location: the
    PE-content heuristic score is zeroed outright (critical
    combinations included — a combination of system-binary
    properties inside a genuine system file is a description of
    Windows, not of malware). Filename/masquerade signals and the
    oversize floor are NOT content heuristics and are never
    zeroed (see :data:`TRUST_PROTECTED_SIGNAL_NAMES`): they keep
    their points and can still carry the verdict. Only the
    HEURISTIC score is affected either way; signature and rule
    detections are combined elsewhere and never cleared here.

    ``trusted_bundle_sibling`` is the same statement for a
    hash-verified Sentinel tool from the bundle's own integrity
    record (:mod:`argus.bundletrust`): identical zeroing terms,
    recorded separately so reports can say WHICH trust applied.
    """
    raw = sum(sig.points for sig in signals)
    names = {sig.name for sig in signals}
    short_circuit = any(combo <= names for combo in CRITICAL_COMBINATIONS)

    if trusted_system_file or trusted_bundle_sibling:
        protected = sum(
            sig.points
            for sig in signals
            if sig.name in TRUST_PROTECTED_SIGNAL_NAMES
        )
        protected_names = names & TRUST_PROTECTED_SIGNAL_NAMES
        return ScoredSignals(
            signals=list(signals),
            raw_score=raw,
            score=protected,
            signed=signed,
            # A critical combination can only be completed by
            # protected signals; the known combinations are pure
            # PE-content, so trust clears them by construction.
            short_circuit=any(
                combo <= protected_names for combo in CRITICAL_COMBINATIONS
            ),
            trusted_system_file=trusted_system_file,
            trusted_bundle_sibling=trusted_bundle_sibling,
        )

    score = raw
    if signed and raw > 0:
        score = raw - SIGNED_DISCOUNT
        if raw >= MALICIOUS_THRESHOLD:
            # Lowers, never erases: a Malicious-level raw score keeps
            # at least a Suspicious verdict after the discount.
            score = max(score, SUSPICIOUS_THRESHOLD)
        score = max(score, 0)
        # Hot-pocket floor: the trim cannot dilute a sliding-window
        # high-entropy pocket's own contribution to zero.
        pocket_points = sum(
            sig.points for sig in signals if sig.name in HOT_POCKET_SIGNAL_NAMES
        )
        if pocket_points:
            score = max(score, min(pocket_points, raw))
    if "oversize_not_fully_analyzed" in names:
        # The oversize signal's own contract: a file that was not
        # fully analysed is rated AT LEAST Suspicious — no trim
        # may talk it back under the line it promises.
        score = max(score, SUSPICIOUS_THRESHOLD)
    if (
        score >= MALICIOUS_THRESHOLD
        and not short_circuit
        and names
        and names <= CORROBORATION_ONLY_SIGNAL_NAMES
    ):
        # Calibration (v1.2.4, corrected v1.2.5): a profile made
        # ONLY of packaging traits — the shape shared by every
        # one-file-packaged program, measured on the real kit —
        # corroborates suspicion but cannot convict alone. Held
        # at the top of Suspicious: the file is still flagged
        # for a closer look, its signals still listed at full
        # weight, and any single behavioural or structural
        # signal lifts this cap.
        score = MALICIOUS_THRESHOLD - 1

    return ScoredSignals(
        signals=list(signals),
        raw_score=raw,
        score=score,
        signed=signed,
        short_circuit=short_circuit,
        trusted_system_file=trusted_system_file,
        trusted_bundle_sibling=trusted_bundle_sibling,
    )
