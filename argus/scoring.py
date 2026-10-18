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


@dataclass
class ScoredSignals:
    """The outcome of scoring one file's heuristic signals."""

    signals: list[Signal] = field(default_factory=list)
    raw_score: int = 0
    score: int = 0
    signed: bool = False
    short_circuit: bool = False

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


def score_signals(signals: list[Signal], *, signed: bool = False) -> ScoredSignals:
    """Combine heuristic *signals* into a score and verdict.

    ``signed`` records that the file carries an Authenticode
    certificate table; it trims the score (see module docstring) but
    never below the Suspicious line when the raw score was at
    Malicious level, and never overrides a critical combination.
    """
    raw = sum(sig.points for sig in signals)
    names = {sig.name for sig in signals}
    short_circuit = any(combo <= names for combo in CRITICAL_COMBINATIONS)

    score = raw
    if signed and raw > 0:
        score = raw - SIGNED_DISCOUNT
        if raw >= MALICIOUS_THRESHOLD:
            # Lowers, never erases: a Malicious-level raw score keeps
            # at least a Suspicious verdict after the discount.
            score = max(score, SUSPICIOUS_THRESHOLD)
        score = max(score, 0)

    return ScoredSignals(
        signals=list(signals),
        raw_score=raw,
        score=score,
        signed=signed,
        short_circuit=short_circuit,
    )
