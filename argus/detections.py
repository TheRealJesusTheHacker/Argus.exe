"""Detections and verdicts for ARGUS.EXE.

Everything the engine finds about a file — a signature hit, a rule hit —
becomes a :class:`Detection` with a plain-language reason. Detections are
combined into one :class:`Verdict` per file:

- **Malicious** — the file's hash matches a known-bad signature, or a
  critical-severity rule matched. Treat as dangerous.
- **Suspicious** — a rule matched but nothing proves the file is bad.
  Worth a closer look, not a verdict of guilt.
- **Clean** — no signature and no rule matched.

Argus is honest about the difference: "suspicious" means "look closer",
never "definitely malware". No scareware math.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .rules import RuleHit
from .signatures import SignatureHit


class Verdict(Enum):
    CLEAN = "Clean"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"

    @property
    def rank(self) -> int:
        return _VERDICT_RANK[self]


_VERDICT_RANK = {Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}

#: Rule severities that, on their own, justify a Malicious verdict.
_MALICIOUS_RULE_SEVERITIES = frozenset({"critical"})


@dataclass(frozen=True)
class Detection:
    """One reason a file was flagged, in plain language."""

    kind: str  # "signature" | "rule"
    name: str
    severity: str
    reason: str
    family: str | None = None

    @classmethod
    def from_signature(cls, hit: SignatureHit) -> "Detection":
        return cls(
            kind="signature",
            name=hit.name,
            severity=hit.severity,
            family=hit.family,
            reason=(
                f"This file is an exact match for known malware "
                f"'{hit.name}' (family: {hit.family}). Its fingerprint "
                f"(SHA-256) is in the signature database."
            ),
        )

    @classmethod
    def from_rule(cls, hit: RuleHit) -> "Detection":
        return cls(
            kind="rule",
            name=hit.rule.name,
            severity=hit.rule.severity,
            reason=hit.rule.description,
        )


@dataclass
class FileAssessment:
    """All detections for one file plus the combined verdict."""

    detections: list[Detection] = field(default_factory=list)

    @property
    def verdict(self) -> Verdict:
        worst = Verdict.CLEAN
        for det in self.detections:
            if det.kind == "signature":
                return Verdict.MALICIOUS
            if det.severity in _MALICIOUS_RULE_SEVERITIES:
                worst = Verdict.MALICIOUS
            elif worst is Verdict.CLEAN:
                worst = Verdict.SUSPICIOUS
        return worst

    @property
    def flagged(self) -> bool:
        return self.verdict is not Verdict.CLEAN


def assess(
    signature_hit: SignatureHit | None, rule_hits: list[RuleHit]
) -> FileAssessment:
    """Combine one file's signature and rule hits into an assessment."""
    detections: list[Detection] = []
    if signature_hit is not None:
        detections.append(Detection.from_signature(signature_hit))
    detections.extend(Detection.from_rule(hit) for hit in rule_hits)
    return FileAssessment(detections=detections)
