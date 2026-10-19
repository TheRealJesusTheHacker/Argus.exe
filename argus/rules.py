"""Pattern rules for ARGUS.EXE — a small YARA-style rule engine.

Signatures catch files we already know are bad. Rules catch files that
*look* bad: byte patterns associated with malicious techniques (a
PowerShell download cradle, process-injection API names, packer markers).

Rule format (plain dicts / JSON)::

    {
      "name": "Process_Injection_API_Combo",
      "description": "Names of Windows APIs used together for process injection",
      "severity": "high",                  # low | medium | high | critical
      "condition": "all",                  # "any" (default) or "all"
      "patterns": [
        {"text": "VirtualAllocEx"},
        {"text": "WriteProcessMemory"},
        {"text": "CreateRemoteThread"},
        {"hex": "55 50 58 30"},            # "UPX0"; "??" = any byte
        {"text": "downloadstring", "nocase": true}
      ]
    }

Evaluation is streaming: :class:`RuleMatcher` accepts chunks of a file
and keeps only a small rolling tail in memory, so even large files are
matched without being loaded whole. Files larger than
``MAX_RULE_SCAN_SIZE`` (64 MB) of NON-executable content are not
rule-scanned — the caller notes the skip; executable content is
matched at any size (see :mod:`argus.scanner`), and hash-based
detection applies regardless.

Abuse caps (v1.0.4): rules are data, and data can be hostile or just
broken. Loading caps the rule count, each pattern's length, and each
pattern's wildcard density — a rule that breaks a cap is rejected
with a warning and the rest still load. Matching runs under a
per-file time budget: when it expires, matching stops and the
matcher says so (``budget_exceeded``) instead of grinding a CPU core
on an adversarial file.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from .signatures import SEVERITIES

log = logging.getLogger("argus.rules")

#: Files larger than this are skipped by the rule engine (hash-only).
MAX_RULE_SCAN_SIZE = 64 * 1024 * 1024  # 64 MB

#: Load-time abuse caps (see the module docstring).
MAX_RULES = 512
MAX_PATTERN_LENGTH = 4096
MAX_WILDCARD_RATIO = 0.5

#: Per-file wall-clock budget for pattern matching, in seconds.
MATCH_TIME_BUDGET_SECONDS = 2.0


class RuleError(Exception):
    """Raised when a rule definition is malformed."""


# ----------------------------------------------------------------------
# Patterns
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Pattern:
    """One byte pattern: literal bytes plus a mask (0xFF = must match,
    0x00 = wildcard). ``nocase`` lowercases ASCII before matching."""

    data: bytes
    mask: bytes
    nocase: bool = False

    def __post_init__(self) -> None:
        if not self.data:
            raise RuleError("pattern must not be empty")
        if len(self.data) != len(self.mask):
            raise RuleError("pattern data/mask length mismatch")
        if self.nocase:
            object.__setattr__(self, "data", self.data.lower())

    @property
    def has_wildcards(self) -> bool:
        return any(m == 0 for m in self.mask)

    @property
    def length(self) -> int:
        return len(self.data)

    @classmethod
    def from_text(cls, text: str, *, nocase: bool = False) -> "Pattern":
        raw = text.encode("utf-8", errors="surrogateescape")
        return cls(data=raw, mask=b"\xff" * len(raw), nocase=nocase)

    @classmethod
    def from_hex(cls, hex_string: str) -> "Pattern":
        """Parse a hex string like ``"55 50 58 ?? 30"`` (spaces optional)."""
        tokens = hex_string.split()
        if len(tokens) == 1 and len(tokens[0]) % 2 == 0 and "?" not in tokens[0]:
            tokens = [tokens[0][i : i + 2] for i in range(0, len(tokens[0]), 2)]
        data = bytearray()
        mask = bytearray()
        for tok in tokens:
            if tok in ("??", "?"):
                data.append(0)
                mask.append(0x00)
            else:
                try:
                    data.append(int(tok, 16))
                except ValueError as exc:
                    raise RuleError(f"invalid hex token {tok!r} in pattern") from exc
                mask.append(0xFF)
        return cls(data=bytes(data), mask=bytes(mask))


def _find_pattern(haystack: bytes, pattern: Pattern) -> int:
    """Return the offset of the first match of *pattern*, or -1."""
    data = haystack.lower() if pattern.nocase else haystack
    if not pattern.has_wildcards:
        return data.find(pattern.data)
    # Wildcard search: anchor on the longest exact run, then verify.
    needle, mask = pattern.data, pattern.mask
    n, m = len(data), len(needle)
    if m > n:
        return -1
    for start in range(n - m + 1):
        for j in range(m):
            if mask[j] and data[start + j] != needle[j]:
                break
        else:
            return start
    return -1


# ----------------------------------------------------------------------
# Rules
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    """A named pattern rule with a severity and a match condition."""

    name: str
    description: str
    severity: str
    patterns: tuple[Pattern, ...]
    condition: str = "any"  # "any" | "all"

    def __post_init__(self) -> None:
        if not self.name:
            raise RuleError("rule must have a name")
        if self.severity not in SEVERITIES:
            raise RuleError(
                f"rule {self.name!r}: severity must be one of {SEVERITIES}, "
                f"got {self.severity!r}"
            )
        if self.condition not in ("any", "all"):
            raise RuleError(
                f"rule {self.name!r}: condition must be 'any' or 'all', "
                f"got {self.condition!r}"
            )
        if not self.patterns:
            raise RuleError(f"rule {self.name!r}: at least one pattern is required")
        for pattern in self.patterns:
            if pattern.length > MAX_PATTERN_LENGTH:
                raise RuleError(
                    f"rule {self.name!r}: pattern is {pattern.length} bytes "
                    f"(cap is {MAX_PATTERN_LENGTH}) — oversized patterns "
                    "are rejected at load"
                )
            if pattern.has_wildcards:
                wild = sum(1 for m in pattern.mask if m == 0)
                if wild / pattern.length > MAX_WILDCARD_RATIO:
                    raise RuleError(
                        f"rule {self.name!r}: pattern is "
                        f"{wild / pattern.length:.0%} wildcards (cap is "
                        f"{MAX_WILDCARD_RATIO:.0%}) — a mostly-wildcard "
                        "pattern matches almost anything and costs a "
                        "full scan per byte"
                    )

    @property
    def max_pattern_length(self) -> int:
        return max(p.length for p in self.patterns)

    @classmethod
    def from_dict(cls, spec: dict) -> "Rule":
        try:
            patterns = []
            for raw in spec["patterns"]:
                if "hex" in raw:
                    patterns.append(Pattern.from_hex(str(raw["hex"])))
                elif "text" in raw:
                    patterns.append(
                        Pattern.from_text(
                            str(raw["text"]), nocase=bool(raw.get("nocase", False))
                        )
                    )
                else:
                    raise RuleError(
                        f"rule {spec.get('name', '?')!r}: pattern needs 'hex' or 'text'"
                    )
            return cls(
                name=str(spec["name"]),
                description=str(spec.get("description", "")),
                severity=str(spec.get("severity", "medium")),
                patterns=tuple(patterns),
                condition=str(spec.get("condition", "any")),
            )
        except KeyError as exc:
            raise RuleError(f"rule is missing required field: {exc}") from exc


@dataclass
class RuleHit:
    """A rule matched a file. ``matched`` lists the pattern indexes hit."""

    rule: Rule
    matched: list[int] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.rule.name

    @property
    def severity(self) -> str:
        return self.rule.severity


class RuleMatcher:
    """Streaming matcher: feed file chunks, then call :meth:`finish`.

    Memory use is bounded by the longest pattern, not the file size:
    only a tail of ``max_pattern_length - 1`` bytes is carried between
    chunks so patterns straddling a chunk boundary still match.

    Matching runs under a per-file time budget
    (:data:`MATCH_TIME_BUDGET_SECONDS`): once it expires, feed()
    becomes a no-op and :attr:`budget_exceeded` is set — the caller
    notes the partial coverage instead of pretending the file was
    fully matched.
    """

    def __init__(
        self, rules: list[Rule], *, time_budget: float = MATCH_TIME_BUDGET_SECONDS
    ) -> None:
        self._rules = rules
        self._tail = b""
        self._matched: dict[int, set[int]] = {}  # rule index -> pattern indexes
        overlap = max((r.max_pattern_length for r in rules), default=1) - 1
        self._keep = max(overlap, 0)
        self._time_budget = max(0.0, float(time_budget))
        self._started: float | None = None
        self.budget_exceeded = False

    def feed(self, chunk: bytes) -> None:
        if not chunk or not self._rules or self.budget_exceeded:
            return
        now = time.monotonic()
        if self._started is None:
            self._started = now
        elif now - self._started > self._time_budget:
            self.budget_exceeded = True
            log.warning(
                "rule matching stopped: per-file time budget "
                "(%.1fs) exhausted — coverage is partial",
                self._time_budget,
            )
            return
        window = self._tail + chunk
        for idx, rule in enumerate(self._rules):
            already = self._matched.setdefault(idx, set())
            if len(already) == len(rule.patterns):
                continue  # everything already found; condition settled
            for p_idx, pattern in enumerate(rule.patterns):
                if p_idx in already:
                    continue
                if _find_pattern(window, pattern) >= 0:
                    already.add(p_idx)
        self._tail = window[-self._keep :] if self._keep else b""

    def finish(self) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for idx, rule in enumerate(self._rules):
            matched = self._matched.get(idx, set())
            if not matched:
                continue
            if rule.condition == "all" and len(matched) != len(rule.patterns):
                continue
            hits.append(RuleHit(rule=rule, matched=sorted(matched)))
        return hits


def evaluate_rules(rules: list[Rule], data: bytes) -> list[RuleHit]:
    """One-shot convenience: evaluate *rules* against an in-memory buffer."""
    matcher = RuleMatcher(rules)
    matcher.feed(data)
    return matcher.finish()


def load_rules(path: Path | str) -> list[Rule]:
    """Load rules from a JSON file (a list of rule dicts).

    A file that is not JSON, or not a list, raises
    :class:`RuleError`. Individual broken or over-cap rules are
    rejected with a logged warning while the rest still load — one
    bad rule must not disarm all the others. At most
    :data:`MAX_RULES` rules are loaded.
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        specs = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuleError(f"rules file is not valid JSON: {exc}") from exc
    if not isinstance(specs, list):
        raise RuleError("rules file must contain a JSON list of rules")
    if len(specs) > MAX_RULES:
        log.warning(
            "rules file has %d rules; loading only the first %d",
            len(specs), MAX_RULES,
        )
        specs = specs[:MAX_RULES]
    rules: list[Rule] = []
    for spec in specs:
        try:
            rules.append(Rule.from_dict(spec))
        except RuleError as exc:
            log.warning("rule rejected at load: %s", exc)
        except (TypeError, AttributeError) as exc:
            log.warning("rule rejected at load: malformed rule (%s)", exc)
    return rules


# ----------------------------------------------------------------------
# Built-in starter rules
# ----------------------------------------------------------------------
BUILTIN_RULES: list[Rule] = [
    Rule.from_dict(
        {
            "name": "Suspicious_PowerShell_Download",
            "description": (
                "Contains strings from a PowerShell 'download cradle' — a "
                "one-liner that pulls code from the internet and runs it "
                "in memory. Common in malware droppers and fileless attacks."
            ),
            "severity": "high",
            "condition": "any",
            "patterns": [
                {"text": "DownloadString", "nocase": True},
                {"text": "DownloadFile", "nocase": True},
                {"text": "Invoke-Expression", "nocase": True},
                {"text": "Net.WebClient", "nocase": True},
            ],
        }
    ),
    Rule.from_dict(
        {
            "name": "Process_Injection_API_Combo",
            "description": (
                "Contains the names of three Windows APIs that are almost "
                "only used together for process injection — running code "
                "inside another program to hide. Legitimate software rarely "
                "references all three."
            ),
            "severity": "high",
            "condition": "all",
            "patterns": [
                {"text": "VirtualAllocEx"},
                {"text": "WriteProcessMemory"},
                {"text": "CreateRemoteThread"},
            ],
        }
    ),
    Rule.from_dict(
        {
            "name": "Credential_Theft_Tool_Strings",
            "description": (
                "Contains strings from Mimikatz, a well-known tool for "
                "stealing passwords and login tokens from memory."
            ),
            "severity": "critical",
            "condition": "any",
            "patterns": [
                {"text": "sekurlsa::logonpasswords", "nocase": True},
                {"text": "Invoke-Mimikatz", "nocase": True},
            ],
        }
    ),
    Rule.from_dict(
        {
            "name": "UPX_Packer_Marker",
            "description": (
                "Packed with UPX, a tool that compresses executables. "
                "Plenty of legitimate software is packed, but malware uses "
                "packing to hide its contents from scanners, so packed "
                "files deserve a second look."
            ),
            "severity": "medium",
            "condition": "any",
            "patterns": [
                {"hex": "55 50 58 30"},  # UPX0
                {"hex": "55 50 58 31"},  # UPX1
                {"text": "UPX!"},
            ],
        }
    ),
]
