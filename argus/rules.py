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

Abuse caps (v1.0.4, hardened v1.1.0): rules are data, and data can
be hostile or just broken. Loading caps the rule count, the total
rules-file size (4 MiB — a larger file is refused outright with
:class:`RuleError`), the patterns per rule (256), each pattern's
length, and each pattern's wildcard density — a rule that breaks
a cap is rejected with a warning and the rest still load.
Matching runs under a per-file time budget: the budget is polled
INSIDE pattern matching (every 64 KiB segment of a literal scan,
periodically through a wildcard scan, between patterns and
between rules), so even a single huge pattern in a single-rule
matcher cannot overrun unboundedly; when the budget expires,
matching stops and the matcher says so (``budget_exceeded``,
surfaced honestly by :meth:`RuleMatcher.finish`) instead of
grinding a CPU core on an adversarial file. If the budget dies
before EOF, :meth:`RuleMatcher.finish` runs a tail pass over
the last 8 MiB of the stream with the full matcher under a
fresh budget, and the coverage note says both passes ran.
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
#: Cap on patterns in a single rule (v1.1.0 P1-14).
MAX_PATTERNS_PER_RULE = 256
#: Cap on the total size of a rules file, in bytes (v1.1.0 P1-14).
#: Rules are small text; 4 MiB is generous for legitimate files
#: and refuses a hostile/bloated one before it is even parsed.
MAX_RULES_FILE_SIZE = 4 * 1024 * 1024  # 4 MiB

#: Per-file wall-clock budget for pattern matching, in seconds.
MATCH_TIME_BUDGET_SECONDS = 2.0

#: The time budget is polled at least once per this many bytes
#: scanned inside a single pattern search (v1.1.0 P1-14).
BUDGET_POLL_BYTES = 64 * 1024  # 64 KiB

#: How much of the stream's tail the budget tail pass re-matches
#: when the primary pass dies before EOF (v1.1.0 P1-21).
TAIL_PASS_SIZE = 8 * 1024 * 1024  # 8 MiB


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


def _find_pattern(haystack: bytes, pattern: Pattern, budget_check=None) -> int:
    """Return the offset of the first match of *pattern*, or -1.

    ``budget_check`` (v1.1.0 P1-14), when given, is polled INSIDE
    the search — once per :data:`BUDGET_POLL_BYTES` (64 KiB)
    segment of a literal scan, and every 1024 start positions of
    a wildcard scan — and the search aborts with -1 as soon as it
    reports the budget spent. Without it a single huge pattern
    could run unboundedly far past the per-file budget before
    any between-rules poll got a chance to notice.
    """
    data = haystack.lower() if pattern.nocase else haystack
    if not pattern.has_wildcards:
        needle = pattern.data
        n, m = len(data), len(needle)
        if m > n:
            return -1
        pos = 0
        last_start = n - m
        while pos <= last_start:
            if pos > 0 and budget_check is not None and budget_check():
                return -1
            end = min(n, pos + BUDGET_POLL_BYTES + m - 1)
            idx = data.find(needle, pos, end)
            if idx >= 0:
                return idx
            if end >= n:
                break
            pos += BUDGET_POLL_BYTES
        return -1
    # Wildcard search: anchor on the longest exact run, then verify.
    needle, mask = pattern.data, pattern.mask
    n, m = len(data), len(needle)
    if m > n:
        return -1
    for start in range(n - m + 1):
        if (
            start > 0
            and start % 1024 == 0
            and budget_check is not None
            and budget_check()
        ):
            return -1
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
        if len(self.patterns) > MAX_PATTERNS_PER_RULE:
            raise RuleError(
                f"rule {self.name!r}: {len(self.patterns)} patterns "
                f"(cap is {MAX_PATTERNS_PER_RULE}) — a rule with an "
                "unbounded pattern list makes matching cost unbounded too"
            )
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

    Memory use is bounded: a tail of ``max_pattern_length - 1``
    bytes is carried between chunks so patterns straddling a
    chunk boundary still match, plus (v1.1.0 P1-21) a rolling
    copy of the last :data:`TAIL_PASS_SIZE` (8 MiB) of the stream,
    kept so the tail pass below can re-match the end of the file
    even when the primary pass died long before EOF.

    Matching runs under a per-file time budget
    (:data:`MATCH_TIME_BUDGET_SECONDS`): once it expires, feed()
    stops MATCHING (it still records the stream tail) and
    :attr:`budget_exceeded` is set — the caller notes the partial
    coverage instead of pretending the file was fully matched.
    The budget is polled between feeds, between rules, between
    patterns, and INSIDE a pattern search every
    :data:`BUDGET_POLL_BYTES` (v1.1.0 P1-14), so not even one
    huge pattern in a one-rule matcher can run unboundedly far
    past it — and :meth:`finish` polls the budget one last time,
    so a budget that died inside that single rule's scan is
    still reported honestly instead of being hidden by the lack
    of a "next rule" to poll at.

    Tail pass (v1.1.0 P1-21): when :meth:`finish` finds the
    primary budget was exceeded, it re-runs the FULL matcher
    over the retained last-8-MiB tail under a FRESH budget and
    merges any hits, sets :attr:`tail_pass_ran`, and writes
    :attr:`coverage_note` stating that both passes ran (coverage
    is still partial — the middle may be unmatched).
    ``argus.scanner.scan_file`` prefers this matcher's
    ``coverage_note`` when present (fix round 2, FIX 6) and only
    falls back to its plain budget note when no matcher produced
    one.

    Time is read through the instance's ``_clock`` attribute
    (``time.monotonic`` in production). Tests substitute a
    deterministic fake so budget behavior never depends on the
    host clock's resolution.
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
        self._clock = time.monotonic
        self.budget_exceeded = False
        #: True once the budget death is attributed to the primary
        #: (streaming) pass — the tail pass runs under its own.
        self.primary_budget_exceeded = False
        #: Tail pass state (see the class docstring).
        self.tail_pass_ran = False
        self.tail_pass_budget_exceeded = False
        #: Human-readable partial-coverage note, set when the
        #: budget was exceeded; states both passes when both ran.
        self.coverage_note: str | None = None
        self.bytes_fed = 0
        self._stream_tail = bytearray()
        self._tail_pass_done = False

    def _budget_spent(self) -> bool:
        """True when the per-file matching budget has expired."""
        return (
            self._started is not None
            and self._clock() - self._started > self._time_budget
        )

    def _note_budget_exceeded(self) -> None:
        if not self.budget_exceeded:
            log.warning(
                "rule matching stopped: per-file time budget "
                "(%.1fs) exhausted — coverage is partial",
                self._time_budget,
            )
        self.budget_exceeded = True
        self.primary_budget_exceeded = True

    def _capture_tail(self, chunk: bytes) -> None:
        """Retain the last :data:`TAIL_PASS_SIZE` bytes fed, even
        after matching has stopped — the tail pass needs the true
        end of the stream, not the end of the budget."""
        self.bytes_fed += len(chunk)
        self._stream_tail.extend(chunk)
        excess = len(self._stream_tail) - TAIL_PASS_SIZE
        if excess > 0:
            del self._stream_tail[:excess]

    def feed(self, chunk: bytes) -> None:
        if not chunk or not self._rules:
            return
        self._capture_tail(chunk)
        if self.budget_exceeded:
            return
        if self._started is None:
            self._started = self._clock()
        elif self._budget_spent():
            self._note_budget_exceeded()
            return
        window = self._tail + chunk
        stop = False
        for idx, rule in enumerate(self._rules):
            if stop:
                break
            if idx > 0 and self._budget_spent():
                self._note_budget_exceeded()
                break
            already = self._matched.setdefault(idx, set())
            if len(already) == len(rule.patterns):
                continue  # everything already found; condition settled
            for p_idx, pattern in enumerate(rule.patterns):
                if p_idx in already:
                    continue
                if self._budget_spent():
                    self._note_budget_exceeded()
                    stop = True
                    break
                if (
                    _find_pattern(
                        window, pattern, budget_check=self._budget_spent
                    )
                    >= 0
                ):
                    already.add(p_idx)
                if self._budget_spent():
                    # The budget died inside (or just after) this
                    # one pattern scan — true even for a matcher
                    # with a single rule and a single pattern.
                    self._note_budget_exceeded()
                    stop = True
                    break
        self._tail = window[-self._keep :] if self._keep else b""

    def _run_tail_pass(self) -> None:
        """Re-match the retained tail under a fresh budget and
        merge the hits into this matcher's results."""
        tail = bytes(self._stream_tail)
        fresh = RuleMatcher(self._rules, time_budget=self._time_budget)
        fresh._clock = self._clock
        fresh._tail_pass_done = True  # a tail pass never recurses
        fresh.feed(tail)
        if fresh._started is not None and fresh._budget_spent():
            fresh._note_budget_exceeded()
        for idx, pats in fresh._matched.items():
            self._matched.setdefault(idx, set()).update(pats)
        self.tail_pass_ran = True
        self.tail_pass_budget_exceeded = bool(fresh.budget_exceeded)
        self.coverage_note = (
            "pattern matching stopped early: the per-file rule time "
            "budget was exhausted during the primary (streaming) "
            f"pass; a tail pass over the last {len(tail)} bytes "
            "(up to 8 MB) then ran with the full matcher under a "
            "fresh budget — both passes ran, but coverage is still "
            "partial: content between the primary-pass cutoff and "
            "the tail window may not have been rule-matched (the "
            "file was still hashed and checked against signatures)"
        )

    def finish(self) -> list[RuleHit]:
        if (
            self._started is not None
            and not self.budget_exceeded
            and self._budget_spent()
        ):
            # Honest surface for the single-rule case: the budget
            # died during matching and no later poll noticed.
            self._note_budget_exceeded()
        if self.budget_exceeded and not self._tail_pass_done:
            self._tail_pass_done = True
            if self._stream_tail:
                self._run_tail_pass()
            else:
                self.coverage_note = (
                    "pattern matching stopped early: the per-file "
                    "rule time budget was exhausted during the "
                    "primary (streaming) pass and no stream data "
                    "was retained for a tail pass — coverage is partial"
                )
        hits: list[RuleHit] = []
        for idx, rule in enumerate(self._rules):
            matched = self._matched.get(idx, set())
            if not matched:
                continue
            if rule.condition == "all" and len(matched) != len(rule.patterns):
                continue
            hits.append(RuleHit(rule=rule, matched=sorted(matched)))
        return hits

    @property
    def partial_coverage(self) -> bool:
        """True when matching stopped early (budget) — with or
        without the tail pass, the whole stream was not matched
        by a single complete pass."""
        return self.budget_exceeded


def evaluate_rules(rules: list[Rule], data: bytes) -> list[RuleHit]:
    """One-shot convenience: evaluate *rules* against an in-memory buffer."""
    matcher = RuleMatcher(rules)
    matcher.feed(data)
    return matcher.finish()


def evaluate_stream(
    chunks, rules: list[Rule], *, time_budget: float = MATCH_TIME_BUDGET_SECONDS
) -> tuple[list[RuleHit], RuleMatcher]:
    """Streaming convenience: feed *chunks* through a matcher and
    finish it, returning ``(hits, matcher)`` so callers can read
    the honest result surface (``budget_exceeded``,
    ``tail_pass_ran``, ``coverage_note``). This is the streaming
    API the tail pass (P1-21) lives behind: when the primary
    budget dies before EOF, ``finish()`` has already run the
    last-8-MiB tail pass by the time this returns."""
    matcher = RuleMatcher(rules, time_budget=time_budget)
    for chunk in chunks:
        matcher.feed(chunk)
    return matcher.finish(), matcher


def load_rules(path: Path | str) -> list[Rule]:
    """Load rules from a JSON file (a list of rule dicts).

    A file that is not JSON, or not a list, raises
    :class:`RuleError`. Individual broken or over-cap rules are
    rejected with a logged warning while the rest still load — one
    bad rule must not disarm all the others. At most
    :data:`MAX_RULES` rules are loaded. A file larger than
    :data:`MAX_RULES_FILE_SIZE` (4 MiB) is refused outright with
    :class:`RuleError` before it is parsed (v1.1.0 P1-14).
    """
    rules_path = Path(path)
    try:
        file_size = rules_path.stat().st_size
    except OSError:
        file_size = None  # read_text below raises the honest error
    if file_size is not None and file_size > MAX_RULES_FILE_SIZE:
        raise RuleError(
            f"rules file is {file_size} bytes, exceeding the "
            f"{MAX_RULES_FILE_SIZE}-byte (4 MiB) cap — refusing to "
            "load it; split or trim the rules file"
        )
    text = rules_path.read_text(encoding="utf-8")
    if len(text.encode("utf-8")) > MAX_RULES_FILE_SIZE:
        raise RuleError(
            f"rules file exceeds the {MAX_RULES_FILE_SIZE}-byte "
            "(4 MiB) cap — refusing to load it"
        )
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
