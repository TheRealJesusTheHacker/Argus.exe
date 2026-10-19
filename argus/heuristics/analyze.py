"""Heuristic analysis orchestration for ARGUS.EXE.

Given a file, decide what kind of analysis applies and run it:

- **Windows executables** (.exe/.dll/.sys/.scr and kin): parse the PE
  structure, then make one streamed content pass computing entropy
  (whole file, sliding windows, per section) and extracting strings.
  Structure + content become signals via
  :mod:`argus.heuristics.signals`.
- **Scripts** (.ps1/.bat/.cmd/.vbs/.js/.jse/.wsf/.hta): decode the text
  and run the script signal library.
- **Any file**: filename signals (double extensions, invisible
  right-to-left override characters, system-binary masquerades) need
  no content at all.

Everything fails safe: a malformed PE produces an honest note and
whatever signals could still be gathered — never an exception that
could take down a scan. Reads are streamed and capped at
``MAX_HEURISTIC_SCAN_SIZE``; memory stays flat.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .entropy import (
    HIGH_ENTROPY_THRESHOLD,
    EntropyAnalyzer,
    EntropySummary,
    SectionEntropyTracker,
)
from .pe import PEError, PEInfo, parse_pe
from .signals import (
    Signal,
    StringIndex,
    filename_signals,
    pe_signals,
    script_signals,
)

#: Files larger than this get filename signals only (mirrors the rule
#: engine's cap); the skip is noted on the report.
MAX_HEURISTIC_SCAN_SIZE = 64 * 1024 * 1024  # 64 MB

#: Scripts are decoded from at most this many bytes.
SCRIPT_READ_CAP = 4 * 1024 * 1024

_CHUNK_SIZE = 1024 * 1024
_MAX_STRINGS = 20_000
_MAX_STRING_CHARS = 4096
_MIN_STRING_LEN = 4

PE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".efi",
    ".mui", ".tlb",
}
SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta",
    ".psm1", ".btm",
}


@dataclass
class HeuristicReport:
    """Everything heuristic analysis found about one file."""

    kind: str  # "pe" | "script" | "file"
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    signed: bool = False
    pe: PEInfo | None = None
    entropy: EntropySummary | None = None


# ----------------------------------------------------------------------
# String extraction (streamed, capped, ASCII + UTF-16LE)
# ----------------------------------------------------------------------
import re as _re

_ASCII_RUN_RE = _re.compile(rb"[\x20-\x7e]+")
_U16_RUN_RE = _re.compile(rb"(?:[\x20-\x7e]\x00)+")


def _is_printable(byte: int) -> bool:
    return 0x20 <= byte <= 0x7E


class _StringExtractor:
    """Pull printable strings (>= 4 chars) out of a byte stream.

    Handles chunk boundaries: a string split across two chunks is
    still found whole. Memory is bounded by the caps above.

    Implementation note: this used to walk the stream byte by byte
    with two state machines (ASCII runs; UTF-16LE pairs). It now
    finds the same runs in bulk with regexes and replays the stores
    in exactly the order the byte machines produced them (event
    position, ASCII before UTF-16 within one byte) — extraction
    results are identical, including the string caps and ordering.
    ``tests/test_heuristics_integration.py`` carries a differential
    test against a reference copy of the original byte machine.
    """

    def __init__(self) -> None:
        self.index = StringIndex()
        self._ascii_pending = b""  # unterminated ASCII run tail
        self._u16_run = bytearray()  # chars of the current UTF-16 run
        self._u16_pending: int | None = None  # printable byte awaiting 0x00

    # ------------------------------------------------------------------
    def _store(self, value: str) -> None:
        if len(self.index.strings) >= _MAX_STRINGS:
            self.index.truncated = True
            return
        self.index.add(value[:_MAX_STRING_CHARS])

    # ------------------------------------------------------------------
    def feed(self, chunk: bytes) -> None:
        # (chunk position, machine order, value) store events; the
        # machine order keeps ASCII (0) ahead of UTF-16 (1) when one
        # byte triggers both, exactly like the original loop.
        events: list[tuple[int, int, str]] = []
        self._feed_ascii(chunk, events)
        self._feed_u16(chunk, events)
        events.sort(key=lambda event: (event[0], event[1]))
        for _pos, _order, value in events:
            self._store(value)

    def _feed_ascii(self, chunk: bytes, events: list) -> None:
        buf = self._ascii_pending + chunk
        prefix = len(self._ascii_pending)
        pending = b""
        for match in _ASCII_RUN_RE.finditer(buf):
            if match.end() == len(buf):
                # Unterminated (always the last match): it may
                # continue in the next chunk. Keep its first
                # _MAX_STRING_CHARS bytes — the same prefix the
                # byte machine accumulated before it stopped taking.
                pending = match.group()[:_MAX_STRING_CHARS]
            else:
                value = match.group()
                if len(value) >= _MIN_STRING_LEN:
                    events.append(
                        (match.end() - prefix, 0,
                         value.decode("ascii", errors="replace"))
                    )
                pending = b""
        self._ascii_pending = pending

    def _feed_u16(self, chunk: bytes, events: list) -> None:
        folded = (
            bytes([self._u16_pending])
            if self._u16_pending is not None
            else b""
        )
        buf = folded + chunk
        prefix = len(folded)
        pos = 0
        for match in _U16_RUN_RE.finditer(buf):
            start, end = match.span()
            if start > pos:
                self._u16_gap(buf[pos:start], False, pos - prefix, events)
            self._u16_append(match.group(), start, prefix, events)
            pos = end
        self._u16_pending = None
        if pos < len(buf):
            self._u16_pending = self._u16_gap(
                buf[pos:], True, pos - prefix, events
            )

    def _u16_gap(
        self, gap: bytes, at_end: bool, base_pos: int, events: list
    ) -> int | None:
        """Process the non-pair bytes between UTF-16 pair runs.

        A gap ends the current run (one flush event), except for the
        single case of one printable byte at the very end of the
        buffer: it becomes the pending byte whose pair may complete
        in the next chunk, and the run survives. Returns the pending
        byte after the gap (only meaningful for a trailing gap).
        """
        if not gap:
            return None
        if at_end and len(gap) == 1 and _is_printable(gap[0]):
            return gap[0]  # pending pair-start; no flush yet
        if len(self._u16_run) >= _MIN_STRING_LEN:
            # The flush is triggered by the first gap byte that is
            # not itself a fresh pair-start.
            flush_at = base_pos + (1 if _is_printable(gap[0]) else 0)
            events.append(
                (flush_at, 1,
                 bytes(self._u16_run).decode("ascii", errors="replace"))
            )
        self._u16_run.clear()
        if at_end and _is_printable(gap[-1]):
            return gap[-1]
        return None

    def _u16_append(
        self, match: bytes, match_start: int, prefix: int, events: list
    ) -> None:
        """Append a run of UTF-16LE pairs to the current run,
        storing each full _MAX_STRING_CHARS block as its own string
        (the byte machine flushed the moment the cap was reached)."""
        chars = match[0::2]
        idx = 0
        while idx < len(chars):
            room = _MAX_STRING_CHARS - len(self._u16_run)
            take = min(room, len(chars) - idx)
            self._u16_run += chars[idx : idx + take]
            idx += take
            if len(self._u16_run) == _MAX_STRING_CHARS:
                # Position of this block's final pair's 0x00 byte.
                events.append(
                    (match_start + 2 * idx - 1 - prefix, 1,
                     bytes(self._u16_run).decode("ascii", errors="replace"))
                )
                self._u16_run.clear()

    def finish(self) -> StringIndex:
        if len(self._ascii_pending) >= _MIN_STRING_LEN:
            self._store(
                self._ascii_pending.decode("ascii", errors="replace")
            )
        self._ascii_pending = b""
        if len(self._u16_run) >= _MIN_STRING_LEN:
            self._store(bytes(self._u16_run).decode("ascii", errors="replace"))
        self._u16_run.clear()
        self._u16_pending = None
        return self.index


def extract_strings(path: Path, cap: int = MAX_HEURISTIC_SCAN_SIZE) -> StringIndex:
    """Extract strings from *path* in one streamed pass."""
    extractor = _StringExtractor()
    read = 0
    with open(path, "rb") as fh:
        while read < cap:
            chunk = fh.read(min(_CHUNK_SIZE, cap - read))
            if not chunk:
                break
            read += len(chunk)
            extractor.feed(chunk)
    return extractor.finish()


# ----------------------------------------------------------------------
# Analysis entry point
# ----------------------------------------------------------------------
def analyze_file(path: Path, size: int | None = None) -> HeuristicReport:
    """Run the heuristic analysis appropriate for *path*.

    Never raises for file-content problems: unreadable or malformed
    content yields notes on the report, not exceptions. (Filesystem
    errors opening the file are likewise converted to a note.)
    """
    name = path.name
    ext = path.suffix.lower()
    signals: list[Signal] = filename_signals(name)
    notes: list[str] = []

    if size is None:
        try:
            size = path.stat().st_size
        except OSError as exc:
            return HeuristicReport(
                kind="file", signals=signals,
                notes=[f"heuristics could not stat file: {exc.strerror or exc}"],
            )

    if ext in PE_EXTENSIONS:
        report = HeuristicReport(kind="pe", signals=signals, notes=notes)
        _analyze_pe(path, size, report)
        return report

    if ext in SCRIPT_EXTENSIONS:
        report = HeuristicReport(kind="script", signals=signals, notes=notes)
        _analyze_script(path, size, report)
        return report

    return HeuristicReport(kind="file", signals=signals, notes=notes)


def _analyze_pe(path: Path, size: int, report: HeuristicReport) -> None:
    pe: PEInfo | None = None
    try:
        pe = parse_pe(path)
    except PEError as exc:
        report.notes.append(
            f"file has a Windows-executable extension but could not be "
            f"parsed as one: {exc}"
        )
    except OSError as exc:
        report.notes.append(f"heuristics could not read file: {exc.strerror or exc}")
        return
    report.pe = pe
    if pe is not None:
        report.signed = pe.signed
        for warning in pe.warnings:
            report.notes.append(f"PE parse note: {warning}")

    if size > MAX_HEURISTIC_SCAN_SIZE:
        report.notes.append(
            f"file is larger than {MAX_HEURISTIC_SCAN_SIZE // (1024 * 1024)} MB — "
            "deep heuristic content analysis skipped (structure and "
            "signature checks still applied)"
        )
        if pe is not None:
            report.signals.extend(pe_signals(pe, StringIndex(), EntropySummary()))
        return

    # One streamed content pass: entropy (whole + windows + per
    # section) and string extraction share the read.
    entropy = EntropyAnalyzer()
    sections = SectionEntropyTracker(
        [(s.raw_offset, s.raw_offset + s.raw_size) for s in pe.sections]
        if pe is not None
        else []
    )
    extractor = _StringExtractor()
    try:
        offset = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                entropy.feed(chunk)
                sections.feed(offset, chunk)
                extractor.feed(chunk)
                offset += len(chunk)
    except OSError as exc:
        report.notes.append(f"heuristics could not read file: {exc.strerror or exc}")
        return

    summary = entropy.finish()
    report.entropy = summary
    strings = extractor.finish()

    if pe is not None:
        for idx, section in enumerate(pe.sections):
            section.entropy = sections.entropy_for(idx)
        report.signals.extend(pe_signals(pe, strings, summary))
    elif summary.whole_entropy >= HIGH_ENTROPY_THRESHOLD:
        report.signals.append(
            Signal(
                name="high_entropy_unparsed_executable",
                severity="medium",
                points=15,
                explanation=(
                    "This file claims to be a Windows program but cannot "
                    "be parsed as one, and its contents measure "
                    f"{summary.whole_entropy:.1f} bits of entropy — nearly "
                    "random, like packed or encrypted data. A program "
                    "whose structure cannot even be read deserves "
                    "suspicion."
                ),
            )
        )


def _analyze_script(path: Path, size: int, report: HeuristicReport) -> None:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(SCRIPT_READ_CAP + 1)
    except OSError as exc:
        report.notes.append(f"heuristics could not read file: {exc.strerror or exc}")
        return
    if len(raw) > SCRIPT_READ_CAP:
        report.notes.append(
            f"script is larger than {SCRIPT_READ_CAP // (1024 * 1024)} MB — "
            "only the beginning was analysed"
        )
        raw = raw[:SCRIPT_READ_CAP]

    text = _decode_script(raw)
    report.signals.extend(script_signals(text, path.name))


def _decode_script(raw: bytes) -> str:
    """Decode script bytes: BOM-aware UTF-16/UTF-8, else latin-1."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")
