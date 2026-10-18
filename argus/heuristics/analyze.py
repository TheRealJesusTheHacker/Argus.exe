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
class _StringExtractor:
    """Pull printable strings (>= 4 chars) out of a byte stream.

    Handles chunk boundaries: a string split across two chunks is
    still found whole. Memory is bounded by the caps above.
    """

    def __init__(self) -> None:
        self.index = StringIndex()
        self._ascii_run = bytearray()
        self._u16_run: list[int] = []
        self._u16_pending: int | None = None

    # ------------------------------------------------------------------
    def _flush_ascii(self) -> None:
        if len(self._ascii_run) >= _MIN_STRING_LEN:
            self._store(self._ascii_run.decode("ascii", errors="replace"))
        self._ascii_run.clear()

    def _flush_u16(self) -> None:
        if len(self._u16_run) >= _MIN_STRING_LEN:
            self._store(bytes(self._u16_run).decode("ascii", errors="replace"))
        self._u16_run.clear()
        self._u16_pending = None

    def _store(self, value: str) -> None:
        if len(self.index.strings) >= _MAX_STRINGS:
            self.index.truncated = True
            return
        self.index.add(value[:_MAX_STRING_CHARS])

    # ------------------------------------------------------------------
    def feed(self, chunk: bytes) -> None:
        for byte in chunk:
            printable = 0x20 <= byte <= 0x7E
            # ASCII runs
            if printable:
                if len(self._ascii_run) < _MAX_STRING_CHARS:
                    self._ascii_run.append(byte)
            else:
                self._flush_ascii()
            # UTF-16LE runs: printable byte followed by 0x00
            if self._u16_pending is None:
                if printable:
                    self._u16_pending = byte
                else:
                    self._flush_u16()
            elif byte == 0:
                self._u16_run.append(self._u16_pending)
                if len(self._u16_run) >= _MAX_STRING_CHARS:
                    self._flush_u16()
                self._u16_pending = None
            else:
                self._flush_u16()
                if printable:
                    self._u16_pending = byte

    def finish(self) -> StringIndex:
        self._flush_ascii()
        self._flush_u16()
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
