"""Heuristic analysis orchestration for ARGUS.EXE.

Given a file, decide what kind of analysis applies and run it.
**Content decides, not the file name** (v1.0.4): the first bytes are
sniffed — MZ magic means PE analysis whatever the extension says,
script markers mean script analysis — and a name that disagrees
with the content is itself a signal. Extension-only routing let a
``payload.txt`` that is really an executable sail past every check.

- **Windows executables**: parse the PE structure, then make one
  streamed content pass computing entropy (whole file, sliding
  windows, per section), extracting strings, and running the
  cap-independent high-value needle search. Structure + content
  become signals via :mod:`argus.heuristics.signals`.
- **Scripts**: decode the text (BOM-aware, plus BOM-less UTF-16)
  and run the script signal library on what the interpreter would
  actually see.
- **Any file**: filename signals (double extensions, invisible
  right-to-left override characters, system-binary masquerades) need
  no content at all.

Everything fails safe: a malformed PE produces an honest note and
whatever signals could still be gathered — never an exception that
could take down a scan. Reads are streamed and capped at
``MAX_HEURISTIC_SCAN_SIZE``; memory stays flat.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..platform_authenticode import (
    STATUS_VERIFIED,
    AuthenticodeVerifier,
    platform_verifier,
)
from .entropy import (
    HIGH_ENTROPY_THRESHOLD,
    EntropyAnalyzer,
    EntropySummary,
    SectionEntropyTracker,
)
from .pe import PEError, PEInfo, parse_pe, signer_is_microsoft
from .signals import (
    Signal,
    StringIndex,
    filename_signals,
    pe_signals,
    script_signals,
)

log = logging.getLogger("argus.heuristics.analyze")

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

#: How many head bytes are sniffed to decide the content kind.
_SNIFF_BYTES = 8192

#: Byte markers that give a script away whatever its extension.
_SCRIPT_MARKERS = (
    b"powershell", b"invoke-expression", b"invoke-command",
    b"wscript.shell", b"@echo off", b"cscript", b"mshta", b"#!/",
)

#: The high-value needles the streaming search hunts for (see
#: :class:`_NeedleSearcher`) — exactly the strings the signal
#: library looks up via ``StringIndex.contains``.
_HIGH_VALUE_NEEDLES = (
    "lsass", "sekurlsa",
    "currentversion\\run", "currentversion/run",
    "schedule.service", "itaskservice",
    "amsiinitfailed", "amsiscanbuffer",
    "requireadministrator", "highestavailable",
    "vmware", "virtualbox", "vbox", "vmtoolsd", "vmmouse", "qemu",
    "sandboxie", "sbie", "virtual pc", "hyper-v", "xen",
)


class _NeedleSearcher:
    """Streaming search for the high-value needle set.

    Independent of string EXTRACTION: it runs on the raw stream
    (ASCII and UTF-16LE forms) with a rolling tail, so it keeps
    working after the extraction cap truncates — flooding a file
    with junk strings cannot hide the needles that matter.
    """

    def __init__(self, needles: tuple[str, ...] = _HIGH_VALUE_NEEDLES) -> None:
        self._ascii = [(n, n.encode("ascii")) for n in needles]
        self._u16 = [(n, n.encode("utf-16-le")) for n in needles]
        self._keep = max(len(n) for _, n in self._u16) - 1
        self._tail = b""
        self.hits: set[str] = set()

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        window = self._tail + chunk
        lowered = window.lower()
        for name, needle in self._ascii:
            if name not in self.hits and needle in lowered:
                self.hits.add(name)
        for name, needle in self._u16:
            if name not in self.hits and needle in lowered:
                self.hits.add(name)
        self._tail = window[-self._keep:] if self._keep else b""


@dataclass
class HeuristicReport:
    """Everything heuristic analysis found about one file."""

    kind: str  # "pe" | "script" | "file"
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    signed: bool = False
    #: True when the signed score trim may be applied (P1-20): the
    #: file is structurally signed AND its certificate payload
    #: DER-parses as PKCS#7 SignedData with an extracted signer.
    #: A ``signed`` table whose payload is junk bytes earns none.
    signed_trim_eligible: bool = False
    #: The signer identity claimed by the certificate ("Microsoft
    #: Windows", ...), when one could be extracted.
    signer: str | None = None
    #: True only when ALL trust conditions hold: the
    #: certificate is structurally valid with a complete
    #: SignerInfo, the signer is Microsoft, the file lives
    #: under the Windows directory outside its user-writable
    #: subtrees (links resolved) — AND, on Windows, the
    #: operating system's own Authenticode verifier
    #: (WinVerifyTrust, FIX 5) vouches for the signature's
    #: chain and digest. Off Windows the last leg is
    #: unavailable and trust stays claim-based (documented
    #: dev/non-Windows fallback — see
    #: :mod:`argus.platform_authenticode`). Scoring zeroes the
    #: PE-CONTENT heuristic score for such a file (never
    #: filename signals, never the oversize floor, and never
    #: its signature-database or pattern-rule detections).
    #:
    #: On Linux the same flag is set by the dpkg gate instead
    #: (v1.2.0): dpkg records the file as an installed package's
    #: payload AND the resolved path is a system location — see
    #: :mod:`argus.platform_dpkg`. The scoring treatment is
    #: identical: heuristic suspicion zeroed, detections stand.
    trusted_system_file: bool = False
    pe: PEInfo | None = None
    entropy: EntropySummary | None = None
    #: True when this report's SCRIPT oversize floor may be
    #: lifted by the caller (see :func:`waive_oversize_floor`):
    #: the file outgrew the script decode cap (so the floor was
    #: applied), it was routed to script analysis by its CONTENT
    #: alone — its name carries no script extension, so it never
    #: claimed to be code — and the heuristic script library
    #: found NO script signals in any passage it actually
    #: decoded (the head read plus every located window past
    #: the cap). The other half of the waiver — the pattern-rule
    #: layer must also have found nothing across its full raw
    #: and folded streaming passes — is known only to the
    #: scanner, so the floor is lifted there, never here.
    oversize_floor_waivable: bool = False


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
def _read_head(path: Path, count: int = _SNIFF_BYTES) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(count)
    except OSError:
        return b""


def _u16le_interleave_offset(sample: bytes) -> int | None:
    """If *sample* looks like UTF-16LE text, return the offset at
    which the text starts (0, or 2 past a BOM); else None.

    The test is the INTERLEAVE PATTERN (P2): character bytes at
    even positions, NUL bytes at odd positions — not raw NUL
    density. A binary blob can be a quarter NULs by chance; it
    cannot alternate character/NUL for dozens of pairs by chance.
    At least 8 pairs must be sampled, >= 80% of the odd bytes
    must be NUL, and >= 80% of the even bytes must be plausible
    text bytes (printable ASCII or tab/CR/LF)."""
    offsets: list[int] = []
    if sample.startswith(b"\xff\xfe"):
        offsets.append(2)
    offsets.append(0)
    for offset in offsets:
        body = sample[offset:]
        pairs = len(body) // 2
        if pairs < 8:
            continue
        even = body[0 : pairs * 2 : 2]
        odd = body[1 : pairs * 2 : 2]
        if odd.count(0) / pairs < 0.8:
            continue
        texty = sum(
            1 for b in even if b in (9, 10, 13) or 0x20 <= b <= 0x7E
        )
        if texty / pairs >= 0.8:
            return offset
    return None


def _looks_like_script(head: bytes) -> bool:
    lowered = head.lower()
    if any(marker in lowered for marker in _SCRIPT_MARKERS):
        return True
    # UTF-16LE in disguise (P0-4): decode the interleaved view —
    # every second byte — and test the same markers against what
    # the interpreter would see, whatever the extension claims.
    offset = _u16le_interleave_offset(head)
    if offset is not None:
        folded = head[offset:][0::2].lower()
        if any(marker in folded for marker in _SCRIPT_MARKERS):
            return True
    # Segment-based check (fix round 2, FIX 4): the all-or-
    # nothing interleave test above drowns when a benign ASCII
    # preface precedes a UTF-16LE passage — the preface's bytes
    # are not NUL-interleaved, so the whole-sample ratios fail
    # even though a long, perfectly interleaved passage sits
    # right there. A strong UTF-16LE SEGMENT anywhere in the
    # sample routes the file to script analysis: the segment
    # folds to plain text for the script decoder, and only the
    # script pipeline reads UTF-16 text correctly at all.
    # (Detection still requires rule/heuristic hits — routing
    # alone flags nothing, so an ordinary UTF-16 document
    # stays Clean.)
    # Only the segment's EXISTENCE is needed here, so the fast
    # lane test answers instead of the pair regex: the two are
    # pinned to agree on the first segment by the differential
    # test in test_fixround3, and the regex costs tens of ms
    # per window on segment-free data (sweep #5). The full span
    # list is still computed where it is actually consumed —
    # the segment-wise decode in _decode_script.
    if _u16le_segment_offset(head) is not None:
        return True
    return False


#: A UTF-16LE passage: at least 16 consecutive (text byte, NUL)
#: pairs. Sixteen pairs cannot happen by chance in binary data,
#: and the pattern is parity-free — it matches a passage at ANY
#: starting offset, which is exactly what mixed-content files
#: (ASCII preface + UTF-16 body) need. The text-byte class is the
#: printable set plus tab/CR/LF, mirroring the interleave test.
_U16_SEGMENT_RE = _re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){16,}")


def _u16le_segment_spans(sample: bytes) -> list[tuple[int, int]]:
    """Spans of *sample* that are strong UTF-16LE text passages
    (see :data:`_U16_SEGMENT_RE`)."""
    return [(m.start(), m.end()) for m in _U16_SEGMENT_RE.finditer(sample)]


#: Runs used by the fast segment-offset test below: text-class
#: runs and NUL runs inside one parity lane of a window.
_TEXT_RUN_RE = _re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{16,}")
_NUL_RUN_RE = _re.compile(rb"\x00+")
_NUL_RUN_16 = b"\x00" * 16


def _u16le_segment_offset(window: bytes) -> int | None:
    """Offset of the first strong UTF-16LE segment in *window*
    (the same >= 16-pair pattern as :data:`_U16_SEGMENT_RE`), or
    None — computed WITHOUT the pair regex.

    The pair regex costs 60-380 ms per MiB on data that contains
    no segment at all, which is far too slow to run on every
    chunk of a streaming scan (fix round 3: the routing test runs
    per chunk, so a negative file must cost ~nothing). This test
    splits the window into its two parity lanes instead: a
    segment is exactly a place where a >= 16 run of text-class
    bytes in one lane OVERLAPS a >= 16 run of NULs in the other
    lane by >= 16 positions. Lane runs are found with memmem-fast
    searches, so a segment-free window costs a few ms per MiB,
    and a differential fuzz test pins this test's answers to the
    pair regex's on thousands of crafted buffers.
    """
    best: int | None = None
    for parity in (0, 1):
        text_lane = window[parity::2]
        nul_lane = window[parity + 1 :: 2]
        lanes = min(len(text_lane), len(nul_lane))
        if lanes < 16:
            continue
        text_lane = text_lane[:lanes]
        nul_lane = nul_lane[:lanes]
        pos = 0
        while pos < lanes:
            hit = nul_lane.find(_NUL_RUN_16, pos)
            if hit < 0:
                break
            run_end = _NUL_RUN_RE.match(nul_lane, hit).end()
            found: int | None = None
            for match in _TEXT_RUN_RE.finditer(text_lane, hit, run_end):
                start = max(hit, match.start())
                if min(run_end, match.end()) - start >= 16:
                    found = start
                    break
            if found is not None:
                offset = parity + 2 * found
                if best is None or offset < best:
                    best = offset
                break  # lane hits increase: this parity's earliest
            pos = run_end
    return best


#: Bounded beyond-the-head script sniff (P0-4, reworked in fix
#: round 2 / FIX 4): when the 8 KB head shows nothing decisive, a
#: TEXT-LIKE file is sampled at its head, middle, and tail (one
#: window each, :data:`_SCRIPT_SAMPLE_WINDOW` bytes) for script
#: markers in the raw view, in BOTH folded parities, and for
#: strong UTF-16LE segments — so a cradle parked at 200 KB or
#: 1.5 MB behind a benign preface still routes to script
#: analysis. The bound is the strategy: at most three windows
#: are read for routing, whatever the file's size; the scanner's
#: pattern rules then stream the WHOLE file (raw + folded) once
#: routing says "script", so sampling depth never limits
#: detection depth.
_SCRIPT_SAMPLE_WINDOW = 256 * 1024


def _head_looks_textual(head: bytes) -> bool:
    """Cheap gate for sampling: bytes that are neither text
    controls, printable, nor NUL (UTF-16's padding) mark the head
    as binary — binary files are not sampled for script content."""
    if not head:
        return False
    binary_bytes = sum(
        1
        for b in head
        if b not in (0, 9, 10, 13) and not (0x20 <= b <= 0x7E)
    )
    return binary_bytes / len(head) <= 0.10


def _window_says_script(window: bytes) -> bool:
    """One sampled window's verdict: script markers in the raw
    view, in either folded parity, or a strong UTF-16LE segment
    (which folds to text the script pipeline must read)."""
    lowered = window.lower()
    if any(marker in lowered for marker in _SCRIPT_MARKERS):
        return True
    # Existence only — the fast lane test, as in
    # _looks_like_script (see its note; the pair regex on a
    # 256 KB segment-free window measured ~56 ms, the lane
    # test ~1 ms, with the same verdict).
    if _u16le_segment_offset(window) is not None:
        return True
    for parity in (0, 1):
        folded = window[parity::2].lower()
        if any(marker in folded for marker in _SCRIPT_MARKERS):
            return True
    return False


def _sniff_script_samples(path: Path, size: int) -> bool:
    """Sample head/middle/tail windows of *path* for script
    content. See :data:`_SCRIPT_SAMPLE_WINDOW`."""
    starts = {
        0,
        max(0, size // 2 - _SCRIPT_SAMPLE_WINDOW // 2),
        max(0, size - _SCRIPT_SAMPLE_WINDOW),
    }
    try:
        with open(path, "rb") as fh:
            for start in sorted(starts):
                fh.seek(start)
                window = fh.read(_SCRIPT_SAMPLE_WINDOW)
                if window and _window_says_script(window):
                    return True
    except OSError:
        return False
    return False


def sniff_script_content(
    path: Path, size: int, *, head: bytes | None = None
) -> bool:
    """The content-routing question, shared by the analyzer and
    the scanner: do this file's CONTENTS say "script"?

    Head first (:func:`_looks_like_script`); when the head is
    indecisive and the file is larger than the head, a text-like
    head earns the bounded head/middle/tail sample
    (:func:`_sniff_script_samples`). The scanner calls this
    BEFORE streaming, so the folded rule views exist from the
    first chunk when the answer is yes."""
    if head is None:
        head = _read_head(path) if size > 0 else b""
    if _looks_like_script(head):
        return True
    if size <= _SNIFF_BYTES:
        return False  # the head sniff already saw all of it
    if not _head_looks_textual(head):
        return False
    return _sniff_script_samples(path, size)


#: Carry kept between chunks of the full-stream routing scan.
#: A UTF-16LE segment straddling a chunk boundary stays
#: contiguous inside (carry + chunk): a segment needs 16 pairs
#: (32 bytes), so at most 15 pairs (30 bytes) of it can sit
#: behind the boundary — well inside a 64-byte carry.
_STREAM_SCAN_CARRY = 64

#: Segment offsets the routing scan records at most: enough to
#: feed the windowed script decode; further offsets would only
#: repeat windows the decoder already covers.
_MAX_STREAM_SEGMENTS = 8


def _stream_script_offsets(
    path: Path, size: int, *, cap: int = MAX_HEURISTIC_SCAN_SIZE
) -> tuple[bool, list[int]]:
    """Placement-independent content routing (fix round 3):
    stream the WHOLE file (up to *cap*) and answer "do its
    contents say script — anywhere?"

    The head sniff and the head/middle/tail sampler both leave a
    geometric blind zone: a UTF-16LE cradle parked BETWEEN the
    sampled windows of a large file routed as plain data and
    scored Clean (the P0-4 lineage, third strike). This scan has
    no geometry to hide in: every chunk is tested for script
    markers in the raw view (a 64-byte carry keeps a marker that
    straddles a chunk boundary whole) and for a strong UTF-16LE
    segment via the fast lane test (:func:`_u16le_segment_offset`,
    a few ms per MiB on negative data). Returns ``(says_script,
    segment_offsets)`` — the absolute offsets of the first
    strong UTF-16LE segments, which the script decoder uses to
    read passages parked beyond its head cap.
    """
    offsets: list[int] = []
    found = False
    carry = b""
    position = 0  # absolute offset of the current chunk's start
    read_total = 0
    try:
        with open(path, "rb") as fh:
            while read_total < cap:
                chunk = fh.read(min(_CHUNK_SIZE, cap - read_total))
                if not chunk:
                    break
                window = carry + chunk
                window_start = position - len(carry)
                lowered = window.lower()
                if any(marker in lowered for marker in _SCRIPT_MARKERS):
                    found = True
                if window.count(0) >= 16:
                    segment = _u16le_segment_offset(window)
                    if segment is not None:
                        found = True
                        absolute = window_start + segment
                        if absolute not in offsets:
                            offsets.append(absolute)
                carry = chunk[-_STREAM_SCAN_CARRY:]
                position += len(chunk)
                read_total += len(chunk)
                if len(offsets) >= _MAX_STREAM_SEGMENTS:
                    break
    except OSError:
        return found, offsets
    return found, offsets


# ----------------------------------------------------------------------
# Windows system-file trust
# ----------------------------------------------------------------------
def windows_root() -> Path:
    """The Windows installation directory (``C:\\Windows``).

    On Windows the directory is asked of the OS itself
    (``GetWindowsDirectoryW``): environment variables are
    user-controllable, and a trust decision ("is this file a
    Windows system file?") must not rest on a variable the
    file's owner could have set. ``%SystemRoot%`` / ``%windir%``
    remain only as the non-Windows / failure fallback (and as
    the seam tests use off-Windows); tests on any platform may
    also inject an override into :func:`analyze_file`.
    """
    if sys.platform == "win32":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetWindowsDirectoryW(  # type: ignore[attr-defined]
                buffer, len(buffer)
            )
            if length and length <= len(buffer) and buffer.value:
                return Path(buffer.value)
        except Exception:
            pass  # fall through to the environment fallback
    root = os.environ.get("SystemRoot") or os.environ.get("windir")
    return Path(root) if root else Path(r"C:\Windows")


def _normalised(path: Path | str) -> str:
    """Canonical string form for location checks: expanded,
    RESOLVED (links/junctions followed — a "system file" reached
    through a junction into a user folder is a user file), and
    platform case-folded."""
    expanded = os.path.expandvars(os.path.expanduser(str(path)))
    return os.path.normcase(os.path.realpath(expanded))


def _is_under(path: Path, root: Path) -> bool:
    candidate = _normalised(path)
    base = _normalised(root)
    if candidate == base:
        return True
    prefix = base if base.endswith(os.sep) else base + os.sep
    return candidate.startswith(prefix)


#: Subtrees of the Windows directory that are user-writable (or
#: historically were) and therefore NEVER earn system-file trust,
#: however genuine the signature on a file inside them looks —
#: anyone can drop a file there, so "it lives in Windows" proves
#: nothing for these corners:
#: - ``Temp`` — the shared scratch folder under the Windows dir;
#: - ``Tasks`` and ``System32\Tasks`` / ``SysWOW64\Tasks`` — the
#:   scheduled-task stores, which hold user-authored task content;
#: - ``Prefetch`` — named in the hunt set: its contents are
#:   produced from programs users chose to run, not shipped OS
#:   components in place;
#: - ``System32\spool\printers`` — the print spool, writable so
#:   unprivileged print jobs can land there.
_WINDOWS_USER_WRITABLE_SUBTREES: tuple[tuple[str, ...], ...] = (
    ("temp",),
    ("tasks",),
    ("prefetch",),
    ("system32", "tasks"),
    ("syswow64", "tasks"),
    ("system32", "spool", "printers"),
)


def _is_trusted_location(path: Path, root: Path) -> bool:
    """The location gate for system-file trust: the RESOLVED
    candidate must live under the RESOLVED Windows root, outside
    every known user-writable subtree of it (P0-3b)."""
    if not _is_under(path, root):
        return False
    try:
        relative = os.path.relpath(_normalised(path), _normalised(root))
    except ValueError:
        return False  # different drives (Windows): not under at all
    parts = tuple(part.lower() for part in Path(relative).parts)
    for subtree in _WINDOWS_USER_WRITABLE_SUBTREES:
        if parts[: len(subtree)] == subtree:
            return False
    return True


def analyze_file(
    path: Path,
    size: int | None = None,
    *,
    windows_root_dir: Path | None = None,
    authenticode_verifier: AuthenticodeVerifier | None = None,
    dpkg_verifier=None,
) -> HeuristicReport:
    """Run the heuristic analysis appropriate for *path*.

    (The full routing documentation lives on
    :func:`_analyze_file_routed`.) On Linux, the routed report
    then passes the **dpkg system-file trust gate**
    (:func:`_apply_dpkg_trust`): a file the package manager
    installed, in its system home, has its heuristic suspicion
    cleared — the exact analog of the Windows Microsoft-signature
    trust, with the same limits (heuristic score only, signals
    stay listed, signature/rule detections never cleared).
    *dpkg_verifier* injects that check (tests); production
    callers leave it None and get the platform's real verifier
    (:mod:`argus.platform_dpkg`). Off Linux the gate never runs.
    """
    report = _analyze_file_routed(
        path,
        size,
        windows_root_dir=windows_root_dir,
        authenticode_verifier=authenticode_verifier,
    )
    if sys.platform.startswith("linux") and not report.trusted_system_file:
        _apply_dpkg_trust(path, report, dpkg_verifier)
    return report


def _apply_dpkg_trust(
    path: Path, report: HeuristicReport, dpkg_verifier
) -> None:
    """Apply Linux system-file trust to *report* in place.

    Trust requires the WHOLE gate in
    :mod:`argus.platform_dpkg`: dpkg records the file as an
    installed package's payload AND the resolved path is a
    system location. A verifier that errors fails CLOSED (no
    trust) and is logged — the same discipline as a broken
    Authenticode verifier on Windows. Ordinary files (the vast
    majority: dpkg does not own them) earn no note; the gate is
    silent unless it grants."""
    try:
        from ..platform_dpkg import STATUS_TRUSTED, platform_dpkg_verifier

        verifier = (
            dpkg_verifier
            if dpkg_verifier is not None
            else platform_dpkg_verifier()
        )
        if verifier is None:
            return
        outcome = verifier(path)
    except Exception as exc:  # a broken verifier fails CLOSED
        log.warning(
            "dpkg verification of %s raised %r — treating the "
            "file as untrusted",
            path, exc,
        )
        return
    if outcome is not None and outcome.status == STATUS_TRUSTED:
        report.trusted_system_file = True
        report.notes.append(
            "recognized as a system file installed by this "
            f"computer's package manager (package: {outcome.package}) "
            "in its proper system location — Argus cleared the "
            "heuristic suspicion for it. Any behaviour-based "
            "findings are still listed, and the signature-database "
            "and pattern-rule checks applied in full."
        )


def _analyze_file_routed(
    path: Path,
    size: int | None = None,
    *,
    windows_root_dir: Path | None = None,
    authenticode_verifier: AuthenticodeVerifier | None = None,
) -> HeuristicReport:
    """Run the heuristic analysis appropriate for *path*.

    Routing is content-first: MZ magic → PE analysis whatever the
    extension; script markers → script analysis; the extension is
    the fallback hint. A name that disagrees with the content earns
    a ``content_extension_mismatch`` signal — masquerading is the
    point of the disagreement.

    *windows_root_dir* overrides the Windows directory used by the
    system-file trust check (tests); production callers leave it
    None and :func:`windows_root` reads the machine's own setting.

    *authenticode_verifier* injects the platform Authenticode
    check used by the trust gate (tests). Production callers leave
    it None: on Windows the real WinVerifyTrust verifier is used,
    off Windows there is none and trust stays claim-based (the
    documented fallback in :mod:`argus.platform_authenticode`).

    Never raises for file-content problems: unreadable or malformed
    content yields notes on the report, not exceptions. (Filesystem
    errors opening the file are likewise converted to a note.)
    """
    root_dir = windows_root_dir if windows_root_dir is not None else windows_root()
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

    head = _read_head(path) if size > 0 else b""
    pe_content = head.startswith(b"MZ")
    script_content = _looks_like_script(head)
    segment_offsets: list[int] = []
    if not pe_content and not script_content and size > _SNIFF_BYTES:
        # A cradle padded past the head window — or hidden behind
        # a benign preface — must not route by extension alone:
        # sample head/middle/tail (bounded — see sniff_script_content).
        script_content = sniff_script_content(path, size, head=head)
    if not pe_content and not script_content and size > _SNIFF_BYTES:
        # Placement-independent routing (fix round 3): the
        # sampler's geometry is a blind zone — a cradle parked
        # between its windows in a large file routed as plain
        # data. Stream the whole file (bounded by the heuristic
        # cap) and let ANY chunk convict it; there is nowhere
        # left to park. (Files no larger than the head need no
        # stream: the head sniff already saw every byte.)
        script_content, segment_offsets = _stream_script_offsets(
            path, size
        )
    elif not pe_content and size > SCRIPT_READ_CAP:
        # Routed as a script already — but when the file outgrows
        # the script decode cap, the decoder needs to know where
        # the UTF-16 passages live so it can read THOSE windows
        # too, not only the head.
        _found, segment_offsets = _stream_script_offsets(path, size)

    # Content outranks extension in BOTH directions: an MZ file is
    # a program whatever it is named, and a file whose contents are
    # script commands gets script analysis even when it wears an
    # executable's name (the disguise is itself the signal below).
    if pe_content:
        report = HeuristicReport(kind="pe", signals=signals, notes=notes)
        if ext not in PE_EXTENSIONS:
            report.signals.append(
                Signal(
                    name="content_extension_mismatch",
                    severity="high",
                    points=30,
                    explanation=(
                        "This file IS a Windows program (its contents "
                        f"start with the MZ executable signature) but "
                        f"its name ends in '{ext or '(no extension)'}', "
                        "which does not say 'program'. Disguising an "
                        "executable as a document or data file is a "
                        "classic masquerade."
                    ),
                )
            )
        _analyze_pe(path, size, report, root_dir,
                    authenticode_verifier=authenticode_verifier)
        return report

    if script_content:
        report = HeuristicReport(kind="script", signals=signals, notes=notes)
        if ext not in SCRIPT_EXTENSIONS and ext:
            report.signals.append(
                Signal(
                    name="script_extension_mismatch",
                    severity="medium",
                    points=15,
                    explanation=(
                        "This file's contents are a script (they "
                        f"contain script commands) but its name ends "
                        f"in '{ext}', which does not say 'script'. "
                        "Scripts wearing innocent extensions are a "
                        "common delivery disguise."
                    ),
                )
            )
        _analyze_script(
            path, size, report,
            segment_offsets=segment_offsets,
            # Content-only routing = the name never claimed to
            # be a script. That distinction decides whether the
            # oversize floor may later be waived (a script
            # extension keeps it unconditionally: a .ps1 is code
            # by claim, however innocent its first 4 MB read).
            content_only_routing=ext not in SCRIPT_EXTENSIONS,
        )
        return report

    # No decisive content: the extension is the fallback hint.
    if ext in PE_EXTENSIONS:
        report = HeuristicReport(kind="pe", signals=signals, notes=notes)
        _analyze_pe(path, size, report, root_dir,
                    authenticode_verifier=authenticode_verifier)
        return report

    if ext in SCRIPT_EXTENSIONS:
        report = HeuristicReport(kind="script", signals=signals, notes=notes)
        _analyze_script(path, size, report, segment_offsets=segment_offsets)
        return report

    return HeuristicReport(kind="file", signals=signals, notes=notes)


def _analyze_pe(
    path: Path,
    size: int,
    report: HeuristicReport,
    root_dir: Path,
    *,
    authenticode_verifier: AuthenticodeVerifier | None = None,
) -> None:
    pe: PEInfo | None = None
    try:
        pe = parse_pe(path)
    except PEError as exc:
        report.notes.append(
            f"file presents as a Windows executable but could not be "
            f"parsed as one: {exc}"
        )
    except OSError as exc:
        report.notes.append(f"heuristics could not read file: {exc.strerror or exc}")
        return
    report.pe = pe
    if pe is not None:
        report.signed = pe.signed
        report.signed_trim_eligible = bool(pe.signed and pe.has_extracted_signer)
        report.signer = pe.signer_name or pe.signer_org
        for warning in pe.warnings:
            report.notes.append(f"PE parse note: {warning}")
        # System-file trust: EVERY condition or nothing —
        # a structurally valid certificate carrying a COMPLETE
        # SignerInfo for a Microsoft signer (identity is only
        # extracted then — see pe.py), a home under the
        # Windows directory outside its user-writable subtrees,
        # with links/junctions resolved — and, on Windows, the
        # operating system's own Authenticode verification
        # (FIX 5): WinVerifyTrust must vouch for the signature's
        # chain and digest, because stdlib parsing can only read
        # the CLAIM, never verify its content. Off Windows no
        # verifier exists and trust stays claim-based (the
        # documented dev/non-Windows fallback). A Microsoft-
        # signed file anywhere else (Downloads, a USB stick,
        # Windows\Temp) is just a signed file; a "Microsoft"
        # claim in a malformed certificate is not even that
        # (``signed`` is False then, and no identity was
        # extracted).
        if pe.signed and signer_is_microsoft(pe) and _is_trusted_location(path, root_dir):
            verifier = (
                authenticode_verifier
                if authenticode_verifier is not None
                else platform_verifier()
            )
            authenticode_ok = True
            if verifier is not None:
                authenticode_ok = False
                try:
                    outcome = verifier(path)
                except Exception as exc:  # a broken verifier fails CLOSED
                    log.warning(
                        "Authenticode verification of %s raised %r — "
                        "treating the signature as unverified",
                        path, exc,
                    )
                    outcome = None
                if outcome is not None:
                    if outcome.status == STATUS_VERIFIED:
                        authenticode_ok = True
                    else:
                        # The exact HRESULT goes to the log (the
                        # service log in production) so field data
                        # can tell a forged signature apart from an
                        # offline-revocation flag problem.
                        log.warning(
                            "WinVerifyTrust did not vouch for %s: "
                            "status=%s hresult=%s detail=%s",
                            path,
                            outcome.status,
                            (
                                f"0x{outcome.hresult:08X}"
                                if outcome.hresult is not None
                                else "n/a"
                            ),
                            outcome.detail,
                        )
            if authenticode_ok:
                report.trusted_system_file = True
                report.notes.append(
                    "recognized as a signed Windows system file "
                    f"(signer: {report.signer}) in its proper system "
                    "location — Argus cleared the heuristic suspicion "
                    "for it. Any behaviour-based findings are still "
                    "listed, and the signature-database and pattern-"
                    "rule checks applied in full."
                )
            else:
                report.notes.append(
                    "this file claims a Microsoft signature and sits "
                    "in a system location, but Windows' own signature "
                    "verification (WinVerifyTrust) did not vouch for "
                    "it — Argus did NOT grant it system-file trust, "
                    "and its heuristic findings stand in full."
                )

    if size > MAX_HEURISTIC_SCAN_SIZE:
        report.notes.append(
            f"file is larger than {MAX_HEURISTIC_SCAN_SIZE // (1024 * 1024)} MB — "
            "deep heuristic content analysis skipped (structure and "
            "signature checks still applied)"
        )
        if pe is not None:
            report.signals.extend(pe_signals(pe, StringIndex(), EntropySummary()))
        # Verdict floor: an executable too large for full analysis
        # is never waved through as Clean on structure alone.
        report.signals.append(
            Signal(
                name="oversize_not_fully_analyzed",
                severity="medium",
                points=25,
                explanation=(
                    "This executable is too large for Argus's full "
                    "content analysis, so only its structure, "
                    "signatures, and pattern rules were checked. "
                    "Argus rates it at least Suspicious rather than "
                    "calling a file it could not fully read 'clean'."
                ),
            )
        )
        return

    # One streamed content pass: entropy (whole + windows + per
    # section), string extraction, and the cap-independent needle
    # search share the read.
    entropy = EntropyAnalyzer()
    sections = SectionEntropyTracker(
        [(s.raw_offset, s.raw_offset + s.raw_size) for s in pe.sections]
        if pe is not None
        else []
    )
    extractor = _StringExtractor()
    needles = _NeedleSearcher()
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
                needles.feed(chunk)
                offset += len(chunk)
    except OSError as exc:
        report.notes.append(f"heuristics could not read file: {exc.strerror or exc}")
        return

    summary = entropy.finish()
    report.entropy = summary
    strings = extractor.finish()
    strings.needle_hits = needles.hits

    if pe is not None:
        for idx, section in enumerate(pe.sections):
            section.entropy = sections.entropy_for(idx)
        report.signals.extend(pe_signals(pe, strings, summary))
    else:
        # Unparseable executable: a modest signal on its own, and
        # together with high entropy it crosses into Suspicious —
        # a "program" whose structure cannot be read AND whose
        # contents look random is not entitled to a Clean verdict.
        report.signals.append(
            Signal(
                name="unparseable_executable",
                severity="low",
                points=10,
                explanation=(
                    "This file presents as a Windows program but its "
                    "structure could not be parsed, so Argus could "
                    "not inspect its sections or imports. Corruption "
                    "happens — but so does deliberate malformation to "
                    "blind analyzers."
                ),
            )
        )
        if summary.whole_entropy >= HIGH_ENTROPY_THRESHOLD:
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


def _oversize_signal(subject: str) -> Signal:
    """The not-fully-analysed floor signal (same name/points for
    PEs and scripts — a verdict floor, never a Clean). One
    documented exception: the SCRIPT floor may be waived for a
    content-routed file that reads as plain text end to end
    (see :func:`waive_oversize_floor`)."""
    return Signal(
        name="oversize_not_fully_analyzed",
        severity="medium",
        points=25,
        explanation=(
            f"This {subject} is too large for Argus's full "
            "heuristic analysis, so only part of it was analysed "
            "in depth (pattern rules still streamed over the "
            "whole file). Argus rates it at least Suspicious "
            "rather than calling a file it could not fully read "
            "'clean'."
        ),
    )


def waive_oversize_floor(
    report: HeuristicReport, *, rule_detection_count: int
) -> bool:
    """Lift the script oversize floor for a plainly innocent text
    file. Returns True when the floor was lifted.

    The P0-5 floor exists so a payload parked past the script
    decode cap cannot score Clean. As first shipped it applied
    to EVERY content-routed file past the cap — and all UTF-16
    text routes as script — so a customer's multi-megabyte
    UTF-16 log or export, plain prose from end to end, read
    "Suspicious" on size alone (script-routing spot audit,
    fix-round-3 follow-up). The waiver is deliberately narrow
    and conjunctive; ALL of these must hold:

    - the report marked the floor waivable
      (:attr:`HeuristicReport.oversize_floor_waivable`):
      content-only routing — a script EXTENSION keeps the floor
      unconditionally, because a .ps1 is code by claim — and
      zero heuristic script signals in every passage the
      decoder actually read (head + located windows);
    - *rule_detection_count* is zero: the pattern-rule layer,
      which streamed the WHOLE file raw and UTF-16-folded,
      detected nothing anywhere.

    If any rule hit or any script signal exists anywhere, the
    floor stands exactly as before. When the floor is lifted,
    the signal is removed from the report and the reason is
    recorded as a note — the decision is visible, never silent.
    Both verdict paths (the scanner and the GUI's re-analysis)
    call this one helper, so they cannot diverge.
    """
    if not report.oversize_floor_waivable or rule_detection_count:
        return False
    kept = [
        sig for sig in report.signals
        if sig.name != "oversize_not_fully_analyzed"
    ]
    if len(kept) == len(report.signals):
        return False  # the floor was never on this report
    report.signals = kept
    report.notes.append(
        "this file is larger than Argus's in-depth script "
        "reading limit, so only part of it was decoded in depth "
        "— but the pattern rules streamed over the whole file "
        "and found nothing, and every passage Argus decoded "
        "read as plain text with no script behaviour, so the "
        "oversize caution rating Argus gives files it could "
        "not fully read was not applied"
    )
    return True


#: How much the script decoder reads around one located UTF-16
#: segment that sits beyond the head cap (fix round 3): the whole
#: passage plus the script lines around it.
_SEGMENT_WINDOW_BYTES = 256 * 1024
#: At most this many segment windows are decoded per file — the
#: windowed decode stays bounded however many passages a file
#: hides.
_MAX_SEGMENT_WINDOWS = 4
#: A window starts this far BEFORE the segment, so the passage
#: is read with a little of its surroundings, not mid-token.
_SEGMENT_WINDOW_BACKSTEP = 1024


def _analyze_script(
    path: Path,
    size: int,
    report: HeuristicReport,
    *,
    segment_offsets: list[int] | tuple[int, ...] = (),
    content_only_routing: bool = False,
) -> None:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(SCRIPT_READ_CAP + 1)
    except OSError as exc:
        report.notes.append(f"heuristics could not read file: {exc.strerror or exc}")
        return
    floor_added = len(raw) > SCRIPT_READ_CAP
    if floor_added:
        report.notes.append(
            f"script is larger than {SCRIPT_READ_CAP // (1024 * 1024)} MB — "
            "only the beginning was analysed by the heuristic "
            "library (pattern rules still stream over the whole file)"
        )
        raw = raw[:SCRIPT_READ_CAP]
        # Scripts get the PE treatment (P0-5): the cap binds the
        # heuristic script analysis only, and passing it adds the
        # same oversize floor signal PEs get — a cradle parked
        # past the cap in a huge script must not score Clean.
        report.signals.append(_oversize_signal("script"))

    text = _decode_script(raw)
    signals = script_signals(text, path.name)
    if segment_offsets:
        # Windowed decode (fix round 3): a UTF-16 passage parked
        # beyond the head cap is decoded and judged too — the
        # routing scan located the passages, so the heuristic
        # library reads windows around them (bounded: at most
        # _MAX_SEGMENT_WINDOWS windows of _SEGMENT_WINDOW_BYTES)
        # instead of pretending the file ends at the cap.
        seen = {signal.name for signal in signals}
        covered_until = len(raw)
        windows_read = 0
        for offset in segment_offsets:
            if windows_read >= _MAX_SEGMENT_WINDOWS:
                break
            if offset < covered_until:
                continue  # the head read already covers this one
            start = max(covered_until, offset - _SEGMENT_WINDOW_BACKSTEP)
            try:
                with open(path, "rb") as fh:
                    fh.seek(start)
                    window = fh.read(_SEGMENT_WINDOW_BYTES)
            except OSError:
                break
            if not window:
                continue
            windows_read += 1
            covered_until = max(covered_until, start + len(window))
            for signal in script_signals(
                _decode_script(window), path.name
            ):
                if signal.name not in seen:
                    seen.add(signal.name)
                    signals.append(signal)
    if floor_added and content_only_routing and not signals:
        # The heuristic half of the oversize-floor waiver (see
        # waive_oversize_floor): this file never claimed to be
        # code (content routed it here, its name did not), and
        # every passage the decoder actually read — the head
        # plus each located window past the cap — produced NO
        # script signals at all. If the rule layer also stayed
        # silent over the whole file, the caller lifts the
        # floor: a big plain-text file is not "Suspicious" for
        # being big. ANY script signal in ANY read window —
        # including one parked past the cap — keeps the floor.
        report.oversize_floor_waivable = True
    report.signals.extend(signals)


def _decode_script(raw: bytes) -> str:
    """Decode script bytes: BOM-aware UTF-16/UTF-8, BOM-less
    UTF-16LE detected by the NUL-interleave pattern, else latin-1.

    PowerShell writes UTF-16LE; plenty of droppers ship it WITHOUT
    the BOM. Without the interleave check such a file "decodes" as
    UTF-8 with a NUL between every character and every text check
    silently misses — the exact hole the UTF-16 cradle audit found.

    Mixed content (fix round 2, FIX 4): the encoding decision is
    no longer made from the first 8 KB alone. When the head is
    not uniformly UTF-16LE, the buffer is decoded SEGMENT-WISE:
    strong UTF-16LE passages (wherever they sit — behind a benign
    ASCII preface, at any offset parity) decode as UTF-16LE and
    the text between them decodes as UTF-8/latin-1, so a cradle
    at 200 KB or 1.5 MB is read exactly as written instead of
    being shredded by a head-only guess.
    """
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    sample = raw[:8192]
    # BOM-less UTF-16LE requires the INTERLEAVE pattern (P2) —
    # alternating character/NUL pairs — not mere NUL density: a
    # binary-ish file dense in scattered NULs must NOT be folded
    # into UTF-16 (folding garbage invents text that was never
    # there and misroutes the file).
    if sample and _u16le_interleave_offset(sample) is not None:
        return raw.decode("utf-16-le", errors="replace")
    spans = _u16le_segment_spans(raw)
    if spans:
        parts: list[str] = []
        cursor = 0
        for start, end in spans:
            if start > cursor:
                parts.append(_decode_plain(raw[cursor:start]))
            parts.append(raw[start:end].decode("utf-16-le", errors="replace"))
            cursor = end
        if cursor < len(raw):
            parts.append(_decode_plain(raw[cursor:]))
        # Segment-aware join (fix round 3): an encoding seam is
        # a LINE boundary. Text on opposite sides of a seam was
        # never one line — joining the parts bare would fuse a
        # preface's last line and a passage's first line into a
        # single fake "line" and feed line-based signals text
        # that exists nowhere in the file.
        return "\n".join(parts)
    return _decode_plain(raw)


def _decode_plain(raw: bytes) -> str:
    """The non-UTF-16 decode: UTF-8, falling back to latin-1
    (which maps every byte, so it can never fail)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")
