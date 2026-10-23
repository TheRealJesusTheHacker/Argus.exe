"""File walking + scanning for ARGUS.EXE.

The scanner walks a directory tree, hashes every file with SHA-256, and
checks each file against the signature database and the pattern rules.

Hard rules learned from real-world scanner bugs:

- **Streamed hashing.** Files are read in 1 MiB chunks. Nothing is ever
  loaded whole into memory — a multi-GB file costs the same RAM as a
  text file. (Whole-file reads crash on large files; see Hellhound's
  MemoryError bug.)
- **Symlink-safe.** Directory symlinks inside a tree are never
  followed, so a scan can never wander out of the tree it was
  pointed at or loop forever. (A symlink to a directory given *as*
  the scan root is entered — that is the user pointing Argus there
  on purpose.) Symlinks to files are scanned like regular files.
- **Permission-error tolerant.** Anything that cannot be read is skipped,
  counted, and reported — never a crash, never silently swallowed.
- **Single pass.** Hashing and rule matching share one read of the file.
- **Heuristics second pass.** Phase 2 heuristic analysis (PE parsing,
  entropy, string extraction) makes its own streamed pass over
  executables and scripts, capped at 64 MB, and merges into the same
  per-file assessment — worst verdict wins, every reason shown.
- **Oversize executables still get pattern rules.** Past the 64 MB
  rule cap, a file whose CONTENT is an executable (MZ magic) still
  has its bytes streamed through the rule matcher — rules chunk, so
  size is no reason to skip them. Only non-executable bulk skips.
- **Locked files are NotScanned, never Clean.** A file Argus cannot
  read (locked by another program, permission denied) is reported
  with the explicit ``NotScanned`` outcome so callers can retry or
  warn — a locked file must never be waved through as "clean".
- **Alternate data streams (Windows).** Named NTFS data streams on a
  scanned file are scanned as virtual files (``path:stream``) — a
  classic hiding place. Non-Windows: a clean no-op.
- **Exclusions honoured.** User-configured exclusions (by path or by
  SHA-256) short-circuit scanning in both on-demand and real-time
  scans — the file is left alone and the skip is noted, never hidden.
- **Argus never scans itself — narrowly defined.** The quarantine
  vault subtree, the signature database file and its key, and the
  identity-proven program file are skipped before any read (see
  :mod:`argus.selftrust`): the program file is exempt only with
  proof of identity, never by name, and a stranger sitting at the
  program's own address whose fingerprint contradicts the record
  setup left is scanned in full and reported as a tamper
  indicator. Everything else — including the user-writable
  ``shared`` data subtree and install-folder support files —
  scans normally.
- **Normal Windows files are recognised.** A structurally-valid
  Microsoft-signed binary in its system location has its heuristic
  suspicion cleared (see :mod:`argus.scoring`) — signature and
  pattern-rule detections on it still stand.
- **Archives are opened, never trusted.** A ZIP (and TAR, including
  gzip-compressed TAR) file's members are scanned through this same
  path — extracted by index to generated flat names inside one
  dedicated temporary folder, never to a path taken from a member
  name, and never executed. Shared hard budgets bound the work
  (member count, total extracted bytes, nesting depth, per-member
  time), enforced while bytes stream, not after. Anything Argus
  could not check — a limit hit, a damaged or encrypted member, a
  link member it will not follow — marks the archive **not fully
  scanned** on the result itself: it is never reported clean and
  never silently skipped.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import stat
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .config import Exclusions
from .detections import Detection, FileAssessment, Verdict, assess
from .heuristics.analyze import (
    SCRIPT_EXTENSIONS,
    _looks_like_script,
    _u16le_segment_offset,
    analyze_file,
    sniff_script_content,
    waive_oversize_floor,
)
from .heuristics.signals import Signal
from .rules import MAX_RULE_SCAN_SIZE, Rule, RuleMatcher
from .scoring import score_signals
from .selftrust import SelfExclusions, default_self_exclusions
from . import bundletrust
from .signatures import SignatureDB

CHUNK_SIZE = 1024 * 1024  # 1 MiB

#: Errnos that mean "there is no file to read at this path" —
#: it vanished between the walk and the scan (ENOENT), or the
#: path crosses something that is not a folder (ENOTDIR). These
#: stay plain read errors: there is nothing to retry, nothing
#: being withheld from the scanner, and the error is still
#: recorded on the result for callers to see.
_NOT_THERE_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR})

#: Cap on named data streams scanned per file (abuse-proofing).
MAX_STREAMS_PER_FILE = 32

# ----------------------------------------------------------------------
# Archive scanning budgets (B-3 Phase 2)
#
# One set of budgets is shared by a whole top-level archive: nested
# archives draw from the SAME counters, so wrapping a payload in
# layers cannot multiply the allowance. Extraction is streaming —
# a budget trips WHILE bytes are being read, never after a member
# has been fully written out.
# ----------------------------------------------------------------------
#: Max archive members (files, folders, links — every entry counts)
#: enumerated for one top-level archive.
MAX_ARCHIVE_MEMBERS = 512
#: Max total extracted (decompressed) bytes for one top-level archive.
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024  # 256 MB
#: Max archive nesting depth: the scanned file itself is depth 1,
#: an archive inside it is depth 2, and so on.
MAX_ARCHIVE_DEPTH = 3
#: Max seconds spent on one archive member (extract + scan), checked
#: cooperatively at every streamed chunk and again before its scan.
ARCHIVE_MEMBER_TIMEOUT_SECONDS = 30.0

#: Prefix of the one dedicated temp root created per top-level
#: archive scan. Member bytes only ever land inside it, under
#: generated flat names, and it is removed when the scan ends —
#: on success, on error, and on exception paths alike.
ARCHIVE_TEMP_PREFIX = "argus-archive-"

#: The note prefix that marks the designed "not fully scanned"
#: archive state on a result. Reporting surfaces (CLI history
#: records, GUI rows) filter notes by this exact prefix.
ARCHIVE_NOT_FULLY_SCANNED_PREFIX = "Archive not fully scanned:"


def _is_scan_blocked(exc: OSError) -> bool:
    """True when *exc* means 'could not read it' (locked/denied).

    EVERY read failure on a file that is there counts — not just
    the classic lock/denied errnos (EACCES, EPERM, EAGAIN, EBUSY,
    and PermissionError itself). What answers a read is not
    Argus's to control: a filesystem filter driver — most often
    the machine's other antivirus, holding a file back while it
    decides — can refuse a read with almost any error it likes.
    The 2026-10-20 field machine answered EINVAL ("Invalid
    argument") for the EICAR test file, and the old errno
    allow-list let that failure fall through to a Clean verdict:
    a file Argus never read, waved through as clean — the exact
    outcome the NotScanned verdict exists to prevent. So the
    rule is inverted: unless the error says the file is not
    there at all, a failed read is a blocked read.
    """
    if isinstance(exc, PermissionError):
        return True
    return exc.errno not in _NOT_THERE_ERRNOS


def _blocked_assessment() -> FileAssessment:
    assessment = FileAssessment()
    assessment.not_scanned = True
    assessment.notes.append(
        "Argus could not read this file (it may be locked by another "
        "program) — it was NOT scanned and is not known to be clean."
    )
    return assessment


class _Utf16Folder:
    """Fold a UTF-16LE byte stream into its ASCII shadow (the byte
    at every even offset), so plain-text rule patterns can match
    UTF-16 scripts. A one-byte carry keeps pair alignment across
    chunk boundaries of any size."""

    def __init__(self) -> None:
        self._carry = b""

    def feed(self, chunk: bytes) -> bytes:
        buf = self._carry + chunk
        even = len(buf) & ~1
        self._carry = buf[even:]
        return buf[:even][0::2]


class _FoldedRuleViews:
    """The pair of UTF-16LE folded rule matchers (even + odd
    parity) over one byte stream, with their folders and the
    odd-stream alignment state. One instance covers exactly one
    full pass over a file — the scan's main pass, or the folded
    second pass a late UTF-16 detection triggers."""

    def __init__(self, rules: list[Rule]) -> None:
        self.matchers: list[RuleMatcher] = [
            RuleMatcher(rules),
            RuleMatcher(rules),
        ]
        self._folders = [_Utf16Folder(), _Utf16Folder()]
        self._odd_started = False

    def feed(self, chunk: bytes) -> None:
        even_matcher, odd_matcher = self.matchers
        even_folder, odd_folder = self._folders
        even_matcher.feed(even_folder.feed(chunk))
        # The odd view is the same stream shifted by one byte:
        # its folder sees every byte from global offset 1 on,
        # so a UTF-16 passage starting at an odd offset folds
        # whole instead of shredded.
        if not self._odd_started:
            odd_input = chunk[1:]
            self._odd_started = True
        else:
            odd_input = chunk
        if odd_input:
            odd_matcher.feed(odd_folder.feed(odd_input))

    def finish(self) -> list:
        hits: list = []
        for matcher in self.matchers:
            hits.extend(matcher.finish())
        return hits


def _folded_second_pass(
    path: Path,
    rules: list[Rule],
    chunk_size: int,
    *,
    include_raw: bool,
) -> tuple[_FoldedRuleViews | None, RuleMatcher | None]:
    """Re-read *path* streaming the UTF-16 folded views (both
    parities) over the WHOLE file — plus a raw matcher when the
    main pass never ran rules at all (oversize script content).

    This is the placement-independent half of the UTF-16 fix
    (fix round 3): the main pass tests every chunk for a UTF-16
    segment, and a positive anywhere — at ANY offset — sends
    the file through this pass, so there is no sampled geometry
    left for a payload to hide between. Each matcher carries
    the standard per-file rule budget (including the tail
    pass), so the second pass is bounded exactly like the main
    one. A file that vanishes mid-scan yields ``(None, None)``:
    the main pass's hash/signature outcome already stands.
    """
    views = _FoldedRuleViews(rules)
    raw_matcher = RuleMatcher(rules) if include_raw else None
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                if raw_matcher is not None:
                    raw_matcher.feed(chunk)
                views.feed(chunk)
    except OSError:
        return None, None
    return views, raw_matcher


#: Carry for the scanner's per-chunk UTF-16 segment test: a
#: segment straddling a chunk boundary stays contiguous inside
#: (carry + chunk) — it needs 16 pairs (32 bytes), so at most
#: 15 pairs (30 bytes) of it can sit behind the boundary.
_SEGMENT_TEST_CARRY = 64

#: A UTF-16LE segment carries at least this many NUL bytes, so a
#: window with fewer cannot contain one — a one-pass C-speed
#: pre-filter that keeps the lane test off NUL-free chunks.
_SEGMENT_MIN_NULS = 16


# ----------------------------------------------------------------------
# Per-file results
# ----------------------------------------------------------------------
@dataclass
class FileResult:
    """The raw outcome of reading one file."""

    path: Path
    size: int | None = None
    sha256: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class ScannedFile:
    """A file after full analysis: read result + security assessment."""

    result: FileResult
    assessment: FileAssessment
    rules_skipped_reason: str | None = None
    #: True when user-configured exclusions told Argus to leave this
    #: file alone (by path or by hash). Excluded files are not scanned
    #: and always carry an explanatory note on the assessment.
    excluded: bool = False
    #: Why Argus left this file alone as one of its OWN (see
    #: :mod:`argus.selftrust`) — "Argus's own data folder", "the
    #: Argus program itself", ... Set only for self-exclusions;
    #: user-configured exclusions explain themselves in the notes.
    exclusion_source: str | None = None
    #: True when this file was recognised (by content) as an archive
    #: and its members were enumerated for scanning.
    is_archive: bool = False
    #: How many archive members were fully scanned for this file
    #: (nested members included, all levels counted together).
    archive_members_scanned: int = 0
    #: The designed partial state: True when ANY part of the archive
    #: could not be scanned (a budget hit, a damaged or encrypted
    #: member, an unfollowed link, ...). Such a file also carries
    #: ``assessment.not_scanned`` and one note per reason — it is
    #: never a clean result.
    archive_not_fully_scanned: bool = False
    #: The plain-language reasons the archive is not fully scanned,
    #: without the shared note prefix (also on the assessment notes,
    #: with the prefix, for surfaces that read notes).
    archive_incomplete_reasons: tuple[str, ...] = ()

    @property
    def path(self) -> Path:
        return self.result.path

    @property
    def verdict(self) -> Verdict:
        return self.assessment.verdict


@dataclass
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped: int = 0  # read errors (permissions, vanished files, ...)
    files_excluded: int = 0  # left alone by user-configured exclusions
    dirs_skipped: int = 0  # unreadable dirs + dir symlinks not followed
    bytes_scanned: int = 0
    archives_seen: int = 0  # files recognised as archives and opened
    archive_members_scanned: int = 0  # members scanned, all levels
    archives_not_fully_scanned: int = 0  # archives in the partial state


@dataclass
class ScanReport:
    root: Path
    files: list[ScannedFile] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    @property
    def detections(self) -> list[ScannedFile]:
        return [f for f in self.files if f.assessment.flagged]

    @property
    def verdict(self) -> Verdict:
        worst = Verdict.CLEAN
        for f in self.files:
            if f.verdict.rank > worst.rank:
                worst = f.verdict
        return worst


# ----------------------------------------------------------------------
# Hashing (streamed — never whole-file)
# ----------------------------------------------------------------------
def hash_file(path: Path, chunk_size: int = CHUNK_SIZE) -> tuple[str, int]:
    """Return (sha256 hex digest, size in bytes) for *path*.

    Reads in chunks; raises OSError on read failure for the caller to
    record. Kept separate from scanning so it can be tested directly
    against known vectors.
    """
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


# ----------------------------------------------------------------------
# Walker (recursive, symlink-safe, error tolerant)
# ----------------------------------------------------------------------
def iter_files(root: Path, stats: ScanStats) -> Iterator[Path]:
    """Yield every scannable file under *root* (or *root* itself).

    Directory symlinks are counted in ``stats.dirs_skipped`` and never
    followed. Unreadable directories are counted and skipped. Special
    files (sockets, devices, broken links) are counted as skipped
    files. Nothing here raises for filesystem problems.
    """
    if root.is_symlink() and root.is_dir():
        # A symlink to a directory AS THE ROOT is the walk's entry
        # point — the user pointed Argus at it deliberately, so the
        # walk enters it. The no-follow rule below applies to links
        # found INSIDE the tree, which are never chased.
        pass
    elif root.is_file() or root.is_symlink():
        stats.files_seen += 1
        yield root
        return

    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            stats.dirs_skipped += 1
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                elif entry.is_symlink() and entry.is_dir(follow_symlinks=True):
                    # Symlink to a directory: never follow.
                    stats.dirs_skipped += 1
                elif entry.is_file(follow_symlinks=True):
                    stats.files_seen += 1
                    yield Path(entry.path)
                else:
                    # Broken symlink, socket, device, fifo — not scannable.
                    stats.files_skipped += 1
            except OSError:
                stats.files_skipped += 1


# ----------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------
def scan_file(
    path: Path,
    db: SignatureDB,
    rules: list[Rule],
    chunk_size: int = CHUNK_SIZE,
    *,
    heuristics: bool = True,
    exclusions: Exclusions | None = None,
    self_exclusions: SelfExclusions | None = None,
) -> ScannedFile:
    """Scan one file: hash it, check signatures, evaluate rules, and
    (unless ``heuristics=False``) run Phase 2 heuristic analysis.

    Hashing and rule matching share a single streamed read. Files over
    ``MAX_RULE_SCAN_SIZE`` get hash/signature checks only; the skip is
    noted on the result rather than hidden. Heuristic results merge
    into the same assessment: worst verdict wins, all reasons kept.

    ``exclusions`` (user configuration) wins over everything: a path
    exclusion returns before the file is even read, and a hash
    exclusion returns a clean, noted result right after hashing —
    Argus leaves excluded files alone, everywhere, always.

    ``self_exclusions`` (Argus's own territory + identity proofs,
    see :mod:`argus.selftrust`) is consulted before ANY read: Argus
    does not scan its own data tree or its own program. When the
    caller does not supply a set, the machine default is built once
    and reused. A file at the program's own address that fails the
    identity proofs is scanned in full and reported as a tamper
    indicator.

    Archives (ZIP, and TAR including gzip-compressed TAR) are not
    an exception to any of the above: the archive file itself is
    scanned exactly as any other file, and then its members are
    scanned through this same function (see
    :func:`_merge_archive_members`) under shared hard budgets.
    """
    return _scan_file_impl(
        path, db, rules, chunk_size,
        heuristics=heuristics, exclusions=exclusions,
        self_exclusions=self_exclusions,
    )


def _scan_file_impl(
    path: Path,
    db: SignatureDB,
    rules: list[Rule],
    chunk_size: int = CHUNK_SIZE,
    *,
    heuristics: bool = True,
    exclusions: Exclusions | None = None,
    self_exclusions: SelfExclusions | None = None,
    _archive_budget: "_ArchiveBudget | None" = None,
    _archive_depth: int = 0,
    _archive_chain: str = "",
) -> ScannedFile:
    """The scan itself. :func:`scan_file` is the public entry point
    (its signature is the contract); archive member scans call this
    directly so a nested member shares the top archive's budgets
    (``_archive_budget``), knows its nesting depth
    (``_archive_depth`` = the depth of the archive that contained
    it, 0 at the top), and carries its attribution chain
    (``_archive_chain``, e.g. "outer.zip → inner.zip")."""
    result = FileResult(path=path)

    # --- self-exclusion, before the file is touched ---------------
    self_check = None
    try:
        self_check = (
            self_exclusions
            if self_exclusions is not None
            else default_self_exclusions()
        ).check(path)
    except Exception:
        # Self-trust must never take a scan down; a failure to even
        # ASK means the file is treated as a stranger's (the safe
        # direction — it gets scanned).
        self_check = None
    if self_check is not None and self_check.excluded:
        try:
            result.size = path.stat().st_size
        except OSError:
            result.size = None
        assessment = FileAssessment()
        assessment.notes.append(
            f"skipped — this is {self_check.source}; "
            "Argus does not scan its own files"
        )
        return ScannedFile(
            result=result,
            assessment=assessment,
            excluded=True,
            exclusion_source=self_check.source,
        )
    tamper_suspect = bool(self_check and self_check.tamper_suspect)

    matcher = RuleMatcher(rules)
    # Scripts also get UTF-16LE-folded views through second
    # matchers: a .ps1 saved as UTF-16 (PowerShell's own default
    # for years) must not sail past text rules just because every
    # other byte is NUL. The folded views are built when the
    # EXTENSION or the CONTENT says "script" (P0-4): a UTF-16
    # cradle wearing a .txt/.dat/no extension gets the same
    # folded treatment as a .ps1.
    #
    # TWO folded views (both byte parities): a UTF-16 passage
    # that starts at an ODD offset (behind an odd-length ASCII
    # preface) folds into the odd view; the even view alone
    # would shred it into garbage and miss every pattern.
    #
    # Placement independence (fix round 3): the folded views
    # normally start before the first byte is fed, on the
    # extension or the head/sample content routing. Any file
    # they did NOT start for is still tested — EVERY chunk of
    # the streaming pass runs the UTF-16 segment test — and a
    # positive at ANY offset triggers a bounded folded second
    # pass over the whole file (:func:`_folded_second_pass`).
    # There is no sampled geometry left for a payload to hide
    # between: not at 200 KB, not at 2 MiB, not at 6 MiB.
    script_by_extension = path.suffix.lower() in SCRIPT_EXTENSIONS
    folded_views: _FoldedRuleViews | None = None
    u16_segment_seen = False
    segment_carry = b""

    def _start_folded() -> None:
        nonlocal folded_views
        if folded_views is None:
            folded_views = _FoldedRuleViews(rules)

    if script_by_extension:
        _start_folded()
    rules_skipped_reason: str | None = None

    try:
        size = path.stat().st_size
    except OSError as exc:
        result.error = f"could not read file: {exc.strerror or exc}"
        assessment = (
            _blocked_assessment() if _is_scan_blocked(exc) else FileAssessment()
        )
        return ScannedFile(result=result, assessment=assessment,
                           rules_skipped_reason="file could not be read")

    if exclusions is not None and exclusions.is_path_excluded(path):
        result.size = size
        assessment = FileAssessment()
        assessment.notes.append(
            "excluded by your configuration (path) — Argus left this file alone"
        )
        return ScannedFile(result=result, assessment=assessment, excluded=True)

    # The blanket oversize skip applies to bulk data only. A file
    # whose content is executable — OR a script (by extension or
    # by content) — gets rule matching at ANY size (P0-5: scripts
    # get the PE treatment; the folded streaming matcher below is
    # how script rules reach a cradle parked at the end of a huge
    # file): the matcher streams in chunks, so a padded file
    # cannot hide its head/tail bytes behind a size cap. Content
    # decides: the first chunk is sniffed before the choice.
    oversize = size > MAX_RULE_SCAN_SIZE
    feed_rules = not oversize or script_by_extension
    rules_ran = False

    hasher = hashlib.sha256()
    read_size = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                if read_size == 0:
                    # Content routing decides BEFORE the first
                    # byte is fed: the head check, backstopped by
                    # bounded head/middle/tail sampling when the
                    # head is an innocent preface (FIX 4).
                    script_by_content = _looks_like_script(chunk)
                    if (
                        not script_by_content
                        and not chunk.startswith(b"MZ")
                        and size > len(chunk)
                    ):
                        script_by_content = sniff_script_content(
                            path, size, head=chunk
                        )
                    if script_by_content:
                        _start_folded()
                    if oversize and (
                        chunk.startswith(b"MZ")
                        or script_by_extension
                        or script_by_content
                    ):
                        feed_rules = True  # program/script content: rules run
                hasher.update(chunk)
                read_size += len(chunk)
                if feed_rules:
                    matcher.feed(chunk)
                    rules_ran = True
                    if folded_views is not None:
                        folded_views.feed(chunk)
                if folded_views is None and not u16_segment_seen:
                    # The placement-independent UTF-16 test: run
                    # on EVERY chunk (with a short carry, so a
                    # segment straddling a chunk boundary is
                    # contiguous in the tested window). A positive
                    # at any offset arms the folded second pass
                    # below — the payload's position no longer
                    # matters, only its presence.
                    window = segment_carry + chunk
                    if (
                        window.count(0) >= _SEGMENT_MIN_NULS
                        and _u16le_segment_offset(window) is not None
                    ):
                        u16_segment_seen = True
                    segment_carry = chunk[-_SEGMENT_TEST_CARRY:]
    except OSError as exc:
        result.error = f"could not read file: {exc.strerror or exc}"
        assessment = (
            _blocked_assessment() if _is_scan_blocked(exc) else FileAssessment()
        )
        return ScannedFile(result=result, assessment=assessment,
                           rules_skipped_reason="file could not be read")

    # Folded second pass (fix round 3): a UTF-16 segment was
    # seen somewhere in the stream but the folded views never
    # covered it (the head/sample routing said "not a script").
    # Run the folded views over the whole file now — and a raw
    # matcher too when rules never ran (oversize content) — so
    # the passage is judged like any other script content.
    folded_second: _FoldedRuleViews | None = None
    second_raw_matcher: RuleMatcher | None = None
    if u16_segment_seen and folded_views is None:
        folded_second, second_raw_matcher = _folded_second_pass(
            path, rules, chunk_size, include_raw=not rules_ran
        )
        if second_raw_matcher is not None:
            rules_ran = True

    if oversize and not rules_ran:
        rules_skipped_reason = (
            f"file is larger than {MAX_RULE_SCAN_SIZE // (1024 * 1024)} MB — "
            "pattern rules skipped (signature check still applied)"
        )

    result.size = read_size
    result.sha256 = hasher.hexdigest()

    if exclusions is not None and exclusions.is_hash_excluded(result.sha256):
        assessment = FileAssessment()
        assessment.notes.append(
            "excluded by your configuration (file fingerprint) — "
            "Argus left this file alone"
        )
        return ScannedFile(result=result, assessment=assessment, excluded=True)

    signature_hit = db.lookup(result.sha256)
    if second_raw_matcher is not None:
        # The main matcher never ran (oversize); the second
        # pass's raw matcher is the raw coverage of this file.
        rule_hits = second_raw_matcher.finish()
    elif rules_ran:
        rule_hits = matcher.finish()
    else:
        rule_hits = []
    folded_sources: list[_FoldedRuleViews] = []
    if folded_views is not None and rules_ran:
        folded_sources.append(folded_views)
    if folded_second is not None:
        folded_sources.append(folded_second)
    if folded_sources:
        seen_names = {hit.name for hit in rule_hits}
        for views in folded_sources:
            for hit in views.finish():
                if hit.name not in seen_names:
                    seen_names.add(hit.name)
                    rule_hits.append(hit)
    assessment = assess(signature_hit, rule_hits)
    # Coverage honesty (fix round 2, FIX 6): when a matcher ran
    # its two-pass coverage (primary + tail), its coverage_note
    # is the statement users see — it says exactly which passes
    # ran. Only when no matcher produced one does the plain
    # budget note apply.
    all_matchers: list[RuleMatcher] = []
    if rules_ran:
        all_matchers.append(
            second_raw_matcher
            if second_raw_matcher is not None
            else matcher
        )
    if folded_views is not None and rules_ran:
        all_matchers.extend(folded_views.matchers)
    if folded_second is not None:
        all_matchers.extend(folded_second.matchers)
    coverage_notes = [
        m.coverage_note for m in all_matchers
        if getattr(m, "coverage_note", None)
    ]
    if coverage_notes:
        for note in dict.fromkeys(coverage_notes):
            assessment.notes.append(note)
    elif any(getattr(m, "budget_exceeded", False) for m in all_matchers):
        assessment.notes.append(
            "pattern matching stopped early: the per-file rule time "
            "budget was exhausted (the file was still hashed and "
            "checked against signatures)"
        )

    if heuristics:
        _apply_heuristics(path, read_size, assessment,
                          tamper_suspect=tamper_suspect,
                          sha256=result.sha256)
    else:
        sibling = bundletrust.check_sibling(path, result.sha256)
        if tamper_suspect or sibling.modified:
            # Tamper evidence is not an optional heuristic: even
            # with heuristic analysis off, a stranger at Argus's
            # own program address — or a bundle tool whose
            # fingerprint no longer matches the bundle's own
            # record — is surfaced on the standard ScannedFile
            # surface (assessment.signals / notes / verdict) that
            # every consumer — CLI, realtime, GUI result rows —
            # reads.
            extra: list[Signal] = []
            if tamper_suspect:
                extra.append(_tamper_signal())
                assessment.notes.append(_TAMPER_NOTE)
            if sibling.modified:
                extra.append(_sibling_modified_signal())
                assessment.notes.append(_SIBLING_MODIFIED_NOTE)
            scored = score_signals(extra)
            assessment.signals = scored.signals
            assessment.score = scored.score
            assessment.heuristic_verdict = scored.verdict

    scanned = ScannedFile(
        result=result, assessment=assessment, rules_skipped_reason=rules_skipped_reason
    )
    # Archive members ride the SAME result: detections and signals
    # found inside merge into this assessment (member-attributed),
    # and anything that could not be checked marks this file not
    # fully scanned. Non-archives return from here untouched.
    _merge_archive_members(
        scanned, path, db, rules, chunk_size,
        heuristics=heuristics, exclusions=exclusions,
        self_exclusions=self_exclusions,
        budget=_archive_budget, depth=_archive_depth, chain=_archive_chain,
    )
    return scanned


# ----------------------------------------------------------------------
# Archive scanning (B-3 Phase 2)
#
# Members are enumerated through one small abstraction (name +
# kind + a byte stream) with two backends — ZIP and TAR — so both
# formats get identical guards:
#
# * **Zip-slip is impossible by construction.** Member bytes are
#   written by INDEX to generated flat names (``member_000001``
#   plus a sanitised extension) inside the one temp root. A member
#   name is reporting data only; it never becomes a path.
# * **Links are never materialised or followed.** A symlink /
#   hardlink member is noted as unscanned (the archive is not
#   fully scanned) and its content is never treated as a file.
# * **Bombs die against the streaming budgets.** The shared byte
#   budget is checked BEFORE each chunk is written; the moment it
#   trips, extraction stops for the whole top-level archive.
# * **Nothing survives the scan.** The temp root belongs to the
#   top-level archive, each member temp is deleted right after its
#   scan, and the root is removed in a ``finally`` that runs on
#   success, error, timeout, and exception paths alike. Extracted
#   temps are only ever READ by the scanner — never executed, and
#   quarantine (if a caller asks) targets the archive file itself,
#   whose path is the result's path.
# ----------------------------------------------------------------------
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar")
_MEMBER_CHUNK = 256 * 1024
_SUFFIX_RE = re.compile(r"^\.[A-Za-z0-9]{1,10}$")


@dataclass
class _ArchiveBudget:
    """The shared budgets + findings for ONE top-level archive."""

    members_seen: int = 0
    members_scanned: int = 0
    total_bytes: int = 0
    stopped: bool = False
    reasons: list[str] = field(default_factory=list)
    temp_root: Path | None = None
    next_index: int = 0

    def add_reason(self, reason: str) -> None:
        if reason in self.reasons:
            return
        if len(self.reasons) >= 50:
            summary = "and more problems were found inside this archive"
            if summary not in self.reasons:
                self.reasons.append(summary)
            return
        self.reasons.append(reason)


def _archive_kind(path: Path) -> str | None:
    """Sniff *path*'s CONTENT for an archive format Argus opens.

    Returns "zip", "tar", "gzip" (a gzip stream that may or may not
    wrap a tar — probed by the tar backend), or None. Detection is
    by magic bytes, never by name: a zip wearing a .dat name is
    opened, and a text file wearing a .zip name is not.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if head[:4] in _ZIP_MAGICS:
        return "zip"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if head[:2] == _GZIP_MAGIC:
        return "gzip"
    return None


def _member_suffix(member_name: str) -> str:
    """The one piece of a member name allowed anywhere near a temp
    path: its final extension, and only when it is a short plain
    suffix. It exists so a member .ps1/.exe still routes through
    the scanner's content+extension logic exactly as a loose file
    would. It can never contain a separator or a dot-dot."""
    suffix = Path(member_name.replace("\\", "/")).suffix
    return suffix if _SUFFIX_RE.match(suffix) else ""


def _extract_member_stream(stream, dest: Path, budget: _ArchiveBudget,
                           started: float, chain: str) -> bool:
    """Stream one member's bytes to *dest* under the shared budgets.

    Returns True when the member was written out in full. On a
    budget or timeout trip the partial temp is deleted, the reason
    is recorded, ``budget.stopped`` is set (the whole archive stops
    — more members cannot change an exhausted budget), and False
    is returned.
    """
    written = 0
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = stream.read(_MEMBER_CHUNK)
                if not chunk:
                    break
                if time.monotonic() - started > ARCHIVE_MEMBER_TIMEOUT_SECONDS:
                    budget.add_reason(
                        f"checking {chain} took too long (over "
                        f"{ARCHIVE_MEMBER_TIMEOUT_SECONDS:g} seconds per "
                        "file inside an archive) — it was not fully checked"
                    )
                    budget.stopped = True
                    break
                if budget.total_bytes + len(chunk) > MAX_ARCHIVE_TOTAL_BYTES:
                    budget.add_reason(
                        f"the total size limit for files inside one "
                        f"archive ({MAX_ARCHIVE_TOTAL_BYTES // (1024 * 1024)} "
                        f"MB) was reached while reading {chain} — the rest "
                        "of the archive was not checked"
                    )
                    budget.stopped = True
                    break
                out.write(chunk)
                budget.total_bytes += len(chunk)
                written += len(chunk)
    except Exception:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    if budget.stopped:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True


def _merge_member_result(scanned: ScannedFile, member: ScannedFile,
                         chain: str) -> None:
    """Merge one scanned member's findings into the archive's own
    assessment: detections and signals keep their identity, with
    the member chain attributed in their text ("archive.zip →
    inner/eicar.com"). Worst heuristic verdict wins; the score
    keeps the strongest member's score (points are per-file
    evidence, not additive across different files)."""
    assessment = scanned.assessment
    for det in member.assessment.detections:
        assessment.detections.append(
            Detection(
                kind=det.kind,
                name=det.name,
                severity=det.severity,
                family=det.family,
                reason=f"Found inside archive: {chain}: {det.reason}",
            )
        )
    for sig in member.assessment.signals:
        assessment.signals.append(
            Signal(
                name=sig.name,
                severity=sig.severity,
                points=sig.points,
                explanation=f"Inside {chain}: {sig.explanation}",
            )
        )
    if member.assessment.score > assessment.score:
        assessment.score = member.assessment.score
    if member.assessment.heuristic_verdict.rank > assessment.heuristic_verdict.rank:
        assessment.heuristic_verdict = member.assessment.heuristic_verdict


def _scan_one_member(scanned: ScannedFile, budget: _ArchiveBudget, *,
                     member_name: str, stream_factory, chain: str,
                     db: SignatureDB, rules: list[Rule], chunk_size: int,
                     heuristics: bool, exclusions, self_exclusions,
                     depth: int) -> None:
    """Extract (streaming, budgeted) and scan one regular member."""
    assert budget.temp_root is not None
    budget.next_index += 1
    dest = budget.temp_root / (
        f"member_{budget.next_index:06d}{_member_suffix(member_name)}"
    )
    started = time.monotonic()
    try:
        stream = stream_factory()
        if stream is None:
            budget.add_reason(
                f"{chain} could not be read — it was not checked"
            )
            return
        with stream:
            complete = _extract_member_stream(
                stream, dest, budget, started, chain
            )
    except Exception as exc:
        budget.add_reason(
            f"{chain} could not be read ({exc}) — it was not checked"
        )
        return
    if not complete:
        return  # reason + stopped already recorded by the extractor
    if time.monotonic() - started > ARCHIVE_MEMBER_TIMEOUT_SECONDS:
        budget.add_reason(
            f"checking {chain} took too long (over "
            f"{ARCHIVE_MEMBER_TIMEOUT_SECONDS:g} seconds per file "
            "inside an archive) — it was not checked"
        )
        budget.stopped = True
        return
    try:
        member = _scan_file_impl(
            dest, db, rules, chunk_size,
            heuristics=heuristics, exclusions=exclusions,
            self_exclusions=self_exclusions,
            _archive_budget=budget, _archive_depth=depth,
            _archive_chain=chain,
        )
    except Exception as exc:  # a member must never take the scan down
        budget.add_reason(
            f"{chain} could not be checked ({exc})"
        )
        return
    finally:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
    if member.excluded:
        # The user's own exclusion (by fingerprint) claims this
        # content wherever it appears — left alone, on purpose.
        return
    budget.members_scanned += 1
    scanned.archive_members_scanned = budget.members_scanned
    if not member.result.ok:
        budget.add_reason(
            f"{chain} could not be read — it was not checked"
        )
        return
    if member.assessment.not_scanned and not member.archive_not_fully_scanned:
        budget.add_reason(
            f"{chain} could not be read — it was not checked"
        )
    _merge_member_result(scanned, member, chain)


def _count_member(budget: _ArchiveBudget, chain: str) -> bool:
    """Count one enumerated entry against the member budget.
    Returns False when the budget is spent (reason recorded, the
    archive stops being enumerated)."""
    budget.members_seen += 1
    if budget.members_seen > MAX_ARCHIVE_MEMBERS:
        budget.add_reason(
            f"the archive holds more than {MAX_ARCHIVE_MEMBERS} files "
            f"— only the first {MAX_ARCHIVE_MEMBERS} were checked "
            f"(stopped at {chain})"
        )
        budget.stopped = True
        return False
    return True


def _scan_zip_members(scanned: ScannedFile, path: Path,
                      budget: _ArchiveBudget, *, display: str,
                      db, rules, chunk_size, heuristics, exclusions,
                      self_exclusions, depth: int) -> None:
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:
        budget.add_reason(
            f"the archive {display} is damaged or unreadable ({exc}) — "
            "its contents were not checked"
        )
        return
    with zf:
        for info in zf.infolist():
            if budget.stopped:
                break
            chain = f"{display} → {info.filename}"
            if not _count_member(budget, chain):
                break
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                budget.add_reason(
                    f"{chain} is a symbolic link — Argus does not "
                    "follow links inside archives, so it was not checked"
                )
                continue
            # Many writers (Python's zipfile included) store only
            # permission bits, with no file-type bits at all: no
            # type stated means a regular file. A type that IS
            # stated and is not regular (fifo, device, socket) is
            # not something Argus materialises.
            if stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                budget.add_reason(
                    f"{chain} is not a regular file — it was not checked"
                )
                continue
            if info.flag_bits & 0x1:
                budget.add_reason(
                    f"{chain} is encrypted — Argus cannot check "
                    "encrypted files inside an archive without the password"
                )
                continue
            if info.compress_type not in (
                zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA,
            ):
                budget.add_reason(
                    f"{chain} uses a compression method Argus cannot "
                    "read — it was not checked"
                )
                continue
            _scan_one_member(
                scanned, budget,
                member_name=info.filename,
                stream_factory=lambda info=info: zf.open(info, "r"),
                chain=chain, db=db, rules=rules, chunk_size=chunk_size,
                heuristics=heuristics, exclusions=exclusions,
                self_exclusions=self_exclusions, depth=depth,
            )


def _scan_tar_members(scanned: ScannedFile, path: Path,
                      budget: _ArchiveBudget, *, display: str,
                      mode: str, db, rules, chunk_size, heuristics,
                      exclusions, self_exclusions,
                      depth: int) -> bool:
    """Scan a TAR's members. Returns False only for the gzip probe
    case where the stream turns out not to be a tar at all (a plain
    gzip file is not an archive Argus claims); every genuine tar
    failure is recorded as a not-fully-scanned reason instead."""
    try:
        tf = tarfile.open(path, mode)
    except Exception as exc:
        if mode == "r:gz" and not path.name.lower().endswith(_TAR_SUFFIXES):
            return False
        budget.add_reason(
            f"the archive {display} is damaged or unreadable ({exc}) — "
            "its contents were not checked"
        )
        return True
    with tf:
        saw_member = False
        while True:
            if budget.stopped:
                break
            try:
                info = tf.next()
            except Exception as exc:
                if (
                    mode == "r:gz" and not saw_member
                    and not path.name.lower().endswith(_TAR_SUFFIXES)
                ):
                    # The gzip probe's verdict: this stream is not
                    # a tar at all (a plain gzip file) — not an
                    # archive Argus claims, so no partial state.
                    return False
                budget.add_reason(
                    f"the archive {display} is damaged or unreadable "
                    f"({exc}) — the rest of it was not checked"
                )
                break
            if info is None:
                break
            saw_member = True
            chain = f"{display} → {info.name}"
            if not _count_member(budget, chain):
                break
            if info.isdir():
                continue
            if info.issym() or info.islnk():
                budget.add_reason(
                    f"{chain} is a link — Argus does not follow links "
                    "inside archives, so it was not checked"
                )
                continue
            if not info.isreg():
                budget.add_reason(
                    f"{chain} is not a regular file — it was not checked"
                )
                continue
            _scan_one_member(
                scanned, budget,
                member_name=info.name,
                stream_factory=lambda info=info: tf.extractfile(info),
                chain=chain, db=db, rules=rules, chunk_size=chunk_size,
                heuristics=heuristics, exclusions=exclusions,
                self_exclusions=self_exclusions, depth=depth,
            )
    return True


def _merge_archive_members(
    scanned: ScannedFile,
    path: Path,
    db: SignatureDB,
    rules: list[Rule],
    chunk_size: int,
    *,
    heuristics: bool,
    exclusions: Exclusions | None,
    self_exclusions: SelfExclusions | None,
    budget: _ArchiveBudget | None,
    depth: int,
    chain: str,
) -> None:
    """If *path* is an archive, scan its members into *scanned*.

    ``depth`` is the depth of the archive that CONTAINED this file
    (0 for a file the user pointed Argus at), so this archive's own
    depth is ``depth + 1``. ``chain`` is this file's attribution
    chain from the top archive ("" at the top, where the display
    name is the file's own name)."""
    if scanned.excluded or not scanned.result.ok:
        return
    kind = _archive_kind(path)
    if kind is None:
        return
    display = chain or path.name
    own_depth = depth + 1
    top_level = budget is None
    if budget is None:
        budget = _ArchiveBudget()
    temp_dir: tempfile.TemporaryDirectory | None = None
    try:
        if own_depth > MAX_ARCHIVE_DEPTH:
            budget.add_reason(
                f"the archive {display} is nested deeper than "
                f"{MAX_ARCHIVE_DEPTH} levels — it was not opened"
            )
            if top_level:
                _apply_archive_state(scanned, budget, is_archive=False)
            return
        if top_level:
            temp_dir = tempfile.TemporaryDirectory(prefix=ARCHIVE_TEMP_PREFIX)
            budget.temp_root = Path(temp_dir.name)
        opened = True
        if kind == "zip":
            _scan_zip_members(
                scanned, path, budget, display=display, db=db,
                rules=rules, chunk_size=chunk_size, heuristics=heuristics,
                exclusions=exclusions, self_exclusions=self_exclusions,
                depth=own_depth,
            )
        elif kind == "tar":
            _scan_tar_members(
                scanned, path, budget, display=display, mode="r:*",
                db=db, rules=rules, chunk_size=chunk_size,
                heuristics=heuristics, exclusions=exclusions,
                self_exclusions=self_exclusions, depth=own_depth,
            )
        else:  # "gzip" — a tar only if the probe says so
            opened = _scan_tar_members(
                scanned, path, budget, display=display, mode="r:gz",
                db=db, rules=rules, chunk_size=chunk_size,
                heuristics=heuristics, exclusions=exclusions,
                self_exclusions=self_exclusions, depth=own_depth,
            )
        if top_level:
            _apply_archive_state(scanned, budget, is_archive=opened)
        elif opened:
            scanned.is_archive = True
            scanned.archive_members_scanned = budget.members_scanned
    finally:
        if temp_dir is not None:
            budget.temp_root = None
            try:
                temp_dir.cleanup()
            except OSError:
                pass


def _apply_archive_state(scanned: ScannedFile, budget: _ArchiveBudget,
                         *, is_archive: bool) -> None:
    """Stamp the shared budget's outcome onto the top-level result:
    members counted, and — when anything could not be checked —
    the designed not-fully-scanned state (flag, tuple of reasons,
    and one prefixed note per reason, plus the ``not_scanned``
    assessment flag that keeps the verdict off Clean)."""
    scanned.is_archive = is_archive
    scanned.archive_members_scanned = budget.members_scanned
    if not budget.reasons:
        return
    reasons = tuple(dict.fromkeys(budget.reasons))
    scanned.archive_not_fully_scanned = True
    scanned.archive_incomplete_reasons = reasons
    scanned.assessment.not_scanned = True
    for reason in reasons:
        note = f"{ARCHIVE_NOT_FULLY_SCANNED_PREFIX} {reason}"
        if note not in scanned.assessment.notes:
            scanned.assessment.notes.append(note)


# ----------------------------------------------------------------------
# Alternate data streams (Windows NTFS)
# ----------------------------------------------------------------------
def iter_data_streams(path: Path) -> list[tuple[str, int]]:
    """Enumerate the NAMED data streams of *path*.

    Returns ``[(stream_name, size), ...]`` for non-empty named
    streams (the unnamed default ``::$DATA`` stream is the file
    itself and is never listed). Windows only, via
    FindFirstStreamW/FindNextStreamW; on every other platform — and
    on any failure — this is a clean no-op returning ``[]``.
    """
    if sys.platform != "win32":
        return []

    class _FindStreamData(ctypes.Structure):
        _fields_ = [
            ("stream_size", ctypes.c_longlong),
            ("name", ctypes.c_wchar * 296),  # MAX_PATH + 36
        ]

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (OSError, AttributeError):
        return []
    find_first = kernel32.FindFirstStreamW
    find_first.restype = ctypes.c_void_p
    find_first.argtypes = [
        ctypes.c_wchar_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
    ]
    find_next = kernel32.FindNextStreamW
    find_next.restype = ctypes.c_bool
    find_next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    find_close = kernel32.FindClose
    find_close.argtypes = [ctypes.c_void_p]

    data = _FindStreamData()
    handle = find_first(str(path), 0, ctypes.byref(data), 0)
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        return []
    streams: list[tuple[str, int]] = []
    try:
        while True:
            raw_name = data.name  # ":name:$DATA" (default: "::$DATA")
            size = int(data.stream_size)
            name = raw_name[1:].split(":$DATA")[0] if raw_name.startswith(":") else ""
            if name and size > 0:
                streams.append((name, size))
                if len(streams) >= MAX_STREAMS_PER_FILE:
                    break
            if not find_next(handle, ctypes.byref(data)):
                break
    finally:
        find_close(handle)
    return streams


def scan_named_streams(
    path: Path,
    db: SignatureDB,
    rules: list[Rule],
    *,
    heuristics: bool = True,
    exclusions: Exclusions | None = None,
    self_exclusions: SelfExclusions | None = None,
) -> list[ScannedFile]:
    """Scan each named data stream of *path* as a virtual file,
    reported as ``path:stream``. Empty list off Windows."""
    results: list[ScannedFile] = []
    for name, _size in iter_data_streams(path):
        stream_path = Path(f"{path}:{name}")
        results.append(
            scan_file(
                stream_path, db, rules,
                heuristics=heuristics, exclusions=exclusions,
                self_exclusions=self_exclusions,
            )
        )
    return results


#: The tamper signal added when a file sits at Argus's own program
#: address but is not the program Argus installed.
_TAMPER_SIGNAL_NAME = "argus_program_file_replaced"

_TAMPER_NOTE = (
    "tamper indicator: a file at Argus's own program "
    "address failed Argus's identity checks — it was "
    "scanned in full, not skipped"
)


def _tamper_signal() -> Signal:
    return Signal(
        name=_TAMPER_SIGNAL_NAME,
        severity="high",
        points=35,
        explanation=(
            "This file sits exactly where Argus's own "
            "program should be, but it is NOT the program "
            "Argus installed — its fingerprint does not match "
            "the fingerprint recorded at setup. Something has "
            "replaced Argus's program file. Treat this as "
            "tampering until proven otherwise, and reinstall "
            "Argus from a trusted source."
        ),
    )


#: The tamper signal for a bundle tool whose fingerprint no
#: longer matches the bundle's own integrity record.
_SIBLING_MODIFIED_SIGNAL_NAME = "bundle_tool_file_modified"

_SIBLING_MODIFIED_NOTE = (
    "tamper indicator: this file claims a Sentinel tool's place "
    "in the bundle, but its fingerprint does not match the "
    "checksum the bundle recorded for it — it was scanned in "
    "full, not trusted"
)


def _sibling_modified_signal() -> Signal:
    return Signal(
        name=_SIBLING_MODIFIED_SIGNAL_NAME,
        severity="high",
        points=35,
        explanation=(
            "This file sits where a Sentinel Safeguard tool "
            "belongs in the Technician's Toolkit bundle, but its "
            "fingerprint does not match the checksum the bundle "
            "recorded for that tool when the bundle was built. "
            "The tool has been changed or replaced since. Treat "
            "this as tampering until proven otherwise, and "
            "rebuild the bundle from a trusted source."
        ),
    )


def _apply_heuristics(
    path: Path,
    size: int,
    assessment: FileAssessment,
    *,
    tamper_suspect: bool = False,
    sha256: str | None = None,
) -> None:
    """Run heuristic analysis and merge its outcome into *assessment*.

    Analysis failures are recorded as notes — heuristics must never
    break a scan that signatures and rules already completed.
    """
    try:
        report = analyze_file(path, size)
    except Exception as exc:  # fail safe: note it, keep the Phase 1 verdict
        assessment.notes.append(f"heuristic analysis failed: {exc}")
        return
    if tamper_suspect:
        report.signals.append(_tamper_signal())
        assessment.notes.append(_TAMPER_NOTE)
    # Bundle sibling trust (v1.2.4): a file the bundle's own
    # integrity record vouches for, fingerprint-matched, gets its
    # heuristic score zeroed on the Microsoft-trust terms — the
    # signals stay listed, signature/rule detections are combined
    # separately and never cleared. A fingerprint MISMATCH on a
    # recorded place is tamper evidence, added as a signal.
    sibling = bundletrust.check_sibling(path, sha256)
    if sibling.modified:
        report.signals.append(_sibling_modified_signal())
        assessment.notes.append(_SIBLING_MODIFIED_NOTE)
    if sibling.verified:
        assessment.notes.append(bundletrust.SIBLING_VERIFIED_NOTE)
    # Oversize script floor waiver (script-routing spot audit,
    # fix-round-3 follow-up): the heuristic half is the report's
    # own flag; the rule half is decided here — the rule layer
    # streamed the WHOLE file (raw and UTF-16-folded passes) and
    # its detections are already on the assessment. One rule hit
    # anywhere keeps the floor exactly as before.
    waive_oversize_floor(
        report,
        rule_detection_count=sum(
            1 for det in assessment.detections if det.kind == "rule"
        ),
    )
    scored = score_signals(
        report.signals,
        # The trim is earned by a DER-parseable PKCS#7 with an
        # extracted signer (P1-20), not by the mere presence of a
        # structurally valid certificate table.
        signed=getattr(report, "signed_trim_eligible", report.signed),
        trusted_system_file=report.trusted_system_file,
        trusted_bundle_sibling=sibling.verified,
    )
    assessment.signals = scored.signals
    assessment.score = scored.score
    assessment.heuristic_verdict = scored.verdict
    assessment.notes.extend(report.notes)


def scan_path(
    root: Path | str,
    db: SignatureDB,
    rules: list[Rule],
    *,
    heuristics: bool = True,
    exclusions: Exclusions | None = None,
    self_exclusions: SelfExclusions | None = None,
) -> ScanReport:
    """Scan a file or directory tree and return a full report."""
    root_path = Path(root)
    stats = ScanStats()
    report = ScanReport(root=root_path, stats=stats)
    if self_exclusions is None:
        self_exclusions = default_self_exclusions()

    for path in iter_files(root_path, stats):
        scanned = scan_file(path, db, rules, heuristics=heuristics,
                            exclusions=exclusions,
                            self_exclusions=self_exclusions)
        batch = [scanned]
        if scanned.result.ok and not scanned.excluded:
            # Named NTFS data streams ride along as virtual files.
            batch.extend(
                scan_named_streams(
                    path, db, rules,
                    heuristics=heuristics, exclusions=exclusions,
                    self_exclusions=self_exclusions,
                )
            )
        for item in batch:
            if item.excluded:
                stats.files_excluded += 1
            elif item.result.ok:
                stats.files_scanned += 1
                stats.bytes_scanned += item.result.size or 0
            else:
                stats.files_skipped += 1
            if item.is_archive:
                stats.archives_seen += 1
                stats.archive_members_scanned += item.archive_members_scanned
            if item.archive_not_fully_scanned:
                stats.archives_not_fully_scanned += 1
            report.files.append(item)

    return report
