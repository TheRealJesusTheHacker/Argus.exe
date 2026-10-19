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
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .config import Exclusions
from .detections import FileAssessment, Verdict, assess
from .heuristics.analyze import SCRIPT_EXTENSIONS, analyze_file
from .rules import MAX_RULE_SCAN_SIZE, Rule, RuleMatcher
from .scoring import score_signals
from .signatures import SignatureDB

CHUNK_SIZE = 1024 * 1024  # 1 MiB

#: Errnos that mean "the file exists but Argus could not read it"
#: (locked by another process, permission denied, busy). These map
#: to the explicit NotScanned outcome; a vanished file (ENOENT) is
#: just gone and is reported as a plain read error instead.
_LOCKED_ERRNOS = frozenset(
    {errno.EACCES, errno.EPERM, errno.EAGAIN, errno.EBUSY}
)

#: Cap on named data streams scanned per file (abuse-proofing).
MAX_STREAMS_PER_FILE = 32


def _is_scan_blocked(exc: OSError) -> bool:
    """True when *exc* means 'could not read it' (locked/denied)."""
    return isinstance(exc, PermissionError) or exc.errno in _LOCKED_ERRNOS


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
    """
    result = FileResult(path=path)
    matcher = RuleMatcher(rules)
    # Scripts also get a UTF-16LE-folded view through a second
    # matcher: a .ps1 saved as UTF-16 (PowerShell's own default for
    # years) must not sail past text rules just because every other
    # byte is NUL.
    folded_matcher = (
        RuleMatcher(rules) if path.suffix.lower() in SCRIPT_EXTENSIONS else None
    )
    folder = _Utf16Folder() if folded_matcher is not None else None
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
    # whose content is executable gets rule matching at ANY size —
    # the matcher streams in chunks, so a padded executable cannot
    # hide its head/tail bytes behind a size cap. Content decides:
    # the first chunk is checked for the MZ magic before the choice.
    oversize = size > MAX_RULE_SCAN_SIZE
    feed_rules = not oversize
    rules_ran = False

    hasher = hashlib.sha256()
    read_size = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                if read_size == 0 and oversize and chunk.startswith(b"MZ"):
                    feed_rules = True  # executable content: rules run
                hasher.update(chunk)
                read_size += len(chunk)
                if feed_rules:
                    matcher.feed(chunk)
                    rules_ran = True
                    if folded_matcher is not None and folder is not None:
                        folded_matcher.feed(folder.feed(chunk))
    except OSError as exc:
        result.error = f"could not read file: {exc.strerror or exc}"
        assessment = (
            _blocked_assessment() if _is_scan_blocked(exc) else FileAssessment()
        )
        return ScannedFile(result=result, assessment=assessment,
                           rules_skipped_reason="file could not be read")

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
    rule_hits = matcher.finish() if rules_ran else []
    if folded_matcher is not None and rules_ran:
        seen_names = {hit.name for hit in rule_hits}
        for hit in folded_matcher.finish():
            if hit.name not in seen_names:
                rule_hits.append(hit)
    assessment = assess(signature_hit, rule_hits)
    if getattr(matcher, "budget_exceeded", False) or (
        folded_matcher is not None
        and getattr(folded_matcher, "budget_exceeded", False)
    ):
        assessment.notes.append(
            "pattern matching stopped early: the per-file rule time "
            "budget was exhausted (the file was still hashed and "
            "checked against signatures)"
        )

    if heuristics:
        _apply_heuristics(path, read_size, assessment)

    return ScannedFile(
        result=result, assessment=assessment, rules_skipped_reason=rules_skipped_reason
    )


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
            )
        )
    return results


def _apply_heuristics(path: Path, size: int, assessment: FileAssessment) -> None:
    """Run heuristic analysis and merge its outcome into *assessment*.

    Analysis failures are recorded as notes — heuristics must never
    break a scan that signatures and rules already completed.
    """
    try:
        report = analyze_file(path, size)
    except Exception as exc:  # fail safe: note it, keep the Phase 1 verdict
        assessment.notes.append(f"heuristic analysis failed: {exc}")
        return
    scored = score_signals(report.signals, signed=report.signed)
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
) -> ScanReport:
    """Scan a file or directory tree and return a full report."""
    root_path = Path(root)
    stats = ScanStats()
    report = ScanReport(root=root_path, stats=stats)

    for path in iter_files(root_path, stats):
        scanned = scan_file(path, db, rules, heuristics=heuristics,
                            exclusions=exclusions)
        batch = [scanned]
        if scanned.result.ok and not scanned.excluded:
            # Named NTFS data streams ride along as virtual files.
            batch.extend(
                scan_named_streams(
                    path, db, rules,
                    heuristics=heuristics, exclusions=exclusions,
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
            report.files.append(item)

    return report
