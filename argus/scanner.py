"""File walking + scanning for ARGUS.EXE.

The scanner walks a directory tree, hashes every file with SHA-256, and
checks each file against the signature database and the pattern rules.

Hard rules learned from real-world scanner bugs:

- **Streamed hashing.** Files are read in 1 MiB chunks. Nothing is ever
  loaded whole into memory — a multi-GB file costs the same RAM as a
  text file. (Whole-file reads crash on large files; see Hellhound's
  MemoryError bug.)
- **Symlink-safe.** Directory symlinks are never followed, so a scan can
  never wander out of the tree it was pointed at or loop forever.
  Symlinks to files are scanned like regular files.
- **Permission-error tolerant.** Anything that cannot be read is skipped,
  counted, and reported — never a crash, never silently swallowed.
- **Single pass.** Hashing and rule matching share one read of the file.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .detections import FileAssessment, Verdict, assess
from .rules import MAX_RULE_SCAN_SIZE, Rule, RuleMatcher
from .signatures import SignatureDB

CHUNK_SIZE = 1024 * 1024  # 1 MiB


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
    if root.is_file() or root.is_symlink():
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
) -> ScannedFile:
    """Scan one file: hash it, check signatures, evaluate rules.

    Hashing and rule matching share a single streamed read. Files over
    ``MAX_RULE_SCAN_SIZE`` get hash/signature checks only; the skip is
    noted on the result rather than hidden.
    """
    result = FileResult(path=path)
    matcher = RuleMatcher(rules)
    rules_skipped_reason: str | None = None

    try:
        size = path.stat().st_size
    except OSError as exc:
        result.error = f"could not read file: {exc.strerror or exc}"
        return ScannedFile(result=result, assessment=FileAssessment(),
                           rules_skipped_reason="file could not be read")

    rule_scan = size <= MAX_RULE_SCAN_SIZE
    if not rule_scan:
        rules_skipped_reason = (
            f"file is larger than {MAX_RULE_SCAN_SIZE // (1024 * 1024)} MB — "
            "pattern rules skipped (signature check still applied)"
        )

    hasher = hashlib.sha256()
    read_size = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                read_size += len(chunk)
                if rule_scan:
                    matcher.feed(chunk)
    except OSError as exc:
        result.error = f"could not read file: {exc.strerror or exc}"
        return ScannedFile(result=result, assessment=FileAssessment(),
                           rules_skipped_reason="file could not be read")

    result.size = read_size
    result.sha256 = hasher.hexdigest()

    signature_hit = db.lookup(result.sha256)
    rule_hits = matcher.finish() if rule_scan else []
    assessment = assess(signature_hit, rule_hits)
    return ScannedFile(
        result=result, assessment=assessment, rules_skipped_reason=rules_skipped_reason
    )


def scan_path(root: Path | str, db: SignatureDB, rules: list[Rule]) -> ScanReport:
    """Scan a file or directory tree and return a full report."""
    root_path = Path(root)
    stats = ScanStats()
    report = ScanReport(root=root_path, stats=stats)

    for path in iter_files(root_path, stats):
        scanned = scan_file(path, db, rules)
        if scanned.result.ok:
            stats.files_scanned += 1
            stats.bytes_scanned += scanned.result.size or 0
        else:
            stats.files_skipped += 1
        report.files.append(scanned)

    return report
