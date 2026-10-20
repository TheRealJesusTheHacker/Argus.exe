"""Bundle trust: Argus must recognise its own Sentinel family —
with the same identity discipline as self-trust, never by name.

Inside the Technician's Toolkit bundle, every tool is a
PyInstaller-built program, and every PyInstaller bootloader
carries traits (an in-memory loader's import table, debugger-
detection imports) that Argus's heuristics honestly score when a
STRANGER's file shows them. On the owner's first real bundle run
(2026-10-20) Argus flagged the bundle's own launcher — and its
siblings — as threats: Argus knew how to identity-verify itself
and how to trust verified Microsoft files, but inside the bundle
it treated its own family as strangers.

The fix follows the established trust doctrine — the same shape
as the Microsoft system-file trust in :mod:`argus.scoring`:

- **No filename-based or path-only trust, ever** (the v1.1.0
  lesson). A sibling earns trust by IDENTITY PROOF: Argus is
  running in bundle mode (see anchors below), the candidate file
  lives in the same bundle tree, AND its SHA-256 matches the hash
  recorded for that exact file in the bundle's own integrity
  record — the bundle-root ``SHA256SUMS.txt`` the bundle assembly
  writes and the bundle launcher's ``check_bundle`` verifies.
- **Trust zeroes the HEURISTIC score only.** Signature-database
  and pattern-rule detections on a verified sibling still fire at
  full weight (they are combined outside the heuristic score),
  and every heuristic signal stays listed on the result, with a
  plain-language note saying why the file was recognised.
- **A hash MISMATCH on a file the record claims is tamper
  evidence**, mirroring the canonical-path rule for Argus's own
  program file: the file is scanned in full and the mismatch is
  itself reported as a signal. A file the record does not claim
  at all is simply a stranger — scanned normally, accused of
  nothing.

Anchors — what makes a folder "the bundle Argus is part of":
the folder that CONTAINS Argus's data root when ``ARGUS_DATA_DIR``
points inside it (the bundle launcher's manifest contract:
``ARGUS_DATA_DIR={bundle}\\ArgusData``), or the folder the
packaged Argus program itself runs from. A folder becomes an
anchor only through Argus's own presence in it, and only counts
as a bundle when it actually carries the bundle's shape — a
parseable ``MANIFEST.json`` with a tools list, next to the
``SHA256SUMS.txt`` integrity record. A stranger's folder that
merely contains a checksums file earns nothing: Argus is not
running from it, so it is never consulted.

Consulted inside :func:`argus.scanner._apply_heuristics` — the
seam the on-demand scanner, the real-time engine, and the service
all share (the real-time engine drives the same
:func:`argus.scanner.scan_file`, so both paths consult this
module identically).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from . import paths

#: The bundle's integrity record + manifest, at the bundle root.
SUMS_NAME = "SHA256SUMS.txt"
MANIFEST_NAME = "MANIFEST.json"

#: User-presentable note for a verified sibling (lands verbatim in
#: scan notes, so it reads like product copy, not debug text).
SIBLING_VERIFIED_NOTE = (
    "verified Sentinel Safeguard tool — this file matches the "
    "checksum recorded for it in the bundle's own integrity "
    "record, so its program traits were not scored against it. "
    "Signature and pattern checks still applied in full."
)

_SUMS_LINE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+[* ]?(.+?)\s*$")


def _norm(path: Path | str) -> str:
    """Canonical comparison form, identical discipline to
    :mod:`argus.selftrust`: expanded, RESOLVED (symlinks and
    junctions followed), absolute, platform case-folded."""
    expanded = os.path.expandvars(os.path.expanduser(str(path)))
    return os.path.normcase(os.path.realpath(expanded))


def _is_under(candidate: str, root: str) -> bool:
    if candidate == root:
        return True
    prefix = root if root.endswith(os.sep) else root + os.sep
    return candidate.startswith(prefix)


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class BundleRecord:
    """A validated bundle integrity record."""

    root: Path
    #: Bundle-relative path (forward slashes, as recorded) ->
    #: expected SHA-256 (lowercase hex).
    sums: dict[str, str]

    def relative_key(self, path: Path | str) -> str | None:
        """The record key for *path*, or None when the file is not
        inside this bundle tree at all."""
        candidate = _norm(path)
        root = _norm(self.root)
        if not _is_under(candidate, root) or candidate == root:
            return None
        # Both sides are resolved absolute paths in platform form;
        # the record's keys are bundle-relative with forward
        # slashes. Rebuild the relative part from the resolved
        # candidate so a junction cannot launder a key. The key is
        # CASE-FOLDED: _norm lowercases whole paths on Windows
        # (normcase), while the record's own keys keep the case
        # they were written with — keys are folded at load time
        # too, so the lookup compares like with like on every
        # platform. (The bundle targets Windows, whose filesystem
        # is case-insensitive; folding loses nothing and the hash
        # still decides.)
        rel = os.path.relpath(candidate, root)
        if rel.startswith(".." + os.sep) or rel == "..":
            return None
        return rel.replace(os.sep, "/").lower()


def load_bundle_record(root: Path | str) -> BundleRecord | None:
    """Load and validate the bundle integrity record at *root*.

    Returns None unless the folder carries the bundle's shape: a
    parseable ``MANIFEST.json`` declaring a tools list, beside a
    ``SHA256SUMS.txt`` with at least one well-formed entry. The
    manifest is the shape check; the checksums are the record."""
    root = Path(root)
    try:
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(manifest, dict) or not isinstance(
        manifest.get("tools"), list
    ):
        return None
    try:
        lines = (root / SUMS_NAME).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    sums: dict[str, str] = {}
    for line in lines:
        match = _SUMS_LINE.match(line.strip())
        if match:
            # Keys are stored case-folded — see BundleRecord.
            # relative_key for why.
            key = match.group(2).replace("\\", "/").lower()
            sums[key] = match.group(1).lower()
    if not sums:
        return None
    return BundleRecord(root=root, sums=sums)


def anchor_roots() -> list[Path]:
    """Folders that could be the root of the bundle Argus is part
    of, by Argus's own presence in them (see module docstring)."""
    anchors: list[Path] = []
    if os.environ.get("ARGUS_DATA_DIR"):
        # The launcher's manifest contract places the data root
        # directly inside the bundle folder.
        anchors.append(paths.data_dir().parent)
    if getattr(sys, "frozen", False):
        anchors.append(Path(sys.executable).resolve().parent)
    seen: set[str] = set()
    unique: list[Path] = []
    for anchor in anchors:
        key = _norm(anchor)
        if key not in seen:
            seen.add(key)
            unique.append(anchor)
    return unique


@dataclass(frozen=True)
class SiblingCheck:
    """The outcome of consulting the bundle record about one file."""

    #: The file's hash matches the bundle record: a verified
    #: Sentinel sibling (heuristics zeroed, everything else full).
    verified: bool = False
    #: The record claims this file's place but the hash differs:
    #: scanned in full; the mismatch itself is a tamper signal.
    modified: bool = False
    #: The record key the file claimed, when it claimed one.
    key: str | None = None


_default_cache: list[BundleRecord] | None = None


def default_bundle_records() -> list[BundleRecord]:
    """The validated bundle records for every anchor root of THIS
    process, built once and cached. Empty when Argus is not
    running in a bundle."""
    global _default_cache
    if _default_cache is None:
        records: list[BundleRecord] = []
        for anchor in anchor_roots():
            record = load_bundle_record(anchor)
            if record is not None:
                records.append(record)
        _default_cache = records
    return _default_cache


def reset_default_cache() -> None:
    """Forget the cached records (tests, layout changes)."""
    global _default_cache
    _default_cache = None


def check_sibling(
    path: Path | str,
    sha256: str | None = None,
    *,
    records: list[BundleRecord] | None = None,
) -> SiblingCheck:
    """Consult the bundle record(s) about *path*.

    ``sha256`` is the digest the scanner already computed for the
    file; when it is not supplied the file is hashed here. Any
    failure to even ask means "no opinion" — the file is treated
    as a stranger's (the safe direction: it gets fully scanned
    and fully scored)."""
    unclaimed_key: str | None = None
    try:
        for record in (
            records if records is not None else default_bundle_records()
        ):
            key = record.relative_key(path)
            if key is None:
                continue
            expected = record.sums.get(key)
            if expected is None:
                # Inside the tree, but the record does not claim
                # this file: a stranger in the bundle folder —
                # scanned normally, trusted not at all, accused
                # of nothing. (Another record could still claim
                # it, so remember the key and keep asking.)
                unclaimed_key = unclaimed_key or key
                continue
            digest = (sha256 or "").lower() or _sha256_of(Path(path))
            if digest == expected:
                return SiblingCheck(verified=True, key=key)
            return SiblingCheck(modified=True, key=key)
    except Exception:
        return SiblingCheck()
    return SiblingCheck(key=unclaimed_key)
