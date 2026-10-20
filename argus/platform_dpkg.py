"""Platform dpkg verification (v1.2.0 — the Linux system-file trust).

The Windows edition recognises a genuine OS file by Authenticode:
a structurally valid Microsoft signature on a file living in its
system home (see :mod:`argus.platform_authenticode` and
:mod:`argus.heuristics.analyze`). Linux has no Authenticode — but
Debian-based systems (Kali, Parrot, Ubuntu, Debian itself) have
something with the same shape of authority: the **dpkg package
database**. A file the package manager installed, from a package
it still tracks, at the address the package put it, is the
distribution's own file in the distribution's own home.

The mapping, kept as conservative as the Windows three legs:

- Windows: structurally valid WIN_CERTIFICATE → Linux: dpkg-query
  answers for the exact resolved path (the file is a recorded
  payload of an installed package — not a claim the file makes,
  but a record the system keeps).
- Windows: WinVerifyTrust checks the signed digest (the file's
  CONTENT is what the signature covers) → Linux: when dpkg also
  recorded an MD5 checksum for the file (``/var/lib/dpkg/info/
  <package>.md5sums`` — recorded for ordinary package payloads),
  the file's current MD5 must still match it. Ownership is a
  statement about a PATH; the checksum is what binds the trust
  to the bytes actually sitting there, so a payload replaced in
  place — same path, different content — earns no trust. When
  dpkg recorded no checksum for the file (generated files, some
  symlinks and alternatives), the checksum leg has no opinion
  and ownership + location decide, exactly as before.
- Windows: the signer is Microsoft → Linux: the owning package is
  whatever dpkg names; the trust is in the *database*, so this
  leg is the dpkg answer itself. (Any package counts — a standard
  user cannot write to the system directories, so a payload
  recorded there was placed by root through the package manager.)
- Windows: the file lives under the Windows root, outside its
  user-writable subtrees → Linux: the resolved path lives under
  /usr, /bin, /sbin, /lib or /lib64, and NOT under /usr/local
  (the admin's hand-installed tree — dpkg never owns it, and the
  gate says so explicitly rather than trusting the lookup).

And the same limits as Windows, unchanged:

- Trust zeroes the HEURISTIC score only. Signature-database and
  pattern-rule detections are never cleared by it, and the
  signals stay listed with an explanatory note.
- Fail closed: dpkg-query missing, erroring, or answering "no
  such path" means NO trust — never a guess, never a fallback.
- Verdicts are cached per (resolved path, size, mtime, sampled
  content) for the life of the process, exactly like the
  Authenticode cache: a same-size, mtime-restored replacement
  re-verifies instead of inheriting trust.

The decision logic is factored into pure functions
(:func:`parse_dpkg_search_output`, :func:`is_system_location`,
:func:`decide_trust`) with the subprocess runner injectable, so
the whole gate is testable off a live dpkg system.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .watcher import sampled_content_hash

log = logging.getLogger("argus.platform_dpkg")

#: dpkg records the file as a payload of an installed package.
STATUS_TRUSTED = "trusted"
#: dpkg answered, and the file is not a recorded package payload.
STATUS_UNTRUSTED = "untrusted"
#: No dpkg answer exists here (non-Linux, dpkg-query missing).
STATUS_UNAVAILABLE = "unavailable"

#: Top-level directories whose contents are the distribution's
#: own. /usr/local is deliberately absent (see the docstring).
SYSTEM_ROOTS = ("/usr", "/bin", "/sbin", "/lib", "/lib64")

#: Subtrees of the system roots that are NOT package territory
#: even when they sit under one: hand-installed admin files.
NON_SYSTEM_SUBTREES = ("/usr/local",)


@dataclass(frozen=True)
class DpkgTrustResult:
    """The dpkg verifier's verdict for one file."""

    status: str  # STATUS_TRUSTED | STATUS_UNTRUSTED | STATUS_UNAVAILABLE
    #: The package dpkg names as the file's owner, when it does.
    package: str | None = None
    detail: str = ""


#: A verifier maps a path to a DpkgTrustResult. Tests inject
#: fakes; production uses :func:`verify_dpkg`.
DpkgVerifier = Callable[[Path], DpkgTrustResult]

#: A runner executes argv and returns (returncode, stdout, stderr)
#: as text. Tests inject fakes; production runs dpkg-query.
DpkgRunner = Callable[[list[str]], tuple[int, str, str]]


#: Where dpkg-query lives on a Debian-based system. The scanner
#: asks this question from inside a root-owned service, so the
#: binary is named by absolute path whenever it exists there —
#: a PATH inherited from elsewhere must never get to substitute
#: a different "dpkg-query" for the trust decision. The bare name
#: (PATH lookup) is only the fallback for layouts without one.
_DPKG_QUERY_CANDIDATES = ("/usr/bin/dpkg-query", "/bin/dpkg-query")

#: dpkg's per-package records (ownership checksums live here).
DPKG_INFO_DIR = Path("/var/lib/dpkg/info")


def _dpkg_query_program() -> str:
    for candidate in _DPKG_QUERY_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "dpkg-query"


def _default_runner(argv: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(
        argv, capture_output=True, text=True, timeout=15
    )
    return completed.returncode, completed.stdout, completed.stderr


def parse_dpkg_search_output(
    stdout: str, stderr: str, returncode: int, path: Path | str
) -> str | None:
    """The package that owns *path* per one dpkg-query -S answer,
    or None when the answer records no owner.

    Output shapes handled (dpkg-query -S <path>):

    - ``package: /abs/path`` — the normal ownership line. Several
      packages may be comma-joined (``pkg-a, pkg-b: /abs/path``);
      the first named is returned.
    - ``diversion by pkg from: /abs/path`` / ``diversion by pkg
      to: /abs/path`` / ``local diversion from: ...`` — diversion
      bookkeeping lines. They are NOT ownership claims; only the
      plain ownership line for the exact path counts.
    - No match: returncode 1 with ``dpkg-query: no path found
      matching pattern`` on stderr and nothing usable on stdout.
    """
    if returncode != 0:
        return None
    target = str(path)
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("diversion"):
            continue
        owner, sep, named = line.rpartition(": ")
        if not sep or named.strip() != target:
            continue
        package = owner.split(",")[0].strip()
        # Architectures ride along as "pkg:amd64" in some outputs;
        # the bare package name is the identity we report.
        package = package.split(":")[0].strip()
        if package and " " not in package:
            return package
    return None


def is_system_location(path: Path | str) -> bool:
    """The location leg: the RESOLVED path (symlinks followed —
    /bin is often a symlink to /usr/bin, and resolution is what
    makes that honest) lives under a system root and outside the
    non-system subtrees."""
    resolved = os.path.realpath(str(path))
    for subtree in NON_SYSTEM_SUBTREES:
        if resolved == subtree or resolved.startswith(subtree + os.sep):
            return False
    for root in SYSTEM_ROOTS:
        if resolved == root or resolved.startswith(root + os.sep):
            return True
    return False


def dpkg_owner(
    path: Path | str, *, runner: DpkgRunner | None = None
) -> DpkgTrustResult:
    """Ask dpkg-query who owns *path* (no location judgement —
    that is :func:`decide_trust`'s other leg).

    ``STATUS_UNAVAILABLE`` when dpkg-query cannot be run at all;
    ``STATUS_UNTRUSTED`` when it runs and records no owner;
    ``STATUS_TRUSTED`` (with the package name) when it does."""
    run = runner or _default_runner
    try:
        returncode, stdout, stderr = run(
            [_dpkg_query_program(), "-S", "--", str(path)]
        )
    except FileNotFoundError:
        return DpkgTrustResult(
            STATUS_UNAVAILABLE, None, "dpkg-query is not installed"
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return DpkgTrustResult(
            STATUS_UNAVAILABLE, None, f"dpkg-query could not run: {exc}"
        )
    package = parse_dpkg_search_output(stdout, stderr, returncode, path)
    if package is None:
        return DpkgTrustResult(
            STATUS_UNTRUSTED,
            None,
            "dpkg records no package as owning this file",
        )
    return DpkgTrustResult(
        STATUS_TRUSTED, package, f"owned by dpkg package {package}"
    )


def recorded_md5(package: str, resolved_path: Path | str) -> str | None:
    """The MD5 checksum dpkg recorded for *resolved_path* as a
    payload of *package* (from ``/var/lib/dpkg/info/
    <package>.md5sums``, including the ``<package>:<arch>``
    spelling), or None when dpkg recorded no checksum for it —
    generated files and link payloads legitimately have none,
    and None means "no opinion", never "mismatch"."""
    info_dir = DPKG_INFO_DIR
    candidates = [info_dir / f"{package}.md5sums"]
    try:
        candidates.extend(sorted(info_dir.glob(f"{package}:*.md5sums")))
    except OSError:
        pass
    target = str(resolved_path).lstrip("/")
    for sums_path in candidates:
        try:
            lines = sums_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            continue
        for line in lines:
            if not line or line.startswith("\\"):
                continue  # escaped-name record: no safe opinion
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            digest, recorded = parts[0].strip().lower(), parts[1].strip()
            if recorded.startswith("*"):
                recorded = recorded[1:]  # md5sum binary-mode marker
            if recorded == target:
                return digest or None
    return None


def recorded_content_matches(
    path: Path | str, package: str
) -> bool | None:
    """The content leg: does the file at the RESOLVED *path*
    still hash (MD5, dpkg's own recorded algorithm) to the
    checksum dpkg recorded for it under *package*?

    True — the bytes are the bytes the package installed.
    False — dpkg recorded a checksum and the current content
    does NOT match it (or cannot even be read): the payload was
    replaced in place, and path ownership alone must not carry
    trust for it. None — no checksum was recorded, so this leg
    has no opinion."""
    resolved = os.path.realpath(str(path))
    expected = recorded_md5(package, resolved)
    if expected is None:
        return None
    digest = hashlib.md5()
    try:
        with open(resolved, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return False
    return digest.hexdigest() == expected


def decide_trust(
    path: Path | str, owner: DpkgTrustResult
) -> DpkgTrustResult:
    """Combine the legs: dpkg ownership AND a system location, or
    no trust. An unavailable verifier stays unavailable (callers
    fail closed on anything but STATUS_TRUSTED)."""
    if owner.status != STATUS_TRUSTED:
        return owner
    if not is_system_location(path):
        return DpkgTrustResult(
            STATUS_UNTRUSTED,
            owner.package,
            f"owned by dpkg package {owner.package}, but "
            f"{path} is not in a system location, so no "
            "system-file trust is granted",
        )
    return owner


_CACHE_LIMIT = 512
_cache: "OrderedDict[tuple[str, int, int, str], DpkgTrustResult]" = (
    OrderedDict()
)


def verify_dpkg(path: Path | str) -> DpkgTrustResult:
    """The production verdict for *path*: cached per (resolved
    path, size, mtime, sampled content) like the Authenticode
    cache — a replaced file re-verifies instead of inheriting
    the previous file's trust. Non-Linux is unavailable; any
    failure to even sample the file fails closed."""
    if not sys.platform.startswith("linux"):
        return DpkgTrustResult(
            STATUS_UNAVAILABLE, None, "dpkg trust is Linux-only"
        )
    target = Path(path)
    try:
        stat = target.stat()
        key = (
            os.path.normcase(os.path.realpath(str(target))),
            stat.st_size,
            stat.st_mtime_ns,
            sampled_content_hash(target, stat.st_size),
        )
    except OSError as exc:
        return DpkgTrustResult(
            STATUS_UNTRUSTED, None, f"could not stat/sample the file: {exc}"
        )
    cached = _cache.get(key)
    if cached is not None:
        _cache.move_to_end(key)
        return cached
    result = decide_trust(target, dpkg_owner(target))
    if result.status == STATUS_TRUSTED and result.package:
        # The content leg (hunt #2): ownership vouches for the
        # PATH, but trust is spent on the BYTES. When dpkg
        # recorded a checksum for this payload and the content
        # no longer matches it, the file was replaced in place —
        # withdraw the trust the path alone would have granted.
        # No recorded checksum = no opinion = ownership stands.
        try:
            intact = recorded_content_matches(target, result.package)
        except Exception:  # a broken content check fails CLOSED
            log.warning(
                "dpkg content check for %s raised — treating the "
                "file as untrusted",
                target,
            )
            intact = False
        if intact is False:
            result = DpkgTrustResult(
                STATUS_UNTRUSTED,
                result.package,
                f"owned by dpkg package {result.package}, but the "
                "file's contents do not match the checksum the "
                "package manager recorded for it — the file may "
                "have been replaced, so no system-file trust is "
                "granted",
            )
    if result.status != STATUS_TRUSTED:
        log.debug("dpkg trust not granted for %s: %s", target, result.detail)
    _cache[key] = result
    while len(_cache) > _CACHE_LIMIT:
        _cache.popitem(last=False)
    return result


def clear_cache() -> None:
    """Forget all cached verdicts (tests)."""
    _cache.clear()


def platform_dpkg_verifier() -> DpkgVerifier | None:
    """The default verifier for this platform, or None when the
    platform has none (non-Linux) — mirroring
    :func:`argus.platform_authenticode.platform_verifier`."""
    if not sys.platform.startswith("linux"):
        return None
    return verify_dpkg
