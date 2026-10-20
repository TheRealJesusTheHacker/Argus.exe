"""Self-trust: Argus must never flag *itself* — and the exemption
must be too narrow for malware to hide inside.

On the owner's first real install, Argus cheerfully analysed its
own program and its own data files as if they were strangers'
binaries — an antivirus that cries wolf over its own reflection
teaches users to ignore it. This module builds the exclusion set
that prevents it, and builds it *defensively*: the exemption is
the most abusable feature an antivirus can have (every piece of
malware would love to be "Argus itself"), so it is granted by
identity and by exact address, never by name or by neighbourhood.

The scope (narrowed in the v1.1.0 hunt fix pass — the previous
blanket exclusion of the whole data tree and install tree was a
hole: the user-writable ``shared\\`` subtree sat inside it, and
even signature detections were suppressed before the file was
read):

- **The quarantine vault subtree is out of scope**
  (``paths.default_vault_dir()`` — vault blobs, vault database,
  vault key). Vault blobs are already-neutralised malware samples
  in encrypted form; scanning them as files is meaningless.
- **The signature database file and its key file are out of
  scope** — those two exact files in the trusted data root, not
  the root around them. Everything else in the data root —
  ``shared\\`` (user-writable), config, history, status, and
  anything a stranger drops there — scans NORMALLY, signature
  detections included.
- **The program file itself is out of scope ONLY with proof of
  identity**, and the proofs are ranked:
    1. *Primary and decisive:* the SHA-256 the setup engine
       recorded in the trusted data root at install time. When a
       record exists, it alone decides: a match exempts the file;
       a mismatch at a program address is a **tamper indicator**
       (scanned in full + tamper signal) — even if the Service
       Control Manager's ImagePath points at that path, because
       an SCM entry can be repointed at a replacement binary,
       while the recorded fingerprint cannot be satisfied by one.
    2. *When no record exists:* the file is the very executable
       this process is running (``sys.executable`` of the packaged
       build) — **at whatever address it lives**. The running-
       process proof is a property of the process, not of the
       install layout: the portable and bundle editions never
       went through setup, so their program file never sits at
       the canonical install address, and gating this proof on
       that address left the portable program a stranger to
       itself (field finding, 2026-10-20: Argus running from the
       Technician's Toolkit bundle flagged its own exe). Nothing
       else exempts it. In particular the SCM ImagePath is NOT an
       identity proof at all — it only helps *locate* the
       candidate program address — so a file whose only claim is
       an SCM entry is scanned normally, with no exclusion and no
       tamper signal (absence of a record is not evidence of
       replacement).
  The file's NAME never earns anything: an ``Argus.exe`` in any
  other folder is scanned like any stranger's binary.
- **Support files in the install folder scan normally.** Only the
  identity-proven program file is exempt there; a dropper that
  lands next to the real program gets no shelter.

All path comparisons are made on RESOLVED paths (symlinks and
junctions followed, :func:`os.path.realpath`) for both the
candidate and every root/file, so a link cannot launder a path
into — or out of — the exclusion set.

Consulted inside :func:`argus.scanner.scan_file` — the one seam
shared by on-demand scans, the real-time engine, and the service —
before the file is read at all.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

#: Where the setup engine records the installed program's
#: fingerprint, inside the trusted data root (users can read the
#: root but not write it — the v1.0.4 trust split is what makes
#: this record trustworthy).
SELF_IDENTITY_NAME = "self-identity.json"

#: User-presentable sources for an exclusion (they land verbatim
#: in scan notes, so they read like product copy, not debug text).
SOURCE_DATA_TREE = "Argus's own data folder"
SOURCE_VAULT = "Argus's own quarantine vault"
SOURCE_SIGNATURE_DB = "Argus's own signature database"
SOURCE_INSTALL_DIR = "Argus's own program folder"
SOURCE_RUNNING_EXE = "the Argus program itself"
SOURCE_SCM_EXE = "the Argus program registered with Windows"
SOURCE_SYSTEMD_EXE = "the Argus program registered with systemd"
SOURCE_RECORDED_EXE = "the Argus program (fingerprint recorded at setup)"


def _norm(path: Path | str) -> str:
    """Canonical comparison form: expanded, RESOLVED (symlinks /
    junctions followed via ``os.path.realpath``), absolute,
    platform case-folded. Resolving BOTH the candidate and the
    roots is what makes link laundering fail in both directions:
    an excluded file reached through a link is still recognised,
    and a link inside an excluded tree that points OUT of it is
    judged by where it actually leads."""
    expanded = os.path.expandvars(os.path.expanduser(str(path)))
    return os.path.normcase(os.path.realpath(expanded))


def _is_under(candidate: str, root: str) -> bool:
    if candidate == root:
        return True
    # A root that is its own root ("C:\" on Windows, "/" on POSIX)
    # already ends in the separator; appending another would
    # double it and no child would ever match.
    prefix = root if root.endswith(os.sep) else root + os.sep
    return candidate.startswith(prefix)


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_recorded_exe_sha256(data_root: Path | None = None) -> str | None:
    """The program fingerprint the setup engine recorded at
    install time, or None when no install recorded one (portable
    edition, source checkout, or an install that never wrote the
    record)."""
    root = Path(data_root) if data_root is not None else paths.data_dir()
    try:
        raw = json.loads((root / SELF_IDENTITY_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(raw, dict):
        value = raw.get("exe_sha256")
        if isinstance(value, str) and value:
            return value.lower()
    return None


def record_exe_identity(
    exe_path: Path, data_root: Path | None = None, *, version: str = ""
) -> Path:
    """Record the installed program's fingerprint in the trusted
    data root. Called by the setup engine right after the program
    file is placed and verified, so later scans can prove the file
    at the program's address is the file setup put there."""
    root = Path(data_root) if data_root is not None else paths.data_dir()
    payload = {
        "exe_path": str(exe_path),
        "exe_sha256": _sha256_of(Path(exe_path)),
        "version": version,
    }
    return paths.write_text_atomic(
        root / SELF_IDENTITY_NAME, json.dumps(payload, indent=2)
    )


def scm_registered_exe(service_name: str | None = None) -> Path | None:
    """The executable the SCM has registered as the protection
    service's ImagePath (marker argument stripped). Windows only;
    None whenever the question cannot be answered.

    NOTE (v1.1.0 hunt fix): this is a LOCATOR, not an identity
    proof. It tells Argus where the canonical program file is
    expected to live; it never by itself exempts a file, because
    whoever can replace the binary can usually repoint (or keep)
    the registration too. The recorded fingerprint decides."""
    if sys.platform != "win32":
        return None
    try:
        import win32service  # type: ignore[import-not-found]
    except ImportError:
        return None
    if service_name is None:
        try:
            from .winservice import SERVICE_NAME

            service_name = SERVICE_NAME
        except Exception:
            return None
    try:
        scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CONNECT
        )
        try:
            handle = win32service.OpenService(
                scm, service_name, win32service.SERVICE_QUERY_CONFIG
            )
            try:
                config = win32service.QueryServiceConfig(handle)
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception:
        return None
    try:
        binary = str(config[3]).strip()  # lpBinaryPathName
    except (TypeError, IndexError):
        return None
    if binary.startswith('"'):
        closing = binary.find('"', 1)
        if closing <= 1:
            return None
        return Path(binary[1:closing])
    lowered = binary.lower()
    exe_end = lowered.find(".exe")
    if exe_end < 0:
        return None
    return Path(binary[: exe_end + 4])


@dataclass(frozen=True)
class SelfCheck:
    """The outcome of consulting the self-exclusion set about one
    path."""

    excluded: bool
    #: Why it was excluded (user-presentable), when it was.
    source: str | None = None
    #: True when the path is the program's own address, a recorded
    #: fingerprint EXISTS, and the file there does not match it:
    #: not excluded, and the scanner treats it as a tamper
    #: indicator. (No record at all is NOT tamper evidence — see
    #: the module docstring.)
    tamper_suspect: bool = False


@dataclass
class SelfExclusions:
    """Argus's own narrow territory + the program's identity proof.

    The territory is exactly: the quarantine vault subtrees in
    ``vault_dirs``, the exact files in ``protected_files`` (the
    signature database and its key), and — via the identity gate —
    the program file at ``own_exe``. ``data_roots`` is retained
    for callers built against the old broad model: each root
    contributes ONLY its ``quarantine\\`` subtree and its
    signature-DB file + key, never the whole tree.
    """

    data_roots: tuple[Path, ...] = ()
    vault_dirs: tuple[Path, ...] = ()
    protected_files: tuple[Path, ...] = ()
    install_dir: Path | None = None
    own_exe: Path | None = None
    running_exe: Path | None = None
    scm_exe: Path | None = None
    recorded_exe_sha256: str | None = None
    #: Injectable for tests; the default streams the candidate.
    hash_file: object = field(default=None, repr=False)

    # ------------------------------------------------------------------
    def _effective_vault_dirs(self) -> list[Path]:
        dirs = list(self.vault_dirs)
        for root in self.data_roots:
            dirs.append(Path(root) / "quarantine")
        return dirs

    def _effective_protected_files(self) -> list[Path]:
        files = list(self.protected_files)
        try:
            from .signatures import DEFAULT_DB_NAME, key_path_for
        except Exception:
            return files
        for root in self.data_roots:
            db_path = Path(root) / DEFAULT_DB_NAME
            files.append(db_path)
            files.append(key_path_for(db_path))
        return files

    def _hash(self, path: Path) -> str | None:
        try:
            if self.hash_file is not None:
                return str(self.hash_file(path)).lower()  # type: ignore[operator]
            return _sha256_of(path)
        except OSError:
            return None

    def check(self, path: Path | str) -> SelfCheck:
        """Should Argus leave *path* alone as one of its own?"""
        candidate = _norm(path)

        # The vault subtree: neutralised samples + their index/key.
        for root in self._effective_vault_dirs():
            if _is_under(candidate, _norm(root)):
                return SelfCheck(excluded=True, source=SOURCE_VAULT)

        # Exact protected files (signature DB + its key): the file
        # itself, at its resolved address — never its folder.
        for protected in self._effective_protected_files():
            if candidate == _norm(protected):
                return SelfCheck(excluded=True, source=SOURCE_SIGNATURE_DB)

        # The program's addresses: the canonical install address
        # (own_exe) AND — for the packaged build — the address of
        # the very file this process is running as (running_exe).
        # The two coincide in an installed layout; in the portable
        # and bundle layouts only running_exe exists, and the
        # identity gate must still be entered for it (see the
        # module docstring's portable-mode note).
        program_addresses = set()
        if self.own_exe is not None:
            program_addresses.add(_norm(self.own_exe))
        if self.running_exe is not None:
            program_addresses.add(_norm(self.running_exe))
        if candidate in program_addresses:
            # A program address: identity decides.
            if self.recorded_exe_sha256:
                # PRIMARY and DECISIVE: when a fingerprint record
                # exists, it alone rules. A mismatch is tamper
                # evidence even if the SCM ImagePath (or any other
                # locator) points at this very path — and even at
                # the running file's own address: a record that the
                # running file fails means the file on disk is not
                # the file setup vouched for.
                digest = self._hash(Path(path))
                if digest is not None and digest == self.recorded_exe_sha256.lower():
                    return SelfCheck(
                        excluded=True, source=SOURCE_RECORDED_EXE
                    )
                return SelfCheck(excluded=False, tamper_suspect=True)
            # No record: the running-process proof is the only one
            # left (the packaged build exempts the file it is
            # actually running as, wherever that file lives). An
            # SCM match alone exempts nothing and accuses nothing,
            # and the canonical address on its own — an at-rest
            # copy Argus is not running — earns nothing either.
            if self.running_exe is not None and candidate == _norm(
                self.running_exe
            ):
                return SelfCheck(excluded=True, source=SOURCE_RUNNING_EXE)
            return SelfCheck(excluded=False, tamper_suspect=False)

        # Everything else — install-dir support files, the shared
        # data subtree, config, history, status — is a stranger's
        # file as far as scanning is concerned.
        return SelfCheck(excluded=False)


# ----------------------------------------------------------------------
# The process-wide default, built from the live machine
# ----------------------------------------------------------------------
_default_cache: dict[tuple[str, str], SelfExclusions] = {}


def default_self_exclusions() -> SelfExclusions:
    """The self-exclusion set for THIS machine, built once per
    (data root, install dir) pair and cached: the vault subtree
    and signature-DB files come from :mod:`argus.paths`, the
    program address from the setup engine's canonical location
    (or, failing that, the SCM registration — a locator), the
    identity proofs from the running process and the fingerprint
    recorded at install time."""
    data_root = paths.data_dir()
    install_dir: Path | None = None
    own_exe: Path | None = None
    if sys.platform.startswith("linux"):
        # The .deb layout's canonical address is an FHS constant
        # (argus.paths), the same kind of fact as the Windows
        # Program Files address — and it gets the same treatment:
        # the address earns NOTHING by itself; the recorded
        # fingerprint (or, with no record, the running-process
        # proof) decides at the address, exactly as on Windows.
        install_dir = paths.LINUX_INSTALL_DIR
        own_exe = paths.LINUX_PROGRAM_PATH
    else:
        try:
            from . import setup_engine

            install_dir = setup_engine.canonical_install_dir()
            own_exe = setup_engine.canonical_exe_path()
        except Exception:
            install_dir = None
            own_exe = None
    key = (
        _norm(data_root),
        _norm(install_dir) if install_dir is not None else "",
    )
    cached = _default_cache.get(key)
    if cached is not None:
        return cached
    scm_exe = scm_registered_exe()
    if sys.platform.startswith("linux") and scm_exe is None:
        # The systemd unit's ExecStart is the SCM ImagePath's
        # twin: a LOCATOR for the candidate program address,
        # never an identity proof.
        try:
            from . import linuxservice

            scm_exe = linuxservice.systemd_registered_exe()
        except Exception:
            scm_exe = None
    if own_exe is None and scm_exe is not None:
        # The SCM entry's one legitimate job: locating the
        # candidate program address when setup's canonical
        # location is unavailable.
        own_exe = scm_exe
    try:
        from .signatures import DEFAULT_DB_NAME, key_path_for

        signature_db = data_root / DEFAULT_DB_NAME
        protected = (signature_db, key_path_for(signature_db))
    except Exception:
        protected = ()
    exclusions = SelfExclusions(
        vault_dirs=(paths.default_vault_dir(),),
        protected_files=protected,
        install_dir=install_dir,
        own_exe=own_exe,
        # The running file is an identity proof only for the
        # packaged build: in a source checkout sys.executable is
        # the Python interpreter, which must NEVER be exempted.
        running_exe=(
            Path(sys.executable) if getattr(sys, "frozen", False) else None
        ),
        scm_exe=scm_exe,
        recorded_exe_sha256=load_recorded_exe_sha256(data_root),
    )
    _default_cache[key] = exclusions
    return exclusions


def reset_default_cache() -> None:
    """Forget the cached default set (tests, setup completion)."""
    _default_cache.clear()
