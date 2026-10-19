"""Signature database for ARGUS.EXE.

The signature database is a single SQLite file holding SHA-256 hashes of
known-bad files. It is deliberately boring technology: SQLite is in the
Python standard library, the file is easy to ship and update, and anyone
can inspect it with off-the-shelf tools.

Layout
------
``hashes`` — one row per known-bad file:
    ``sha256``   hex-encoded SHA-256 digest (primary key)
    ``name``     detection name, e.g. "EICAR-Test-File"
    ``family``   malware family / category, e.g. "Test"
    ``severity`` one of: low, medium, high, critical

``meta`` — key/value bookkeeping:
    ``schema_version``  format version this file was written with
    ``version``         human-facing database version string
    ``built_at``        ISO-8601 UTC timestamp of the build
    ``count``           number of rows in ``hashes`` (kept in sync so a
                        truncated or tampered file is detected on load)
    ``auth_hmac``       HMAC-SHA256 tag over the canonical sorted hash
                        list (see "Authenticity" below)

The database file itself is NEVER committed to git (see .gitignore).
It is built locally with ``python -m argus sigdb init``; the only
signature that ships in source code is the industry-standard EICAR
test file, used so detection can be verified end-to-end safely.

Authenticity (v1.0.4)
---------------------
The protection service runs as LocalSystem and enforces whatever
this database says, so the database must be tamper-evident.
``init_db`` — and ONLY ``init_db``, inside its creation
transaction — mints an HMAC-SHA256 tag over the canonical
per-row form (digest + name + severity + family, sorted by
digest, with unambiguous length-prefixed separators), keyed by
a random secret (see :func:`key_path_for` for where the key
lives; created owner-only, ``0600``). Nothing ever re-signs an
existing database: bootstrap/ensure verify the tag READ-ONLY,
so a drifted tag can never be quietly "refreshed" over tampered
rows. :meth:`SignatureDB.open` verifies the tag whenever both
the tag and the key are available — a present tag that does not
match is a loud refusal, never a silent "clean". Callers that
pass ``require_auth=True`` (the service) get enforcement, not
just a report: a missing tag OR a missing key raises
:class:`SignatureError`. With ``require_auth=False`` a missing
tag/key is still only reported on :class:`SignatureInfo`
(``auth_missing`` / ``auth_verified``).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .paths import data_dir, default_vault_dir

log = logging.getLogger("argus.signatures")

SCHEMA_VERSION = 1
DB_VERSION = "1.0"
DEFAULT_DB_NAME = "signatures.sigdb"

SEVERITIES = ("low", "medium", "high", "critical")

# The EICAR anti-malware test file: a harmless, industry-standard string
# that every scanner is expected to flag. Seeding it lets anyone verify
# the whole pipeline (walk -> hash -> lookup -> verdict) with zero risk.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_NAME = "EICAR-Test-File"
EICAR_FAMILY = "Test"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hashes (
    sha256   TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    family   TEXT NOT NULL,
    severity TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

#: Meta key holding the HMAC-SHA256 auth tag (hex) over the hash list.
_AUTH_META_KEY = "auth_hmac"
#: Size of the generated database key, in bytes.
_KEY_BYTES = 32


class SignatureError(Exception):
    """Raised when a signature database is missing, corrupt, fails
    its integrity check, or fails authentication. Callers should
    treat this as fatal for a scan: scanning with an unverified
    database would be dishonest."""


@dataclass(frozen=True)
class SignatureHit:
    """A hash matched a signature in the database."""

    sha256: str
    name: str
    family: str
    severity: str


@dataclass(frozen=True)
class SignatureInfo:
    """Summary of a loaded signature database (for `sigdb info`)."""

    version: str
    built_at: str
    count: int
    schema_version: int
    #: True when an HMAC auth tag was present AND verified.
    auth_verified: bool = False
    #: True when no verifiable auth tag exists for this database
    #: (no tag recorded, or no key file beside it). Surfaced so the
    #: service can warn loudly instead of bricking protection.
    auth_missing: bool = False
    #: True when THIS process could not perform the auth check at
    #: all because the auth key is not readable to it (v1.1.0 fix
    #: round 2, FIX 3): the installed layout keeps the default
    #: database's key inside the ACL'd vault subtree, which a
    #: standard user's GUI/CLI process must never read. Bootstrap
    #: then verifies the database's STRUCTURE only and defers the
    #: HMAC verdict to the protection service — the key holder,
    #: which verifies strictly (``require_auth=True``) and reports
    #: tampering loudly in its status. A deferred check is NOT a
    #: verified one; ``auth_verified`` stays False.
    auth_deferred: bool = False


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ----------------------------------------------------------------------
# Authenticity: HMAC key + tag
# ----------------------------------------------------------------------

def _canon_path(path: Path | str) -> str:
    """Canonical comparison form for a path: fully RESOLVED
    (symlinks/junctions followed) and platform case-folded.

    Path-identity comparisons (auditor item g) must not be
    fooled by spelling: the same database reached through a
    symlinked directory, a ``.`` segment, or a case variant is
    the same database, and its key belongs wherever the DEFAULT
    database's key belongs. ``Path.absolute()`` does none of
    that resolving, so it is never used for identity checks.
    """
    try:
        return os.path.normcase(str(Path(path).resolve()))
    except (OSError, RuntimeError):
        return os.path.normcase(str(Path(path).absolute()))


def _is_default_db_path(db_path: Path | str) -> bool:
    """True when *db_path* IS the default signature database,
    however it is spelled (links resolved on both sides)."""
    try:
        return _canon_path(db_path) == _canon_path(
            default_signature_db_path()
        )
    except Exception:
        return False


def key_path_for(db_path: Path | str) -> Path:
    """The auth-key file that belongs to *db_path*
    (``signatures.sigdb`` → ``signatures.sigdb.key``).

    Installed layout (v1.1.0): when *db_path* IS the default
    database (:func:`default_signature_db_path`), the key does
    NOT sit beside the database — a database in the trusted data
    root must not have its authentication secret in the same
    user-readable place. It lives in the quarantine vault
    directory (:func:`argus.paths.default_vault_dir`), which the
    installer ACLs so standard users cannot read it at all.
    Every other (custom / portable / dev) database keeps its key
    beside the database file, as before. Portable mode
    (``ARGUS_DATA_DIR`` set) still resolves through
    :func:`argus.paths.data_dir` on both sides of the comparison,
    so the installed-layout rule follows the override
    automatically.

    The default-database comparison is CANONICAL (v1.1.0 fix
    round 2, auditor item g): both sides are fully resolved
    before comparing, so a non-canonical spelling of the default
    path in a custom config cannot smuggle the key back beside
    the database in the user-readable root.
    """
    path = Path(db_path)
    if _is_default_db_path(path):
        return default_vault_dir() / (path.name + ".key")
    return path.with_name(path.name + ".key")


def _load_or_create_key(db_path: Path) -> bytes:
    """Return the database's HMAC key, creating it (0600) if absent.

    Mirrors the vault key helper: binary mode via ``O_BINARY`` so a
    key containing byte 0x0A is not mangled by Windows text-mode
    translation, and an existing key of the wrong length is refused
    outright — never silently truncated or padded.
    """
    key_path = key_path_for(db_path)
    if key_path.is_file():
        key = key_path.read_bytes()
        if len(key) != _KEY_BYTES:
            raise SignatureError(
                f"signature database key at {key_path} has the wrong length "
                f"({len(key)} bytes, expected {_KEY_BYTES}) — refusing to "
                "use it to authenticate the signature database"
            )
        return key
    if key_path.parent and not key_path.parent.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(_KEY_BYTES)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(key_path, flags, 0o600)
    except FileExistsError:
        # Lost a creation race — the file is there now; read it.
        return _load_or_create_key(db_path)
    try:
        with os.fdopen(fd, "wb") as fh:
            if fh.write(key) != len(key):
                raise SignatureError(
                    f"short write while creating signature database key at "
                    f"{key_path}"
                )
    except BaseException:
        # Never leave a partial key file behind to brick future opens.
        key_path.unlink(missing_ok=True)
        raise
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # some platforms (Windows ACLs) manage this differently
    return key


def _auth_tag(key: bytes, rows) -> str:
    """HMAC-SHA256 over the canonical per-row form (v1.1.0).

    Each row contributes its digest, name, severity and family —
    NOT just its digest (the pre-v1.1.0 form), so editing a row's
    name, severity or family without touching its digest fails
    verification exactly like editing the digest does. Rows are
    sorted by (lower-cased) digest so insertion order never
    matters, and every field is fed as ``<byte-length>:<utf-8
    bytes>`` followed by a NUL separator, with a newline ending
    each row — length prefixes make field boundaries unambiguous,
    so no two different row sets can collide by sliding text
    across a separator.

    *rows* is an iterable of ``(sha256, name, family, severity)``
    tuples as stored (note the table's column order); a bare
    digest string is also accepted and treated as a row with
    empty name/severity/family, for internal convenience.
    """
    normalised: list[tuple[str, str, str, str]] = []
    for row in rows:
        if isinstance(row, str):
            normalised.append((row.lower(), "", "", ""))
        else:
            digest, name, family, severity = row
            normalised.append(
                (str(digest).lower(), str(name), str(family), str(severity))
            )
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for digest, name, family, severity in sorted(
        normalised, key=lambda r: r[0]
    ):
        # Canonical field order: digest + name + severity + family.
        for field in (digest, name, severity, family):
            encoded = field.encode("utf-8")
            mac.update(str(len(encoded)).encode("ascii"))
            mac.update(b":")
            mac.update(encoded)
            mac.update(b"\x00")
        mac.update(b"\n")
    return mac.hexdigest()


def _auth_rows(conn: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    """All signature rows in the table's column order."""
    return [
        (row[0], row[1], row[2], row[3])
        for row in conn.execute(
            "SELECT sha256, name, family, severity FROM hashes"
        )
    ]


def _mint_auth_tag(conn: sqlite3.Connection, key: bytes) -> str:
    """Compute the auth tag from the hashes table and store it.

    This is called ONLY from :func:`init_db`, inside the creation
    transaction, for a database that init just built. There is
    deliberately no "refresh" path for existing databases
    (v1.1.0 P1-1/2/3): re-signing an existing file would let any
    tampered database launder itself back to "verified" on the
    next bootstrap, which is the hole this replaces.
    """
    tag = _auth_tag(key, _auth_rows(conn))
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        (_AUTH_META_KEY, tag),
    )
    return tag


def _auth_status(
    db_path: Path,
    meta: dict,
    rows: list[tuple[str, str, str, str]],
    *,
    require_auth: bool,
) -> tuple[bool, bool]:
    """Check the HMAC auth tag read-only. Returns ``(verified, missing)``.

    - A PRESENT tag that does not verify is always fatal
      (:class:`SignatureError`) — tamper-evidence doing its job.
    - A missing tag or a missing/unreadable key is ``missing``
      when ``require_auth`` is False (reported, not bricked), and
      is :class:`SignatureError` when ``require_auth`` is True —
      enforcement, per the pinned v1.1.0 interface.
    - A key of the wrong length is always fatal.
    """
    tag = meta.get(_AUTH_META_KEY)
    key_file = key_path_for(db_path)
    if tag is None:
        if require_auth:
            raise SignatureError(
                f"signature database at {db_path} has no authentication "
                "tag — an existing database that this build did not just "
                "create cannot be authenticated. Rebuild it with "
                "'argus sigdb init' from a trusted copy."
            )
        return False, True
    if not key_file.is_file():
        if require_auth:
            raise SignatureError(
                f"signature database at {db_path} cannot be authenticated: "
                f"its auth key is missing (expected at {key_file}). "
                "Rebuild it with 'argus sigdb init' from a trusted copy."
            )
        return False, True
    try:
        key = key_file.read_bytes()
    except OSError as exc:
        if require_auth:
            raise SignatureError(
                f"signature database at {db_path} cannot be authenticated: "
                f"its auth key at {key_file} could not be read: {exc}"
            ) from exc
        return False, True
    if len(key) != _KEY_BYTES:
        raise SignatureError(
            f"signature database key at {key_file} has the wrong length "
            f"({len(key)} bytes, expected {_KEY_BYTES}) — cannot "
            "authenticate the signature database"
        )
    expected = _auth_tag(key, rows)
    if not hmac.compare_digest(expected, tag):
        raise SignatureError(
            f"signature database at {db_path} failed authentication: "
            "its contents do not match the HMAC tag recorded when it "
            "was built — it may have been tampered with. Rebuild it "
            "with 'argus sigdb init' from a trusted copy."
        )
    return True, False


def _verify_existing_auth(db_path: Path) -> bool:
    """Verify an existing database's auth tag READ-ONLY.

    Used by :func:`ensure_signature_db` for a structurally-ok
    existing file. Never writes, never creates a key, never
    re-signs.

    Returns True when the auth check was DEFERRED (fix round 2,
    FIX 3): the database is the DEFAULT database — whose key by
    design lives in the ACL'd vault subtree — and the key is not
    readable by THIS process (a standard user's GUI/CLI on an
    installed machine). Bootstrap then vouches for the database's
    structure only; the HMAC verdict belongs to the protection
    service, the key holder, which opens with
    ``require_auth=True`` and reports tampering loudly in its
    status. Deferral is deliberately narrow:

    - a key that IS readable is always used: a wrong tag, a
      missing tag, or a wrong-length key raises exactly as
      before, default database or not;
    - a CUSTOM database never defers — portable/dev layouts keep
      their key beside the database, readable by their owner, so
      an unreadable/missing key there is the tamper signal it
      has always been.

    Everything else raises :class:`SignatureError`.
    """
    try:
        conn = sqlite3.connect(
            f"{db_path.absolute().as_uri()}?mode=ro", uri=True
        )
    except sqlite3.Error as exc:
        raise SignatureError(
            f"could not open signature database at {db_path}: {exc}"
        ) from exc
    try:
        meta = dict(conn.execute("SELECT key, value FROM meta"))
        rows = _auth_rows(conn)
    except sqlite3.Error as exc:
        raise SignatureError(
            f"signature database at {db_path} failed verification: {exc}"
        ) from exc
    finally:
        conn.close()
    key_file = key_path_for(db_path)
    key: bytes | None = None
    try:
        key = key_file.read_bytes()
    except OSError:
        key = None  # missing OR unreadable to this process
    if key is not None:
        if len(key) != _KEY_BYTES:
            raise SignatureError(
                f"signature database key at {key_file} has the wrong "
                f"length ({len(key)} bytes, expected {_KEY_BYTES}) — "
                "cannot authenticate the signature database"
            )
        # The key is in hand: verify strictly, whatever this raises.
        _auth_status(db_path, meta, rows, require_auth=True)
        return False
    if _is_default_db_path(db_path):
        log.info(
            "signature database auth deferred at %s: the auth key "
            "at %s is not readable by this process (installed "
            "layout) — structure verified; the protection service "
            "performs the strict authentication check.",
            db_path, key_file,
        )
        return True
    # Custom database with an unavailable key: strict, as always.
    _auth_status(db_path, meta, rows, require_auth=True)
    return False


def _structural_info(db_path: Path, *, auth_deferred: bool) -> SignatureInfo:
    """Build a :class:`SignatureInfo` from structure alone (meta
    table read-only, no auth verdict). Used for the deferred
    bootstrap outcome (FIX 3): version/count are facts about the
    file; ``auth_verified`` is False and ``auth_missing`` True
    because THIS process performed no authentication."""
    try:
        conn = sqlite3.connect(
            f"{db_path.absolute().as_uri()}?mode=ro", uri=True
        )
        try:
            meta = dict(conn.execute("SELECT key, value FROM meta"))
            count = int(
                conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            )
        finally:
            conn.close()
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise SignatureError(
            f"signature database at {db_path} failed structural "
            f"verification: {exc}"
        ) from exc
    return SignatureInfo(
        version=str(meta.get("version", "unknown")),
        built_at=str(meta.get("built_at", "")),
        count=count,
        schema_version=int(meta.get("schema_version", 0) or 0),
        auth_verified=False,
        auth_missing=True,
        auth_deferred=auth_deferred,
    )


# ----------------------------------------------------------------------
# Building / bootstrap
# ----------------------------------------------------------------------

def _probe_existing(path: Path) -> str:
    """Classify an existing would-be signature database file.

    Returns ``"ok"`` (usable SQLite with the expected tables),
    ``"empty"`` (zero bytes — a placeholder, safe to initialize),
    ``"no_tables"`` (a real SQLite file that was never initialized),
    or ``"invalid"`` (not a SQLite file at all, or unreadable —
    genuine corruption/tampering territory: never silently
    overwritten, opening it must say so loudly).
    """
    try:
        if path.stat().st_size == 0:
            return "empty"
    except OSError:
        return "invalid"
    try:
        conn = sqlite3.connect(
            f"{path.absolute().as_uri()}?mode=ro", uri=True
        )
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        finally:
            conn.close()
    except sqlite3.Error:
        return "invalid"
    if {"hashes", "meta"} <= tables:
        return "ok"
    return "no_tables"


def init_db(path: Path | str, *, seed: bool = True) -> SignatureInfo:
    """Create a new signature database at *path*.

    "Create a new database" is literal: the file is rebuilt from
    scratch (in a temp file in the same directory, ``os.replace``d
    over the target) so re-initializing can never leave a stale mix
    behind, and a crash mid-build never leaves a half-written
    database at the real path. Creates parent directories as
    needed. With ``seed=True`` (the default) the EICAR test
    signature is inserted so detection can be verified immediately,
    and the auth tag (see module docstring) is written. SQLite
    failures surface as :class:`SignatureError` — never a raw
    ``sqlite3.Error`` leaking to callers, never silent.
    """
    db_path = Path(path)
    try:
        if db_path.parent and not db_path.parent.exists():
            db_path.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_name = tempfile.mkstemp(
            dir=str(db_path.parent) if str(db_path.parent) else ".",
            prefix=db_path.name + ".",
            suffix=".tmp",
        )
    except OSError as exc:
        # Auditor item f: a data root this process may not write
        # (e.g. the trusted root before the service has ever run)
        # must surface as this module's one error type with a
        # plain message — never a raw PermissionError traceback
        # escaping to the GUI/CLI.
        raise SignatureError(
            f"could not create a temporary file beside the signature "
            f"database at {db_path}: this account cannot write to "
            f"that folder. If Argus is installed, the protection "
            f"service creates the database; otherwise pick a "
            f"location this account can write to."
        ) from exc
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        try:
            conn = sqlite3.connect(tmp_path)
            try:
                conn.executescript(_SCHEMA)
                conn.execute("DELETE FROM hashes")
                if seed:
                    conn.execute(
                        "INSERT OR REPLACE INTO hashes (sha256, name, family, severity)"
                        " VALUES (?, ?, ?, ?)",
                        (EICAR_SHA256, EICAR_NAME, EICAR_FAMILY, "high"),
                    )
                count = int(
                    conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
                )
                built_at = _utcnow_iso()
                meta = {
                    "schema_version": str(SCHEMA_VERSION),
                    "version": DB_VERSION,
                    "built_at": built_at,
                    "count": str(count),
                }
                conn.executemany(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    meta.items(),
                )
                key = _load_or_create_key(db_path)
                # The ONLY place an auth tag is ever minted: here,
                # inside the creation transaction of a fresh build.
                _mint_auth_tag(conn, key)
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise SignatureError(
                f"could not build signature database at {db_path}: {exc}"
            ) from exc
        try:
            os.replace(tmp_path, db_path)
        except OSError as exc:
            # Windows refuses to replace a file that is still open
            # anywhere (a live SignatureDB handle in this or another
            # process) — WinError 5. Name the likely cause and keep
            # the failure in this module's one error type instead of
            # leaking a raw OSError to callers.
            raise SignatureError(
                f"could not publish signature database at {db_path}: "
                f"{exc} — the existing database may still be open in "
                "another Argus process or window; close it and retry"
            ) from exc
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    return SignatureInfo(
        version=DB_VERSION,
        built_at=built_at,
        count=count,
        schema_version=SCHEMA_VERSION,
        auth_verified=True,
    )


def ensure_signature_db(path: Path | str) -> SignatureInfo | None:
    """Make sure a usable signature database exists at *path*.

    * A missing file is created and seeded.
    * A zero-byte placeholder or a never-initialized SQLite file is
      (re)initialized — it is a database someone started, not data.
    * A valid existing database is left exactly as-is and its auth
      tag is verified READ-ONLY (v1.1.0): a present-but-wrong tag
      raises :class:`SignatureError`; a missing tag raises too —
      whether or not a key file exists (with a key it looks like
      tampering; without one, an existing database this init did
      not create simply cannot be authenticated). Bootstrap NEVER
      re-signs an existing database.
    * A file that exists but is not a database at all is NEVER
      touched — :meth:`SignatureDB.open` reports it loudly instead
      of the damage being quietly papered over.
    * ONE exception to the strict verification above (fix round
      2, FIX 3): the DEFAULT database whose key is not readable
      BY THIS PROCESS — a standard user's GUI/CLI on an installed
      machine, where the key lives in the ACL'd vault subtree by
      design. Bootstrap then verifies structure only and returns
      a :class:`SignatureInfo` with ``auth_deferred`` set: the
      protection service (the key holder) is the strict verifier
      and reports the verdict in its status.

    Returns :class:`SignatureInfo` when a database was (re)built
    OR when an existing database's auth check was deferred,
    ``None`` when a valid verified one was already there.
    """
    db_path = Path(path)
    if not db_path.is_file():
        return init_db(db_path, seed=True)
    state = _probe_existing(db_path)
    if state in ("empty", "no_tables"):
        return init_db(db_path, seed=True)
    if state == "ok":
        if _verify_existing_auth(db_path):
            return _structural_info(db_path, auth_deferred=True)
    return None


def default_signature_db_path() -> Path:
    """The one location startup bootstrap may auto-create at: the
    default signature database in the data root."""
    return data_dir() / DEFAULT_DB_NAME


def bootstrap_signature_db(path: Path | str) -> SignatureInfo | None:
    """The startup bootstrap used by the service, the GUI, and CLI
    scans.

    Auto-creation is a convenience for exactly one location — the
    DEFAULT database path — because that is the fresh-install case
    (the P0 this bootstrap exists for). A *configured* database
    somewhere else that is missing means the configuration points
    at a database that was never built (or was removed): Argus
    refuses to silently invent an empty one and says so, the same
    honesty as an explicit ``--db`` that does not exist.
    """
    db_path = Path(path)
    if db_path.is_file():
        return ensure_signature_db(db_path)
    if _canon_path(db_path) == _canon_path(default_signature_db_path()):
        return init_db(db_path, seed=True)
    raise SignatureError(
        f"signature database not found at {db_path} — build it with "
        "'argus sigdb init', or fix the configured signature_db path"
    )


class SignatureDB:
    """An opened, integrity-verified signature database.

    Use :meth:`open` rather than constructing directly — it runs the
    full integrity check before a single lookup is allowed.
    """

    def __init__(self, conn: sqlite3.Connection, info: SignatureInfo) -> None:
        self._conn = conn
        self.info = info
        # Real-time protection looks signatures up from its worker
        # thread while the connection was opened on the caller's
        # thread — serialize lookups so the connection stays sound.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Loading + integrity
    # ------------------------------------------------------------------
    @classmethod
    def open(
        cls, path: Path | str, *, require_auth: bool = False
    ) -> "SignatureDB":
        """Open and verify the signature database at *path*.

        Raises :class:`SignatureError` if the file is missing, is not a
        valid SQLite database, has the wrong schema version, fails
        SQLite's own integrity check, its recorded signature count
        does not match the actual row count — or its HMAC auth tag
        (when a tag and its key are both present) does not match its
        contents. ``require_auth=True`` ENFORCES authentication
        (pinned v1.1.0 interface): a missing tag or a missing key
        raises :class:`SignatureError` too. With the default
        ``require_auth=False``, a missing tag/key is only *reported*
        — the database still opens with ``info.auth_missing`` set,
        so the caller can warn loudly instead of bricking protection.
        """
        db_path = Path(path)
        if not db_path.is_file():
            raise SignatureError(f"signature database not found: {db_path}")

        try:
            # as_uri() percent-encodes the path properly — a plain
            # f-string breaks on folders containing '#', '?' or '%'.
            conn = sqlite3.connect(
                f"{db_path.absolute().as_uri()}?mode=ro",
                uri=True, check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise SignatureError(f"could not open signature database: {exc}") from exc

        try:
            info = cls._verify(conn, db_path, require_auth=require_auth)
        except Exception:
            conn.close()
            raise
        return cls(conn, info)

    @staticmethod
    def _verify(
        conn: sqlite3.Connection,
        db_path: Path,
        *,
        require_auth: bool = False,
    ) -> SignatureInfo:
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if not {"hashes", "meta"} <= tables:
                raise SignatureError(
                    "signature database is missing required tables "
                    "(hashes, meta) — file is corrupt or not an Argus database"
                )

            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise SignatureError(
                    f"SQLite integrity check failed: {integrity[0] if integrity else 'no result'}"
                )

            meta = dict(conn.execute("SELECT key, value FROM meta"))
            for key in ("schema_version", "version", "built_at", "count"):
                if key not in meta:
                    raise SignatureError(f"signature database meta is missing '{key}'")

            schema_version = int(meta["schema_version"])
            if schema_version != SCHEMA_VERSION:
                raise SignatureError(
                    f"signature database schema version {schema_version} is not "
                    f"supported by this build (expected {SCHEMA_VERSION})"
                )

            recorded_count = int(meta["count"])
            actual_count = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            if recorded_count != actual_count:
                raise SignatureError(
                    f"signature count mismatch: meta records {recorded_count} "
                    f"but the database holds {actual_count} — file may be "
                    "truncated or tampered with"
                )
            auth_verified, auth_missing = SignatureDB._verify_auth(
                conn, db_path, meta, require_auth=require_auth
            )
        except SignatureError:
            raise
        except (sqlite3.Error, ValueError) as exc:
            raise SignatureError(f"signature database failed verification: {exc}") from exc

        return SignatureInfo(
            version=meta["version"],
            built_at=meta["built_at"],
            count=actual_count,
            schema_version=schema_version,
            auth_verified=auth_verified,
            auth_missing=auth_missing,
        )

    @staticmethod
    def _verify_auth(
        conn: sqlite3.Connection,
        db_path: Path,
        meta: dict,
        *,
        require_auth: bool = False,
    ) -> tuple[bool, bool]:
        """Check the HMAC auth tag. Returns ``(verified, missing)``.

        Delegates to :func:`_auth_status`: a PRESENT tag that does
        not verify is always fatal; a missing tag/key is reported
        as ``missing`` unless ``require_auth`` enforces it as
        :class:`SignatureError`.
        """
        return _auth_status(
            db_path, meta, _auth_rows(conn), require_auth=require_auth
        )

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------
    def lookup(self, sha256: str) -> SignatureHit | None:
        """Return the signature matching *sha256*, or None if clean."""
        with self._lock:
            row = self._conn.execute(
                "SELECT sha256, name, family, severity FROM hashes WHERE sha256 = ?",
                (sha256.lower(),),
            ).fetchone()
        if row is None:
            return None
        return SignatureHit(sha256=row[0], name=row[1], family=row[2], severity=row[3])

    def __contains__(self, sha256: str) -> bool:
        return self.lookup(sha256) is not None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SignatureDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
