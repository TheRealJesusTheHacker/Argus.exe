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
``init_db`` / ``ensure_signature_db`` compute an HMAC-SHA256 tag
over the canonical sorted list of hash digests, keyed by a random
secret stored in ``<db name>.key`` next to the database (created
owner-only, ``0600``). :meth:`SignatureDB.open` verifies the tag
whenever both the tag and the key are available — a present tag
that does not match is a loud refusal, never a silent "clean".
Callers that pass ``require_auth=True`` (the service) also get a
missing tag/key reported on :class:`SignatureInfo` so they can warn
loudly without bricking protection.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .paths import data_dir

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


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ----------------------------------------------------------------------
# Authenticity: HMAC key + tag
# ----------------------------------------------------------------------

def key_path_for(db_path: Path | str) -> Path:
    """The auth-key file that belongs to *db_path*
    (``signatures.sigdb`` → ``signatures.sigdb.key``)."""
    path = Path(db_path)
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


def _auth_tag(key: bytes, digests) -> str:
    """HMAC-SHA256 over the canonical sorted hash list.

    Canonical form: digests lower-cased, sorted ascending, each
    followed by a newline. Two databases holding the same set of
    hashes produce the same tag regardless of insertion order.
    """
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for digest in sorted(d.lower() for d in digests):
        mac.update(digest.encode("ascii"))
        mac.update(b"\n")
    return mac.hexdigest()


def _refresh_auth_tag(conn: sqlite3.Connection, db_path: Path, key: bytes) -> str:
    """Recompute the auth tag from the hashes table and store it."""
    digests = [row[0] for row in conn.execute("SELECT sha256 FROM hashes")]
    tag = _auth_tag(key, digests)
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        (_AUTH_META_KEY, tag),
    )
    return tag


def _try_refresh_auth(db_path: Path) -> None:
    """Best-effort: bring an existing valid database's auth tag up
    to date (creating the key file if needed).

    Failures are swallowed by design: a standard-user process may
    not have write access to the trusted data root, and refreshing
    must never brick a working open. The service surfaces a missing
    tag loudly through its status instead.
    """
    try:
        key = _load_or_create_key(db_path)
        conn = sqlite3.connect(db_path)
        try:
            current = _auth_tag(
                key, [row[0] for row in conn.execute("SELECT sha256 FROM hashes")]
            )
            row = conn.execute(
                "SELECT value FROM meta WHERE key = ?", (_AUTH_META_KEY,)
            ).fetchone()
            if row is None or row[0] != current:
                _refresh_auth_tag(conn, db_path, key)
                conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error, SignatureError, OSError):
        pass


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
    if db_path.parent and not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        dir=str(db_path.parent) if str(db_path.parent) else ".",
        prefix=db_path.name + ".",
        suffix=".tmp",
    )
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
                _refresh_auth_tag(conn, db_path, key)
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
    * A valid existing database is left as-is; its auth tag is
      refreshed (best-effort) when it drifted or is missing.
    * A file that exists but is not a database at all is NEVER
      touched — :meth:`SignatureDB.open` reports it loudly instead
      of the damage being quietly papered over.

    Returns :class:`SignatureInfo` when a database was (re)built,
    ``None`` when a valid one was already there.
    """
    db_path = Path(path)
    if not db_path.is_file():
        return init_db(db_path, seed=True)
    state = _probe_existing(db_path)
    if state in ("empty", "no_tables"):
        return init_db(db_path, seed=True)
    if state == "ok":
        _try_refresh_auth(db_path)
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
    if os.path.normcase(str(db_path.absolute())) == os.path.normcase(
        str(default_signature_db_path().absolute())
    ):
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
        contents. ``require_auth=True`` additionally guarantees the
        outcome is *reported*: a database without a verifiable tag
        still opens, but with ``info.auth_missing`` set, so the
        caller can warn loudly instead of bricking protection.
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
            info = cls._verify(conn, db_path)
        except Exception:
            conn.close()
            raise
        return cls(conn, info)

    @staticmethod
    def _verify(conn: sqlite3.Connection, db_path: Path) -> SignatureInfo:
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
                conn, db_path, meta
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
        conn: sqlite3.Connection, db_path: Path, meta: dict
    ) -> tuple[bool, bool]:
        """Check the HMAC auth tag. Returns ``(verified, missing)``.

        A PRESENT tag that does not verify is always fatal — that
        is the tamper-evidence doing its job. A tag or key that is
        simply absent is reported as ``missing`` (the service warns
        loudly and keeps protecting) rather than bricking startup.
        """
        tag = meta.get(_AUTH_META_KEY)
        key_file = key_path_for(db_path)
        if tag is None or not key_file.is_file():
            return False, True
        try:
            key = key_file.read_bytes()
        except OSError:
            return False, True
        if len(key) != _KEY_BYTES:
            raise SignatureError(
                f"signature database key at {key_file} has the wrong length "
                f"({len(key)} bytes, expected {_KEY_BYTES}) — cannot "
                "authenticate the signature database"
            )
        digests = [row[0] for row in conn.execute("SELECT sha256 FROM hashes")]
        expected = _auth_tag(key, digests)
        if not hmac.compare_digest(expected, tag):
            raise SignatureError(
                f"signature database at {db_path} failed authentication: "
                "its contents do not match the HMAC tag recorded when it "
                "was built — it may have been tampered with. Rebuild it "
                "with 'argus sigdb init' from a trusted copy."
            )
        return True, False

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
