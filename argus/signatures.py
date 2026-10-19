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

The database file itself is NEVER committed to git (see .gitignore).
It is built locally with ``python -m argus sigdb init``; the only
signature that ships in source code is the industry-standard EICAR
test file, used so detection can be verified end-to-end safely.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

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


class SignatureError(Exception):
    """Raised when a signature database is missing, corrupt, or fails
    its integrity check. Callers should treat this as fatal for a scan:
    scanning with an unverified database would be dishonest."""


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


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db(path: Path | str, *, seed: bool = True) -> SignatureInfo:
    """Create a new signature database at *path*.

    "Create a new database" is literal: any signatures already in the
    file are cleared first, so re-initializing can never leave a
    stale mix behind. Creates parent directories as needed. With
    ``seed=True`` (the default) the EICAR test signature is inserted
    so detection can be verified immediately. The recorded count is
    read back from the table itself, so the integrity check in
    :meth:`SignatureDB.open` always agrees with what was written.
    Returns the database's info summary.
    """
    db_path = Path(path)
    if db_path.parent and not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        conn.execute("DELETE FROM hashes")
        if seed:
            conn.execute(
                "INSERT OR REPLACE INTO hashes (sha256, name, family, severity)"
                " VALUES (?, ?, ?, ?)",
                (EICAR_SHA256, EICAR_NAME, EICAR_FAMILY, "high"),
            )
        count = int(conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0])
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
        conn.commit()
    finally:
        conn.close()

    return SignatureInfo(
        version=DB_VERSION,
        built_at=built_at,
        count=count,
        schema_version=SCHEMA_VERSION,
    )


def ensure_signature_db(path: Path | str) -> SignatureInfo | None:
    """Create + seed the signature database at *path* if it is
    missing; do nothing (and return None) when one is already there.

    This is the first-run bootstrap: a fresh install has no database
    yet, and protection must come up working rather than failing on a
    file nobody was ever told to build. An *existing* file is never
    touched here — if it is corrupt, :meth:`SignatureDB.open` says so
    loudly instead of the damage being quietly papered over.
    """
    db_path = Path(path)
    if db_path.is_file():
        return None
    return init_db(db_path, seed=True)


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
    def open(cls, path: Path | str) -> "SignatureDB":
        """Open and verify the signature database at *path*.

        Raises :class:`SignatureError` if the file is missing, is not a
        valid SQLite database, has the wrong schema version, fails
        SQLite's own integrity check, or its recorded signature count
        does not match the actual row count.
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
            info = cls._verify(conn)
        except Exception:
            conn.close()
            raise
        return cls(conn, info)

    @staticmethod
    def _verify(conn: sqlite3.Connection) -> SignatureInfo:
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
        except SignatureError:
            raise
        except (sqlite3.Error, ValueError) as exc:
            raise SignatureError(f"signature database failed verification: {exc}") from exc

        return SignatureInfo(
            version=meta["version"],
            built_at=meta["built_at"],
            count=actual_count,
            schema_version=schema_version,
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
