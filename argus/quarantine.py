"""The ARGUS.EXE quarantine vault.

When Argus finds a malicious file and the user says "quarantine it"
(or their real-time policy says so for Critical findings), the file
comes here. Quarantine is a *reversible holding cell*, not a shredder:

- the file is encrypted as it is copied in, so what sits in the vault
  is inert — it cannot run, and its original name and extension are
  gone (vault files are opaque ``<entry-id>.blob`` names);
- an index remembers everything about it: where it lived, its
  SHA-256 fingerprint, when it was taken, what detection caught it,
  how severe it was, and the plain-language reasons;
- the user can **restore** it (decrypted back to where it lived),
  **allow** it (restored + vouched for), or **delete** it for good.

**Fail-safe ordering is the whole point.** Quarantining streams the
file into an encrypted blob, verifies the blob end-to-end (decrypt it
back and compare fingerprints), and only *then* removes the original.
If anything fails along the way, the original file stays exactly
where it was and no vault entry is created. Restoring verifies the
blob's tamper tag before a single byte is put back, and never
overwrites a file that has since appeared at the original location.

**Honest note on the encryption.** The vault cipher is a pure-stdlib
construction (HMAC-SHA256 keystream, encrypt-then-MAC) keyed by a
machine-local secret file. Its job is to *neutralize* threats and
make tampering evident — it is obfuscation-grade protection for
malware at rest, not a vault for your secrets, and it does not try
to defeat an attacker who already owns the machine (they could read
the key file). Never keep the only copy of anything in quarantine:
if the key file is lost, vault contents cannot be restored.

This module also stores the **pending actions** queue: actions that
policy says Argus may take but a human has not approved yet
(approve/reject lives in :mod:`argus.actions`). Since v1.0.4 the
queue lives in its OWN database (``pending.db``) — by default in the
shared data subdirectory, not inside vault.db: pending rows are
written and decided by user-side processes, while the vault itself
sits in the trusted root that standard users cannot write (see
:mod:`argus.paths`). vault.db keeps entries only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import stat as statmod
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

log = logging.getLogger("argus.quarantine")

CHUNK_SIZE = 1024 * 1024  # 1 MiB — streamed, flat memory, like the scanner
MAGIC = b"ARGUSQ1\x00"  # 8 bytes, format marker at the head of every blob
NONCE_SIZE = 16
TAG_SIZE = 32  # HMAC-SHA256
KEY_SIZE = 32
KEY_FILENAME = "vault.key"
DB_FILENAME = "vault.db"
PENDING_DB_FILENAME = "pending.db"
BLOBS_DIRNAME = "blobs"

#: How long a ``*.tmp`` file in the blob store must sit untouched
#: before the open-time sweep may remove it. A temp younger than this
#: might belong to a quarantine/restore running in ANOTHER Argus
#: process right now (the service and the GUI share the vault), so
#: only genuinely stale leftovers are swept.
STALE_TEMP_AGE_SECONDS = 3600.0

#: Statuses a vault entry can be in. ``quarantined`` is the only live
#: state; the rest are terminal outcomes the audit trail keeps.
ENTRY_STATUSES = ("quarantined", "restored", "deleted", "allowed")

#: Statuses a pending action can be in.
PENDING_STATUSES = ("pending", "approved", "rejected", "done", "failed")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id             TEXT PRIMARY KEY,
    original_path  TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    size           INTEGER NOT NULL,
    quarantined_at TEXT NOT NULL,
    detection_name TEXT NOT NULL,
    severity       TEXT,
    verdict        TEXT,
    reasons        TEXT NOT NULL DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'quarantined',
    blob_name      TEXT,
    resolved_at    TEXT,
    restored_path  TEXT,
    note           TEXT,
    mode           INTEGER,
    row_mac        TEXT,
    claimed_at     TEXT
);
"""

_PENDING_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_actions (
    id             TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    decided_at     TEXT,
    source         TEXT NOT NULL,
    path           TEXT NOT NULL,
    sha256         TEXT,
    action         TEXT NOT NULL,
    severity       TEXT,
    verdict        TEXT,
    detection_name TEXT,
    reasons        TEXT NOT NULL DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'pending',
    entry_id       TEXT,
    error          TEXT
);
"""


class QuarantineError(Exception):
    """Raised when a vault operation cannot be completed safely.

    Callers can rely on this contract: when QuarantineError is raised,
    nothing irreversible has happened — the original file (for
    quarantine/restore) is still where it was.
    """


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex


# ----------------------------------------------------------------------
# Vault cipher (pure stdlib — see the honesty note in the docstring)
# ----------------------------------------------------------------------
class _Keystream:
    """HMAC-SHA256 counter-mode keystream with an XOR interface."""

    def __init__(self, enc_key: bytes, nonce: bytes) -> None:
        self._enc_key = enc_key
        self._nonce = nonce
        self._counter = 0
        self._buffer = b""

    def _refill(self) -> None:
        self._buffer = hmac.new(
            self._enc_key,
            self._nonce + struct.pack(">Q", self._counter),
            hashlib.sha256,
        ).digest()
        self._counter += 1

    def xor(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        pos = 0
        while pos < len(data):
            if not self._buffer:
                self._refill()
            take = min(len(self._buffer), len(data) - pos)
            piece = data[pos : pos + take]
            stream = self._buffer[:take]
            self._buffer = self._buffer[take:]
            mixed = int.from_bytes(piece, "little") ^ int.from_bytes(stream, "little")
            out[pos : pos + take] = mixed.to_bytes(take, "little")
            pos += take
        return bytes(out)


def _derive_keys(master_key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    enc_key = hmac.new(
        master_key, b"argus-vault-enc\x00" + nonce, hashlib.sha256
    ).digest()
    mac_key = hmac.new(
        master_key, b"argus-vault-mac\x00" + nonce, hashlib.sha256
    ).digest()
    return enc_key, mac_key


def _load_or_create_key(vault_dir: Path) -> bytes:
    """Read the vault key, creating it (0600 where supported) if absent."""
    key_path = vault_dir / KEY_FILENAME
    if key_path.is_file():
        # A key being created by ANOTHER Argus process right now
        # exists before its bytes land (the creator's O_EXCL open
        # precedes its write): a reader arriving in that window
        # sees a short file and must not mistake a birth for
        # damage. Wait briefly for the write to land; a key that
        # is STILL the wrong size after the wait is genuinely
        # damaged and errors exactly as before (hunt #2).
        deadline = time.monotonic() + 2.5
        while True:
            try:
                key = key_path.read_bytes()
            except FileNotFoundError:
                break  # vanished mid-race — fall through to creation
            if len(key) == KEY_SIZE:
                return key
            if time.monotonic() >= deadline:
                raise QuarantineError(
                    f"vault key file {key_path} is damaged (expected "
                    f"{KEY_SIZE} bytes, found {len(key)}). Vault "
                    "contents cannot be read without the original key."
                )
            time.sleep(0.05)
    key = os.urandom(KEY_SIZE)
    try:
        # O_BINARY matters on Windows: without it the fd is text-mode and
        # any 0x0A byte in the key would be written as CRLF, corrupting
        # the key on disk (32-byte key read back as 33 bytes).
        fd = os.open(
            key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:  # lost a creation race — read the winner's key
        return _load_or_create_key(vault_dir)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(key_path, 0o600)  # best effort (limited on Windows)
    except OSError:
        pass
    return key


def _encrypt_stream(source, dest, master_key: bytes, nonce: bytes) -> str:
    """Encrypt *source* into *dest* (blob format); return plaintext SHA-256.

    Layout: ``MAGIC | nonce | ciphertext | tag`` where the tag is
    HMAC-SHA256 over everything before it (encrypt-then-MAC).
    """
    enc_key, mac_key = _derive_keys(master_key, nonce)
    stream = _Keystream(enc_key, nonce)
    mac = hmac.new(mac_key, digestmod=hashlib.sha256)
    header = MAGIC + nonce
    mac.update(header)
    dest.write(header)
    hasher = hashlib.sha256()
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)
        cipher = stream.xor(chunk)
        mac.update(cipher)
        dest.write(cipher)
    dest.write(mac.digest())
    dest.flush()
    os.fsync(dest.fileno())
    return hasher.hexdigest()


def _decrypt_stream(blob_path: Path, master_key: bytes) -> Iterator[bytes]:
    """Yield plaintext chunks from a blob, verifying its tamper tag.

    The tag sits at the end of the blob, so verification completes
    only when the generator is exhausted: it raises
    :class:`QuarantineError` at the end if the tag does not match.
    Callers must treat any output as untrusted until the generator
    has finished without raising (restore writes to a temp file for
    exactly this reason).
    """
    size = blob_path.stat().st_size
    header_size = len(MAGIC) + NONCE_SIZE
    if size < header_size + TAG_SIZE:
        raise QuarantineError(f"vault blob {blob_path.name} is truncated or corrupt")
    with open(blob_path, "rb") as fh:
        header = fh.read(header_size)
        if header[: len(MAGIC)] != MAGIC:
            raise QuarantineError(
                f"vault blob {blob_path.name} is not an Argus quarantine file"
            )
        nonce = header[len(MAGIC) :]
        enc_key, mac_key = _derive_keys(master_key, nonce)
        stream = _Keystream(enc_key, nonce)
        mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        mac.update(header)
        remaining = size - header_size - TAG_SIZE
        while remaining > 0:
            chunk = fh.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise QuarantineError(f"vault blob {blob_path.name} ended early")
            remaining -= len(chunk)
            mac.update(chunk)
            yield stream.xor(chunk)
        tag = fh.read(TAG_SIZE)
        if len(tag) != TAG_SIZE or not hmac.compare_digest(mac.digest(), tag):
            raise QuarantineError(
                f"vault blob {blob_path.name} failed its tamper check — "
                "it may have been modified or damaged, so Argus will not "
                "restore it."
            )


# ----------------------------------------------------------------------
# Records
# ----------------------------------------------------------------------
@dataclass
class QuarantineEntry:
    """One file in the vault, and everything known about it."""

    id: str
    original_path: str
    sha256: str
    size: int
    quarantined_at: str
    detection_name: str
    severity: str | None
    verdict: str | None
    reasons: list[str] = field(default_factory=list)
    status: str = "quarantined"
    blob_name: str | None = None
    resolved_at: str | None = None
    restored_path: str | None = None
    note: str | None = None
    #: The original file's permission bits (POSIX mode), recorded at
    #: quarantine time so a restore can put them back. None for
    #: entries recorded before v1.0.4 (or where stat was unavailable).
    mode: int | None = None
    #: HMAC over the identity fields (see Vault._entry_mac). Internal
    #: integrity data — never published in to_dict().
    row_mac: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "original_path": self.original_path,
            "sha256": self.sha256,
            "size": self.size,
            "quarantined_at": self.quarantined_at,
            "detection_name": self.detection_name,
            "severity": self.severity,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "status": self.status,
            "blob_name": self.blob_name,
            "resolved_at": self.resolved_at,
            "restored_path": self.restored_path,
            "note": self.note,
            "mode": self.mode,
        }

    @classmethod
    def _from_row(cls, row: sqlite3.Row) -> "QuarantineEntry":
        return cls(
            id=row["id"],
            original_path=row["original_path"],
            sha256=row["sha256"],
            size=row["size"],
            quarantined_at=row["quarantined_at"],
            detection_name=row["detection_name"],
            severity=row["severity"],
            verdict=row["verdict"],
            reasons=json.loads(row["reasons"] or "[]"),
            status=row["status"],
            blob_name=row["blob_name"],
            resolved_at=row["resolved_at"],
            restored_path=row["restored_path"],
            note=row["note"],
            mode=row["mode"] if "mode" in row.keys() else None,
            row_mac=row["row_mac"] if "row_mac" in row.keys() else None,
        )


@dataclass
class PendingAction:
    """An action policy requested but a human has not decided yet."""

    id: str
    created_at: str
    source: str
    path: str
    action: str  # "quarantine" | "delete"
    sha256: str | None = None
    severity: str | None = None
    verdict: str | None = None
    detection_name: str | None = None
    reasons: list[str] = field(default_factory=list)
    status: str = "pending"
    decided_at: str | None = None
    entry_id: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "source": self.source,
            "path": self.path,
            "sha256": self.sha256,
            "action": self.action,
            "severity": self.severity,
            "verdict": self.verdict,
            "detection_name": self.detection_name,
            "reasons": list(self.reasons),
            "status": self.status,
            "entry_id": self.entry_id,
            "error": self.error,
        }

    @classmethod
    def _from_row(cls, row: sqlite3.Row) -> "PendingAction":
        return cls(
            id=row["id"],
            created_at=row["created_at"],
            decided_at=row["decided_at"],
            source=row["source"],
            path=row["path"],
            sha256=row["sha256"],
            action=row["action"],
            severity=row["severity"],
            verdict=row["verdict"],
            detection_name=row["detection_name"],
            reasons=json.loads(row["reasons"] or "[]"),
            status=row["status"],
            entry_id=row["entry_id"],
            error=row["error"],
        )


# ----------------------------------------------------------------------
# Loose pending-DB reads (no vault key needed)
# ----------------------------------------------------------------------
def read_pending_db(path: Path | str) -> list[PendingAction]:
    """Read pending actions straight from a pending database file.

    For callers that cannot open the vault itself (a standard-user
    GUI on an installed machine: the vault sits in the trusted root,
    the pending DB in the shared folder). Missing file/table reads
    as an empty queue — the queue simply has nothing in it yet.
    """
    db_path = Path(path)
    if not db_path.is_file():
        return []
    try:
        conn = sqlite3.connect(
            f"{db_path.absolute().as_uri()}?mode=ro", uri=True
        )
    except sqlite3.Error:
        return []
    conn.row_factory = sqlite3.Row
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "pending_actions" not in tables:
            return []
        rows = conn.execute(
            "SELECT * FROM pending_actions ORDER BY created_at"
        ).fetchall()
        out: list[PendingAction] = []
        for row in rows:
            try:
                out.append(PendingAction._from_row(row))
            except Exception:
                log.warning(
                    "skipping malformed pending row %s in %s",
                    row["id"] if "id" in row.keys() else "?", db_path,
                )
        return out
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def read_pending_view(path: Path | str) -> list[PendingAction]:
    """Read the service-published pending-view snapshot.

    Parses ``{"generated_at": ..., "pending": [PendingAction.to_dict(),
    ...]}``. Missing or corrupt input reads as an empty queue — the
    snapshot is a display copy; the trusted queue itself lives with
    the service.
    """
    view_path = Path(path)
    try:
        raw = json.loads(view_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, dict) or not isinstance(raw.get("pending"), list):
        return []
    known = set(PendingAction.__dataclass_fields__)  # type: ignore[attr-defined]
    out: list[PendingAction] = []
    for item in raw["pending"]:
        if not isinstance(item, dict):
            continue
        try:
            out.append(
                PendingAction(**{k: v for k, v in item.items() if k in known})
            )
        except Exception:
            log.warning("skipping malformed pending-view item in %s", view_path)
    return out


# ----------------------------------------------------------------------
# The vault
# ----------------------------------------------------------------------
class Vault:
    """An opened quarantine vault (directory + key + SQLite index).

    Two databases: ``vault.db`` (entries only — the trusted record
    of what is held) and the pending-actions database, which by
    default lives beside the vault but in production sits in the
    shared data subdirectory (see :meth:`open`).
    """

    def __init__(
        self,
        vault_dir: Path,
        key: bytes,
        conn: sqlite3.Connection,
        pending_conn: sqlite3.Connection,
        pending_path: Path,
    ) -> None:
        self.dir = vault_dir
        self.blobs_dir = vault_dir / BLOBS_DIRNAME
        self._key = key
        self._conn = conn
        self._pending_conn = pending_conn
        self.pending_path = pending_path
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Opening
    # ------------------------------------------------------------------
    @classmethod
    def open(
        cls, vault_dir: Path | str, pending_db_path: Path | str | None = None
    ) -> "Vault":
        """Open (creating if needed) the vault at *vault_dir*.

        *pending_db_path* locates the pending-actions database; when
        omitted it defaults to ``pending.db`` inside the vault
        directory (portable / dev / direct use). Production callers
        pass the shared location (:func:`argus.paths.default_pending_db`)
        so the queue lives outside the trusted vault tree. Pending
        rows recorded by older versions INSIDE vault.db are migrated
        across on first open (copied, then the old table is dropped —
        vault.db keeps entries only).

        Also sweeps stale temp files: ``*.tmp`` leftovers in the blob
        store, and ``.*.argus-restore-*.tmp`` staging files older
        than :data:`STALE_TEMP_AGE_SECONDS` in the original folders
        of recorded entries. Only temps older than that are removed:
        a younger one may belong to an operation in flight in another
        Argus process sharing this vault.
        """
        root = Path(vault_dir)
        blobs = root / BLOBS_DIRNAME
        blobs.mkdir(parents=True, exist_ok=True)
        key = _load_or_create_key(root)
        conn = sqlite3.connect(root / DB_FILENAME, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        pending_path = (
            Path(pending_db_path)
            if pending_db_path is not None
            else root / PENDING_DB_FILENAME
        )
        if pending_path.parent and not pending_path.parent.exists():
            pending_path.parent.mkdir(parents=True, exist_ok=True)
        pending_conn = sqlite3.connect(pending_path, check_same_thread=False)
        pending_conn.row_factory = sqlite3.Row
        try:
            # The service and the GUI share these databases: WAL lets
            # readers and a writer coexist, and busy_timeout makes a
            # contender wait instead of erroring out.
            for candidate in (conn, pending_conn):
                candidate.execute("PRAGMA journal_mode=WAL")
                candidate.execute("PRAGMA busy_timeout=5000")
            conn.executescript(_SCHEMA)
            # Entries recorded before v1.0.4 have no mode column.
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(entries)")
            }
            if "mode" not in columns:
                conn.execute("ALTER TABLE entries ADD COLUMN mode INTEGER")
            if "row_mac" not in columns:
                conn.execute("ALTER TABLE entries ADD COLUMN row_mac TEXT")
            if "claimed_at" not in columns:
                conn.execute("ALTER TABLE entries ADD COLUMN claimed_at TEXT")
            pending_conn.executescript(_PENDING_SCHEMA)
            conn.commit()
            pending_conn.commit()
            Vault._migrate_pending_rows(conn, pending_conn)
        except sqlite3.Error as exc:
            conn.close()
            pending_conn.close()
            log.warning("could not open the vault index: %r", exc)
            raise QuarantineError(
                "could not open the vault index — Argus's records "
                "may be damaged. The technical detail was written "
                "to the Argus log."
            ) from exc
        vault = cls(root, key, conn, pending_conn, pending_path)
        vault._adopt_legacy_entry_macs()
        vault._recover_stale_restore_claims()
        cutoff = time.time() - STALE_TEMP_AGE_SECONDS
        for stale in blobs.glob("*.tmp"):
            try:
                if stale.stat().st_mtime >= cutoff:
                    continue  # possibly in use by another process
                stale.unlink()
            except OSError:
                log.warning("could not remove stale vault temp file %s", stale)
        vault._sweep_stale_restore_staging(cutoff)
        return vault

    @staticmethod
    def _migrate_pending_rows(
        conn: sqlite3.Connection, pending_conn: sqlite3.Connection
    ) -> None:
        """Move any pending_actions rows still living in vault.db
        (pre-v1.0.4 layout) into the pending database, then drop the
        old table so vault.db keeps entries only. Idempotent."""
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "pending_actions" not in tables:
            return
        rows = conn.execute("SELECT * FROM pending_actions").fetchall()
        if rows:
            columns = [row[1] for row in conn.execute(
                "PRAGMA table_info(pending_actions)")]
            placeholders = ", ".join("?" for _ in columns)
            pending_conn.executemany(
                f"INSERT OR IGNORE INTO pending_actions "
                f"({', '.join(columns)}) VALUES ({placeholders})",
                [tuple(row[col] for col in columns) for row in rows],
            )
            pending_conn.commit()
            log.info(
                "migrated %d pending action(s) from vault.db to %s",
                len(rows), "the pending database",
            )
        conn.execute("DROP TABLE pending_actions")
        conn.commit()

    def _recover_stale_restore_claims(self) -> None:
        """Return entries stuck in ``restoring`` to ``quarantined``
        when their restore claim is provably stale (hunt #2).

        A restore claims its entry (status ``restoring`` +
        ``claimed_at``) so exactly one restore proceeds. If the
        claiming process dies mid-restore — crash, power loss —
        nothing ever releases the claim, and the entry used to be
        bricked: neither restorable nor deletable, forever. A
        claim older than :data:`STALE_TEMP_AGE_SECONDS` (the same
        staleness horizon as the temp-file sweep) cannot belong
        to a restore still running — restores are single-file
        decrypt-and-publish operations — so at open it is
        released. A FRESH claim is left untouched: another live
        Argus process may be mid-restore with this very vault.
        Rows with no timestamp predate the claim clock (a crash
        under an older build) and are definitionally stale.
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=STALE_TEMP_AGE_SECONDS
        )
        try:
            stuck = [
                entry
                for entry in self.list_entries()
                if entry.status == "restoring"
            ]
        except Exception:
            return
        for entry in stuck:
            claimed_at = None
            try:
                with self._lock:
                    row = self._conn.execute(
                        "SELECT claimed_at FROM entries WHERE id = ?",
                        (entry.id,),
                    ).fetchone()
                if row is not None:
                    claimed_at = row[0]
            except sqlite3.Error:
                return
            stale = True
            if claimed_at:
                try:
                    stamp = datetime.fromisoformat(str(claimed_at))
                    if stamp.tzinfo is None:
                        stamp = stamp.replace(tzinfo=timezone.utc)
                    stale = stamp <= cutoff
                except ValueError:
                    stale = True
            if not stale:
                continue
            try:
                self._update_entry(
                    entry.id, status="quarantined", claimed_at=None
                )
                log.warning(
                    "vault entry %s was left mid-restore by a "
                    "process that never finished; its claim was "
                    "released and it can be acted on again",
                    entry.id,
                )
            except QuarantineError:
                log.warning(
                    "could not release the stale restore claim on "
                    "vault entry %s",
                    entry.id,
                )

    def _sweep_stale_restore_staging(self, cutoff: float) -> None:
        """Remove abandoned restore staging files
        (``.<name>.argus-restore-*.tmp``) from the original folders
        of recorded entries. Best-effort: a restore stages its file
        in the destination folder, and a crash mid-publish used to
        leave it there forever."""
        try:
            parents = {
                str(Path(entry.original_path).parent)
                for entry in self.list_entries()
            }
        except QuarantineError:
            return
        for parent in parents:
            folder = Path(parent)
            try:
                candidates = list(folder.glob(".*.argus-restore-*.tmp"))
            except OSError:
                continue
            for stale in candidates:
                try:
                    if stale.stat().st_mtime >= cutoff:
                        continue
                    stale.unlink()
                except OSError:
                    pass

    def close(self) -> None:
        with self._lock:
            self._conn.close()
            self._pending_conn.close()

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------
    def quarantine_file(
        self,
        path: Path | str,
        *,
        detection_name: str,
        severity: str | None = None,
        verdict: str | None = None,
        reasons: list[str] | None = None,
        sha256: str | None = None,
    ) -> QuarantineEntry:
        """Move *path* into the vault. Returns the new entry.

        Order of operations is the safety guarantee: stream-encrypt
        to a temp blob → verify the blob decrypts back to the exact
        same fingerprint → publish the blob → record the entry → and
        only then remove the original. Any failure before the last
        step raises :class:`QuarantineError` with the original file
        untouched and nothing recorded.
        """
        source_path = Path(path)
        if not source_path.is_file():
            raise QuarantineError(f"nothing to quarantine at {source_path}")
        entry_id = _new_id()
        blob_name = f"{entry_id}.blob"
        blob_path = self.blobs_dir / blob_name
        tmp_path = self.blobs_dir / f"{entry_id}.encrypt.tmp"
        nonce = os.urandom(NONCE_SIZE)
        try:
            source_stat = source_path.stat()
            size = source_stat.st_size
            mode = statmod.S_IMODE(source_stat.st_mode)
            with open(source_path, "rb") as src, open(tmp_path, "wb") as dst:
                plain_sha = _encrypt_stream(src, dst, self._key, nonce)
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            log.warning("quarantine copy failed for %s: %r", source_path, exc)
            raise QuarantineError(
                f"could not copy {source_path} into the vault. "
                "The original file has not been touched."
            ) from exc
        if sha256 is not None and sha256.lower() != plain_sha:
            tmp_path.unlink(missing_ok=True)
            raise QuarantineError(
                f"{source_path} changed while it was being quarantined "
                "(its fingerprint no longer matches the scan). Argus left "
                "it alone — scan it again."
            )
        try:
            os.replace(tmp_path, blob_path)
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            log.warning("quarantine move failed for %s: %r", source_path, exc)
            raise QuarantineError(
                f"could not move {source_path} into the vault. "
                "The original file has not been touched."
            ) from exc
        try:
            self._verify_blob(blob_path, plain_sha)
        except QuarantineError:
            blob_path.unlink(missing_ok=True)
            raise

        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(source_path),
            sha256=plain_sha,
            size=size,
            quarantined_at=_utcnow_iso(),
            detection_name=detection_name,
            severity=severity,
            verdict=verdict,
            reasons=list(reasons or []),
            status="quarantined",
            blob_name=blob_name,
            mode=mode,
        )
        try:
            self._insert_entry(entry)
        except QuarantineError:
            blob_path.unlink(missing_ok=True)
            raise
        try:
            os.remove(source_path)
        except OSError as exc:
            log.warning(
                "quarantined %s but could not remove the original: %r",
                source_path, exc,
            )
            note = (
                "secured in the vault, but the original could not be "
                "removed (it may be open in another program)"
            )
            self._update_entry(entry.id, note=note)
            entry.note = note
            raise QuarantineError(
                f"{source_path} is safely encrypted in the vault, but "
                "Argus could not remove the original file. It "
                "may be open in another program."
            ) from exc
        log.info("quarantined %s as entry %s", source_path, entry_id)
        return entry

    def _verify_blob(self, blob_path: Path, expected_sha256: str) -> None:
        """Decrypt *blob_path* in memory (streamed) and check both the
        tamper tag and the plaintext fingerprint."""
        hasher = hashlib.sha256()
        try:
            for chunk in _decrypt_stream(blob_path, self._key):
                hasher.update(chunk)
        except OSError as exc:
            log.warning("could not read vault blob %s: %r", blob_path.name, exc)
            raise QuarantineError(
                f"could not verify vault blob {blob_path.name} — "
                "it could not be read."
            ) from exc
        if hasher.hexdigest() != expected_sha256:
            raise QuarantineError(
                f"vault blob {blob_path.name} does not decrypt to the "
                "expected file — refusing to trust it."
            )

    # ------------------------------------------------------------------
    # Entry index integrity (row MAC, P1-4)
    # ------------------------------------------------------------------
    def _entry_mac(
        self, *, entry_id: str, original_path: str,
        blob_name: str | None, sha256: str,
    ) -> str:
        msg = b"\x1f".join(
            part.encode("utf-8")
            for part in (
                "argus-entry-mac-v1", entry_id, original_path,
                blob_name or "", sha256,
            )
        )
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def _mac_for_entry(self, entry: QuarantineEntry) -> str:
        return self._entry_mac(
            entry_id=entry.id, original_path=entry.original_path,
            blob_name=entry.blob_name, sha256=entry.sha256,
        )

    def _verify_entry_mac(self, entry: QuarantineEntry) -> None:
        """Refuse a row whose covered fields do not match its MAC.

        A NULL mac means a legacy row that could not be re-validated
        at open (see :meth:`_adopt_legacy_entry_macs`) — it is refused
        here too, as possible tampering, never trusted on sight.
        """
        expected = entry.row_mac
        if not expected or not hmac.compare_digest(
            expected, self._mac_for_entry(entry)
        ):
            raise QuarantineError(
                f"vault entry {entry.id} failed its integrity check — "
                "its index record may have been tampered with, so "
                "Argus will not restore, delete, or allow it. "
                "The record does not match the vault's tamper seal."
            )

    def verified_entry(self, entry_id: str) -> QuarantineEntry | None:
        """get_entry + MAC verification (None when there is no row)."""
        entry = self.get_entry(entry_id)
        if entry is not None:
            self._verify_entry_mac(entry)
        return entry

    def entry_content_matches(self, entry_id: str, sha256: str) -> bool:
        """Provenance check for migration (fix round 2, FIX 2):
        True only when the entry exists, passes its row-MAC
        integrity check, has a live blob, and that blob DECRYPTS
        (tamper tag verified) to bytes hashing exactly to
        *sha256* — proof anchored in vault records and vault
        cryptography that only the service could have written.
        Any doubt is False; this never raises."""
        try:
            entry = self.verified_entry(entry_id)
        except QuarantineError:
            return False
        if entry is None or not sha256:
            return False
        if entry.sha256.lower() != sha256.lower():
            return False
        if entry.blob_name is None:
            return False
        try:
            blob_path = self._blob_path_for(entry)
            if not blob_path.is_file():
                return False
            self._verify_blob(blob_path, entry.sha256)
        except QuarantineError:
            return False
        return True

    def _adopt_legacy_entry_macs(self) -> None:
        """Verify-and-adopt legacy (NULL-mac) rows ONCE at open.

        A row is adopted only when its blob exists, decrypts, and
        hashes to the row's recorded sha256 — full re-validation,
        not blind trust. Rows failing that keep a NULL mac and are
        refused at execution time with a tamper error.
        """
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM entries WHERE row_mac IS NULL"
                ).fetchall()
        except sqlite3.Error:
            return
        for row in rows:
            try:
                entry = QuarantineEntry._from_row(row)
            except Exception:
                log.warning("legacy vault row could not be parsed; not adopting it")
                continue
            if entry.blob_name is None:
                continue  # terminal row with no blob left to verify
            try:
                blob_path = self._blob_path_for(entry)
                if not blob_path.is_file():
                    continue
                self._verify_blob(blob_path, entry.sha256)
            except QuarantineError:
                log.warning(
                    "legacy vault entry %s could not be re-validated; "
                    "it will be refused as possibly tampered with",
                    entry.id,
                )
                continue
            mac = self._mac_for_entry(entry)
            with self._lock:
                try:
                    self._conn.execute(
                        "UPDATE entries SET row_mac = ? WHERE id = ? AND row_mac IS NULL",
                        (mac, entry.id),
                    )
                    self._conn.commit()
                except sqlite3.Error:
                    log.warning("could not adopt a MAC for vault entry %s", entry.id)

    # ------------------------------------------------------------------
    # Blob-name validation (traversal guard, P1-4)
    # ------------------------------------------------------------------
    def _blob_path_for(self, entry: QuarantineEntry) -> Path:
        """Resolve an entry's blob, refusing any blob_name that is
        not the internal ``<32-hex>.blob`` format or that would
        escape the blob store."""
        import re as _re

        blob_name = entry.blob_name or ""
        if not _re.fullmatch(r"[0-9a-f]{32}\.blob", blob_name):
            raise QuarantineError(
                f"vault entry {entry.id} has an invalid blob name — "
                "its index record may have been tampered with, so "
                "Argus will not act on it."
            )
        resolved = (self.blobs_dir / blob_name).resolve()
        if not resolved.is_relative_to(self.blobs_dir.resolve()):
            raise QuarantineError(
                f"vault entry {entry.id} points outside the vault — "
                "its index record may have been tampered with, so "
                "Argus will not act on it."
            )
        return resolved

    # ------------------------------------------------------------------
    # Restore / delete / allow bookkeeping
    # ------------------------------------------------------------------
    def restore(
        self, entry_id: str, *, final_status: str = "restored"
    ) -> Path:
        """Decrypt an entry back to its original location.

        The blob's tamper tag is verified *while* decrypting into a
        temp file inside the vault; those verified bytes are then
        published only after verification passes, so a damaged blob
        restores nothing. Publishing is careful in two ways:

        - the file is stream-copied (via a staging file in the
          DESTINATION directory), never renamed across volumes — a
          vault and a home folder on different drives restore fine;
        - the destination name is claimed atomically (hard link /
          exclusive create), so a file that appeared at the original
          location in the meantime is **never overwritten** — the
          restored file lands next to it as
          ``name (restored by Argus).ext`` (numbered if needed).

        Returns the path the file was restored to.
        """
        entry = self._require_entry(entry_id, live=True)
        blob_path = self._blob_path_for(entry)
        if not blob_path.is_file():
            raise QuarantineError(
                f"the vault copy of {entry.original_path} is missing — "
                "it cannot be restored."
            )
        # Atomic status claim (P2): exactly one concurrent restore
        # may proceed; the loser gets a clean error, not a second
        # publish of the same bytes.
        self._claim_entry_for_restore(entry.id)
        try:
            return self._restore_claimed(entry, blob_path, final_status=final_status)
        except BaseException:
            # Release the claim so a failed restore can be retried.
            try:
                current = self.get_entry(entry.id)
                if current is not None and current.status == "restoring":
                    self._update_entry(
                        entry.id, status="quarantined", claimed_at=None
                    )
            except QuarantineError:
                pass
            raise

    def _claim_entry_for_restore(self, entry_id: str) -> None:
        with self._lock:
            try:
                cur = self._conn.execute(
                    "UPDATE entries SET status = 'restoring',"
                    " claimed_at = ?"
                    " WHERE id = ? AND status = 'quarantined'",
                    (_utcnow_iso(), entry_id),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                log.warning("restore claim failed for %s: %r", entry_id, exc)
                raise QuarantineError(
                    "could not claim the vault entry for restore"
                ) from exc
            if cur.rowcount != 1:
                raise QuarantineError(
                    "this vault entry is already being restored — "
                    "the other restore will finish it, or fail and "
                    "make it available again."
                )

    def _restore_claimed(
        self, entry: QuarantineEntry, blob_path: Path, *, final_status: str = "restored"
    ) -> Path:
        tmp_path = self.blobs_dir / f"{entry.id}.restore.tmp"
        hasher = hashlib.sha256()
        try:
            with open(tmp_path, "wb") as dst:
                for chunk in _decrypt_stream(blob_path, self._key):
                    hasher.update(chunk)
                    dst.write(chunk)
                dst.flush()
                os.fsync(dst.fileno())
        except QuarantineError:
            tmp_path.unlink(missing_ok=True)
            raise
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            log.warning("restore of %s failed: %r", entry.original_path, exc)
            raise QuarantineError(
                f"could not restore {entry.original_path}"
            ) from exc
        if hasher.hexdigest() != entry.sha256:
            tmp_path.unlink(missing_ok=True)
            raise QuarantineError(
                f"the restored copy of {entry.original_path} does not "
                "match its fingerprint — Argus removed it rather than "
                "hand you a damaged file."
            )
        try:
            destination = self._publish_restored(
                tmp_path, Path(entry.original_path)
            )
        finally:
            tmp_path.unlink(missing_ok=True)
        # Put the original permission bits back (recorded at
        # quarantine time). Best-effort: some filesystems have no
        # POSIX modes to restore.
        if entry.mode is not None:
            try:
                os.chmod(destination, entry.mode)
            except OSError:
                pass
        # Bookkeeping BEFORE destroying the blob: if the index
        # update fails, the entry must still match the vault's
        # contents — an entry saying "quarantined" with no blob
        # behind it would be a zombie nobody can act on. On failure
        # the entry is annotated with what happened and the blob is
        # KEPT, so the restore can be retried cleanly.
        try:
            self._update_entry(
                entry.id,
                status=final_status,
                resolved_at=_utcnow_iso(),
                restored_path=str(destination),
                blob_name=None,
                claimed_at=None,
            )
        except QuarantineError as exc:
            note = (
                f"restored to {destination}, but Argus could not update "
                "its records; the vault copy is being kept so "
                "nothing is lost — restoring again is safe."
            )
            try:
                self._update_entry(entry.id, note=note)
            except QuarantineError:
                log.warning(
                    "could not annotate vault entry %s after restore: %s",
                    entry.id, note,
                )
            raise QuarantineError(note) from exc
        blob_path.unlink(missing_ok=True)
        log.info("restored entry %s to %s", entry.id, destination)
        return destination

    def _publish_restored(self, verified_tmp: Path, original: Path) -> Path:
        """Put the verified plaintext at *original* (or beside it),
        never overwriting anything. Returns the path used.

        The bytes are first stream-copied to a staging file inside
        the destination directory (so no cross-volume rename is ever
        involved), then each candidate name is claimed atomically.
        Raises :class:`QuarantineError` with everything cleaned up if
        no name can be claimed.
        """
        parent = original.parent
        stage_path = parent / f".{original.name}.argus-restore-{_new_id()}.tmp"
        try:
            if parent and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)
            with open(verified_tmp, "rb") as src, open(stage_path, "wb") as dst:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    dst.write(chunk)
                dst.flush()
                os.fsync(dst.fileno())
        except OSError as exc:
            stage_path.unlink(missing_ok=True)
            log.warning("restore publish failed for %s: %r", original, exc)
            raise QuarantineError(
                f"could not put {original} back"
            ) from exc
        try:
            for candidate in self._restore_candidates(original):
                try:
                    os.link(stage_path, candidate)
                except FileExistsError:
                    continue  # name taken — try the next variant
                except OSError:
                    # No hard links here (filesystem limits): claim
                    # the name exclusively and copy into it instead.
                    try:
                        self._claim_and_copy(verified_tmp, candidate)
                    except FileExistsError:
                        continue
                    except OSError as exc:
                        log.warning(
                            "restore publish (copy) failed for %s: %r",
                            original, exc,
                        )
                        raise QuarantineError(
                            f"could not put {original} back"
                        ) from exc
                    return candidate
                return candidate
            raise QuarantineError(
                f"could not put {original} back: every restored-name "
                "variant is taken."
            )
        finally:
            stage_path.unlink(missing_ok=True)

    @staticmethod
    def _claim_and_copy(source: Path, candidate: Path) -> None:
        """Create *candidate* exclusively (O_EXCL — fails if it
        exists) and stream *source* into it. On any failure the
        claimed file is removed again: a partial restore must never
        be left behind."""
        fd = os.open(
            candidate,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o666,
        )
        try:
            with os.fdopen(fd, "wb") as dst, open(source, "rb") as src:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    dst.write(chunk)
                dst.flush()
                os.fsync(dst.fileno())
        except BaseException:
            candidate.unlink(missing_ok=True)
            raise

    @staticmethod
    def _restore_candidates(original: Path) -> Iterator[Path]:
        """Names a restore may use, in order: the original name,
        then ``name (restored by Argus).ext``, numbered upwards."""
        yield original
        stem, suffix = original.stem, original.suffix
        yield original.with_name(f"{stem} (restored by Argus){suffix}")
        counter = 2
        while counter <= 100:
            yield original.with_name(
                f"{stem} (restored by Argus {counter}){suffix}"
            )
            counter += 1

    def delete_permanent(self, entry_id: str) -> None:
        """Destroy a quarantined file for good. Bookkeeping BEFORE
        shred (P2, matching restore's ordering): the index is updated
        first, and only then is the blob destroyed — if the update
        fails the blob stays untouched. The index row stays as the
        audit record."""
        entry = self._require_entry(entry_id, live=True)
        blob_path = self._blob_path_for(entry) if entry.blob_name else None
        self._update_entry(
            entry.id, status="deleted", resolved_at=_utcnow_iso(), blob_name=None
        )
        if blob_path is not None and blob_path.is_file():
            self._shred(blob_path)
        log.info("permanently deleted vault entry %s (%s)", entry.id, entry.original_path)

    @staticmethod
    def _shred(blob_path: Path) -> None:
        """Best-effort overwrite before unlink. (On SSDs and journaled
        filesystems overwriting is not a guarantee — this is hygiene,
        not a promise.)"""
        try:
            size = blob_path.stat().st_size
            with open(blob_path, "r+b") as fh:
                remaining = size
                while remaining > 0:
                    piece = os.urandom(min(CHUNK_SIZE, remaining))
                    fh.write(piece)
                    remaining -= len(piece)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            log.warning("could not overwrite %s before deleting it", blob_path)
        blob_path.unlink(missing_ok=True)

    def mark_allowed(self, entry_id: str, restored_path: Path | str) -> None:
        """Record that an entry was allowed (restored + vouched for)."""
        self._update_entry(
            entry_id,
            status="allowed",
            resolved_at=_utcnow_iso(),
            restored_path=str(restored_path),
        )

    # ------------------------------------------------------------------
    # Entry access
    # ------------------------------------------------------------------
    def get_entry(self, entry_id: str) -> QuarantineEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM entries WHERE id = ?", (entry_id,)
            ).fetchone()
        return QuarantineEntry._from_row(row) if row else None

    def find_entry_by_sha256(self, sha256: str) -> QuarantineEntry | None:
        """Most recent live entry for a fingerprint, if any."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM entries WHERE sha256 = ? AND status = 'quarantined'"
                " ORDER BY quarantined_at DESC LIMIT 1",
                (sha256.lower(),),
            ).fetchone()
        return QuarantineEntry._from_row(row) if row else None

    def list_entries(self, status: str | None = None) -> list[QuarantineEntry]:
        with self._lock:
            if status is None:
                rows = self._conn.execute(
                    "SELECT * FROM entries ORDER BY quarantined_at DESC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM entries WHERE status = ?"
                    " ORDER BY quarantined_at DESC",
                    (status,),
                ).fetchall()
        return [QuarantineEntry._from_row(r) for r in rows]

    def count(self, status: str | None = None) -> int:
        with self._lock:
            if status is None:
                row = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM entries WHERE status = ?", (status,)
                ).fetchone()
        return int(row[0])

    def _require_entry(self, entry_id: str, *, live: bool) -> QuarantineEntry:
        entry = self.get_entry(entry_id)
        if entry is None:
            raise QuarantineError(f"no vault entry with id {entry_id}")
        # Integrity gates execution (restore/delete/allow all funnel
        # through here with live=True; a non-live lookup for display
        # does not need to hard-fail a tampered terminal row).
        if live:
            self._verify_entry_mac(entry)
        if live and entry.status != "quarantined":
            raise QuarantineError(
                f"vault entry {entry_id} is already {entry.status} — "
                "there is no live file to act on."
            )
        return entry

    def _insert_entry(self, entry: QuarantineEntry) -> None:
        entry.row_mac = self._mac_for_entry(entry)
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO entries (id, original_path, sha256, size,"
                    " quarantined_at, detection_name, severity, verdict,"
                    " reasons, status, blob_name, resolved_at, restored_path,"
                    " note, mode, row_mac)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.id, entry.original_path, entry.sha256, entry.size,
                        entry.quarantined_at, entry.detection_name,
                        entry.severity, entry.verdict,
                        json.dumps(entry.reasons), entry.status, entry.blob_name,
                        entry.resolved_at, entry.restored_path, entry.note,
                        entry.mode, entry.row_mac,
                    ),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                raise QuarantineError(
                    "could not record the vault entry"
                ) from exc

    def _update_entry(self, entry_id: str, **fields) -> None:
        if not fields:
            return
        with self._lock:
            try:
                # Recompute the row MAC over the POST-update row on
                # every update (P1-4), so a covered field can never
                # change without the seal changing with it — and a
                # hand edit without the key breaks the seal.
                row = self._conn.execute(
                    "SELECT * FROM entries WHERE id = ?", (entry_id,)
                ).fetchone()
                if row is not None:
                    merged = {k: row[k] for k in row.keys()}
                    merged.update(fields)
                    fields["row_mac"] = self._entry_mac(
                        entry_id=entry_id,
                        original_path=merged.get("original_path") or "",
                        blob_name=merged.get("blob_name"),
                        sha256=merged.get("sha256") or "",
                    )
                assignments = ", ".join(f"{name} = ?" for name in fields)
                self._conn.execute(
                    f"UPDATE entries SET {assignments} WHERE id = ?",
                    (*fields.values(), entry_id),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                raise QuarantineError(
                    "could not update the vault entry"
                ) from exc

    # ------------------------------------------------------------------
    # Pending actions queue (decisions live in argus.actions)
    # ------------------------------------------------------------------
    def add_pending(
        self,
        *,
        source: str,
        path: Path | str,
        action: str,
        sha256: str | None = None,
        severity: str | None = None,
        verdict: str | None = None,
        detection_name: str | None = None,
        reasons: list[str] | None = None,
    ) -> PendingAction:
        pending = PendingAction(
            id=_new_id(),
            created_at=_utcnow_iso(),
            source=source,
            path=str(path),
            action=action,
            sha256=sha256.lower() if sha256 else None,
            severity=severity,
            verdict=verdict,
            detection_name=detection_name,
            reasons=list(reasons or []),
        )
        with self._lock:
            try:
                self._pending_conn.execute(
                    "INSERT INTO pending_actions (id, created_at, decided_at,"
                    " source, path, sha256, action, severity, verdict,"
                    " detection_name, reasons, status, entry_id, error)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        pending.id, pending.created_at, pending.decided_at,
                        pending.source, pending.path, pending.sha256,
                        pending.action, pending.severity, pending.verdict,
                        pending.detection_name, json.dumps(pending.reasons),
                        pending.status, pending.entry_id, pending.error,
                    ),
                )
                self._pending_conn.commit()
            except sqlite3.Error as exc:
                raise QuarantineError(
                    "could not record the pending action"
                ) from exc
        return pending

    def import_pending(self, pending: PendingAction) -> None:
        """Insert a pending row preserving its identity (used by
        the service's one-time legacy migration, after the row has
        been re-validated). INSERT OR IGNORE: an id already in the
        trusted queue is never overwritten."""
        with self._lock:
            try:
                self._pending_conn.execute(
                    "INSERT OR IGNORE INTO pending_actions (id, created_at,"
                    " decided_at, source, path, sha256, action, severity,"
                    " verdict, detection_name, reasons, status, entry_id,"
                    " error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        pending.id, pending.created_at, pending.decided_at,
                        pending.source, pending.path, pending.sha256,
                        pending.action, pending.severity, pending.verdict,
                        pending.detection_name, json.dumps(pending.reasons),
                        pending.status, pending.entry_id, pending.error,
                    ),
                )
                self._pending_conn.commit()
            except sqlite3.Error as exc:
                raise QuarantineError(
                    "could not import the pending action"
                ) from exc

    def get_pending(self, pending_id: str) -> PendingAction | None:
        with self._lock:
            row = self._pending_conn.execute(
                "SELECT * FROM pending_actions WHERE id = ?", (pending_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            return PendingAction._from_row(row)
        except Exception:
            log.warning("skipping malformed pending row %s", pending_id)
            return None

    def list_pending(self, status: str | None = "pending") -> list[PendingAction]:
        with self._lock:
            if status is None:
                rows = self._pending_conn.execute(
                    "SELECT * FROM pending_actions ORDER BY created_at"
                ).fetchall()
            else:
                rows = self._pending_conn.execute(
                    "SELECT * FROM pending_actions WHERE status = ?"
                    " ORDER BY created_at",
                    (status,),
                ).fetchall()
        out: list[PendingAction] = []
        for r in rows:
            try:
                out.append(PendingAction._from_row(r))
            except Exception:
                log.warning(
                    "skipping malformed pending row %s",
                    r["id"] if "id" in r.keys() else "?",
                )
        return out

    def pending_count(self) -> int:
        with self._lock:
            row = self._pending_conn.execute(
                "SELECT COUNT(*) FROM pending_actions WHERE status = 'pending'"
            ).fetchone()
        return int(row[0])

    def update_pending(
        self,
        pending_id: str,
        *,
        status: str,
        entry_id: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            try:
                self._pending_conn.execute(
                    "UPDATE pending_actions SET status = ?, decided_at = ?,"
                    " entry_id = ?, error = ? WHERE id = ?",
                    (status, _utcnow_iso(), entry_id, error, pending_id),
                )
                self._pending_conn.commit()
            except sqlite3.Error as exc:
                raise QuarantineError(
                    "could not update the pending action"
                ) from exc
