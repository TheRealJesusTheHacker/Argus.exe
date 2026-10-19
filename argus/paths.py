"""Standard locations for ARGUS.EXE's own data.

Argus keeps three kinds of state of its own: the quarantine vault
(neutralized threats + their index), the scan history database, and
the config/status files. All of it lives under one data root so it
survives updates and is shared by the CLI, the service, and the GUI:

- Windows: ``%PROGRAMDATA%\\Argus`` (``C:\\ProgramData\\Argus``) —
  machine-wide on purpose: the protection service runs as LocalSystem
  while the GUI and CLI run as the signed-in user, and all three must
  see the SAME config, signature database, vault, and history. A
  per-user location would give each its own private copy and the
  pieces would silently disagree.
- macOS:   ``~/Library/Application Support/Argus``
- Linux:   ``$XDG_DATA_HOME/argus`` (default ``~/.local/share/argus``)

Set the ``ARGUS_DATA_DIR`` environment variable to override the whole
tree (tests and the portable edition do exactly that — portable mode
is unaffected by the Windows location, because the override wins).

Trust split (v1.0.4)
--------------------
The data root is the **trusted root**: it holds the config and the
signature database, and the ``quarantine\\`` vault beneath it. The
installer ACLs it so standard users can *read* the config and
signature database but cannot write them, and cannot read the vault
at all — a compromised user process must not be able to rewrite the
rules the LocalSystem service enforces, forge signatures, or reach
into the vault.

Everything the user-side processes legitimately write lives in the
**shared** subdirectory (:func:`shared_dir`): the heartbeat status
file, the scan history, the pending-actions database, the
service action-request channel (``requests\\`` / ``results\\``), and
the read-only vault snapshot (``vault-view.json``) the service
publishes for the GUI. The installer grants users modify rights
there — and only there.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path


def data_dir() -> Path:
    """Root folder for Argus's data (vault, history, config, DB)."""
    override = os.environ.get("ARGUS_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        # Machine-wide, shared by the LocalSystem service and every
        # user's GUI/CLI (see the module docstring).
        base = os.environ.get("ProgramData") or r"C:\ProgramData"
        return Path(base) / "Argus"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Argus"
    xdg = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(xdg) / "argus"


def shared_dir() -> Path:
    """The user-writable shared subdirectory of the data root.

    Holds everything the GUI/CLI write and the service reads (and
    vice versa) under the trust split: status heartbeat, history,
    pending actions, action requests/results, vault view. On
    Windows the installer ACLs this subtree ``Users: modify`` while
    the root above it stays read-only for users.
    """
    return data_dir() / "shared"


def default_vault_dir() -> Path:
    """Where the quarantine vault lives by default (trusted root)."""
    return data_dir() / "quarantine"


def default_history_db() -> Path:
    """Where the scan history database lives by default (shared)."""
    return shared_dir() / "history.db"


def default_pending_db() -> Path:
    """Where the pending-actions database lives by default (shared).

    Pending rows are written by whichever process noticed a threat
    and decided by whichever human-facing process the user drives —
    they are shared state, NOT vault state, so since v1.0.4 they
    live in their own database here instead of inside vault.db.
    """
    return shared_dir() / "pending.db"


def default_status_file() -> Path:
    """Where the service heartbeat lives by default (shared)."""
    return shared_dir() / "argus-status.json"


def requests_dir() -> Path:
    """Where action requests for the service are dropped (shared)."""
    return shared_dir() / "requests"


def results_dir() -> Path:
    """Where the service writes action-request results (shared)."""
    return shared_dir() / "results"


def vault_view_path() -> Path:
    """The service-published read-only snapshot of vault entries."""
    return shared_dir() / "vault-view.json"


def write_text_atomic(path: Path | str, text: str, *, encoding: str = "utf-8") -> Path:
    """Write *text* to *path* atomically and crash-safely.

    A uniquely-named temp file is created in the SAME directory
    (``tempfile.mkstemp``), fully written and fsynced, given the
    existing file's permission bits when there is one, and then
    ``os.replace``d over the target. A crash or power loss leaves
    either the old file or the new one — never a truncated mix —
    and concurrent writers never collide on a shared temp name.
    Returns the target path.
    """
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    existing_mode: int | None = None
    try:
        existing_mode = stat.S_IMODE(target.stat().st_mode)
    except OSError:
        existing_mode = None
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent) if str(target.parent) else ".",
        prefix=target.name + ".",
        suffix=".tmp",
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if existing_mode is not None:
            try:
                os.chmod(tmp, existing_mode)
            except OSError:
                pass  # best effort — content integrity is the point
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target
