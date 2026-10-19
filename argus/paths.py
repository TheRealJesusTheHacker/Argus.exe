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
"""

from __future__ import annotations

import os
import sys
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


def default_vault_dir() -> Path:
    """Where the quarantine vault lives by default."""
    return data_dir() / "quarantine"


def default_history_db() -> Path:
    """Where the scan history database lives by default."""
    return data_dir() / "history.db"
