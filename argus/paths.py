"""Standard locations for ARGUS.EXE's own data.

Argus keeps three kinds of state of its own: the quarantine vault
(neutralized threats + their index), the scan history database, and
the config/status files. Config and status live wherever the user (or
the service) points them; the vault and history get a proper
per-user application-data home so they survive updates and are shared
by the CLI, the service, and (in Phase 5) the GUI:

- Windows: ``%LOCALAPPDATA%\\Argus``
- macOS:   ``~/Library/Application Support/Argus``
- Linux:   ``$XDG_DATA_HOME/argus`` (default ``~/.local/share/argus``)

Set the ``ARGUS_DATA_DIR`` environment variable to override the whole
tree (tests and portable setups do exactly that).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    """Root folder for Argus's per-user data (vault, history)."""
    override = os.environ.get("ARGUS_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(
            Path.home() / "AppData" / "Local"
        )
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
