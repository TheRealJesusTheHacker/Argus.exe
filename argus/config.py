"""Configuration for ARGUS.EXE real-time protection.

Real-time protection needs knobs a one-off scan does not: which folders
to watch, how quickly to poll, what to do about each severity, and
which files Argus should leave alone (exclusions). Those live in a
plain JSON file so a person can read and edit them without a manual.

Design rules:

- **Sensible defaults.** No config file at all is a perfectly good
  setup — Argus watches the usual drop zones (Downloads, Desktop,
  Documents, temp) with safe per-severity actions.
- **Never crash on a bad config.** A typo in a JSON file must not take
  down the machine's protection. Unreadable or invalid values fall
  back to defaults *per key*, and every problem is collected into
  :attr:`ArgusConfig.load_warnings` so it can be reported loudly
  instead of failing silently.
- **Exclusions are honoured everywhere.** The same exclusion set is
  used by the real-time engine and by on-demand scans, so "leave this
  alone" means everywhere, not just sometimes.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .paths import data_dir, shared_dir, write_text_atomic
from .signatures import DEFAULT_DB_NAME, SEVERITIES

log = logging.getLogger("argus.config")

#: Actions the response policy can assign to a severity. ``quarantine``
#: and ``delete`` are *requests*: the real-time engine emits an action
#: event, and :mod:`argus.actions` decides what happens under the
#: user's ``realtime_default`` policy — the queue, or (for Critical
#: only, if the user chose it) immediate quarantine. Deletion always
#: needs a human decision.
VALID_ACTIONS = ("quarantine", "delete", "alert", "log", "ignore")

#: Default per-severity actions: the worst threats ask for quarantine,
#: medium findings alert the user, low findings are just written down.
DEFAULT_SEVERITY_ACTIONS: dict[str, str] = {
    "critical": "quarantine",
    "high": "quarantine",
    "medium": "alert",
    "low": "log",
}

#: How real-time action *requests* are handled (Phase 4):
#: - ``ask`` — queue every request in the pending-actions queue for a
#:   human decision (the default; nothing is touched);
#: - ``auto-quarantine-critical`` — Critical-severity files are
#:   quarantined immediately under the user's own policy; everything
#:   else waits in the queue. Deletion is NEVER automatic;
#: - ``log-only`` — requests are written to history, nothing is queued
#:   or moved (simulation-style).
REALTIME_POLICIES = ("ask", "auto-quarantine-critical", "log-only")
DEFAULT_REALTIME_POLICY = "ask"

DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_STABLE_POLLS = 2
DEFAULT_PROCESS_POLL_INTERVAL = 2.0
DEFAULT_MAX_REALTIME_FILE_SIZE = 256 * 1024 * 1024  # 256 MB
DEFAULT_STATUS_FILE = "argus-status.json"
DEFAULT_CONFIG_NAME = "argus-config.json"


def default_watch_dirs() -> list[Path]:
    """The folders threats most often land in: Downloads, Desktop,
    Documents, and the system temp folder."""
    home = Path.home()
    dirs = [home / "Downloads", home / "Desktop", home / "Documents"]
    dirs.append(Path(tempfile.gettempdir()))
    return dirs


def _normalize_path_str(raw: str) -> str:
    """Canonical form for path comparison: expanded, absolute,
    case-normalized for the platform."""
    expanded = os.path.expanduser(os.path.expandvars(raw))
    return os.path.normcase(os.path.abspath(expanded))


@dataclass
class Exclusions:
    """Files Argus must leave alone: by location and by fingerprint.

    ``paths`` holds normalized absolute paths; a file is excluded when
    it *is* one of them or lives anywhere underneath one. ``hashes``
    holds lowercase SHA-256 digests; a file whose fingerprint matches
    is excluded no matter where it shows up.
    """

    paths: tuple[str, ...] = ()
    hashes: frozenset[str] = frozenset()

    def is_path_excluded(self, path: Path | str) -> bool:
        if not self.paths:
            return False
        candidate = _normalize_path_str(str(path))
        for excluded in self.paths:
            if candidate == excluded:
                return True
            prefix = excluded + os.sep
            if candidate.startswith(prefix):
                return True
        return False

    def is_hash_excluded(self, sha256: str | None) -> bool:
        return sha256 is not None and sha256.lower() in self.hashes

    def is_excluded(self, path: Path | str, sha256: str | None = None) -> bool:
        return self.is_path_excluded(path) or self.is_hash_excluded(sha256)

    @property
    def empty(self) -> bool:
        return not self.paths and not self.hashes


@dataclass
class ArgusConfig:
    """Everything the real-time engine needs, with defaults."""

    watch_dirs: list[Path] = field(default_factory=default_watch_dirs)
    poll_interval: float = DEFAULT_POLL_INTERVAL
    stable_polls: int = DEFAULT_STABLE_POLLS
    process_monitor_enabled: bool = True
    process_poll_interval: float = DEFAULT_PROCESS_POLL_INTERVAL
    severity_actions: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_ACTIONS)
    )
    exclusions: Exclusions = field(default_factory=Exclusions)
    max_realtime_file_size: int = DEFAULT_MAX_REALTIME_FILE_SIZE
    #: Absolute by default, under the shared data root: a bare
    #: relative name resolved against whatever directory the process
    #: happened to start in, so the service, GUI, and CLI each looked
    #: in a different place on a fresh install and found nothing.
    signature_db: str = field(
        default_factory=lambda: str(data_dir() / DEFAULT_DB_NAME)
    )
    rules_file: str | None = None
    heuristics: bool = True
    #: Absolute for the same reason: the service, the GUI, and
    #: ``argus watch-status`` must all read the SAME heartbeat file.
    #: It lives in the SHARED subdirectory (v1.0.4 trust split):
    #: the heartbeat is written by the service and read by user
    #: processes, and the trusted data root is read-only for users.
    status_file: str = field(
        default_factory=lambda: str(shared_dir() / DEFAULT_STATUS_FILE)
    )
    event_log_file: str | None = None
    heartbeat_interval: float = 5.0
    #: How real-time action requests are handled (see REALTIME_POLICIES).
    realtime_default: str = DEFAULT_REALTIME_POLICY
    #: Quarantine vault location (None = the standard app-data home).
    vault_dir: str | None = None
    #: Scan history database location (None = standard app-data home).
    history_db: str | None = None
    #: Pending-actions database location (None = shared app-data home).
    pending_db: str | None = None
    #: Watcher dwell deadline: a file that keeps changing is scanned
    #: anyway once it has been tracked this long (seconds), instead
    #: of waiting forever for it to sit still.
    max_dwell_seconds: float = 30.0
    #: True once the user has finished the first-run welcome wizard
    #: (Phase 5 GUI). Stored in config so the wizard shows exactly once.
    onboarding_completed: bool = False
    #: Problems found while loading (empty when the config was clean).
    load_warnings: list[str] = field(default_factory=list)
    #: Where the config was loaded from (None = pure defaults).
    source_path: Path | None = None

    # ------------------------------------------------------------------
    # Policy helpers
    # ------------------------------------------------------------------
    def action_for(self, severity: str | None) -> str:
        """The configured action for a severity (default: ``log``)."""
        if severity is None:
            return "log"
        return self.severity_actions.get(severity.lower(), "log")

    def is_excluded(self, path: Path | str, sha256: str | None = None) -> bool:
        return self.exclusions.is_excluded(path, sha256)

    def add_hash_exclusion(self, sha256: str) -> None:
        """Vouch for a file by fingerprint: Argus will leave any file
        with this SHA-256 alone, wherever it appears. In-memory only —
        call :meth:`save` to make it permanent."""
        digest = sha256.lower()
        if digest not in self.exclusions.hashes:
            self.exclusions = Exclusions(
                paths=self.exclusions.paths,
                hashes=self.exclusions.hashes | {digest},
            )

    def absorb_disk_exclusions(self, path: Path | str) -> None:
        """Merge the exclusions currently ON DISK at *path* into this
        config (union of paths and hashes).

        The service and the GUI each hold their own in-memory copy of
        the config. If one of them vouches for a file (Allow) and the
        other later saves its own stale copy, the vouch would be
        silently erased — a lost update. Callers that save on the
        user's behalf absorb the on-disk exclusions first, so a save
        can add exclusions but never quietly remove someone else's.
        """
        if not Path(path).is_file():
            return
        disk = ArgusConfig.load(path)
        merged_paths = tuple(
            dict.fromkeys([*self.exclusions.paths, *disk.exclusions.paths])
        )
        merged_hashes = self.exclusions.hashes | disk.exclusions.hashes
        self.exclusions = Exclusions(paths=merged_paths, hashes=merged_hashes)

    def save(self, path: Path | str) -> None:
        """Write this config back to *path* as JSON (the same shape
        :meth:`load` reads). Used when Argus itself changes a setting
        on the user's behalf — e.g. Allow adds an exclusion."""
        data = {
            "watch_dirs": [str(d) for d in self.watch_dirs],
            "poll_interval_seconds": self.poll_interval,
            "stable_polls": self.stable_polls,
            "process_monitor_enabled": self.process_monitor_enabled,
            "process_poll_interval_seconds": self.process_poll_interval,
            "heartbeat_interval_seconds": self.heartbeat_interval,
            "heuristics": self.heuristics,
            "severity_actions": dict(self.severity_actions),
            "realtime_default": self.realtime_default,
            "exclusions": {
                "paths": list(self.exclusions.paths),
                "hashes": sorted(self.exclusions.hashes),
            },
            "max_realtime_file_size_mb": round(
                self.max_realtime_file_size / (1024 * 1024), 3
            ),
            "signature_db": self.signature_db,
            "rules_file": self.rules_file,
            "status_file": self.status_file,
            "event_log_file": self.event_log_file,
            "vault_dir": self.vault_dir,
            "history_db": self.history_db,
            "pending_db": self.pending_db,
            "max_dwell_seconds": self.max_dwell_seconds,
            "onboarding_completed": self.onboarding_completed,
        }
        target = Path(path)
        # Atomic, crash-safe write (unique temp file in the same
        # directory + fsync + permission-preserving rename): a crash
        # mid-write must never leave a half-written config behind
        # for the next start to choke on.
        write_text_atomic(target, json.dumps(data, indent=2) + "\n")
        self.source_path = target

    # ------------------------------------------------------------------
    # Loading — tolerant by design: defaults + loud warnings, no raises
    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | str | None) -> "ArgusConfig":
        """Load config from *path*, falling back to defaults.

        A missing file is fine (pure defaults, no warning beyond a
        note). A corrupt file, wrong-typed values, or unknown action
        names each produce a warning and a per-key fallback — never
        an exception.
        """
        config = cls()
        if path is None:
            return config
        config_path = Path(path)
        config.source_path = config_path
        if not config_path.is_file():
            config.load_warnings.append(
                f"config file not found: {config_path} — using defaults"
            )
            log.warning(config.load_warnings[-1])
            return config
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            config.load_warnings.append(
                f"could not read config {config_path}: {exc} — using defaults"
            )
            log.warning(config.load_warnings[-1])
            return config
        if not isinstance(raw, dict):
            config.load_warnings.append(
                f"config {config_path} is not a JSON object — using defaults"
            )
            log.warning(config.load_warnings[-1])
            return config
        config._apply(raw)
        for warning in config.load_warnings:
            log.warning("config: %s", warning)
        return config

    def _apply(self, raw: dict) -> None:
        warn = self.load_warnings.append

        dirs = raw.get("watch_dirs")
        if dirs is not None:
            if isinstance(dirs, list) and all(isinstance(d, str) for d in dirs):
                self.watch_dirs = [
                    Path(os.path.expanduser(os.path.expandvars(d))) for d in dirs
                ]
            else:
                warn("'watch_dirs' must be a list of path strings — keeping defaults")

        self.poll_interval = self._float(
            raw, "poll_interval_seconds", DEFAULT_POLL_INTERVAL, minimum=0.05
        )
        self.stable_polls = self._int(raw, "stable_polls", DEFAULT_STABLE_POLLS, minimum=1)
        self.process_poll_interval = self._float(
            raw, "process_poll_interval_seconds",
            DEFAULT_PROCESS_POLL_INTERVAL, minimum=0.1,
        )
        self.heartbeat_interval = self._float(
            raw, "heartbeat_interval_seconds", 5.0, minimum=0.5
        )
        self.max_dwell_seconds = self._float(
            raw, "max_dwell_seconds", 30.0, minimum=1.0
        )

        pm = raw.get("process_monitor_enabled")
        if isinstance(pm, bool):
            self.process_monitor_enabled = pm
        elif pm is not None:
            warn("'process_monitor_enabled' must be true/false — keeping default")

        heur = raw.get("heuristics")
        if isinstance(heur, bool):
            self.heuristics = heur
        elif heur is not None:
            warn("'heuristics' must be true/false — keeping default")

        onboarded = raw.get("onboarding_completed")
        if isinstance(onboarded, bool):
            self.onboarding_completed = onboarded
        elif onboarded is not None:
            warn("'onboarding_completed' must be true/false — keeping default")

        actions = raw.get("severity_actions")
        if actions is not None:
            if not isinstance(actions, dict):
                warn("'severity_actions' must be an object — keeping defaults")
            else:
                for severity, action in actions.items():
                    key = str(severity).lower()
                    value = str(action).lower()
                    if key not in SEVERITIES:
                        warn(f"unknown severity {severity!r} in severity_actions — ignored")
                    elif value not in VALID_ACTIONS:
                        warn(
                            f"unknown action {action!r} for severity {key!r} "
                            f"(valid: {', '.join(VALID_ACTIONS)}) — ignored"
                        )
                    else:
                        self.severity_actions[key] = value

        excl = raw.get("exclusions")
        if excl is not None:
            if not isinstance(excl, dict):
                warn("'exclusions' must be an object — no exclusions loaded")
            else:
                paths = excl.get("paths", [])
                hashes = excl.get("hashes", [])
                norm_paths: list[str] = []
                norm_hashes: set[str] = set()
                if isinstance(paths, list):
                    for entry in paths:
                        if isinstance(entry, str):
                            norm_paths.append(_normalize_path_str(entry))
                        else:
                            warn(f"exclusion path {entry!r} is not a string — ignored")
                else:
                    warn("'exclusions.paths' must be a list — ignored")
                if isinstance(hashes, list):
                    for entry in hashes:
                        if isinstance(entry, str) and len(entry) == 64:
                            norm_hashes.add(entry.lower())
                        else:
                            warn(f"exclusion hash {entry!r} is not a SHA-256 hex digest — ignored")
                else:
                    warn("'exclusions.hashes' must be a list — ignored")
                self.exclusions = Exclusions(
                    paths=tuple(norm_paths), hashes=frozenset(norm_hashes)
                )

        max_mb = raw.get("max_realtime_file_size_mb")
        if max_mb is not None:
            if isinstance(max_mb, (int, float)) and max_mb > 0:
                self.max_realtime_file_size = int(max_mb * 1024 * 1024)
            else:
                warn("'max_realtime_file_size_mb' must be a positive number — keeping default")

        for key, attr in (("signature_db", "signature_db"),
                          ("status_file", "status_file")):
            value = raw.get(key)
            if isinstance(value, str) and value:
                setattr(self, attr, value)
            elif value is not None:
                warn(f"'{key}' must be a non-empty string — keeping default")

        for key, attr in (("rules_file", "rules_file"),
                          ("event_log_file", "event_log_file"),
                          ("vault_dir", "vault_dir"),
                          ("history_db", "history_db"),
                          ("pending_db", "pending_db")):
            value = raw.get(key)
            if isinstance(value, str) and value:
                setattr(self, attr, value)
            elif value is not None and value is not False:
                warn(f"'{key}' must be a path string or null — keeping default")

        policy = raw.get("realtime_default")
        if policy is not None:
            if isinstance(policy, str) and policy.lower() in REALTIME_POLICIES:
                self.realtime_default = policy.lower()
            else:
                warn(
                    f"'realtime_default' must be one of "
                    f"{', '.join(REALTIME_POLICIES)} — keeping "
                    f"'{DEFAULT_REALTIME_POLICY}'"
                )

    def _float(self, raw: dict, key: str, default: float, *, minimum: float) -> float:
        value = raw.get(key)
        if value is None:
            return default
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= minimum:
            return float(value)
        self.load_warnings.append(
            f"'{key}' must be a number >= {minimum} — keeping default {default}"
        )
        return default

    def _int(self, raw: dict, key: str, default: int, *, minimum: int) -> int:
        value = raw.get(key)
        if value is None:
            return default
        if isinstance(value, int) and not isinstance(value, bool) and value >= minimum:
            return value
        self.load_warnings.append(
            f"'{key}' must be an integer >= {minimum} — keeping default {default}"
        )
        return default
