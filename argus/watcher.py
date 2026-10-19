"""Filesystem watcher for ARGUS.EXE real-time protection.

The watcher keeps an eye on the folders threats land in — Downloads,
Desktop, Documents, temp — and reports files that are new or changed
*and finished changing*.

Why polling? It works everywhere with nothing but the standard
library: no third-party packages, no platform-specific event APIs, no
admin rights. The cost is a small delay (one poll interval), which
the debounce below deliberately adds to anyway.

**Debounce matters.** A browser download, a torrent, an installer —
files arrive in pieces. Scanning a half-written file wastes work and
can produce a verdict on bytes that are about to change. So a file is
only reported once its size and modification time have stayed
identical across several consecutive polls: it is *stable*, finished,
ready to judge.

Hard rules, shared with the scanner:

- **Symlinks are never followed.** Directory links are not descended
  into; file links are skipped and counted.
- **Races are normal.** Files vanish mid-poll, folders disappear,
  permissions change. Nothing here raises for filesystem problems —
  problems are counted, and the watch goes on.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

log = logging.getLogger("argus.watcher")

#: A file's identity-for-change purposes: (size, mtime in nanoseconds).
Signature = tuple[int, int]


@dataclass
class _Tracked:
    signature: Signature
    stable_polls: int = 1
    scanned_signature: Signature | None = None


@dataclass
class WatcherStats:
    polls: int = 0
    files_tracked: int = 0
    files_ready: int = 0  # times a file was handed over for scanning
    symlink_files_skipped: int = 0
    dirs_missing: int = 0
    dirs_unreadable: int = 0
    stat_errors: int = 0


class DirectoryWatcher:
    """Polls directories and reports new/changed files once stable.

    ``on_ready(path)`` is called (from the polling thread, or from
    whoever calls :meth:`poll_once`) for each file that has become
    stable since it was last reported. A file that changes again after
    being reported goes through the same stability wait and is
    reported again — modifications are re-scanned.
    """

    def __init__(
        self,
        dirs: list[Path | str],
        *,
        poll_interval: float = 1.0,
        stable_polls: int = 2,
        on_ready: Callable[[Path], None] | None = None,
    ) -> None:
        self.dirs = [Path(d) for d in dirs]
        self.poll_interval = poll_interval
        self.stable_polls = max(1, stable_polls)
        self.on_ready = on_ready
        self.stats = WatcherStats()
        self._tracked: dict[Path, _Tracked] = {}
        self._warned_missing: set[Path] = set()

    # ------------------------------------------------------------------
    # Snapshot: what is on disk right now
    # ------------------------------------------------------------------
    def _walk(self, root: Path) -> Iterator[Path]:
        """Yield regular files under *root* without following symlinks."""
        stack: list[Path] = [root]
        while stack:
            current = stack.pop()
            try:
                entries = list(os.scandir(current))
            except OSError:
                self.stats.dirs_unreadable += 1
                continue
            for entry in entries:
                try:
                    if entry.is_symlink():
                        if entry.is_dir(follow_symlinks=True):
                            continue  # directory link: never follow
                        self.stats.symlink_files_skipped += 1
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        yield Path(entry.path)
                except OSError:
                    self.stats.stat_errors += 1

    def snapshot(self) -> dict[Path, Signature]:
        """Map of path -> (size, mtime_ns) for everything watched."""
        snap: dict[Path, Signature] = {}
        for root in self.dirs:
            if not root.is_dir():
                if root not in self._warned_missing:
                    self._warned_missing.add(root)
                    self.stats.dirs_missing += 1
                    log.warning("watch folder does not exist (yet): %s", root)
                continue
            for path in self._walk(root):
                try:
                    st = path.stat()
                except OSError:
                    # Vanished between listing and stat — normal race.
                    self.stats.stat_errors += 1
                    continue
                snap[path] = (st.st_size, st.st_mtime_ns)
        return snap

    # ------------------------------------------------------------------
    # One poll cycle: diff + stability bookkeeping
    # ------------------------------------------------------------------
    def poll_once(self) -> list[Path]:
        """Run one snapshot/diff cycle.

        Returns the files that became stable (finished writing) since
        they were last reported, and fires ``on_ready`` for each.
        """
        self.stats.polls += 1
        snap = self.snapshot()
        ready: list[Path] = []

        # Forget files that are gone.
        for path in list(self._tracked):
            if path not in snap:
                del self._tracked[path]

        for path, signature in snap.items():
            tracked = self._tracked.get(path)
            if tracked is None:
                tracked = _Tracked(signature=signature)
                self._tracked[path] = tracked
            elif tracked.signature != signature:
                # Still being written (or rewritten): restart the wait.
                tracked.signature = signature
                tracked.stable_polls = 1
            else:
                tracked.stable_polls += 1

            if (
                tracked.stable_polls >= self.stable_polls
                and tracked.scanned_signature != tracked.signature
            ):
                tracked.scanned_signature = tracked.signature
                ready.append(path)

        self.stats.files_tracked = len(self._tracked)
        for path in ready:
            self.stats.files_ready += 1
            if self.on_ready is not None:
                try:
                    self.on_ready(path)
                except Exception:  # a broken callback must not kill the watch
                    log.exception("watcher on_ready callback failed for %s", path)
        return ready

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------
    def run(
        self,
        stop_event: threading.Event,
        paused_event: threading.Event | None = None,
    ) -> None:
        """Poll forever until *stop_event* is set.

        When *paused_event* is set the loop idles without polling, so
        pausing protection stops new scans from being queued.
        """
        while not stop_event.is_set():
            if paused_event is not None and paused_event.is_set():
                stop_event.wait(0.1)
                continue
            try:
                self.poll_once()
            except Exception:  # the watch must survive any single bad poll
                log.exception("watcher poll failed; continuing")
            stop_event.wait(self.poll_interval)
