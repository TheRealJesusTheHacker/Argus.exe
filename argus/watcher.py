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

**Dwell deadline.** Stability alone has a hole: a file that NEVER
sits still (a slow drip-feed download, malware appending to itself)
would never be scanned at all. So a tracked file that has been
changing for longer than ``max_dwell_seconds`` is reported anyway —
flagged as force-scanned (:meth:`DirectoryWatcher.consume_forced`)
so the scan result can say it judged a moving target.

**Coverage note.** The watcher tracks base files only. Alternate
data streams (Windows ADS) attached to a watched file are covered by
the on-demand scanner, not by the watcher's change tracking.

**Content identity (v1.1.0 P1-18).** A file's signature is
``(size, mtime_ns, sampled_hash)`` where ``sampled_hash`` is a
SHA-256 over the first 64 KiB plus the last 64 KiB of the file.
Size+mtime alone can be forged — a same-size content swap with a
restored ("timestomped") mtime looked identical to the old
signature and was never re-scanned. The sampled hash makes the
swap visible while keeping per-poll cost bounded (at most
128 KiB read per file, however large the file is).

Hard rules, shared with the scanner:

- **Symlinks are never followed.** Directory links are not descended
  into; file links are skipped and counted.
- **Races are normal.** Files vanish mid-poll, folders disappear,
  permissions change. Nothing here raises for filesystem problems —
  problems are counted, and the watch goes on.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

log = logging.getLogger("argus.watcher")

#: Bytes sampled from each end of a file for its content hash.
SAMPLE_BYTES = 64 * 1024  # 64 KiB

#: A file's identity-for-change purposes: (size, mtime in
#: nanoseconds, sampled content hash — see the module docstring).
#: The hash element is None for a poll where the file's stat had
#: just changed (fix round 2: no content read was needed — the
#: stat difference already proves the file differs).
Signature = tuple[int, int, "str | None"]


def _signature_changed(old: Signature, new: Signature) -> bool:
    """Did the file actually change between two signatures?

    A stat difference always means change. With equal stats, a
    change exists only when BOTH polls took the content hash and
    the hashes differ (the timestomp case). A None -> hash
    transition at equal stats is the hash ARRIVING, not the file
    changing, so it must not restart the stability wait."""
    if old[:2] != new[:2]:
        return True
    return (
        old[2] is not None
        and new[2] is not None
        and old[2] != new[2]
    )


def sampled_content_hash(path: Path, size: int) -> str:
    """SHA-256 over the first 64 KiB + the last 64 KiB of *path*.

    For a file of 64 KiB or less the "first" sample is the whole
    file and there is no separate tail sample. Raises OSError if
    the file cannot be read — the caller (snapshot) counts that
    as a stat error, like any other mid-poll race.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        head = fh.read(SAMPLE_BYTES)
        hasher.update(head)
        if size > SAMPLE_BYTES:
            fh.seek(size - SAMPLE_BYTES)
            hasher.update(fh.read(SAMPLE_BYTES))
    return hasher.hexdigest()


@dataclass
class _Tracked:
    signature: Signature
    stable_polls: int = 1
    scanned_signature: Signature | None = None
    #: Monotonic time the file was first tracked in its current
    #: unscanned state — the dwell deadline is measured from here.
    first_seen: float = 0.0


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

    #: How change detection is fed: this portable baseline polls.
    #: The Linux inotify backend (argus.inotify_watcher) reports
    #: "inotify". The service status surfaces the value so a
    #: fallback is visible, never silent.
    backend = "polling"

    def __init__(
        self,
        dirs: list[Path | str],
        *,
        poll_interval: float = 1.0,
        stable_polls: int = 2,
        on_ready: Callable[[Path], None] | None = None,
        max_dwell_seconds: float = 30.0,
    ) -> None:
        self.dirs = [Path(d) for d in dirs]
        self.poll_interval = poll_interval
        self.stable_polls = max(1, stable_polls)
        self.on_ready = on_ready
        self.max_dwell_seconds = max(1.0, float(max_dwell_seconds))
        self.stats = WatcherStats()
        self._tracked: dict[Path, _Tracked] = {}
        self._warned_missing: set[Path] = set()
        #: Paths whose latest report was a dwell-deadline force-scan.
        self._forced: set[Path] = set()

    def consume_forced(self, path: Path) -> bool:
        """True (once) if *path*'s latest report was a force-scan:
        the dwell deadline hit while the file was still changing."""
        if path in self._forced:
            self._forced.discard(path)
            return True
        return False

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
        """Map of path -> (size, mtime_ns, sampled content hash)
        for everything watched.

        The sampled content hash is EXPENSIVE (up to 128 KiB of
        reads) and is only computed when it answers a question
        (fix round 2, FIX 6): when the file's stat MATCHES the
        previous snapshot's — identity confirmation, the
        timestomp case — or when the file is new here (a scan
        candidate taking its first fingerprint). A file whose
        stat CHANGED is already known to differ, so this poll
        records ``None`` for its hash and lets stat alone restart
        its stability wait; the hash is taken on the first poll
        where its stat stands still. The old code hashed every
        file on every poll, forever."""
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
                    # Vanished between listing and stat, or became
                    # unreadable mid-poll — a normal race.
                    self.stats.stat_errors += 1
                    continue
                tracked = self._tracked.get(path)
                previous = tracked.signature if tracked is not None else None
                if previous is not None and previous[:2] != (
                    st.st_size,
                    st.st_mtime_ns,
                ):
                    content_hash = None  # stat changed: differs already
                else:
                    try:
                        content_hash = sampled_content_hash(path, st.st_size)
                    except OSError:
                        self.stats.stat_errors += 1
                        continue
                snap[path] = (st.st_size, st.st_mtime_ns, content_hash)
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
        now = time.monotonic()
        ready: list[Path] = []

        # Forget files that are gone.
        for path in list(self._tracked):
            if path not in snap:
                del self._tracked[path]
                self._forced.discard(path)

        for path, signature in snap.items():
            tracked = self._tracked.get(path)
            if tracked is None:
                tracked = _Tracked(signature=signature, first_seen=now)
                self._tracked[path] = tracked
            elif _signature_changed(tracked.signature, signature):
                # Still being written (or rewritten): restart the wait.
                tracked.signature = signature
                tracked.stable_polls = 1
            else:
                tracked.signature = signature
                tracked.stable_polls += 1
                # A signature recorded by a force-scan may carry
                # no content hash (stat-changed poll); when the
                # hash arrives at identical stats it is the SAME
                # content confirmed, so the scanned record keeps
                # up instead of triggering a redundant rescan.
                if (
                    tracked.scanned_signature is not None
                    and tracked.scanned_signature[:2] == signature[:2]
                    and tracked.scanned_signature[2] is None
                ):
                    tracked.scanned_signature = signature

            if tracked.scanned_signature == tracked.signature:
                continue  # this exact content was already reported
            stable = tracked.stable_polls >= self.stable_polls
            dwell_expired = (
                tracked.first_seen > 0
                and now - tracked.first_seen >= self.max_dwell_seconds
            )
            if stable or dwell_expired:
                tracked.scanned_signature = tracked.signature
                # The dwell clock restarts from this report: a file
                # that keeps changing gets force-scanned once per
                # dwell window, not on every poll.
                tracked.first_seen = now
                if dwell_expired and not stable:
                    self._forced.add(path)
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
