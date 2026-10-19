"""inotify backend for the real-time watcher (v1.2.0, Linux).

The polling :class:`~argus.watcher.DirectoryWatcher` is the
portable baseline: it works everywhere with nothing but the
standard library, and the Windows product still uses it. On Linux
the kernel offers something better — **inotify**: the filesystem
itself reports writes, moves, and deletions the moment they
happen, so the watcher notices a finished download in
milliseconds instead of at the next poll, and idle watch folders
cost no repeated directory walks.

This module is a *backend*, not a new watcher. The detection
contract is the parent's and is unchanged: a file is reported
only once its (size, mtime, sampled content hash) signature is
stable across consecutive polls (the debounce that keeps
half-written files from being judged mid-write) or at the dwell
deadline. inotify feeds that machinery *which paths changed*;
the stability bookkeeping, the dwell deadline, the symlink
rules, and the race tolerance are all inherited as-is.

Implementation notes:

- inotify is reached through **ctypes libc calls** — no new
  dependency (the engine stays pure standard library).
- Snapshots stay honest: structural changes (a directory
  created, a watch lost, a queue overflow) trigger a full
  re-walk through the parent's snapshot; ordinary file events
  update just the touched entries in the cached map.
- If inotify cannot be initialised on a machine (no libc
  inotify, exhausted watch limits at start-up), construction
  raises :class:`InotifyUnavailable` and the engine falls back
  to the polling watcher — logged, and reported in the service
  status as ``watcher_backend: "polling"``. The fallback is a
  smaller notice latency, never a loss of protection, and the
  code says so where it happens.
"""

from __future__ import annotations

import ctypes
import errno
import logging
import os
import select
import struct
import threading
from pathlib import Path

from .watcher import DirectoryWatcher, Signature, sampled_content_hash

log = logging.getLogger("argus.inotify_watcher")


class InotifyUnavailable(RuntimeError):
    """inotify cannot be used on this machine; poll instead."""


# inotify event masks (linux/inotify.h)
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_ISDIR = 0x40000000

_WATCH_MASK = (
    IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

_IN_NONBLOCK = 0o4000
_IN_CLOEXEC = 0o2000000

_EVENT_STRUCT = struct.Struct("iIII")
_READ_CHUNK = 256 * 1024


def _libc():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_add_watch.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32,
    ]
    libc.inotify_rm_watch.restype = ctypes.c_int
    libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
    return libc


class _Inotify:
    """A thin, honest wrapper over the libc inotify calls."""

    def __init__(self) -> None:
        try:
            self._libc = _libc()
        except (OSError, AttributeError) as exc:
            raise InotifyUnavailable(f"libc inotify is unavailable: {exc}")
        fd = self._libc.inotify_init1(_IN_NONBLOCK | _IN_CLOEXEC)
        if fd < 0:
            err = ctypes.get_errno()
            raise InotifyUnavailable(
                f"inotify_init1 failed: {os.strerror(err)}"
            )
        self.fd = fd
        self._wd_dirs: dict[int, Path] = {}

    def add_watch(self, directory: Path) -> int | None:
        """Watch one directory; None (logged) when it cannot be
        watched — a missing or unreadable folder is a normal
        race in this product, never a fatal error."""
        wd = self._libc.inotify_add_watch(
            self.fd, os.fsencode(str(directory)), _WATCH_MASK
        )
        if wd < 0:
            err = ctypes.get_errno()
            log.warning(
                "inotify cannot watch %s: %s", directory, os.strerror(err)
            )
            return None
        self._wd_dirs[wd] = directory
        return wd

    def dir_for(self, wd: int) -> Path | None:
        return self._wd_dirs.get(wd)

    def forget(self, wd: int) -> None:
        self._wd_dirs.pop(wd, None)
        try:
            self._libc.inotify_rm_watch(self.fd, wd)
        except Exception:
            pass

    def read_events(self, timeout: float) -> list[tuple[int, int, str]]:
        """Wait up to *timeout* seconds for events; return a list
        of (watch descriptor, mask, name). An empty list is a
        quiet timeout, not an error."""
        if timeout > 0:
            ready, _, _ = select.select([self.fd], [], [], timeout)
            if not ready:
                return []
        try:
            data = os.read(self.fd, _READ_CHUNK)
        except BlockingIOError:
            return []
        except OSError as exc:
            if exc.errno == errno.EINTR:
                return []
            raise
        events: list[tuple[int, int, str]] = []
        offset = 0
        while offset + _EVENT_STRUCT.size <= len(data):
            wd, mask, _cookie, name_len = _EVENT_STRUCT.unpack_from(
                data, offset
            )
            offset += _EVENT_STRUCT.size
            raw_name = data[offset:offset + name_len]
            offset += name_len
            name = raw_name.split(b"\x00", 1)[0].decode(
                "utf-8", "surrogateescape"
            )
            events.append((wd, mask, name))
        return events

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


class InotifyDirectoryWatcher(DirectoryWatcher):
    """DirectoryWatcher fed by inotify events (Linux).

    Same constructor and contract as the polling parent; the
    poll interval becomes the *idle cadence* — how often the
    stability bookkeeping runs when nothing has happened — and
    the event wait that replaces the blind sleep in between.
    """

    def __init__(self, dirs, **kwargs) -> None:
        super().__init__(dirs, **kwargs)
        # inotify is initialised LAZILY (first snapshot / drain /
        # run): constructing a watcher must be free, because the
        # engine builds one per service and most never start —
        # an eager fd per engine would exhaust the process limit
        # in long-lived hosts and test suites alike.
        self._inotify: _Inotify | None = None
        self._inotify_failed = False
        self._watches_ready = False
        self._cache: dict[Path, Signature] = {}
        self._cache_primed = False
        self._structure_dirty = True
        self._dirty_paths: set[Path] = set()

    @property
    def backend(self) -> str:
        """Which backend is ACTUALLY feeding detection: if
        inotify proved unavailable on this machine, the honest
        answer is "polling" (the fallback this class degrades
        to), never the aspirational "inotify"."""
        return "polling" if self._inotify_failed else "inotify"

    def _get_inotify(self) -> _Inotify | None:
        """The live inotify handle, created on first use; None
        (permanently, with the fallback logged once) when the
        machine cannot provide one."""
        if self._inotify is not None:
            return self._inotify
        if self._inotify_failed:
            return None
        try:
            self._inotify = _Inotify()
        except InotifyUnavailable as exc:
            self._inotify_failed = True
            log.warning(
                "inotify is unavailable on this machine (%s) — "
                "this watcher polls instead: same detection, "
                "slightly slower notice.",
                exc,
            )
            return None
        return self._inotify

    # ------------------------------------------------------------------
    # Watch maintenance
    # ------------------------------------------------------------------
    def _add_tree_watches(self, root: Path) -> None:
        """Watch *root* and every real subdirectory beneath it
        (symlinked directories are never followed — the same rule
        the walk enforces)."""
        inotify = self._get_inotify()
        if inotify is None:
            return
        stack = [root]
        while stack:
            current = stack.pop()
            if inotify.add_watch(current) is None:
                continue
            try:
                entries = list(os.scandir(current))
            except OSError:
                continue
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                except OSError:
                    continue

    def _ensure_watches(self) -> None:
        if self._watches_ready:
            return
        for root in self.dirs:
            if root.is_dir():
                self._add_tree_watches(root)
            else:
                if root not in self._warned_missing:
                    self._warned_missing.add(root)
                    self.stats.dirs_missing += 1
                    log.warning(
                        "watch folder does not exist (yet): %s", root
                    )
        self._watches_ready = True

    # ------------------------------------------------------------------
    # Event intake
    # ------------------------------------------------------------------
    def _absorb_events(self, events: list[tuple[int, int, str]]) -> None:
        inotify = self._get_inotify()
        if inotify is None:
            return
        for wd, mask, name in events:
            if mask & IN_Q_OVERFLOW:
                # The kernel dropped events: the only honest
                # answer is a full re-walk.
                log.warning(
                    "inotify event queue overflowed — rescanning "
                    "the watched folders in full"
                )
                self._structure_dirty = True
                continue
            directory = inotify.dir_for(wd)
            if directory is None:
                continue
            if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                inotify.forget(wd)
                self._structure_dirty = True
                continue
            if not name:
                self._structure_dirty = True
                continue
            path = directory / name
            if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
                # A new directory: watch it, and re-walk so its
                # contents enter the map with proper signatures.
                if path.is_dir() and not path.is_symlink():
                    self._add_tree_watches(path)
                self._structure_dirty = True
                continue
            self._dirty_paths.add(path)

    def drain_events(self, timeout: float = 0.0) -> int:
        """Read and absorb whatever inotify has (waiting up to
        *timeout* for the first batch). Returns events absorbed.
        Public so tests can drive the backend without the loop."""
        self._ensure_watches()
        inotify = self._get_inotify()
        if inotify is None:
            return 0
        total = 0
        first = True
        while True:
            events = inotify.read_events(timeout if first else 0.0)
            first = False
            if not events:
                return total
            total += len(events)
            self._absorb_events(events)

    # ------------------------------------------------------------------
    # Snapshot: the parent's map, maintained incrementally
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[Path, Signature]:
        # Absorb whatever the kernel has reported since the last
        # look (non-blocking): direct poll_once() callers get the
        # polling contract — the map reflects the disk NOW — not
        # only whatever the run loop happened to drain. With no
        # inotify available, every snapshot is the parent's full
        # walk (the polling fallback, honestly reported).
        if self._get_inotify() is None:
            return super().snapshot()
        self.drain_events(timeout=0.0)
        if self._structure_dirty or not self._cache_primed:
            self._cache = super().snapshot()
            self._cache_primed = True
            self._structure_dirty = False
            self._dirty_paths.clear()
            return dict(self._cache)
        for path in list(self._dirty_paths):
            self._dirty_paths.discard(path)
            self._refresh_entry(path)
        return dict(self._cache)

    def _refresh_entry(self, path: Path) -> None:
        """Re-stat one event-touched path into the cached map,
        mirroring the parent snapshot's signature rules: a stat
        change is proof of difference on its own (content hash
        None); an unchanged stat takes the sampled hash (the
        timestomp check). Vanished/unreadable files leave the
        map — races are normal."""
        try:
            if path.is_symlink() or not path.is_file():
                self._cache.pop(path, None)
                return
            st = path.stat()
        except OSError:
            self._cache.pop(path, None)
            return
        previous = self._cache.get(path)
        tracked = self._tracked.get(path)
        if tracked is not None:
            previous = tracked.signature
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
                self._cache.pop(path, None)
                return
        self._cache[path] = (st.st_size, st.st_mtime_ns, content_hash)

    # ------------------------------------------------------------------
    # Background loop: events wake the poll; the poll keeps the
    # parent's debounce/dwell contract exactly.
    # ------------------------------------------------------------------
    def run(
        self,
        stop_event: threading.Event,
        paused_event: threading.Event | None = None,
    ) -> None:
        self._ensure_watches()
        while not stop_event.is_set():
            if paused_event is not None and paused_event.is_set():
                stop_event.wait(0.1)
                continue
            try:
                # Wait for filesystem activity (or the idle
                # cadence to elapse), then run the parent's poll:
                # stability is still proven across polls, never
                # assumed from a single event.
                self.drain_events(timeout=self.poll_interval)
                self.poll_once()
            except Exception:  # the watch must survive any bad cycle
                log.exception("inotify watcher cycle failed; continuing")
            # poll_once already consumed the elapsed interval via
            # the event wait; no additional blind sleep.
        if self._inotify is not None:
            try:
                self._inotify.close()
            except Exception:
                pass
            self._inotify = None
