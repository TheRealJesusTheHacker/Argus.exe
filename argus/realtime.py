"""Real-time protection engine for ARGUS.EXE.

This module ties the pieces together into always-on protection:

- a :class:`~argus.watcher.DirectoryWatcher` notices new and changed
  files in the watched folders (downloads, desktop, documents, temp);
- a :class:`ProcessMonitor` notices programs starting and has the
  file they were launched from scanned;
- a worker thread scans everything with the full Phase 1 + 2 engine
  (signatures, pattern rules, heuristics, scoring);
- a **response policy** turns each verdict into an outcome by
  severity: Critical/High ask for quarantine, Medium alerts, Low is
  logged (all configurable).

**Honesty box — what "real-time" means here.** Files are
scanned the moment they finish being written. Programs are scanned
when the process monitor *notices* them starting (it polls), which
means a fast program may already be running when its scan completes:
Argus raises the alarm immediately, but it does not yet *block* a
program before it runs. True pre-execution blocking needs the Windows
service + driver work in the install phase, and Argus will not claim
otherwise. This module never deletes or moves anything itself: it
emits *action events*, and :mod:`argus.actions` carries them out
under the user's ``realtime_default`` policy — queued for a human
decision by default; deletion is never automatic, under any policy.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import sys
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import ArgusConfig
from .detections import Verdict
from .rules import BUILTIN_RULES, Rule
from .scanner import ScannedFile, scan_file, scan_named_streams
from .signatures import SignatureDB
from .watcher import DirectoryWatcher

log = logging.getLogger("argus.realtime")

#: How many times a locked (unreadable) file is re-queued with
#: backoff before Argus reports it as NotScanned and stops trying.
MAX_LOCKED_RETRIES = 5

#: Hard bound on pending locked-file retry timers (v1.1.0 P2).
#: The retry list is pruned — finished timers, timers whose file
#: vanished, and timers for files that exhausted their retries
#: are dropped (see :meth:`RealtimeEngine._prune_retry_timers`) —
#: and this cap bounds what pruning alone cannot: a flood of
#: distinct locked files cannot grow the list without limit.
MAX_PENDING_RETRY_TIMERS = 256


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ----------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------
@dataclass
class RealtimeEvent:
    """Something the user (or a future GUI/service) should know about.

    ``kind`` is one of:

    - ``"detection"`` — a scanned file was flagged;
    - ``"action"`` — the response policy asks for something to be done
      (quarantine/delete). Emitted here; carried out by
      :mod:`argus.actions` under the user's real-time policy, never
      by this module, and deletion always waits for a human;
    - ``"process"`` — a program was seen starting and its file scanned;
    - ``"info"`` — operational notes (unreadable files, oversized
      files, watcher problems).
    """

    kind: str
    message: str
    timestamp: str = field(default_factory=_utcnow_iso)
    path: str | None = None
    verdict: str | None = None
    severity: str | None = None
    action: str | None = None
    source: str | None = None  # "watch" | "process"
    sha256: str | None = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "kind": self.kind,
            "message": self.message,
            "path": self.path,
            "verdict": self.verdict,
            "severity": self.severity,
            "action": self.action,
            "source": self.source,
            "sha256": self.sha256,
        }


# ----------------------------------------------------------------------
# Process monitoring (portable polling — see the honesty box above)
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    image_path: Path | None


def list_processes_procfs() -> list[ProcessInfo]:
    """Enumerate processes from /proc (Linux). Never raises."""
    processes: list[ProcessInfo] = []
    proc_root = Path("/proc")
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return processes
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            image = os.readlink(entry / "exe")
            # A deleted-but-running binary shows a " (deleted)" suffix.
            if image.endswith(" (deleted)"):
                image = image[: -len(" (deleted)")]
            image_path: Path | None = Path(image)
            name = image_path.name
        except OSError:
            image_path = None
            try:
                name = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue  # process vanished mid-enumeration — normal
        processes.append(ProcessInfo(pid=pid, name=name, image_path=image_path))
    return processes


def _declare_toolhelp_prototypes(kernel32, entry_type) -> None:
    """Declare the ctypes signatures for the Toolhelp32 / process
    APIs used below (split out so tests can verify them anywhere).

    The handle-returning functions MUST have ``restype = c_void_p``:
    with the default int restype a 64-bit handle is truncated to 32
    bits, and the INVALID_HANDLE_VALUE comparison (and every handle
    use after it) is wrong on 64-bit Windows.
    """
    import ctypes
    from ctypes import wintypes

    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.CreateToolhelp32Snapshot.argtypes = [
        wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32FirstW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(entry_type),
    ]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(entry_type),
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [
        wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD,
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]


def list_processes_windows() -> list[ProcessInfo]:
    """Enumerate processes on Windows via Toolhelp32 (ctypes, no
    third-party modules). Best effort: any failure returns what was
    gathered so far. Only used on win32."""
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    processes: list[ProcessInfo] = []
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    _declare_toolhelp_prototypes(kernel32, PROCESSENTRY32W)
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return processes
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32ProcessID)
            name = entry.szExeFile
            image_path: Path | None = None
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if handle:
                try:
                    buffer = ctypes.create_unicode_buffer(1024)
                    size = wintypes.DWORD(len(buffer))
                    if kernel32.QueryFullProcessImageNameW(
                        handle, 0, buffer, ctypes.byref(size)
                    ):
                        image_path = Path(buffer.value)
                finally:
                    kernel32.CloseHandle(handle)
            processes.append(ProcessInfo(pid=pid, name=name, image_path=image_path))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    except Exception:
        log.exception("Windows process enumeration failed partway")
    finally:
        kernel32.CloseHandle(snapshot)
    return processes


def default_process_enumerator() -> Callable[[], list[ProcessInfo]]:
    if sys.platform.startswith("linux"):
        return list_processes_procfs
    if sys.platform == "win32":
        return list_processes_windows
    return lambda: []


class ProcessMonitor:
    """Polls the process list and reports programs that just started.

    A program counts as "launched" when a pid appears that was not in
    the previous snapshot, or when a known pid suddenly points at a
    different image (pid reuse). The baseline snapshot at startup is
    silent — Argus does not raise events for everything that was
    already running before it started watching.
    """

    def __init__(
        self,
        on_launch: Callable[[ProcessInfo], None] | None = None,
        enumerator: Callable[[], list[ProcessInfo]] | None = None,
    ) -> None:
        self.on_launch = on_launch
        self._enumerate = enumerator or default_process_enumerator()
        self._seen: dict[int, str | None] = {}
        self._baselined = False
        self.poll_count = 0

    def poll_once(self) -> list[ProcessInfo]:
        """Enumerate once; return (and report) newly launched programs."""
        self.poll_count += 1
        try:
            current = self._enumerate()
        except Exception:
            log.exception("process enumeration failed; continuing")
            return []
        launched: list[ProcessInfo] = []
        now: dict[int, str | None] = {}
        for proc in current:
            key = str(proc.image_path) if proc.image_path else None
            now[proc.pid] = key
            if not self._baselined:
                continue
            if proc.pid not in self._seen or self._seen[proc.pid] != key:
                launched.append(proc)
        self._seen = now
        self._baselined = True
        for proc in launched:
            if self.on_launch is not None:
                try:
                    self.on_launch(proc)
                except Exception:
                    log.exception("process on_launch callback failed for pid %s", proc.pid)
        return launched

    def run(
        self,
        stop_event: threading.Event,
        paused_event: threading.Event | None = None,
        interval: float = 2.0,
    ) -> None:
        while not stop_event.is_set():
            if paused_event is not None and paused_event.is_set():
                stop_event.wait(0.1)
                continue
            try:
                self.poll_once()
            except Exception:
                log.exception("process monitor poll failed; continuing")
            stop_event.wait(interval)


def _create_watcher(dirs, **kwargs) -> DirectoryWatcher:
    """The watcher for this platform: on Linux, the inotify
    backend (the kernel reports changes as they happen); anywhere
    else — and on a Linux machine where inotify cannot be
    initialised — the portable polling watcher.

    The fallback is stated, not silent: it is logged here and the
    engine's status snapshot reports ``watcher_backend`` so the
    service heartbeat shows which backend is actually running.
    Detection semantics are identical either way (same debounce,
    same dwell deadline, same signatures); only notice latency
    differs."""
    if sys.platform.startswith("linux"):
        try:
            from .inotify_watcher import (
                InotifyDirectoryWatcher,
                InotifyUnavailable,
            )

            try:
                return InotifyDirectoryWatcher(dirs, **kwargs)
            except InotifyUnavailable as exc:
                log.warning(
                    "inotify is unavailable on this machine (%s) — "
                    "real-time watch falls back to polling: same "
                    "detection, slightly slower notice.",
                    exc,
                )
        except Exception:
            log.exception(
                "the inotify watcher could not be constructed — "
                "falling back to the polling watcher"
            )
    return DirectoryWatcher(dirs, **kwargs)


# ----------------------------------------------------------------------
# The engine
# ----------------------------------------------------------------------
@dataclass
class RealtimeStats:
    scans_completed: int = 0
    detections: int = 0
    actions_emitted: int = 0
    files_excluded: int = 0
    files_oversized: int = 0
    scan_errors: int = 0
    processes_seen: int = 0


@dataclass
class _WorkItem:
    path: Path
    source: str  # "watch" | "process"
    process: ProcessInfo | None = None
    #: Bypass the real-time size gate (a deferred full scan queued
    #: by the oversize path — the file gets its full check once).
    force: bool = False
    #: The watcher force-reported this file at its dwell deadline
    #: while it was still changing.
    forced_dwell: bool = False
    #: How many times this item has been re-queued (locked retries).
    attempts: int = 0


class RealtimeEngine:
    """Always-on protection: watch -> queue -> scan -> policy -> events.

    Lifecycle: construct, :meth:`start`, :meth:`stop`. ``pause()``
    halts new polling and scanning until ``resume()``. Events are
    delivered to every callback in ``on_event`` and kept in a bounded
    in-memory log (:meth:`recent_events`).
    """

    def __init__(
        self,
        config: ArgusConfig,
        db: SignatureDB,
        rules: list[Rule] | None = None,
        on_event: Callable[[RealtimeEvent], None] | None = None,
    ) -> None:
        self.config = config
        self.db = db
        self.rules = rules if rules is not None else BUILTIN_RULES
        self.stats = RealtimeStats()
        self._callbacks: list[Callable[[RealtimeEvent], None]] = []
        if on_event is not None:
            self._callbacks.append(on_event)
        self._events: deque[RealtimeEvent] = deque(maxlen=5000)
        self._queue: queue.Queue[_WorkItem | None] = queue.Queue()
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._threads: list[threading.Thread] = []
        self._started_at: str | None = None
        self._lock = threading.Lock()

        self.watcher = _create_watcher(
            config.watch_dirs,
            poll_interval=config.poll_interval,
            stable_polls=config.stable_polls,
            on_ready=self._on_file_ready,
            max_dwell_seconds=config.max_dwell_seconds,
        )
        self.process_monitor = ProcessMonitor(on_launch=self._on_process_launch)
        self._retry_timers: list[threading.Timer] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._started_at is not None and not self._stop.is_set()

    @property
    def paused(self) -> bool:
        return self._paused.is_set()

    @property
    def started_at(self) -> str | None:
        return self._started_at

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._paused.clear()
        self._started_at = _utcnow_iso()
        self._threads = [
            threading.Thread(target=self._scan_worker, name="argus-scan", daemon=True),
            threading.Thread(
                target=self.watcher.run,
                args=(self._stop, self._paused),
                name="argus-watch",
                daemon=True,
            ),
        ]
        if self.config.process_monitor_enabled:
            self._threads.append(
                threading.Thread(
                    target=self.process_monitor.run,
                    args=(self._stop, self._paused),
                    kwargs={"interval": self.config.process_poll_interval},
                    name="argus-procmon",
                    daemon=True,
                )
            )
        for thread in self._threads:
            thread.start()
        log.info(
            "real-time protection started; watching %s",
            ", ".join(str(d) for d in self.config.watch_dirs),
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        for timer in self._retry_timers:
            timer.cancel()
        self._retry_timers = []
        self._queue.put(None)  # wake the worker so it can exit
        for thread in self._threads:
            thread.join(timeout=timeout)
        self._threads = []
        log.info("real-time protection stopped")

    def pause(self) -> None:
        self._paused.set()
        log.info("real-time protection paused")

    def resume(self) -> None:
        self._paused.clear()
        log.info("real-time protection resumed")

    def add_event_callback(self, callback: Callable[[RealtimeEvent], None]) -> None:
        self._callbacks.append(callback)

    def recent_events(self, limit: int = 100) -> list[RealtimeEvent]:
        with self._lock:
            return list(self._events)[-limit:]

    # ------------------------------------------------------------------
    # Intake: watcher + process monitor feed the queue
    # ------------------------------------------------------------------
    def _on_file_ready(self, path: Path) -> None:
        self._queue.put(
            _WorkItem(
                path=path,
                source="watch",
                forced_dwell=self.watcher.consume_forced(path),
            )
        )

    def _on_process_launch(self, proc: ProcessInfo) -> None:
        with self._lock:
            self.stats.processes_seen += 1
        if proc.image_path is None:
            self._emit(
                RealtimeEvent(
                    kind="info",
                    source="process",
                    message=(
                        f"A program started ({proc.name}, process {proc.pid}) "
                        "but Argus could not see which file it came from, "
                        "so there was nothing to scan."
                    ),
                )
            )
            return
        self._queue.put(_WorkItem(path=proc.image_path, source="process", process=proc))

    def submit_scan(self, path: Path, source: str = "watch") -> None:
        """Queue a file for scanning (used by watchers, tests, tools)."""
        self._queue.put(_WorkItem(path=Path(path), source=source))

    # ------------------------------------------------------------------
    # Worker: scan, judge, apply policy
    # ------------------------------------------------------------------
    def _scan_worker(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is None:
                continue
            if self._paused.is_set():
                # Hold the item until resumed (or stopped).
                while self._paused.is_set() and not self._stop.is_set():
                    self._stop.wait(0.1)
                if self._stop.is_set():
                    break
            try:
                self._process(item)
            except Exception:  # one bad file must never kill protection
                log.exception("scan failed unexpectedly for %s", item.path)
                with self._lock:
                    self.stats.scan_errors += 1

    def _process(self, item: _WorkItem) -> None:
        path = item.path
        cfg = self.config

        try:
            size = path.stat().st_size
        except OSError:
            self._emit(
                RealtimeEvent(
                    kind="info",
                    source=item.source,
                    path=str(path),
                    message=(
                        f"{path.name} disappeared before Argus could scan it. "
                        "Nothing to do — files that vanish on their own are "
                        "usually temp files being cleaned up."
                    ),
                )
            )
            return

        if item.forced_dwell:
            self._emit(
                RealtimeEvent(
                    kind="info",
                    source=item.source,
                    path=str(path),
                    message=(
                        f"{path.name} kept changing for more than "
                        f"{cfg.max_dwell_seconds:.0f} seconds without "
                        "settling, so Argus scanned it anyway (dwell "
                        "deadline) — a file that never sits still does "
                        "not get a free pass."
                    ),
                )
            )

        if size > cfg.max_realtime_file_size and not item.force:
            with self._lock:
                self.stats.files_oversized += 1
            # Detection-grade, not info-only: an unscanned oversized
            # drop is exactly the kind of thing a user must SEE, and
            # the file still gets a full (deferred) scan — being big
            # must not be a way to dodge the scanner entirely.
            self._emit(
                RealtimeEvent(
                    kind="detection",
                    source=item.source,
                    path=str(path),
                    verdict=Verdict.SUSPICIOUS.value,
                    severity="medium",
                    message=(
                        f"{path.name} is {size / (1024 * 1024):.0f} MB — "
                        f"larger than the "
                        f"{cfg.max_realtime_file_size // (1024 * 1024)} MB "
                        "real-time limit. Argus has queued a full scan "
                        "of it; until that finishes, treat it as "
                        "unverified."
                    ),
                )
            )
            self._queue.put(
                _WorkItem(path=path, source=item.source, force=True)
            )
            return

        scanned = scan_file(
            path,
            self.db,
            self.rules,
            heuristics=cfg.heuristics,
            exclusions=cfg.exclusions,
        )
        with self._lock:
            self.stats.scans_completed += 1

        if scanned.excluded:
            with self._lock:
                self.stats.files_excluded += 1
            return

        if not scanned.result.ok:
            with self._lock:
                self.stats.scan_errors += 1
            if scanned.assessment.not_scanned:
                self._handle_locked(item)
            else:
                self._emit(
                    RealtimeEvent(
                        kind="info",
                        source=item.source,
                        path=str(path),
                        message=(
                            f"Argus could not scan {path.name}: "
                            f"{scanned.result.error}. The file may be locked by "
                            "another program. It will be checked again if it changes."
                        ),
                    )
                )
            return

        self._report(item, scanned)

        if item.source in ("watch", "process"):
            # Named NTFS data streams on the file get the same
            # treatment on BOTH intake paths (v1.1.0 P2): a file
            # the watcher noticed AND the image a process launched
            # from. ADS enumeration lives in the scanner
            # (scan_named_streams / iter_data_streams) and was
            # previously wired only to the watch path, so a
            # launched program's hidden streams were never checked
            # in real time. Windows only; a no-op elsewhere.
            for stream_scanned in scan_named_streams(
                path, self.db, self.rules,
                heuristics=cfg.heuristics, exclusions=cfg.exclusions,
            ):
                if stream_scanned.result.ok and not stream_scanned.excluded:
                    self._report(
                        _WorkItem(path=stream_scanned.path, source=item.source),
                        stream_scanned,
                    )

    def _prune_retry_timers(self, *, drop_path: Path | None = None) -> int:
        """Drop stale locked-file retry timers; return how many.

        An entry is dropped (and its timer cancelled) when it has
        already fired, when its file has vanished, when its retry
        count exceeds :data:`MAX_LOCKED_RETRIES`, or when it names
        *drop_path* (a file whose retries are finished). Called
        whenever a retry is scheduled, whenever one fires, from
        the status snapshot, and before the exhaustion report —
        the list can no longer grow by one entry per locked file
        forever (v1.1.0 P2).
        """
        kept: list[threading.Timer] = []
        dropped = 0
        for timer in list(self._retry_timers):
            timer_path = getattr(timer, "argus_path", None)
            attempts = getattr(timer, "argus_attempts", None)
            drop = bool(timer.finished.is_set())
            if not drop and drop_path is not None and timer_path is not None:
                drop = Path(timer_path) == drop_path
            if not drop and attempts is not None:
                drop = attempts > MAX_LOCKED_RETRIES
            if not drop and timer_path is not None:
                try:
                    drop = not Path(timer_path).exists()
                except OSError:
                    drop = True
            if drop:
                dropped += 1
                try:
                    timer.cancel()
                except Exception:
                    pass
            else:
                kept.append(timer)
        self._retry_timers[:] = kept
        return dropped

    def _handle_locked(self, item: _WorkItem) -> None:
        """A file Argus could not read (locked/denied): retry with
        backoff a bounded number of times, then report it plainly
        as NotScanned — never as scanned-and-clean."""
        path = item.path
        if item.attempts < MAX_LOCKED_RETRIES:
            delay = min(2.0 ** item.attempts, 30.0)
            retry = _WorkItem(
                path=path,
                source=item.source,
                process=item.process,
                force=item.force,
                attempts=item.attempts + 1,
            )
            self._prune_retry_timers()
            holder: dict = {}

            def _fire() -> None:
                fired = holder.get("timer")
                if fired is not None and fired in self._retry_timers:
                    self._retry_timers.remove(fired)
                self._requeue(retry)

            timer = threading.Timer(delay, _fire)
            timer.daemon = True
            # Bookkeeping for _prune_retry_timers (attributes on
            # the Timer object keep the list's element type —
            # plain Timers — unchanged for stop() and callers).
            timer.argus_path = path  # type: ignore[attr-defined]
            timer.argus_attempts = retry.attempts  # type: ignore[attr-defined]
            holder["timer"] = timer
            self._retry_timers.append(timer)
            # Bound the list even under a flood of distinct
            # locked files: the oldest pending retries are
            # cancelled and dropped past the cap.
            while len(self._retry_timers) > MAX_PENDING_RETRY_TIMERS:
                oldest = self._retry_timers.pop(0)
                try:
                    oldest.cancel()
                except Exception:
                    pass
            timer.start()
            log.info(
                "could not read %s (locked?) — retry %d/%d in %.0fs",
                path, retry.attempts, MAX_LOCKED_RETRIES, delay,
            )
            return
        # Retries exhausted: no pending timer for this file may
        # linger — prune every entry that names it.
        self._prune_retry_timers(drop_path=path)
        self._emit(
            RealtimeEvent(
                kind="detection",
                source=item.source,
                path=str(path),
                verdict=Verdict.NOT_SCANNED.value,
                severity=None,
                message=(
                    f"Argus could not scan {path.name}: the file stayed "
                    f"locked or unreadable through {MAX_LOCKED_RETRIES} "
                    "retries. It has NOT been checked and is not known "
                    "to be clean. Close the program using it and run a "
                    "manual scan."
                ),
            )
        )

    def _requeue(self, item: _WorkItem) -> None:
        self._prune_retry_timers()
        if self._stop.is_set():
            return
        try:
            exists = item.path.exists()
        except OSError:
            exists = False
        if not exists:
            # The locked file vanished while its retry was
            # pending: the retry is dropped, never queued, and
            # any other pending entries for it are pruned.
            self._prune_retry_timers(drop_path=item.path)
            return
        self._queue.put(item)

    # ------------------------------------------------------------------
    # Reporting + response policy
    # ------------------------------------------------------------------
    def _report(self, item: _WorkItem, scanned: ScannedFile) -> None:
        assessment = scanned.assessment
        path = scanned.path

        if item.source == "process":
            proc = item.process
            who = (
                f"{proc.name} (process {proc.pid})"
                if proc is not None
                else "a program"
            )
            self._emit(
                RealtimeEvent(
                    kind="process",
                    source="process",
                    path=str(path),
                    verdict=scanned.verdict.value,
                    sha256=scanned.result.sha256,
                    message=(
                        f"{who} just started. Argus scanned the file it "
                        f"launched from — verdict: {scanned.verdict.value}. "
                        "Note: the scan happens as the program starts; "
                        "stopping a program *before* it runs arrives with "
                        "the service phase of Argus."
                    ),
                )
            )

        if not assessment.flagged:
            return

        verdict = scanned.verdict
        severity = assessment.max_severity or (
            "high" if verdict is Verdict.MALICIOUS else "medium"
        )
        reasons = [d.reason for d in assessment.detections]
        reasons += [s.explanation for s in assessment.signals]
        reason_text = " ".join(reasons) if reasons else "It matched Argus's checks."
        with self._lock:
            self.stats.detections += 1
        self._emit(
            RealtimeEvent(
                kind="detection",
                source=item.source,
                path=str(path),
                verdict=verdict.value,
                severity=severity,
                sha256=scanned.result.sha256,
                message=(
                    f"Argus flagged {path.name} as {verdict.value} "
                    f"(severity: {severity.capitalize()}). {reason_text}"
                ),
            )
        )

        action = self.config.action_for(severity)
        if action in ("quarantine", "delete"):
            with self._lock:
                self.stats.actions_emitted += 1
            verb = "quarantine" if action == "quarantine" else "delete"
            self._emit(
                RealtimeEvent(
                    kind="action",
                    source=item.source,
                    path=str(path),
                    verdict=verdict.value,
                    severity=severity,
                    action=action,
                    sha256=scanned.result.sha256,
                    message=(
                        f"Policy asks to {verb} {path.name} "
                        f"(severity: {severity.capitalize()}). What happens "
                        f"next follows your real-time setting "
                        f"(currently '{self.config.realtime_default}'): by "
                        "default the request waits in the pending-actions "
                        "queue for your decision, and Argus never deletes "
                        "a file on its own."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Event plumbing
    # ------------------------------------------------------------------
    def _emit(self, event: RealtimeEvent) -> None:
        with self._lock:
            self._events.append(event)
        if self.config.event_log_file:
            try:
                log_path = Path(self.config.event_log_file)
                if log_path.parent and not log_path.parent.exists():
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict()) + "\n")
            except OSError:
                log.exception("could not write event log %s", self.config.event_log_file)
        for callback in list(self._callbacks):
            try:
                callback(event)
            except Exception:
                log.exception("event callback failed")

    def status_snapshot(self) -> dict:
        """Numbers the service layer publishes in its heartbeat."""
        # The heartbeat is the engine's regular housekeeping
        # moment: stale locked-file retries are pruned here too.
        self._prune_retry_timers()
        with self._lock:
            stats = self.stats
            snapshot = {
                "watcher_backend": self.watcher.backend,
                "files_watched": self.watcher.stats.files_tracked,
                "scans_completed": stats.scans_completed,
                "detections": stats.detections,
                "actions_emitted": stats.actions_emitted,
                "files_excluded": stats.files_excluded,
                "files_oversized": stats.files_oversized,
                "scan_errors": stats.scan_errors,
                "processes_seen": stats.processes_seen,
            }
        return snapshot
