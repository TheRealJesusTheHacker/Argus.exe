"""Shannon entropy analysis for ARGUS.EXE.

Entropy measures how "random" data looks, in bits per byte (0–8):

- plain text:            ~4.5
- native machine code:   ~6.0
- packed/encrypted data: ~7.2 and up

Malware is very often packed or encrypted to hide its contents, so a
region of near-maximum entropy inside an executable is a classic
telltale. Entropy alone proves nothing — installers and media files are
high-entropy too — so Argus treats it as one weighted signal among
many (see :mod:`argus.heuristics.signals`), never a verdict by itself.

Everything here is streamed: feed chunks of any size and memory stays
flat (byte counters plus one 4 KiB window buffer), whether the file is
1 KB or 60 MB.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

#: At or above this, data is considered high-entropy (packed/encrypted
#: territory). Calibrated: text ~4.5, native code ~6.0, packed ~7.2+.
HIGH_ENTROPY_THRESHOLD = 7.2

#: Windows at or above this entropy are merged into "high regions".
REGION_ENTROPY_THRESHOLD = 7.0

#: Sliding-window size for region analysis.
WINDOW_SIZE = 4096

#: Windows smaller than this are too noisy to judge regions by.
_MIN_REGION_WINDOW = 1024


def _entropy_from_counts(counts: list[int] | tuple[int, ...], total: int) -> float:
    """Shannon entropy (bits/byte) from a 256-bin byte histogram."""
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _add_counts(histogram: list[int], data: bytes) -> None:
    """Add *data*'s byte histogram into *histogram* (a 256-bin list).

    Bulk-counted with :class:`collections.Counter` (C-accelerated)
    instead of a per-byte Python loop — identical results, far less
    time on multi-MB streams.
    """
    for value, n in Counter(data).items():
        histogram[value] += n


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of an in-memory buffer (0.0–8.0 bits per byte)."""
    if not data:
        return 0.0
    counts = [0] * 256
    _add_counts(counts, data)
    return _entropy_from_counts(counts, len(data))


@dataclass(frozen=True)
class EntropyRegion:
    """A run of consecutive high-entropy windows."""

    offset: int
    length: int
    entropy: float  # peak window entropy inside the region


@dataclass
class EntropySummary:
    """Result of analysing one byte stream."""

    size: int = 0
    whole_entropy: float = 0.0
    max_window_entropy: float = 0.0
    high_regions: list[EntropyRegion] = field(default_factory=list)


class EntropyAnalyzer:
    """Streaming entropy analysis: whole-stream + sliding windows.

    Feed chunks of any size; window boundaries are tracked internally,
    so results do not depend on how the caller chunks the stream.
    """

    def __init__(self, window_size: int = WINDOW_SIZE) -> None:
        if window_size < _MIN_REGION_WINDOW:
            raise ValueError(f"window_size must be >= {_MIN_REGION_WINDOW}")
        self._window_size = window_size
        self._total_counts = [0] * 256
        self._total = 0
        self._win_counts = [0] * 256
        self._win_len = 0
        self._win_start = 0
        self._max_window_entropy = 0.0
        self._regions: list[EntropyRegion] = []

    # ------------------------------------------------------------------
    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        _add_counts(self._total_counts, chunk)
        self._total += len(chunk)

        view = chunk
        while view:
            room = self._window_size - self._win_len
            take = view[:room]
            _add_counts(self._win_counts, take)
            self._win_len += len(take)
            view = view[len(take):]
            if self._win_len == self._window_size:
                self._close_window()

    def _close_window(self) -> None:
        entropy = _entropy_from_counts(self._win_counts, self._win_len)
        if entropy > self._max_window_entropy:
            self._max_window_entropy = entropy
        if entropy >= REGION_ENTROPY_THRESHOLD:
            if self._regions and (
                self._regions[-1].offset + self._regions[-1].length == self._win_start
            ):
                last = self._regions[-1]
                self._regions[-1] = EntropyRegion(
                    offset=last.offset,
                    length=last.length + self._win_len,
                    entropy=max(last.entropy, entropy),
                )
            else:
                self._regions.append(
                    EntropyRegion(
                        offset=self._win_start, length=self._win_len, entropy=entropy
                    )
                )
        self._win_counts = [0] * 256
        self._win_start += self._win_len
        self._win_len = 0

    # ------------------------------------------------------------------
    def finish(self) -> EntropySummary:
        # A trailing partial window still counts toward the peak if it
        # is big enough to judge; it never forms a region on its own.
        if self._win_len >= _MIN_REGION_WINDOW:
            entropy = _entropy_from_counts(self._win_counts, self._win_len)
            if entropy > self._max_window_entropy:
                self._max_window_entropy = entropy
        return EntropySummary(
            size=self._total,
            whole_entropy=_entropy_from_counts(self._total_counts, self._total),
            max_window_entropy=self._max_window_entropy,
            high_regions=list(self._regions),
        )


class SectionEntropyTracker:
    """Per-range entropy: feed ``(offset, chunk)`` pairs, get the
    entropy of each configured byte range (e.g. PE sections) back.

    Chunks may span range boundaries; bytes outside every range are
    ignored. Memory is one 256-bin histogram per range.
    """

    def __init__(self, ranges: list[tuple[int, int]]) -> None:
        # ranges: (start, end) byte offsets, end exclusive
        self._ranges = list(ranges)
        self._counts: list[list[int]] = [[0] * 256 for _ in ranges]
        self._totals: list[int] = [0] * len(ranges)

    def feed(self, offset: int, chunk: bytes) -> None:
        if not chunk:
            return
        chunk_end = offset + len(chunk)
        for idx, (start, end) in enumerate(self._ranges):
            lo = max(offset, start)
            hi = min(chunk_end, end)
            if lo >= hi:
                continue
            piece = chunk[lo - offset : hi - offset]
            _add_counts(self._counts[idx], piece)
            self._totals[idx] += len(piece)

    def entropy_for(self, index: int) -> float | None:
        """Entropy of range *index*, or None if no bytes were fed."""
        total = self._totals[index]
        if total == 0:
            return None
        return _entropy_from_counts(self._counts[index], total)
