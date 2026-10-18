"""Tests for entropy analysis: calibration, windows, regions, sections."""

from argus.heuristics.entropy import (
    EntropyAnalyzer,
    SectionEntropyTracker,
    shannon_entropy,
)
from tests.pe_fixtures import code_bytes, packed_bytes

TEXT = (b"The quick brown fox jumps over the lazy dog. " * 400)[:16384]


def test_entropy_known_values():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    # Uniform over 256 symbols -> exactly 8 bits/byte.
    assert abs(shannon_entropy(bytes(range(256)) * 16) - 8.0) < 1e-9
    # Uniform over 2 symbols -> exactly 1 bit/byte.
    assert abs(shannon_entropy(b"\x00\xff" * 500) - 1.0) < 1e-9


def test_entropy_calibration_bands():
    """The bands the thresholds are calibrated against:
    text ~4.5, native code ~6.0, packed ~7.2+."""
    text_h = shannon_entropy(TEXT)
    assert 3.5 < text_h < 5.5
    code_h = shannon_entropy(code_bytes(16384))
    assert 5.5 < code_h < 6.8
    packed_h = shannon_entropy(packed_bytes(16384))
    assert packed_h > 7.2


def test_analyzer_whole_and_windows():
    data = TEXT + packed_bytes(8192)
    analyzer = EntropyAnalyzer()
    analyzer.feed(data)
    summary = analyzer.finish()
    assert summary.size == len(data)
    assert summary.max_window_entropy > 7.5  # the packed half
    assert 4.0 < summary.whole_entropy < 8.0


def test_analyzer_chunking_does_not_change_results():
    data = packed_bytes(10000) + TEXT
    one_shot = EntropyAnalyzer()
    one_shot.feed(data)
    dribbled = EntropyAnalyzer()
    for i in range(0, len(data), 997):  # awkward chunk size on purpose
        dribbled.feed(data[i : i + 997])
    a, b = one_shot.finish(), dribbled.finish()
    assert a.whole_entropy == b.whole_entropy
    assert a.max_window_entropy == b.max_window_entropy
    assert a.high_regions == b.high_regions


def test_analyzer_high_regions_located_and_merged():
    data = TEXT[:8192] + packed_bytes(8192) + TEXT[:4096]
    analyzer = EntropyAnalyzer()
    analyzer.feed(data)
    summary = analyzer.finish()
    assert len(summary.high_regions) == 1
    region = summary.high_regions[0]
    assert region.offset == 8192
    assert region.length == 8192
    assert region.entropy > 7.5


def test_analyzer_no_regions_in_plain_text():
    analyzer = EntropyAnalyzer()
    analyzer.feed(TEXT)
    summary = analyzer.finish()
    assert summary.high_regions == []


def test_section_tracker_splits_across_boundaries():
    first = TEXT[:4096]
    second = packed_bytes(4096)
    data = first + second
    tracker = SectionEntropyTracker([(0, 4096), (4096, 8192)])
    # Feed in chunks that straddle the boundary.
    tracker.feed(0, data[:2000])
    tracker.feed(2000, data[2000:6000])
    tracker.feed(6000, data[6000:])
    assert tracker.entropy_for(0) < 5.5
    assert tracker.entropy_for(1) > 7.5


def test_section_tracker_empty_range_is_none():
    tracker = SectionEntropyTracker([(0, 100)])
    assert tracker.entropy_for(0) is None
