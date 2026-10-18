"""Tests for the risk scoring model: thresholds, short-circuit,
signature discount."""

from argus.detections import Verdict
from argus.heuristics.signals import Signal
from argus.scoring import (
    MALICIOUS_THRESHOLD,
    SIGNED_DISCOUNT,
    SUSPICIOUS_THRESHOLD,
    score_signals,
)


def sig(name: str, severity: str, points: int) -> Signal:
    return Signal(name=name, severity=severity, points=points, explanation="test")


def test_no_signals_is_clean():
    scored = score_signals([])
    assert scored.score == 0
    assert scored.verdict is Verdict.CLEAN
    assert scored.max_severity is None


def test_below_threshold_stays_clean():
    scored = score_signals([sig("a", "medium", SUSPICIOUS_THRESHOLD - 1)])
    assert scored.verdict is Verdict.CLEAN


def test_suspicious_threshold():
    scored = score_signals([sig("a", "high", SUSPICIOUS_THRESHOLD)])
    assert scored.verdict is Verdict.SUSPICIOUS


def test_malicious_threshold_from_sum():
    scored = score_signals(
        [sig("a", "high", 35), sig("b", "high", MALICIOUS_THRESHOLD - 35)]
    )
    assert scored.score == MALICIOUS_THRESHOLD
    assert scored.verdict is Verdict.MALICIOUS


def test_critical_combination_short_circuits():
    """Injection combo + high-entropy section is Malicious even with
    artificially tiny point values — combination over arithmetic."""
    scored = score_signals(
        [
            sig("process_injection_combo", "critical", 5),
            sig("high_entropy_executable_section", "high", 5),
        ]
    )
    assert scored.short_circuit is True
    assert scored.verdict is Verdict.MALICIOUS


def test_injection_alone_does_not_short_circuit():
    scored = score_signals([sig("process_injection_combo", "critical", 45)])
    assert scored.short_circuit is False
    assert scored.verdict is Verdict.SUSPICIOUS  # 45 points: strong, not proof


def test_signed_discount_lowers_score():
    signals = [sig("a", "high", 40)]
    unsigned = score_signals(signals, signed=False)
    signed = score_signals(signals, signed=True)
    assert signed.score == 40 - SIGNED_DISCOUNT
    assert signed.score < unsigned.score
    assert signed.score > 0


def test_signed_discount_never_erases_malicious_level():
    """Raw Malicious-level score + signature -> at worst Suspicious,
    never Clean."""
    signals = [sig("a", "critical", 45), sig("b", "high", 25)]  # raw 70
    scored = score_signals(signals, signed=True)
    assert scored.raw_score == 70
    assert scored.score == 70 - SIGNED_DISCOUNT  # 55
    assert scored.verdict is Verdict.SUSPICIOUS


def test_signed_never_cancels_short_circuit():
    scored = score_signals(
        [
            sig("process_injection_combo", "critical", 45),
            sig("high_entropy_executable_section", "high", 25),
        ],
        signed=True,
    )
    assert scored.short_circuit is True
    assert scored.verdict is Verdict.MALICIOUS


def test_max_severity_reported():
    scored = score_signals(
        [sig("a", "low", 5), sig("b", "critical", 45), sig("c", "medium", 15)]
    )
    assert scored.max_severity == "critical"
