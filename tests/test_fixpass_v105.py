"""Regression tests for the v1.0.5 fix pass.

The v1.0.4 Windows CI build failed on exactly three tests that all
passed on Linux. Two of the fixes touched production code; they
are pinned here:

- ``init_db`` publishing: Windows refuses ``os.replace`` over a
  file that is still open (WinError 5). The publish step now
  surfaces any OS failure as :class:`SignatureError` — the
  signatures module's one error type — with the likely cause
  named, instead of leaking a raw ``PermissionError``. (The
  companion fix in ``test_fixpass_v102.py`` closes the test's own
  database handle before re-init, as every real caller does.)

- Rule-matcher time budget: the budget is now also polled
  between rules *inside* a feed, so a single huge chunk cannot
  run unboundedly far past the per-file budget. Driven here with
  a deterministic advancing clock — no wall-clock dependence
  (the v1.0.4 budget test's reliance on real-clock resolution is
  what failed on Windows; see ``test_fixpass_v104.py``).

The third failure (dashboard service-managed) was a test-only
fix in ``test_gui_smoke.py``: production's SCM confirmation gate
is correct and stays; the test now simulates the SCM.
"""

from __future__ import annotations

import pytest

from argus.rules import Rule, RuleMatcher
from argus.signatures import SignatureError, init_db


def _rule_spec(name: str, pattern: dict) -> dict:
    return {
        "name": name,
        "description": "test",
        "severity": "high",
        "condition": "any",
        "patterns": [pattern],
    }


# ----------------------------------------------------------------------
# init_db publish failures surface as SignatureError
# ----------------------------------------------------------------------
def test_init_db_publish_failure_is_signature_error(tmp_path, monkeypatch):
    """Simulate the Windows failure mode exactly: os.replace
    denied (WinError 5 — the destination is open somewhere).
    init_db must translate it to SignatureError and must not
    leave the unpublished temp database behind."""
    import argus.signatures as signatures

    def denied(src, dst):
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(signatures.os, "replace", denied)
    with pytest.raises(SignatureError):
        init_db(tmp_path / "sigs.sigdb", seed=True)
    assert list(tmp_path.glob("*.tmp")) == []


# ----------------------------------------------------------------------
# Rule budget trips mid-feed, not only at feed boundaries
# ----------------------------------------------------------------------
class _AdvancingClock:
    """Each read reports a time ``step`` later than the previous
    read, so elapsed time grows exactly as fast as the matcher
    polls — deterministically, on every platform."""

    def __init__(self, step: float = 1.0) -> None:
        self._next = 0.0
        self._step = step

    def __call__(self) -> float:
        value = self._next
        self._next += self._step
        return value


def test_rule_match_budget_trips_mid_feed():
    rules = [
        Rule.from_dict(_rule_spec(f"R{i}", {"text": f"needle-{i}"}))
        for i in range(50)
    ]
    matcher = RuleMatcher(rules, time_budget=2.0)
    matcher._clock = _AdvancingClock(step=1.0)
    matcher.feed(b"needle-0 in here, and needle-49 too")
    # Clock reads: the feed entry starts the clock (0.0); the
    # between-rule polls then read 1.0 and 2.0 (within budget) and
    # 3.0 — past it. Matching must stop DURING this single feed,
    # not at some later feed boundary: before the v1.0.5 fix the
    # budget was only polled between feeds, so this feed would
    # have run to completion with budget_exceeded still False.
    assert matcher.budget_exceeded is True
    hits = {h.name for h in matcher.finish()}
    assert "R0" in hits  # evaluated before the budget blew
    assert "R49" not in hits  # never reached — coverage is partial
