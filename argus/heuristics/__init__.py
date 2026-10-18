"""Heuristic analysis for ARGUS.EXE (Phase 2).

Submodules:

- :mod:`argus.heuristics.entropy` — Shannon entropy analysis (whole
  file and sliding-window regions) for spotting packed/encrypted data.
- :mod:`argus.heuristics.pe` — a pure-stdlib Windows PE parser.
- :mod:`argus.heuristics.signals` — the signal library: weighted,
  plain-language risk signals derived from PE structure, file content,
  script content, and filenames.
- :mod:`argus.heuristics.analyze` — orchestration: run the right
  analysis for a file and collect its signals.

Heuristics never *prove* a file is malware — they score how strongly a
file resembles known-bad techniques so unknown threats get caught by
what they look like and do, not just by name. Every signal is explained
in plain language; see :mod:`argus.scoring` for how signals combine
into a verdict.
"""

from __future__ import annotations

from .analyze import HeuristicReport, analyze_file
from .entropy import (
    HIGH_ENTROPY_THRESHOLD,
    EntropyAnalyzer,
    EntropySummary,
    shannon_entropy,
)
from .pe import PEError, PEInfo, parse_pe
from .signals import Signal

__all__ = [
    "HIGH_ENTROPY_THRESHOLD",
    "EntropyAnalyzer",
    "EntropySummary",
    "HeuristicReport",
    "PEError",
    "PEInfo",
    "Signal",
    "analyze_file",
    "parse_pe",
    "shannon_entropy",
]
