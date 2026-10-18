"""End-to-end Phase 2 tests: scanner + CLI with heuristics on the
fixture corpus — packed injector, clean PE, signed PE, scripts."""

import json

import pytest

from argus.cli import EXIT_CLEAN, EXIT_DETECTIONS, main
from argus.detections import Verdict
from argus.rules import BUILTIN_RULES
from argus.scanner import scan_path
from argus.signatures import SignatureDB, init_db
from tests.pe_fixtures import (
    RWX_CHARS,
    TEXT_CHARS,
    PEBuilder,
    clean_pe,
    code_bytes,
    packed_injector_pe,
)

BENIGN_PS = "Write-Host 'hello'\nGet-ChildItem .\\docs\n"
ENCODED_PS = "powershell.exe -nop -enc " + "SQBFAFgA" * 30 + "\n"


def _discount_pe(signed: bool) -> bytes:
    """Injection imports + a writable/executable section with ordinary
    (low-entropy) content: raw score 45 + 25 = 70, no short-circuit."""
    builder = (
        PEBuilder()
        .add_section(".text", code_bytes(4096), TEXT_CHARS)
        .add_section(".rwx", code_bytes(2048), RWX_CHARS)
        .set_imports(
            {
                "KERNEL32.dll": [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "ExitProcess",
                ]
            }
        )
        .set_entry(0)
    )
    if signed:
        builder.set_cert(0x1000)
    return builder.build()


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    with SignatureDB.open(path) as handle:
        yield handle


@pytest.fixture()
def tree(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "injector.exe").write_bytes(packed_injector_pe())
    (root / "clean.exe").write_bytes(clean_pe())
    (root / "benign.ps1").write_text(BENIGN_PS)
    (root / "encoded.ps1").write_text(ENCODED_PS)
    return root


def _by_name(report):
    return {f.path.name: f for f in report.files}


def test_fixture_corpus_scores_correctly(tree, db):
    report = scan_path(tree, db, BUILTIN_RULES)
    files = _by_name(report)

    injector = files["injector.exe"]
    assert injector.verdict is Verdict.MALICIOUS
    assert injector.assessment.score >= 60
    names = {s.name for s in injector.assessment.signals}
    assert "process_injection_combo" in names
    assert "high_entropy_executable_section" in names
    assert injector.assessment.max_severity == "critical"

    assert files["clean.exe"].verdict is Verdict.CLEAN
    assert files["clean.exe"].assessment.signals == []
    assert files["clean.exe"].assessment.score == 0

    assert files["benign.ps1"].verdict is Verdict.CLEAN

    encoded = files["encoded.ps1"]
    assert encoded.verdict is Verdict.SUSPICIOUS
    assert "encoded_powershell_command" in {
        s.name for s in encoded.assessment.signals
    }

    assert report.verdict is Verdict.MALICIOUS


def test_heuristics_disabled_means_no_signals(tree, db):
    report = scan_path(tree, db, BUILTIN_RULES, heuristics=False)
    for scanned in report.files:
        assert scanned.assessment.signals == []
        assert scanned.assessment.score == 0
    # Phase 1 still flags the injector's import strings via rules.
    injector = _by_name(report)["injector.exe"]
    assert injector.verdict is Verdict.SUSPICIOUS


def test_signed_pe_loses_points_but_not_its_verdict(tmp_path, db):
    (tmp_path / "unsigned.exe").write_bytes(_discount_pe(signed=False))
    (tmp_path / "signed.exe").write_bytes(_discount_pe(signed=True))
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    files = _by_name(report)

    unsigned = files["unsigned.exe"]
    signed = files["signed.exe"]
    assert unsigned.assessment.score == 70
    assert unsigned.verdict is Verdict.MALICIOUS
    assert signed.assessment.score == 55  # 70 - 15 signature discount
    assert signed.assessment.score < unsigned.assessment.score
    assert signed.assessment.score > 0
    assert signed.verdict is Verdict.SUSPICIOUS  # lowered, not erased


def test_malformed_exe_fails_safe(tmp_path, db):
    (tmp_path / "broken.exe").write_bytes(b"MZ" + b"\x99" * 500)
    report = scan_path(tmp_path, db, BUILTIN_RULES)
    scanned = report.files[0]
    assert scanned.result.ok  # the scan itself completed
    assert any("could not be parsed" in n for n in scanned.assessment.notes)


def test_cli_json_includes_signals_score_severity(tree, tmp_path, capsys):
    db_path = tmp_path / "sigs.sigdb"
    assert main(["sigdb", "init", str(db_path)]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(["scan", str(tree), "--db", str(db_path), "--json"]) == EXIT_DETECTIONS
    payload = json.loads(capsys.readouterr().out)
    by_name = {f["path"].split("/")[-1]: f for f in payload["files"]}

    injector = by_name["injector.exe"]
    assert injector["verdict"] == "Malicious"
    assert injector["score"] >= 60
    assert injector["max_severity"] == "critical"
    signal_names = {s["name"] for s in injector["signals"]}
    assert "process_injection_combo" in signal_names
    combo = next(s for s in injector["signals"] if s["name"] == "process_injection_combo")
    assert combo["severity"] == "critical"
    assert combo["points"] > 0
    assert combo["explanation"]

    clean = by_name["clean.exe"]
    assert clean["verdict"] == "Clean"
    assert clean["signals"] == []
    assert clean["score"] == 0


def test_cli_human_output_groups_signals(tree, tmp_path, capsys):
    db_path = tmp_path / "sigs.sigdb"
    assert main(["sigdb", "init", str(db_path)]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(["scan", str(tree), "--db", str(db_path)]) == EXIT_DETECTIONS
    out = capsys.readouterr().out
    assert "Heuristic signals (risk score:" in out
    assert "process_injection_combo (Critical," in out
    assert "Highest severity: Critical" in out


def test_cli_no_heuristics_flag(tree, tmp_path, capsys):
    db_path = tmp_path / "sigs.sigdb"
    assert main(["sigdb", "init", str(db_path)]) == EXIT_CLEAN
    capsys.readouterr()
    rc = main(["scan", str(tree), "--db", str(db_path), "--json", "--no-heuristics"])
    assert rc == EXIT_DETECTIONS
    payload = json.loads(capsys.readouterr().out)
    for f in payload["files"]:
        assert f["signals"] == []
        assert f["score"] == 0


def test_cli_clean_tree_still_exit_0(tmp_path, capsys):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "clean.exe").write_bytes(clean_pe())
    db_path = tmp_path / "sigs.sigdb"
    assert main(["sigdb", "init", str(db_path)]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(["scan", str(tree), "--db", str(db_path)]) == EXIT_CLEAN
