"""End-to-end CLI tests: sigdb init/info, scan exit codes and output."""

import json

import pytest

from argus.cli import EXIT_CLEAN, EXIT_DETECTIONS, EXIT_ERROR, main

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def workspace(tmp_path):
    """A folder tree with one clean file, and a path for the DB."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "readme.txt").write_text("perfectly ordinary document")
    return tree, tmp_path / "sigs.sigdb"


def test_sigdb_init_and_info(tmp_path, capsys):
    db = tmp_path / "sigs.sigdb"
    assert main(["sigdb", "init", str(db)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Signatures: 1" in out

    assert main(["sigdb", "info", str(db)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Integrity: OK" in out
    assert "Signatures: 1" in out


def test_sigdb_info_missing_db_is_error(tmp_path, capsys):
    assert main(["sigdb", "info", str(tmp_path / "nope.sigdb")]) == EXIT_ERROR
    assert "Error" in capsys.readouterr().err


def test_scan_clean_tree_exit_0(workspace, capsys):
    tree, db = workspace
    assert main(["sigdb", "init", str(db)]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(["scan", str(tree), "--db", str(db)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Detections: none" in out


def test_scan_eicar_exit_1_and_named(workspace, capsys):
    tree, db = workspace
    (tree / "eicar.com").write_bytes(EICAR)
    assert main(["sigdb", "init", str(db)]) == EXIT_CLEAN
    capsys.readouterr()

    assert main(["scan", str(tree), "--db", str(db)]) == EXIT_DETECTIONS
    out = capsys.readouterr().out
    assert "EICAR-Test-File" in out
    assert "MALICIOUS" in out


def test_scan_json_output(workspace, capsys):
    tree, db = workspace
    (tree / "eicar.com").write_bytes(EICAR)
    assert main(["sigdb", "init", str(db)]) == EXIT_CLEAN
    capsys.readouterr()

    assert main(["scan", str(tree), "--db", str(db), "--json"]) == EXIT_DETECTIONS
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "Malicious"
    names = [
        d["name"]
        for f in payload["files"]
        for d in f["detections"]
    ]
    assert "EICAR-Test-File" in names
    assert payload["stats"]["files_scanned"] == 2


def test_scan_single_file(workspace, capsys):
    tree, db = workspace
    target = tree / "eicar.com"
    target.write_bytes(EICAR)
    assert main(["sigdb", "init", str(db)]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(["scan", str(target), "--db", str(db)]) == EXIT_DETECTIONS


def test_scan_missing_db_exit_2(workspace, capsys):
    tree, _ = workspace
    missing = tree / "no-such.sigdb"
    assert main(["scan", str(tree), "--db", str(missing)]) == EXIT_ERROR
    assert "sigdb init" in capsys.readouterr().err


def test_scan_missing_target_exit_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "ghost")]) == EXIT_ERROR


def test_no_command_prints_help_exit_2(capsys):
    assert main([]) == EXIT_ERROR
    assert "usage" in capsys.readouterr().out.lower()


def test_scan_respects_config_exclusions(tmp_path, capsys):
    """Exclusions are honoured in on-demand scans, not just real-time."""
    import hashlib
    import json as json_mod

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "eicar.com").write_bytes(EICAR)
    db = tmp_path / "sigs.sigdb"
    assert main(["sigdb", "init", str(db)]) == EXIT_CLEAN
    capsys.readouterr()

    # Exclude the folder by path via a config file.
    config_path = tmp_path / "argus-config.json"
    config_path.write_text(json_mod.dumps({
        "exclusions": {"paths": [str(tree)], "hashes": []},
    }), encoding="utf-8")
    assert main(["scan", str(tree), "--db", str(db),
                 "--config", str(config_path)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Detections: none" in out
    assert "Excluded by you: 1" in out

    # Exclude by hash instead — same result.
    digest = hashlib.sha256(EICAR).hexdigest()
    config_path.write_text(json_mod.dumps({
        "exclusions": {"paths": [], "hashes": [digest]},
    }), encoding="utf-8")
    assert main(["scan", str(tree), "--db", str(db),
                 "--config", str(config_path), "--json"]) == EXIT_CLEAN
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["files_excluded"] == 1
    assert payload["files"][0]["excluded"] is True


def test_scan_loose_file_name_cannot_forge_output_lines(tmp_path, capsys):
    """Sweep #4: the B-3 member-name forging class, for a loose
    file. A file whose NAME carries a newline and a fake verdict
    line must print escaped, on one line, in the human scan
    output (Linux permits such names; Windows forbids control
    characters in file names, so creation is attempted and the
    test skips where the platform refuses it)."""
    tree = tmp_path / "tree"
    tree.mkdir()
    evil_name = "innocent.txt\n[MALICIOUS] forged.exe was flagged"
    try:
        (tree / evil_name).write_bytes(EICAR)
    except OSError:
        pytest.skip("platform forbids control characters in file names")
    db = tmp_path / "sigs.sigdb"
    assert main(["sigdb", "init", str(db)]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(["scan", str(tree), "--db", str(db)]) == EXIT_DETECTIONS
    out = capsys.readouterr().out
    assert "\n[MALICIOUS] forged.exe" not in out
    assert "\\x0a[MALICIOUS] forged.exe" in out
