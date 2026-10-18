"""Tests for the pure-stdlib PE parser, using hand-crafted fixtures."""

import pytest

from argus.heuristics.pe import PEError, parse_pe
from tests.pe_fixtures import (
    DATA_RW_CHARS,
    RDATA_CHARS,
    TEXT_CHARS,
    PEBuilder,
    clean_pe,
    code_bytes,
    packed_injector_pe,
)


@pytest.fixture()
def clean(tmp_path):
    path = tmp_path / "clean.exe"
    path.write_bytes(clean_pe())
    return path


def test_parse_clean_pe(clean):
    info = parse_pe(clean)
    assert info.machine == "x64"
    assert info.is_64bit
    assert not info.is_dll
    assert info.timestamp == 1_700_000_000
    assert [s.name for s in info.sections] == [".text", ".rdata", ".idata"]
    assert info.entry_section is not None
    assert info.entry_section.name == ".text"
    assert info.entry_section_index == 0
    assert info.signed is False
    assert info.cert_size == 0
    assert info.overlay_size == 0
    assert info.has_tls is False
    assert info.warnings == []


def test_parse_imports(clean):
    info = parse_pe(clean)
    assert set(info.imports) == {"KERNEL32.dll", "USER32.dll"}
    assert "ExitProcess" in info.imports["KERNEL32.dll"]
    assert "MessageBoxA" in info.imports["USER32.dll"]
    assert "VirtualAllocEx" not in info.imported_functions


def test_parse_injector_structure():
    import tempfile, os

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "inj.exe")
        with open(path, "wb") as fh:
            fh.write(packed_injector_pe())
        info = parse_pe(path)
    assert [s.name for s in info.sections][:2] == ["UPX0", "UPX1"]
    funcs = info.imported_functions
    assert {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"} <= funcs
    assert info.entry_section is not None
    assert info.entry_section.name == "UPX1"
    upx1 = info.sections[1]
    assert upx1.is_executable and upx1.is_writable


def test_parse_exports(tmp_path):
    path = tmp_path / "lib.dll"
    path.write_bytes(
        PEBuilder(is_dll=True)
        .add_section(".text", code_bytes(2048), TEXT_CHARS)
        .set_exports(["AlphaFunc", "BetaFunc"])
        .set_entry(0)
        .build()
    )
    info = parse_pe(path)
    assert info.is_dll
    assert info.exports == ["AlphaFunc", "BetaFunc"]


def test_parse_ordinal_imports(tmp_path):
    path = tmp_path / "ord.exe"
    path.write_bytes(
        PEBuilder()
        .add_section(".text", code_bytes(2048), TEXT_CHARS)
        .set_imports({"KERNEL32.dll": ["ExitProcess", "#42"]})
        .set_entry(0)
        .build()
    )
    info = parse_pe(path)
    assert "#42" in info.imports["KERNEL32.dll"]


def test_parse_tls_callbacks(tmp_path):
    path = tmp_path / "tls.exe"
    path.write_bytes(
        PEBuilder()
        .add_section(".text", code_bytes(2048), TEXT_CHARS)
        .set_tls(2)
        .set_entry(0)
        .build()
    )
    info = parse_pe(path)
    assert info.has_tls is True
    assert info.tls_callback_count == 2


def test_parse_certificate_table(tmp_path):
    path = tmp_path / "signed.exe"
    path.write_bytes(
        PEBuilder()
        .add_section(".text", code_bytes(2048), TEXT_CHARS)
        .set_cert(0x1000)
        .set_entry(0)
        .build()
    )
    info = parse_pe(path)
    assert info.signed is True
    assert info.cert_size == 0x1000
    assert info.overlay_size == 0  # the cert block is not overlay


def test_parse_overlay(tmp_path):
    overlay = b"\x00" * 100_000
    path = tmp_path / "overlay.exe"
    path.write_bytes(
        PEBuilder()
        .add_section(".text", code_bytes(2048), TEXT_CHARS)
        .set_overlay(overlay)
        .set_entry(0)
        .build()
    )
    info = parse_pe(path)
    assert info.overlay_size == len(overlay)


def test_parse_zero_raw_section(tmp_path):
    path = tmp_path / "hollow.exe"
    path.write_bytes(
        PEBuilder()
        .add_section(".text", b"", TEXT_CHARS, virtual_size=0x2000)
        .add_section(".rdata", b"data", RDATA_CHARS)
        .set_entry(0)
        .build()
    )
    info = parse_pe(path)
    text = info.sections[0]
    assert text.raw_size == 0
    assert text.virtual_size == 0x2000


def test_parse_data_section_properties(tmp_path):
    path = tmp_path / "props.exe"
    path.write_bytes(
        PEBuilder()
        .add_section(".data", b"x" * 512, DATA_RW_CHARS)
        .set_entry(0)
        .build()
    )
    info = parse_pe(path)
    sec = info.sections[0]
    assert sec.is_writable and sec.is_readable and not sec.is_executable


# ----------------------------------------------------------------------
# Malformed input: fail safe with PEError, never anything else
# ----------------------------------------------------------------------
def test_parse_rejects_non_pe(tmp_path):
    path = tmp_path / "nope.exe"
    path.write_bytes(b"this is plainly not a windows executable at all")
    with pytest.raises(PEError):
        parse_pe(path)


def test_parse_rejects_empty_and_tiny(tmp_path):
    for payload in (b"", b"MZ", b"MZ" + b"\x00" * 10):
        path = tmp_path / "tiny.exe"
        path.write_bytes(payload)
        with pytest.raises(PEError):
            parse_pe(path)


def test_parse_rejects_truncated(tmp_path):
    path = tmp_path / "trunc.exe"
    path.write_bytes(clean_pe()[:100])
    with pytest.raises(PEError):
        parse_pe(path)


def test_parse_rejects_bad_pe_signature(tmp_path):
    data = bytearray(clean_pe())
    data[0x80:0x84] = b"PX\x00\x00"
    path = tmp_path / "bad.exe"
    path.write_bytes(bytes(data))
    with pytest.raises(PEError):
        parse_pe(path)
