"""A pure-stdlib parser for Windows PE (Portable Executable) files.

Argus inspects executables the way a mechanic inspects an engine:
headers, sections, imports, exports, TLS callbacks, signature block,
overlay. This module extracts those facts and nothing more — turning
facts into risk judgements is :mod:`argus.heuristics.signals`' job.

Design rules:

- **Standard library only**, ``struct`` + bounded reads. No third-party
  PE library: one less supply chain to trust, and the format is stable.
- **Fail safe, never crash.** A structurally impossible file raises
  :class:`PEError`; a partially odd file (unreadable import table,
  truncated export names) parses what it can and records a warning in
  ``PEInfo.warnings``. A malformed file must never take a scan down.
- **Bounded everything.** Every count read from the file (sections,
  import descriptors, thunks, names) is capped, so a hostile header
  cannot make the parser loop or allocate without limit.
- **Presence, not validation, for signatures.** The Authenticode
  certificate table is reported as present/absent with its size.
  Cryptographic chain validation is deliberately out of scope here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

# COFF / optional-header constants
_MACHINE_NAMES = {0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM", 0xAA64: "ARM64"}
_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B
_FILE_CHARACTERISTIC_DLL = 0x2000

# Section characteristic bits (IMAGE_SCN_MEM_*)
SECTION_MEM_EXECUTE = 0x20000000
SECTION_MEM_READ = 0x40000000
SECTION_MEM_WRITE = 0x80000000
SECTION_CNT_CODE = 0x00000020

# Data directory indexes
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_CERTIFICATE = 4
DIR_TLS = 9

# Hard caps so hostile files cannot make us loop or allocate forever.
MAX_SECTIONS = 96
MAX_IMPORT_DESCRIPTORS = 256
MAX_IMPORT_FUNCTIONS = 4096
MAX_EXPORT_NAMES = 1024
MAX_TLS_CALLBACKS = 32
_MAX_NAME_BYTES = 512
_MAX_DLL_NAME_BYTES = 256


class PEError(Exception):
    """Raised when a file is not a parseable PE at all."""


@dataclass
class Section:
    """One PE section (``.text``, ``.rdata``, ...)."""

    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float | None = None  # filled in by the analyzer, if run

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & SECTION_MEM_EXECUTE)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & SECTION_MEM_WRITE)

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & SECTION_MEM_READ)

    @property
    def contains_code(self) -> bool:
        return bool(self.characteristics & SECTION_CNT_CODE)

    @property
    def span(self) -> int:
        """Address span the section occupies in memory."""
        return max(self.virtual_size, self.raw_size)


@dataclass
class PEInfo:
    """Structural facts about one PE file."""

    size: int
    machine: str
    is_64bit: bool
    is_dll: bool
    timestamp: int
    image_base: int
    entry_point_rva: int
    entry_section_index: int | None
    subsystem: int
    sections: list[Section] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    has_tls: bool = False
    tls_callback_count: int | None = None
    signed: bool = False
    cert_size: int = 0
    overlay_offset: int = 0
    overlay_size: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def entry_section(self) -> Section | None:
        if self.entry_section_index is None:
            return None
        return self.sections[self.entry_section_index]

    @property
    def imported_functions(self) -> set[str]:
        """All imported function names across every DLL."""
        funcs: set[str] = set()
        for names in self.imports.values():
            funcs.update(names)
        return funcs


# ----------------------------------------------------------------------
# Bounded file reader
# ----------------------------------------------------------------------
class _Reader:
    def __init__(self, path: Path) -> None:
        self._fh = open(path, "rb")
        self._fh.seek(0, 2)
        self.size = self._fh.tell()

    def close(self) -> None:
        self._fh.close()

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise PEError(
                f"read of {size} bytes at offset {offset} exceeds file size {self.size}"
            )
        self._fh.seek(offset)
        data = self._fh.read(size)
        if len(data) != size:
            raise PEError(f"short read at offset {offset}")
        return data

    def u8(self, offset: int) -> int:
        return self.read_at(offset, 1)[0]

    def u16(self, offset: int) -> int:
        return struct.unpack("<H", self.read_at(offset, 2))[0]

    def u32(self, offset: int) -> int:
        return struct.unpack("<I", self.read_at(offset, 4))[0]

    def u64(self, offset: int) -> int:
        return struct.unpack("<Q", self.read_at(offset, 8))[0]

    def c_string(self, offset: int, max_bytes: int) -> str:
        """Read a NUL-terminated ASCII string, bounded."""
        if offset < 0 or offset >= self.size:
            raise PEError(f"string offset {offset} outside file")
        end = min(self.size, offset + max_bytes)
        raw = self.read_at(offset, end - offset)
        nul = raw.find(b"\x00")
        if nul >= 0:
            raw = raw[:nul]
        return raw.decode("ascii", errors="replace")


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------
def parse_pe(path: Path | str) -> PEInfo:
    """Parse the PE file at *path*.

    Raises :class:`PEError` if the file is not a structurally valid PE
    (bad magic, truncated headers, impossible layout). Partial problems
    below the header level are recorded as warnings on the result.
    """
    reader = _Reader(Path(path))
    try:
        return _parse(reader)
    finally:
        reader.close()


def _parse(r: _Reader) -> PEInfo:
    if r.size < 64:
        raise PEError("file too small to be a PE (no DOS header)")
    if r.read_at(0, 2) != b"MZ":
        raise PEError("missing MZ signature — not a Windows executable")

    pe_offset = r.u32(0x3C)  # e_lfanew
    if pe_offset <= 0 or pe_offset + 24 > r.size:
        raise PEError("DOS header points outside the file (bad e_lfanew)")
    if r.read_at(pe_offset, 4) != b"PE\x00\x00":
        raise PEError("missing PE signature")

    coff = pe_offset + 4
    machine_raw = r.u16(coff)
    num_sections = r.u16(coff + 2)
    timestamp = r.u32(coff + 4)
    opt_size = r.u16(coff + 16)
    file_chars = r.u16(coff + 18)
    if num_sections == 0 or num_sections > MAX_SECTIONS:
        raise PEError(f"implausible section count: {num_sections}")
    if opt_size < 96:
        raise PEError(f"optional header too small: {opt_size} bytes")

    opt = coff + 20
    magic = r.u16(opt)
    if magic == _PE32PLUS_MAGIC:
        is_64bit = True
        dd_start = opt + 112
    elif magic == _PE32_MAGIC:
        is_64bit = False
        dd_start = opt + 96
    else:
        raise PEError(f"unknown optional-header magic: {magic:#x}")
    if opt + opt_size > r.size:
        raise PEError("optional header runs past end of file")

    entry_point_rva = r.u32(opt + 16)
    image_base = r.u64(opt + 24) if is_64bit else r.u32(opt + 28)
    size_of_headers = r.u32(opt + 60)
    subsystem = r.u16(opt + 68)
    num_dirs = r.u32(opt + (108 if is_64bit else 92))
    num_dirs = min(num_dirs, 16)

    directories: list[tuple[int, int]] = []
    for i in range(16):
        if i < num_dirs and dd_start + i * 8 + 8 <= opt + opt_size:
            directories.append((r.u32(dd_start + i * 8), r.u32(dd_start + i * 8 + 4)))
        else:
            directories.append((0, 0))

    # ---- sections ------------------------------------------------------
    sec_table = opt + opt_size
    if sec_table + num_sections * 40 > r.size:
        raise PEError("section table runs past end of file")
    sections: list[Section] = []
    for i in range(num_sections):
        off = sec_table + i * 40
        raw_name = r.read_at(off, 8)
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        sections.append(
            Section(
                name=name,
                virtual_size=r.u32(off + 8),
                virtual_address=r.u32(off + 12),
                raw_size=r.u32(off + 16),
                raw_offset=r.u32(off + 20),
                characteristics=r.u32(off + 36),
            )
        )

    def rva_to_offset(rva: int) -> int | None:
        if rva < size_of_headers:
            return rva  # header region maps 1:1
        for sec in sections:
            start = sec.virtual_address
            if start <= rva < start + sec.span:
                delta = rva - start
                if delta >= sec.raw_size:
                    return None  # virtual-only tail (zero fill)
                return sec.raw_offset + delta
        return None

    entry_section_index: int | None = None
    for idx, sec in enumerate(sections):
        start = sec.virtual_address
        if start <= entry_point_rva < start + sec.span:
            entry_section_index = idx
            break

    info = PEInfo(
        size=r.size,
        machine=_MACHINE_NAMES.get(machine_raw, f"unknown ({machine_raw:#06x})"),
        is_64bit=is_64bit,
        is_dll=bool(file_chars & _FILE_CHARACTERISTIC_DLL),
        timestamp=timestamp,
        image_base=image_base,
        entry_point_rva=entry_point_rva,
        entry_section_index=entry_section_index,
        subsystem=subsystem,
        sections=sections,
    )

    # ---- certificate table (Authenticode) ------------------------------
    # NOTE: for the certificate directory, the "RVA" field is a file
    # offset — the one exception in the PE format.
    cert_offset, cert_size = directories[DIR_CERTIFICATE]
    if cert_size >= 8 and 0 < cert_offset < r.size:
        info.signed = True
        info.cert_size = cert_size

    # ---- overlay --------------------------------------------------------
    data_end = size_of_headers
    for sec in sections:
        if sec.raw_size:
            data_end = max(data_end, sec.raw_offset + sec.raw_size)
    overlay_start = data_end
    if info.signed and cert_offset >= data_end:
        info.overlay_size = max(0, cert_offset - data_end)
    else:
        info.overlay_size = max(0, r.size - data_end)
    info.overlay_offset = overlay_start

    # ---- imports ---------------------------------------------------------
    imp_rva, _ = directories[DIR_IMPORT]
    if imp_rva:
        try:
            info.imports = _parse_imports(r, rva_to_offset, imp_rva, is_64bit)
        except PEError as exc:
            info.warnings.append(f"import table could not be parsed: {exc}")

    # ---- exports ---------------------------------------------------------
    exp_rva, _ = directories[DIR_EXPORT]
    if exp_rva:
        try:
            info.exports = _parse_exports(r, rva_to_offset, exp_rva)
        except PEError as exc:
            info.warnings.append(f"export table could not be parsed: {exc}")

    # ---- TLS callbacks -----------------------------------------------------
    tls_rva, _ = directories[DIR_TLS]
    if tls_rva:
        info.has_tls = True
        try:
            info.tls_callback_count = _count_tls_callbacks(
                r, rva_to_offset, tls_rva, image_base, is_64bit
            )
        except PEError:
            info.tls_callback_count = None  # presence known, count unreadable

    return info


def _parse_imports(r: _Reader, rva_to_offset, imp_rva: int, is_64bit: bool) -> dict[str, list[str]]:
    base = rva_to_offset(imp_rva)
    if base is None:
        raise PEError("import directory RVA does not map to file data")
    thunk_size = 8 if is_64bit else 4
    ordinal_flag = 0x8000000000000000 if is_64bit else 0x80000000
    unpack_thunk = "<Q" if is_64bit else "<I"

    imports: dict[str, list[str]] = {}
    for d in range(MAX_IMPORT_DESCRIPTORS):
        desc = base + d * 20
        fields = struct.unpack("<IIIII", r.read_at(desc, 20))
        if fields == (0, 0, 0, 0, 0):
            break
        original_first_thunk, _stamp, _chain, name_rva, first_thunk = fields
        name_off = rva_to_offset(name_rva)
        if name_off is None:
            continue
        dll_name = r.c_string(name_off, _MAX_DLL_NAME_BYTES)

        thunk_rva = original_first_thunk or first_thunk
        thunk_off = rva_to_offset(thunk_rva)
        functions: list[str] = []
        if thunk_off is not None:
            for i in range(MAX_IMPORT_FUNCTIONS):
                raw = r.read_at(thunk_off + i * thunk_size, thunk_size)
                (value,) = struct.unpack(unpack_thunk, raw)
                if value == 0:
                    break
                if value & ordinal_flag:
                    functions.append(f"#{value & 0xFFFF}")
                    continue
                name_entry = rva_to_offset(value)
                if name_entry is None:
                    continue
                # 2-byte hint precedes the function name.
                functions.append(r.c_string(name_entry + 2, _MAX_NAME_BYTES))
        imports[dll_name] = functions
    return imports


def _parse_exports(r: _Reader, rva_to_offset, exp_rva: int) -> list[str]:
    base = rva_to_offset(exp_rva)
    if base is None:
        raise PEError("export directory RVA does not map to file data")
    num_names = r.u32(base + 24)
    names_rva = r.u32(base + 32)
    names_off = rva_to_offset(names_rva)
    if names_off is None:
        raise PEError("export name table RVA does not map to file data")
    names: list[str] = []
    for i in range(min(num_names, MAX_EXPORT_NAMES)):
        name_rva_i = r.u32(names_off + i * 4)
        name_off = rva_to_offset(name_rva_i)
        if name_off is None:
            continue
        names.append(r.c_string(name_off, _MAX_NAME_BYTES))
    return names


def _count_tls_callbacks(r: _Reader, rva_to_offset, tls_rva: int, image_base: int, is_64bit: bool) -> int | None:
    base = rva_to_offset(tls_rva)
    if base is None:
        return None
    if is_64bit:
        callbacks_va = r.u64(base + 24)
        ptr_size, fmt = 8, "<Q"
    else:
        callbacks_va = r.u32(base + 12)
        ptr_size, fmt = 4, "<I"
    if callbacks_va < image_base:
        return None
    callbacks_off = rva_to_offset(callbacks_va - image_base)
    if callbacks_off is None:
        return None
    count = 0
    for i in range(MAX_TLS_CALLBACKS):
        (value,) = struct.unpack(fmt, r.read_at(callbacks_off + i * ptr_size, ptr_size))
        if value == 0:
            break
        count += 1
    return count
