"""A hand-crafted minimal PE builder for tests.

Builds small, structurally valid Windows PE files in pure Python —
chosen sections, imports, exports, TLS callbacks, overlay, and
certificate table — so heuristic tests need no real malware and no
external samples. The files are fixtures, not runnable programs.
"""

from __future__ import annotations

import struct

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
IMAGE_BASE = 0x140000000

# Section characteristics
CNT_CODE = 0x00000020
CNT_INITIALIZED = 0x00000040
MEM_EXECUTE = 0x20000000
MEM_READ = 0x40000000
MEM_WRITE = 0x80000000
TEXT_CHARS = CNT_CODE | MEM_EXECUTE | MEM_READ
RDATA_CHARS = CNT_INITIALIZED | MEM_READ
DATA_RW_CHARS = CNT_INITIALIZED | MEM_READ | MEM_WRITE
RWX_CHARS = CNT_INITIALIZED | MEM_EXECUTE | MEM_READ | MEM_WRITE


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def code_bytes(n: int, seed: int = 1337) -> bytes:
    """Deterministic 'native code' — byte entropy ≈ 6.0 bits/byte."""
    import random

    rng = random.Random(seed)
    return bytes(rng.choices(range(64), k=n))


def packed_bytes(n: int, seed: int = 42) -> bytes:
    """Deterministic 'packed' data — byte entropy ≈ 8.0 bits/byte."""
    import random

    return random.Random(seed).randbytes(n)


class PEBuilder:
    """Compose a minimal PE32+ (x64) file section by section."""

    def __init__(self, *, timestamp: int = 1_700_000_000, is_dll: bool = False):
        self.timestamp = timestamp
        self.is_dll = is_dll
        self._sections: list[tuple[str, bytes, int, int | None]] = []
        self._imports: dict[str, list[str]] | None = None
        self._exports: list[str] | None = None
        self._tls_callbacks = 0
        self._entry_section = 0
        self._entry_offset = 0
        self._overlay = b""
        self._cert_size = 0

    # ------------------------------------------------------------------
    def add_section(
        self,
        name: str,
        data: bytes,
        characteristics: int,
        *,
        virtual_size: int | None = None,
    ) -> "PEBuilder":
        self._sections.append((name, data, characteristics, virtual_size))
        return self

    def set_imports(self, imports: dict[str, list[str]]) -> "PEBuilder":
        self._imports = imports
        return self

    def set_exports(self, names: list[str]) -> "PEBuilder":
        self._exports = names
        return self

    def set_tls(self, callbacks: int = 1) -> "PEBuilder":
        self._tls_callbacks = callbacks
        return self

    def set_entry(self, section_index: int, offset: int = 0) -> "PEBuilder":
        self._entry_section = section_index
        self._entry_offset = offset
        return self

    def set_overlay(self, data: bytes) -> "PEBuilder":
        self._overlay = data
        return self

    def set_cert(self, size: int = 0x1000) -> "PEBuilder":
        self._cert_size = size
        return self

    # ------------------------------------------------------------------
    # Import / export / TLS blobs (lengths don't depend on base RVA, so
    # build once with base 0 to size the auto section, then for real).
    # ------------------------------------------------------------------
    def _imports_blob(self, base_rva: int) -> bytes:
        assert self._imports is not None
        imports = self._imports
        desc_size = (len(imports) + 1) * 20
        cursor = desc_size
        layout = []
        for dll, funcs in imports.items():
            ilt_off = cursor
            cursor += (len(funcs) + 1) * 8
            iat_off = cursor
            cursor += (len(funcs) + 1) * 8
            name_off = cursor
            cursor += len(dll) + 1
            if cursor % 2:
                cursor += 1
            hn_offs = []
            for func in funcs:
                if func.startswith("#"):
                    hn_offs.append(None)
                    continue
                hn_offs.append(cursor)
                cursor += 2 + len(func) + 1
                if cursor % 2:
                    cursor += 1
            layout.append((dll, funcs, ilt_off, iat_off, name_off, hn_offs))

        blob = bytearray(cursor)
        for d, (dll, funcs, ilt_off, iat_off, name_off, hn_offs) in enumerate(layout):
            struct.pack_into(
                "<IIIII", blob, d * 20,
                base_rva + ilt_off, 0, 0, base_rva + name_off, base_rva + iat_off,
            )
            blob[name_off : name_off + len(dll)] = dll.encode()
            for i, func in enumerate(funcs):
                if func.startswith("#"):
                    value = 0x8000000000000000 | int(func[1:])
                else:
                    value = base_rva + hn_offs[i]
                    hn = hn_offs[i]
                    blob[hn + 2 : hn + 2 + len(func)] = func.encode()
                struct.pack_into("<Q", blob, ilt_off + i * 8, value)
                struct.pack_into("<Q", blob, iat_off + i * 8, value)
        return bytes(blob)

    def _exports_blob(self, base_rva: int, entry_rva: int) -> bytes:
        assert self._exports is not None
        names = self._exports
        dll_name = b"fixture.dll\x00"
        cursor = 40
        funcs_off = cursor
        cursor += len(names) * 4
        names_off = cursor
        cursor += len(names) * 4
        ords_off = cursor
        cursor += len(names) * 2
        dll_name_off = cursor
        cursor += len(dll_name)
        name_offs = []
        for name in names:
            name_offs.append(cursor)
            cursor += len(name) + 1

        blob = bytearray(cursor)
        struct.pack_into("<I", blob, 12, base_rva + dll_name_off)  # Name
        struct.pack_into("<I", blob, 16, 1)                        # Base
        struct.pack_into("<I", blob, 20, len(names))               # NumberOfFunctions
        struct.pack_into("<I", blob, 24, len(names))               # NumberOfNames
        struct.pack_into("<I", blob, 28, base_rva + funcs_off)     # AddressOfFunctions
        struct.pack_into("<I", blob, 32, base_rva + names_off)     # AddressOfNames
        struct.pack_into("<I", blob, 36, base_rva + ords_off)      # AddressOfNameOrdinals
        blob[dll_name_off : dll_name_off + len(dll_name)] = dll_name
        for i, name in enumerate(names):
            struct.pack_into("<I", blob, funcs_off + i * 4, entry_rva)
            struct.pack_into("<I", blob, names_off + i * 4, base_rva + name_offs[i])
            struct.pack_into("<H", blob, ords_off + i * 2, i)
            off = name_offs[i]
            blob[off : off + len(name)] = name.encode()
        return bytes(blob)

    def _tls_blob(self, base_rva: int, entry_va: int) -> bytes:
        count = self._tls_callbacks
        array_off = 40
        total = array_off + (count + 1) * 8
        blob = bytearray(total)
        struct.pack_into("<Q", blob, 24, IMAGE_BASE + base_rva + array_off)
        for i in range(count):
            struct.pack_into("<Q", blob, array_off + i * 8, entry_va)
        return bytes(blob)

    # ------------------------------------------------------------------
    def build(self) -> bytes:
        sections = list(self._sections)

        # Size the auto (.idata) section: blob lengths are base-independent.
        auto_parts: list[tuple[str, bytes]] = []
        need_auto = (
            self._imports is not None
            or self._exports is not None
            or self._tls_callbacks > 0
        )
        auto_index: int | None = None
        if need_auto:
            auto_index = len(sections)
            sections.append((".idata", b"", RDATA_CHARS, None))

        num_sections = len(sections)
        header_size = _align(
            0x80 + 4 + 20 + 240 + num_sections * 40, FILE_ALIGNMENT
        )

        # Assign RVAs and raw offsets.
        rvas: list[int] = []
        raw_offsets: list[int] = []
        next_rva = SECTION_ALIGNMENT
        next_raw = header_size
        for _name, data, _chars, vsize in sections:
            rvas.append(next_rva)
            raw_offsets.append(next_raw)
            span = vsize if vsize is not None else len(data)
            next_rva += _align(max(span, 1), SECTION_ALIGNMENT)
            next_raw += _align(len(data), FILE_ALIGNMENT) if data else 0
        size_of_image = next_rva

        entry_rva = 0
        if sections:
            entry_rva = rvas[self._entry_section] + self._entry_offset

        # Build the auto-section blobs now that its RVA is known.
        directories: dict[int, tuple[int, int]] = {}
        if need_auto:
            assert auto_index is not None
            base = rvas[auto_index]
            blobs: list[bytes] = []
            cursor = 0
            if self._imports is not None:
                blob = self._imports_blob(base + cursor)
                directories[1] = (base + cursor, len(blob))
                blobs.append(blob)
                cursor += len(blob)
            if self._exports is not None:
                blob = self._exports_blob(base + cursor, entry_rva)
                directories[0] = (base + cursor, len(blob))
                blobs.append(blob)
                cursor += len(blob)
            if self._tls_callbacks > 0:
                blob = self._tls_blob(base + cursor, IMAGE_BASE + entry_rva)
                directories[9] = (base + cursor, len(blob))
                blobs.append(blob)
                cursor += len(blob)
            auto_data = b"".join(blobs)
            name, _d, chars, _v = sections[auto_index]
            sections[auto_index] = (name, auto_data, chars, None)
            # Raw layout after the auto section does not shift: it is last.

        total_raw_end = header_size
        for (_n, data, _c, _v), raw_off in zip(sections, raw_offsets):
            if data:
                total_raw_end = max(total_raw_end, raw_off + _align(len(data), FILE_ALIGNMENT))
        overlay_offset = total_raw_end
        cert_offset = overlay_offset + len(self._overlay)
        total_size = cert_offset + self._cert_size
        if self._cert_size:
            directories[4] = (cert_offset, self._cert_size)

        out = bytearray(total_size)

        # DOS header + stub
        out[0:2] = b"MZ"
        struct.pack_into("<I", out, 0x3C, 0x80)
        out[0x80:0x84] = b"PE\x00\x00"

        # COFF header
        coff = 0x84
        file_chars = 0x0022 | (0x2000 if self.is_dll else 0)
        struct.pack_into(
            "<HHIIIHH", out, coff,
            0x8664, num_sections, self.timestamp, 0, 0, 240, file_chars,
        )

        # Optional header (PE32+)
        opt = coff + 20
        struct.pack_into("<H", out, opt, 0x20B)
        size_of_code = sum(
            len(d) for (_n, d, c, _v) in sections if c & CNT_CODE
        )
        struct.pack_into("<I", out, opt + 4, size_of_code)
        struct.pack_into("<I", out, opt + 16, entry_rva)
        struct.pack_into("<I", out, opt + 20, rvas[0] if rvas else 0)
        struct.pack_into("<Q", out, opt + 24, IMAGE_BASE)
        struct.pack_into("<I", out, opt + 32, SECTION_ALIGNMENT)
        struct.pack_into("<I", out, opt + 36, FILE_ALIGNMENT)
        struct.pack_into("<I", out, opt + 56, size_of_image)
        struct.pack_into("<I", out, opt + 60, header_size)
        struct.pack_into("<H", out, opt + 68, 3)  # subsystem: console
        struct.pack_into("<I", out, opt + 108, 16)
        for idx, (rva, size) in directories.items():
            struct.pack_into("<II", out, opt + 112 + idx * 8, rva, size)

        # Section headers + data
        sec_table = opt + 240
        for i, ((name, data, chars, vsize), rva, raw_off) in enumerate(
            zip(sections, rvas, raw_offsets)
        ):
            off = sec_table + i * 40
            encoded = name.encode()[:8]
            out[off : off + len(encoded)] = encoded
            struct.pack_into("<I", out, off + 8, vsize if vsize is not None else len(data))
            struct.pack_into("<I", out, off + 12, rva)
            struct.pack_into(
                "<I", out, off + 16, _align(len(data), FILE_ALIGNMENT) if data else 0
            )
            struct.pack_into("<I", out, off + 20, raw_off if data else 0)
            struct.pack_into("<I", out, off + 36, chars)
            if data:
                out[raw_off : raw_off + len(data)] = data

        # Overlay + certificate blob
        if self._overlay:
            out[overlay_offset : overlay_offset + len(self._overlay)] = self._overlay
        if self._cert_size:
            struct.pack_into(
                "<IHH", out, cert_offset, self._cert_size, 0x0200, 0x0002
            )

        return bytes(out)


# ----------------------------------------------------------------------
# Ready-made fixtures
# ----------------------------------------------------------------------
def clean_pe() -> bytes:
    """A small, honest-looking executable: normal imports, code ~6.0
    entropy in .text, standard entry point, no funny business."""
    return (
        PEBuilder()
        .add_section(".text", code_bytes(4096), TEXT_CHARS)
        .add_section(
            ".rdata",
            b"Fixture Program\x00Version 1.0\x00Copyright FixtureSoft\x00"
            b"ordinary configuration strings live here\x00",
            RDATA_CHARS,
        )
        .set_imports(
            {
                "KERNEL32.dll": [
                    "GetProcAddress",
                    "LoadLibraryA",
                    "GetModuleHandleA",
                    "ExitProcess",
                ],
                "USER32.dll": ["MessageBoxA"],
            }
        )
        .set_entry(0)
        .build()
    )


def packed_injector_pe() -> bytes:
    """A UPX-style packed injector: injection import trio, RWX packed
    section with ~8.0 entropy, entry point in the last section."""
    return (
        PEBuilder()
        .add_section("UPX0", b"", RWX_CHARS, virtual_size=0x3000)
        .add_section("UPX1", packed_bytes(8192), RWX_CHARS)
        .set_imports(
            {
                "KERNEL32.dll": [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "LoadLibraryA",
                    "GetProcAddress",
                ]
            }
        )
        .set_entry(1)
        .build()
    )
