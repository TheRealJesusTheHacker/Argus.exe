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
  cannot make the parser loop or allocate without limit. Thunk
  arrays are read in batches under a combined work cap; hitting a
  cap is recorded (``imports_truncated``), never silent.
- **Structural validation for signatures.** The Authenticode
  certificate table is validated structurally: the WIN_CERTIFICATE
  chain must be length-consistent, in bounds, and of type
  0x0002 (PKCS signed data). A region that merely CLAIMS to be a
  certificate but fails validation is reported as overlay data with
  ``cert_malformed`` set — it earns no "signed" credit. Full
  cryptographic digest/chain verification is future work.
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
#: Combined descriptor+thunk entries the import parser will process
#: across the WHOLE table before declaring it truncated — stops a
#: header claiming hundreds of fat descriptors from grinding.
MAX_IMPORT_WORK = 65536
#: Thunk entries read per batch (one read_at per batch, not per thunk).
_THUNK_BATCH = 256
MAX_EXPORT_NAMES = 1024
MAX_TLS_CALLBACKS = 32
_MAX_NAME_BYTES = 512
_MAX_DLL_NAME_BYTES = 256

#: WIN_CERTIFICATE type for PKCS#7 signed data (Authenticode).
_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

#: WIN_CERTIFICATE revision for Authenticode (WIN_CERT_REVISION_2_0).
_CERT_REVISION = 0x0200

#: Subject names Argus accepts as "Microsoft" for the system-file
#: trust in :mod:`argus.heuristics.analyze`. Both spellings appear
#: on genuine Windows code-signing certificates: operating-system
#: components are signed "Microsoft Windows", other Microsoft
#: binaries "Microsoft Corporation" (as Common Name and/or
#: Organization). Pinned in ONE place so the field data from real
#: machines only ever has to correct a single constant.
MICROSOFT_SIGNER_NAMES = ("Microsoft Windows", "Microsoft Corporation")


def signer_is_microsoft(info: "PEInfo") -> bool:
    """True when *info*'s extracted signer identity is Microsoft —
    the Common Name OR the Organization matches one of
    :data:`MICROSOFT_SIGNER_NAMES` exactly — AND the identity is
    backed by a structurally complete SignerInfo (see
    :attr:`PEInfo.signer_info_complete`). Identity alone never
    grants trust (see analyze.py): it must combine with a
    structurally valid certificate AND a system location."""
    return info.signer_info_complete and (
        info.signer_name in MICROSOFT_SIGNER_NAMES
        or info.signer_org in MICROSOFT_SIGNER_NAMES
    )


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
    #: Signer identity from the certificate's signer certificate
    #: (subject Common Name / Organization), extracted from the
    #: PKCS#7 blob by a bounded DER walk. ``None`` when the file is
    #: unsigned, the certificate is malformed, the blob does not
    #: parse — OR the blob carries no structurally complete
    #: SignerInfo for that certificate (see
    #: ``signer_info_complete`` below): a name a certificate merely
    #: *claims*, unbacked by a complete signer entry, yields NO
    #: identity and therefore no identity-based trust. Chain /
    #: digest verification remains future work, exactly as for the
    #: "signed" credit above.
    signer_name: str | None = None
    signer_org: str | None = None
    #: True when the PKCS#7 carries a structurally COMPLETE
    #: SignerInfo for the signer certificate: an entry in the
    #: SignedData ``signerInfos`` set that references that very
    #: certificate by issuer + serial, declares a digest
    #: algorithm, and carries a signature octet string of plausible
    #: RSA length (>= 128 bytes). ``signer_name``/``signer_org``
    #: are only populated when this is true — identity claimed by
    #: a certificate alone ("first-cert-only"), with a missing,
    #: dangling, or toy-length signature, earns NO identity and
    #: therefore no identity-based trust (v1.1.0 hunt P0-3).
    signer_info_complete: bool = False
    #: True when a signer identity could be EXTRACTED from the
    #: certificate (the PKCS#7 DER-parses as SignedData and a
    #: signer certificate with a subject name is present) —
    #: regardless of SignerInfo completeness or of WHO the signer
    #: is. This is the (weaker, structural) bar for the signed
    #: score trim (P1-20): structure, not identity, and never a
    #: substitute for the completeness gate above.
    has_extracted_signer: bool = False
    #: True when a certificate region was claimed but failed
    #: structural validation — it is overlay data, NOT a signature.
    cert_malformed: bool = False
    #: True when the import table hit a parser cap (per-descriptor
    #: thunks or the combined work cap) before its natural end.
    imports_truncated: bool = False
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

    # ---- overlay extent (needed before the certificate checks) --------
    data_end = size_of_headers
    for sec in sections:
        if sec.raw_size:
            data_end = max(data_end, sec.raw_offset + sec.raw_size)

    # ---- certificate table (Authenticode) ------------------------------
    # NOTE: for the certificate directory, the "RVA" field is a file
    # offset — the one exception in the PE format. The region only
    # counts as a signature if the WIN_CERTIFICATE chain inside it
    # is structurally sound (length-consistent, in bounds, PKCS
    # type) — malware can otherwise fake the "signed" trim by
    # pointing the directory at junk bytes. The certificate
    # directory must also lie AT OR AFTER the end of the section
    # data (``data_end``): a "certificate" overlapping real section
    # bytes is not appended Authenticode data at all, it is a
    # forgery planted inside the image (P1-20).
    cert_offset, cert_size = directories[DIR_CERTIFICATE]
    if cert_size >= 8 and 0 < cert_offset:
        if cert_offset < data_end:
            info.cert_malformed = True
            info.cert_size = cert_size
            info.warnings.append(
                "certificate directory lies inside the section data "
                "instead of after it — the claimed signature region "
                "is treated as overlay data"
            )
        elif cert_offset + cert_size <= r.size and _validate_certificate_table(
            r, cert_offset, cert_size
        ):
            info.signed = True
            info.cert_size = cert_size
            # Identity is a bonus on top of structural validity —
            # and (P0-3) it is only granted when the blob carries
            # a complete SignerInfo for the certificate. Any
            # failure leaves the identity empty — never raises,
            # never affects the "signed" fact itself.
            try:
                (
                    info.signer_name,
                    info.signer_org,
                    info.signer_info_complete,
                    info.has_extracted_signer,
                ) = _extract_signer_identity(r, cert_offset)
            except Exception:
                info.signer_name = None
                info.signer_org = None
                info.signer_info_complete = False
                info.has_extracted_signer = False
        else:
            info.cert_malformed = True
            info.cert_size = cert_size
            info.warnings.append(
                "certificate table failed structural validation — the "
                "claimed signature region is treated as overlay data"
            )

    # ---- overlay --------------------------------------------------------
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
            info.imports, info.imports_truncated = _parse_imports(
                r, rva_to_offset, imp_rva, is_64bit
            )
            if info.imports_truncated:
                info.warnings.append(
                    "import table hit a parser cap before its natural "
                    "end — the import list is partial"
                )
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


def _validate_certificate_table(r: _Reader, offset: int, size: int) -> bool:
    """Structurally validate the WIN_CERTIFICATE chain at
    ``offset``/``size`` (bounds are checked by the caller).

    Each entry: ``dwLength`` (u32, includes the 8-byte header),
    ``wRevision`` (u16, must be 0x0200 on EVERY entry),
    ``wCertificateType`` (u16, must be 0x0002 on EVERY entry —
    checking only the first let a valid-looking head vouch for
    junk chained behind it, P1-20). Entries are 8-byte aligned;
    the chain must exactly consume the table (final zero padding
    of fewer than 8 bytes is tolerated). This is structural
    sanity — it proves the region is a well-formed certificate
    table, NOT that the signature is genuine (digest verification
    is future work).
    """
    end = offset + size
    pos = offset
    first = True
    while pos < end:
        remaining = end - pos
        if remaining < 8:
            # Only zero padding may trail the last entry.
            return not first and r.read_at(pos, remaining) == b"\x00" * remaining
        try:
            length = r.u32(pos)
            revision = r.u16(pos + 4)
            cert_type = r.u16(pos + 6)
        except PEError:
            return False
        if revision != _CERT_REVISION:
            return False
        if cert_type != _CERT_TYPE_PKCS_SIGNED_DATA:
            return False
        if length < 8 or length > remaining:
            return False
        pos += (length + 7) & ~7
        if pos > end:
            return False
        first = False
    return not first and pos == end


def _parse_imports(r: _Reader, rva_to_offset, imp_rva: int, is_64bit: bool) -> tuple[dict[str, list[str]], bool]:
    """Parse the import table. Returns ``(imports, truncated)`` —
    ``truncated`` is True when a cap (per-descriptor thunks or the
    combined work budget) stopped parsing before the table's
    natural end, instead of grinding through a hostile header.

    Thunk arrays are read in batches (one read per
    :data:`_THUNK_BATCH` entries) rather than one read per thunk.
    """
    base = rva_to_offset(imp_rva)
    if base is None:
        raise PEError("import directory RVA does not map to file data")
    thunk_size = 8 if is_64bit else 4
    ordinal_flag = 0x8000000000000000 if is_64bit else 0x80000000
    unpack_thunk = "<Q" if is_64bit else "<I"

    imports: dict[str, list[str]] = {}
    truncated = False
    work = 0
    for d in range(MAX_IMPORT_DESCRIPTORS):
        desc = base + d * 20
        try:
            fields = struct.unpack("<IIIII", r.read_at(desc, 20))
        except PEError:
            # Descriptor loop ran into EOF (P1-19): keep every
            # import parsed so far and flag the table truncated —
            # the same fail-soft the thunk parser below uses —
            # instead of raising and discarding the whole table.
            truncated = True
            break
        if fields == (0, 0, 0, 0, 0):
            break
        work += 1
        if work > MAX_IMPORT_WORK:
            truncated = True
            break
        original_first_thunk, _stamp, _chain, name_rva, first_thunk = fields
        name_off = rva_to_offset(name_rva)
        if name_off is None:
            continue
        try:
            dll_name = r.c_string(name_off, _MAX_DLL_NAME_BYTES)
        except PEError:
            truncated = True  # name string runs off EOF: keep prior imports
            break

        thunk_rva = original_first_thunk or first_thunk
        thunk_off = rva_to_offset(thunk_rva)
        functions: list[str] = []
        if thunk_off is not None:
            index = 0
            terminated = False
            batch_hint = _THUNK_BATCH
            while not terminated:
                if index >= MAX_IMPORT_FUNCTIONS:
                    truncated = True
                    break
                batch = min(batch_hint, MAX_IMPORT_FUNCTIONS - index)
                block: bytes | None = None
                # Batch reads stop at the file's end: if the full
                # batch overruns, halve until a read succeeds — a
                # thunk array ending flush with EOF (terminator
                # included) must parse completely, while one that
                # runs off the file entirely is truncated.
                while batch >= 1:
                    try:
                        block = r.read_at(
                            thunk_off + index * thunk_size, batch * thunk_size
                        )
                        break
                    except PEError:
                        batch //= 2
                if block is None:
                    truncated = True  # ran off the file with no terminator
                    break
                batch_hint = batch
                values = struct.unpack(
                    f"<{len(block) // thunk_size}{unpack_thunk[1]}", block
                )
                for value in values:
                    work += 1
                    if work > MAX_IMPORT_WORK:
                        truncated = True
                        terminated = True
                        break
                    if value == 0:
                        terminated = True
                        break
                    index += 1
                    if value & ordinal_flag:
                        functions.append(f"#{value & 0xFFFF}")
                        continue
                    name_entry = rva_to_offset(value)
                    if name_entry is None:
                        continue
                    # 2-byte hint precedes the function name.
                    try:
                        functions.append(
                            r.c_string(name_entry + 2, _MAX_NAME_BYTES)
                        )
                    except PEError:
                        truncated = True
                        terminated = True
                        break
            # (loop ends when terminated or truncated)
        if dll_name in imports:
            # The same DLL can appear in more than one descriptor
            # (duplicates, delay-load mirrors): merge the function
            # lists instead of silently discarding the earlier one.
            imports[dll_name].extend(functions)
        else:
            imports[dll_name] = functions
        if truncated:
            break
    else:
        truncated = True  # descriptor cap reached without a terminator
    return imports, truncated


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


# ----------------------------------------------------------------------
# Signer identity extraction (bounded DER walk of the PKCS#7 blob)
#
# A real Authenticode blob is a PKCS#7 ContentInfo wrapping a
# SignedData; the signer's certificate sits in SignedData's
# certificate set, conventionally first, and its Subject name is
# who the signature CLAIMS to speak for. Argus needs that claim to
# recognise normal Windows system files ("Microsoft Windows").
#
# This is a structural walk, not a cryptographic verification:
# every tag/length is bounds-checked, every deviation returns "no
# identity", and nothing here can raise or loop (each step consumes
# input or fails). Malformed DER therefore means "no identity,
# no trust" — the fail-safe direction. Full chain + digest
# verification stays future work, documented with the rest of the
# signature model.
# ----------------------------------------------------------------------

#: DER content bytes of the OID 1.2.840.113549.1.7.2 (signedData).
_OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
#: DER content bytes of the attribute-type OIDs we read from a
#: certificate Subject: 2.5.4.3 (commonName), 2.5.4.10 (organization).
_OID_COMMON_NAME = bytes.fromhex("550403")
_OID_ORGANIZATION = bytes.fromhex("55040a")

_TAG_INTEGER = 0x02
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_CONTEXT_0 = 0xA0  # [0] constructed: version (cert) / certs (SignedData)

#: Cap on the PKCS#7 payload handed to the DER walker. Real
#: Authenticode blobs are a few KB; the cap keeps a hostile cert
#: table from making the parser chew a giant region.
_MAX_PKCS7_BYTES = 1024 * 1024


def _der_tlv(data: bytes, pos: int, end: int) -> tuple[int, int, int, int] | None:
    """Read one DER TLV header at *pos* (bounded by *end*).

    Returns ``(tag, content_start, content_end, next_pos)`` or None
    for anything malformed: multi-byte tags, indefinite lengths,
    over-long length fields, or a content span outside the buffer.
    """
    if pos + 2 > end:
        return None
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        return None  # multi-byte tag numbers: not valid in this walk
    first_len = data[pos + 1]
    cursor = pos + 2
    if first_len < 0x80:
        length = first_len
    elif first_len == 0x80:
        return None  # indefinite length is not DER
    else:
        count = first_len & 0x7F
        if count == 0 or count > 4 or cursor + count > end:
            return None
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    content_end = cursor + length
    if content_end > end:
        return None
    return tag, cursor, content_end, content_end


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]] | None:
    """Split the constructed value ``data[start:end]`` into child
    TLVs as ``(tag, content_start, content_end)`` triples. None if
    the children do not exactly tile the parent."""
    children: list[tuple[int, int, int]] = []
    pos = start
    while pos < end:
        parsed = _der_tlv(data, pos, end)
        if parsed is None:
            return None
        tag, c_start, c_end, next_pos = parsed
        children.append((tag, c_start, c_end))
        pos = next_pos
    if pos != end:
        return None
    return children


def _der_string(data: bytes, tag: int, start: int, end: int) -> str | None:
    """Decode a DER string value by its tag, or None when the tag
    is a string type we do not read (or decoding fails)."""
    raw = data[start:end]
    try:
        if tag in (0x0C, 0x13, 0x16, 0x1B):  # UTF8 / Printable / IA5 / Visible
            return raw.decode("utf-8", errors="strict").strip()
        if tag == 0x14:  # TeletexString: close enough as latin-1
            return raw.decode("latin-1").strip()
        if tag == 0x1E:  # BMPString: UTF-16BE
            return raw.decode("utf-16-be").strip()
    except (UnicodeDecodeError, ValueError):
        return None
    return None


def _parse_der_name(data: bytes, start: int, end: int) -> tuple[str | None, str | None]:
    """Read an X.501 Name (SEQUENCE OF SET OF SEQUENCE {OID, value})
    and return its ``(commonName, organization)`` — either may be
    absent. Anything unexpected yields what was found so far."""
    cn: str | None = None
    org: str | None = None
    rdns = _der_children(data, start, end)
    if rdns is None:
        return None, None
    for tag, r_start, r_end in rdns:
        if tag != _TAG_SET:
            continue
        attributes = _der_children(data, r_start, r_end)
        if attributes is None:
            continue
        for a_tag, a_start, a_end in attributes:
            if a_tag != _TAG_SEQUENCE:
                continue
            pair = _der_children(data, a_start, a_end)
            if pair is None or len(pair) != 2:
                continue
            (oid_tag, o_start, o_end), (val_tag, v_start, v_end) = pair
            if oid_tag != _TAG_OID:
                continue
            oid = data[o_start:o_end]
            if oid == _OID_COMMON_NAME and cn is None:
                cn = _der_string(data, val_tag, v_start, v_end)
            elif oid == _OID_ORGANIZATION and org is None:
                org = _der_string(data, val_tag, v_start, v_end)
    return cn, org


#: Minimum plausible length (bytes) for the RSA signature octet
#: string on a SignerInfo: 1024-bit RSA signs at exactly 128.
_MIN_SIGNATURE_OCTETS = 128
_TAG_OCTET_STRING = 0x04
_TAG_SET_OF = 0x31


def _signer_info_is_complete(
    blob: bytes,
    signer_infos: tuple[int, int, int],
    cert_issuer: tuple[str | None, str | None],
    cert_serial: int,
) -> bool:
    """True when some SignerInfo in the SET at *signer_infos*
    structurally completes the signature for the certificate
    identified by *cert_issuer* + *cert_serial*:

    - its ``issuerAndSerialNumber`` references that certificate
      (issuer Name equal AND serial number equal),
    - it declares a digest algorithm (an AlgorithmIdentifier
      SEQUENCE whose first element is an OID),
    - it carries a signature OCTET STRING of at least
      :data:`_MIN_SIGNATURE_OCTETS` bytes (a plausible RSA length;
      the known forgery's 2-byte signature fails here).

    Any structural anomaly returns False — incomplete means no
    identity, no trust."""
    _tag, infos_start, infos_end = signer_infos
    infos = _der_children(blob, infos_start, infos_end)
    if not infos:
        return False
    for info_tag, info_start, info_end in infos:
        if info_tag != _TAG_SEQUENCE:
            continue
        fields = _der_children(blob, info_start, info_end)
        if fields is None or len(fields) < 4:
            continue
        # [0] version INTEGER, [1] issuerAndSerialNumber SEQUENCE.
        if fields[0][0] != _TAG_INTEGER or fields[1][0] != _TAG_SEQUENCE:
            continue
        pair = _der_children(blob, fields[1][1], fields[1][2])
        if pair is None or len(pair) != 2:
            continue
        (iss_tag, iss_start, iss_end), (ser_tag, ser_start, ser_end) = pair
        if iss_tag != _TAG_SEQUENCE or ser_tag != _TAG_INTEGER:
            continue
        if _parse_der_name(blob, iss_start, iss_end) != cert_issuer:
            continue
        if int.from_bytes(blob[ser_start:ser_end], "big") != cert_serial:
            continue
        # [2] digestAlgorithm: SEQUENCE { OID, ... }.
        if fields[2][0] != _TAG_SEQUENCE:
            continue
        alg = _der_children(blob, fields[2][1], fields[2][2])
        if not alg or alg[0][0] != _TAG_OID:
            continue
        # A signature OCTET STRING of plausible RSA length among
        # the remaining elements (after the optional [0]
        # authenticated attributes and the digest-encryption
        # algorithm SEQUENCE comes the encryptedDigest).
        for f_tag, f_start, f_end in fields[3:]:
            if f_tag == _TAG_OCTET_STRING and f_end - f_start >= _MIN_SIGNATURE_OCTETS:
                return True
    return False


def _signer_from_pkcs7(
    blob: bytes,
) -> tuple[str | None, str | None, bool, bool]:
    """Walk a PKCS#7 SignedData blob and return
    ``(signer_cn, signer_org, signer_info_complete,
    has_extracted_signer)``.

    ``has_extracted_signer`` records that a signer certificate
    with a subject name was extracted at all (the structural bar
    for the signed score trim). The identity pair itself is only
    returned when a structurally COMPLETE SignerInfo for that
    certificate is present (see
    :func:`_signer_info_is_complete`): a certificate that merely
    *claims* a name — the first-cert-only forgery — yields
    ``(None, None, False, True)``. Every step is verified against
    the expected Authenticode shape; any deviation fails safe."""
    none4: tuple[str | None, str | None, bool, bool] = (None, None, False, False)
    top = _der_tlv(blob, 0, len(blob))
    if top is None:
        return none4
    tag, start, end, _next = top
    if tag != _TAG_SEQUENCE:
        return none4
    content_info = _der_children(blob, start, end)
    if content_info is None or len(content_info) < 2:
        return none4
    oid_tag, o_start, o_end = content_info[0]
    if oid_tag != _TAG_OID or blob[o_start:o_end] != _OID_SIGNED_DATA:
        return none4
    wrap_tag, w_start, w_end = content_info[1]
    if wrap_tag != _TAG_CONTEXT_0:
        return none4
    signed_data = _der_children(blob, w_start, w_end)
    if signed_data is None or len(signed_data) != 1:
        return none4
    sd_tag, sd_start, sd_end = signed_data[0]
    if sd_tag != _TAG_SEQUENCE:
        return none4
    parts = _der_children(blob, sd_start, sd_end)
    if parts is None:
        return none4
    # SignedData: version, digestAlgorithms, contentInfo come
    # first; the certificate set ([0]) follows, before signerInfos.
    certs: tuple[int, int, int] | None = None
    certs_index = -1
    for index in range(3, len(parts)):
        if parts[index][0] == _TAG_CONTEXT_0:
            certs = parts[index]
            certs_index = index
            break
    if certs is None:
        return none4
    _c_tag, certs_start, certs_end = certs
    certificates = _der_children(blob, certs_start, certs_end)
    if not certificates:
        return none4
    cert_tag, cert_start, cert_end = certificates[0]
    if cert_tag != _TAG_SEQUENCE:
        return none4
    cert_parts = _der_children(blob, cert_start, cert_end)
    if not cert_parts:
        return none4
    tbs_tag, tbs_start, tbs_end = cert_parts[0]
    if tbs_tag != _TAG_SEQUENCE:
        return none4
    fields = _der_children(blob, tbs_start, tbs_end)
    if fields is None:
        return none4
    idx = 0
    if idx < len(fields) and fields[idx][0] == _TAG_CONTEXT_0:
        idx += 1  # [0] version
    # serial (INTEGER), signature (SEQUENCE), issuer (Name),
    # validity (SEQUENCE), subject (Name) — five fixed slots.
    slots = fields[idx : idx + 5]
    if len(slots) < 5:
        return none4
    if slots[0][0] != _TAG_INTEGER or slots[4][0] != _TAG_SEQUENCE:
        return none4
    cert_serial = int.from_bytes(blob[slots[0][1] : slots[0][2]], "big")
    cert_issuer = _parse_der_name(blob, slots[2][1], slots[2][2])
    subject = _parse_der_name(blob, slots[4][1], slots[4][2])
    has_signer = subject[0] is not None or subject[1] is not None

    # signerInfos: the SET that follows the certificate set.
    signer_infos: tuple[int, int, int] | None = None
    for part in parts[certs_index + 1 :]:
        if part[0] == _TAG_SET_OF:
            signer_infos = part
            break
    complete = (
        signer_infos is not None
        and _signer_info_is_complete(blob, signer_infos, cert_issuer, cert_serial)
    )
    if complete:
        return subject[0], subject[1], True, has_signer
    return None, None, False, has_signer


def _extract_signer_identity(
    r: _Reader, cert_offset: int
) -> tuple[str | None, str | None, bool, bool]:
    """Read the FIRST WIN_CERTIFICATE entry's PKCS#7 payload and
    extract its signer's identity (see :func:`_signer_from_pkcs7`
    for the four-tuple). The caller has already validated the
    certificate table structurally, so the first entry's length
    is sane; the payload read is still capped and the DER walk
    itself fully defensive."""
    length = r.u32(cert_offset)
    if length < 8 or length > _MAX_PKCS7_BYTES + 8:
        return None, None, False, False
    payload = r.read_at(cert_offset + 8, length - 8)
    return _signer_from_pkcs7(payload)
