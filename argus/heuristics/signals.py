"""The heuristic signal library for ARGUS.EXE.

A *signal* is one observable fact about a file that resembles a known
malicious technique: an import combination used for process injection,
a packed (high-entropy) executable section, a PowerShell encoded
command, a filename disguised with a double extension. Each signal
carries:

- a **severity** (low / medium / high / critical — how alarming the
  fact is on its own),
- a **weight in points** (how much it adds to the file's risk score —
  see :mod:`argus.scoring`),
- a **plain-language explanation** a non-expert can act on.

No single signal is a conviction. Legitimate software trips some of
these sometimes; that is exactly why signals are *scored*, and why the
explanations say what was seen rather than declaring guilt.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .entropy import HIGH_ENTROPY_THRESHOLD, EntropySummary
from .pe import PEInfo, Section


@dataclass(frozen=True)
class Signal:
    """One weighted, explained risk observation about a file."""

    name: str
    severity: str  # low | medium | high | critical
    points: int
    explanation: str


# ----------------------------------------------------------------------
# Extracted strings (built by the analyzer's streamed content pass)
# ----------------------------------------------------------------------
@dataclass
class StringIndex:
    """ASCII + UTF-16LE strings pulled from a file, with capped size."""

    strings: list[str] = field(default_factory=list)
    truncated: bool = False
    #: High-value needles found by the analyzer's independent
    #: streaming needle search — which keeps running even after the
    #: extraction cap truncates the string list, so flooding a file
    #: with junk strings cannot push the interesting ones out of
    #: view.
    needle_hits: set[str] = field(default_factory=set)

    _lower_set: set[str] = field(default_factory=set, repr=False)
    _blob: str = field(default="", repr=False)

    def add(self, value: str) -> None:
        self.strings.append(value)
        lowered = value.lower()
        self._lower_set.add(lowered)
        if len(self._blob) < 8_000_000:
            self._blob += lowered + "\n"

    def has_exact(self, needle: str) -> bool:
        """True if *needle* appears as a whole extracted string."""
        return needle.lower() in self._lower_set

    def contains(self, needle: str) -> bool:
        """True if *needle* appears anywhere in the extracted text
        — including via the cap-independent needle search."""
        lowered = needle.lower()
        return lowered in self._blob or lowered in self.needle_hits


# ----------------------------------------------------------------------
# Filename signals (no file content needed)
# ----------------------------------------------------------------------
_DOC_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "bmp", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "txt", "zip", "rar", "mp3", "mp4", "avi",
}
_EXEC_EXTENSIONS = {
    "exe", "scr", "com", "bat", "cmd", "js", "jse", "vbs", "wsf",
    "hta", "msi", "dll", "ps1",
}
_SYSTEM_BINARY_NAMES = {
    "svchost", "csrss", "lsass", "smss", "winlogon", "wininit",
    "spoolsv", "explorer", "dwm", "services", "conhost", "taskhost",
    "taskhostw", "rundll32", "dllhost", "searchindexer",
}
_RTL_OVERRIDE = "‮"
_RTL_EMBEDDING = "‫"


def filename_signals(filename: str) -> list[Signal]:
    """Signals derivable from the file's name alone."""
    signals: list[Signal] = []

    if _RTL_OVERRIDE in filename or _RTL_EMBEDDING in filename:
        signals.append(
            Signal(
                name="rtl_override_filename",
                severity="critical",
                points=60,
                explanation=(
                    "The filename contains an invisible right-to-left "
                    "override character. This trick makes a name display "
                    "backwards — for example an executable can be made to "
                    "look like a photo or document. There is almost never "
                    "an honest reason for it."
                ),
            )
        )

    parts = filename.split(".")
    if len(parts) >= 3:
        inner, outer = parts[-2].lower(), parts[-1].lower()
        if inner in _DOC_EXTENSIONS and outer in _EXEC_EXTENSIONS:
            signals.append(
                Signal(
                    name="double_extension",
                    severity="high",
                    points=30,
                    explanation=(
                        f"The file has a double extension ('.{inner}.{outer}') "
                        "that disguises a program as a document, photo, or "
                        "archive. A classic malware masquerade."
                    ),
                )
            )

    if len(parts) >= 2 and parts[-1].lower() == "exe":
        stem = parts[0].lower() if len(parts) == 2 else ".".join(parts[:-1]).lower()
        if stem in _SYSTEM_BINARY_NAMES:
            signals.append(
                Signal(
                    name="system_binary_masquerade",
                    severity="medium",
                    points=15,
                    explanation=(
                        f"The file is named '{filename}', imitating a core "
                        "Windows system program. Real system programs live "
                        "in protected Windows folders; a copy under any other "
                        "name-owner deserves suspicion. (Where the file "
                        "lives is weighed during real-time protection.)"
                    ),
                )
            )

    return signals


# ----------------------------------------------------------------------
# PE signals
# ----------------------------------------------------------------------
def _variants(name: str) -> tuple[str, ...]:
    """API name with common A/W suffix variants."""
    return (name, name + "A", name + "W")


def _has_any(funcs: set[str], *names: str) -> bool:
    for name in names:
        for variant in _variants(name):
            if variant in funcs:
                return True
    return False


# Standard names for a first/entry code section in honest toolchains.
_STANDARD_ENTRY_SECTIONS = {".text", ".code", "code", "text", ".itext"}
_PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", ".packed", "mpress1", "mpress2", ".petite",
    "aspack", ".aspack", ".nspack", ".vmp0", ".vmp1", ".themida",
    ".enigma1", ".enigma2", "pec2", ".pec", "pebundle", ".bind",
}
_VM_STRINGS = (
    "vmware", "virtualbox", "vbox", "vmtoolsd", "vmmouse", "qemu",
    "sandboxie", "sbie", "virtual pc", "hyper-v", "xen",
)

#: DLLs whose named import combinations Argus scores as combos
#: (see pe_signals), mapped to (named combo points, label). Used
#: by the ordinal-hidden inference (P1-22): a combo-set DLL
#: imported almost entirely by ordinal earns partial points.
_ORDINAL_COMBO_DLLS: dict[str, tuple[int, str]] = {
    # VirtualAllocEx + WriteProcessMemory + CreateRemoteThread —
    # the process-injection trio (45 points when named) — all live
    # in KERNEL32.
    "kernel32.dll": (45, "process-injection"),
}


def pe_signals(
    pe: PEInfo, strings: StringIndex, entropy: EntropySummary
) -> list[Signal]:
    """Signals from a parsed PE: imports, strings, structure, entropy."""
    signals: list[Signal] = []
    funcs = pe.imported_functions

    # ---- dangerous capability combinations --------------------------
    if (
        _has_any(funcs, "VirtualAllocEx")
        and _has_any(funcs, "WriteProcessMemory")
        and "CreateRemoteThread" in funcs
    ):
        signals.append(
            Signal(
                name="process_injection_combo",
                severity="critical",
                points=45,
                explanation=(
                    "Imports the three Windows APIs that together perform "
                    "process injection — reserving memory in another "
                    "program, writing code into it, and starting it there. "
                    "This is how malware hides inside trusted programs. "
                    "Legitimate software almost never needs all three."
                ),
            )
        )

    # ---- ordinal-hidden combo suspicion (P1-22) -------------------
    # When a DLL that hosts a known-dangerous named combination is
    # imported almost entirely BY ORDINAL, the named combo check
    # above is blind — the names are exactly what ordinals hide.
    # Pinned heuristic: DLL in the combo set + >= 80% of its
    # imports by ordinal + >= 3 imports earns PARTIAL points
    # (strictly less than the named combination it might be
    # hiding). This is INFERENTIAL — Argus cannot see which APIs
    # the ordinals name — and the explanation says so.
    for dll_name, dll_funcs in pe.imports.items():
        combo = _ORDINAL_COMBO_DLLS.get(dll_name.lower())
        if combo is None or len(dll_funcs) < 3:
            continue
        named_points, combo_label = combo
        ordinal_count = sum(1 for fn in dll_funcs if fn.startswith("#"))
        if ordinal_count / len(dll_funcs) < 0.8:
            continue
        partial_points = named_points // 2
        if partial_points <= 0 or partial_points >= named_points:
            continue
        signals.append(
            Signal(
                name="ordinal_hidden_combo_suspect",
                severity="medium",
                points=partial_points,
                explanation=(
                    f"{ordinal_count} of {len(dll_funcs)} functions "
                    f"imported from {dll_name} are referenced by "
                    "ordinal (number) instead of by name. That DLL "
                    f"is where the {combo_label} combination lives, "
                    "and importing by ordinal is precisely how a "
                    "program hides that it uses it. This is an "
                    "INFERENCE, not a sighting: Argus cannot tell "
                    "which APIs the numbers name, so it scores a "
                    f"partial {partial_points} points instead of the "
                    f"named combination's {named_points} — suspicion "
                    "proportional to what could be hidden, honestly "
                    "labeled as such."
                ),
            )
        )
        break

    cred_api = _has_any(funcs, "CredEnumerate", "CredRead", "VaultEnumerateItems")
    lsass_dump = "MiniDumpWriteDump" in funcs and strings.contains("lsass")
    if cred_api or lsass_dump or strings.contains("sekurlsa"):
        signals.append(
            Signal(
                name="credential_access",
                severity="high",
                points=35,
                explanation=(
                    "Reaches for stored credentials or the LSASS process, "
                    "where Windows keeps login passwords and tokens in "
                    "memory. Password-stealing tools do exactly this."
                ),
            )
        )

    run_key = strings.contains("currentversion\\run") or strings.contains(
        "currentversion/run"
    )
    persistence_api = (
        _has_any(funcs, "RegSetValueEx", "RegCreateKeyEx")
        and run_key
    ) or _has_any(funcs, "CreateService")
    scheduler = strings.contains("schedule.service") or strings.contains("itaskservice")
    if persistence_api or scheduler:
        signals.append(
            Signal(
                name="persistence_mechanism",
                severity="high",
                points=30,
                explanation=(
                    "Contains a persistence mechanism — a way to relaunch "
                    "itself automatically at every login or boot (registry "
                    "Run key, service, or scheduled task). Malware installs "
                    "these to survive reboots."
                ),
            )
        )

    hook = _has_any(funcs, "SetWindowsHookEx")
    keystate = "GetAsyncKeyState" in funcs or "GetKeyState" in funcs
    if hook and keystate:
        signals.append(
            Signal(
                name="keylogging_combo",
                severity="high",
                points=30,
                explanation=(
                    "Combines a system-wide keyboard hook with key-state "
                    "polling — the two ingredients of a keylogger that "
                    "records everything typed, including passwords."
                ),
            )
        )
    elif hook or keystate:
        signals.append(
            Signal(
                name="keylogging_api",
                severity="medium",
                points=12,
                explanation=(
                    "Uses a keyboard-hooking or key-state API. These have "
                    "honest uses (hotkeys, accessibility tools) but are "
                    "also how keyloggers watch what you type."
                ),
            )
        )

    if _has_any(funcs, "URLDownloadToFile") and (
        _has_any(funcs, "ShellExecute") or "WinExec" in funcs or _has_any(funcs, "CreateProcess")
    ):
        signals.append(
            Signal(
                name="download_and_execute",
                severity="high",
                points=35,
                explanation=(
                    "Can both download a file from the internet and launch "
                    "programs — the defining behavior of a 'dropper' that "
                    "fetches the real malware after it lands."
                ),
            )
        )

    if _has_any(funcs, "IsDebuggerPresent", "CheckRemoteDebuggerPresent"):
        signals.append(
            Signal(
                name="anti_debug_imports",
                severity="medium",
                points=15,
                explanation=(
                    "Imports debugger-detection APIs. Some honest software "
                    "checks for debuggers, but malware uses these to notice "
                    "it is being analyzed and change behavior."
                ),
            )
        )

    if any(strings.contains(vm) for vm in _VM_STRINGS):
        signals.append(
            Signal(
                name="vm_evasion_strings",
                severity="medium",
                points=15,
                explanation=(
                    "Contains names of virtual-machine environments. "
                    "Malware checks for these to avoid running where "
                    "researchers study it. (Also present in some honest "
                    "compatibility code.)"
                ),
            )
        )

    if strings.contains("amsiinitfailed") or strings.contains("amsiscanbuffer"):
        signals.append(
            Signal(
                name="amsi_bypass_strings",
                severity="high",
                points=25,
                explanation=(
                    "References AMSI, Windows' built-in script-scanning "
                    "interface, in a way associated with disabling it. "
                    "Blinding the built-in scanner is a known malware "
                    "technique."
                ),
            )
        )

    # ---- structure ----------------------------------------------------
    if pe.cert_malformed:
        signals.append(
            Signal(
                name="malformed_certificate",
                severity="high",
                points=25,
                explanation=(
                    "The file CLAIMS an Authenticode signature, but the "
                    "certificate region is structurally invalid — wrong "
                    "type, impossible lengths, or running past the end "
                    "of the file. It is not a real signature: it earns "
                    "no trust, and the bytes are counted as unexplained "
                    "overlay data. Forged signature blocks are a known "
                    "way to make malware look signed."
                ),
            )
        )

    if pe.imports_truncated:
        signals.append(
            Signal(
                name="imports_truncated",
                severity="medium",
                points=10,
                explanation=(
                    "The import table was so large that Argus stopped "
                    "reading it at a safety cap before its natural end. "
                    "Honest programs have modest import tables; a "
                    "bloated or looping one is a way to exhaust or "
                    "blind analyzers."
                ),
            )
        )

    all_funcs = [fn for names in pe.imports.values() for fn in names]
    if len(all_funcs) >= 8:
        ordinals = sum(1 for fn in all_funcs if fn.startswith("#"))
        if ordinals / len(all_funcs) >= 0.5:
            signals.append(
                Signal(
                    name="ordinal_heavy_imports",
                    severity="medium",
                    points=15,
                    explanation=(
                        f"{ordinals} of {len(all_funcs)} imported "
                        "functions are referenced by number (ordinal) "
                        "instead of by name. Importing by ordinal hides "
                        "what a program actually calls — a deliberate "
                        "concealment technique, rare in honest software "
                        "at this ratio."
                    ),
                )
            )

    if strings.truncated:
        signals.append(
            Signal(
                name="string_extraction_truncated",
                severity="low",
                points=10,
                explanation=(
                    "The file contains more embedded text strings than "
                    "Argus extracts, so string analysis hit its cap. "
                    "Flooding a file with junk strings is a known way "
                    "to push the interesting ones out of an analyzer's "
                    "view. (Argus's high-value needle search keeps "
                    "running independently of the cap.)"
                ),
            )
        )

    for sec in pe.sections:
        if sec.is_executable and sec.entropy is not None and sec.entropy >= HIGH_ENTROPY_THRESHOLD:
            signals.append(
                Signal(
                    name="high_entropy_executable_section",
                    severity="high",
                    points=25,
                    explanation=(
                        f"Section '{sec.name}' is executable and its contents "
                        f"measure {sec.entropy:.1f} bits of entropy — nearly "
                        "random. Normal code measures around 6. This is the "
                        "mark of packed or encrypted code hiding its real "
                        "contents until it runs."
                    ),
                )
            )
            break

    # ---- entropy geography ------------------------------------------
    # A section's AVERAGE entropy can look tame while one region
    # inside it is packed solid — and high-entropy data can hide
    # entirely outside every section (overlay / inter-section gaps),
    # where per-section analysis never looks. Judge the map, not
    # just the averages.
    section_ranges = [
        (s.raw_offset, s.raw_offset + s.raw_size) for s in pe.sections if s.raw_size
    ]

    def _uncovered_length(region) -> int:
        # The part of the region no section accounts for. A region
        # that merely TOUCHES a section is not "covered" — a window
        # straddling the section boundary holds most of its bytes
        # outside, and those outside bytes are the hiding place
        # this signal exists for. (Section raw ranges are disjoint,
        # so per-range overlaps can simply be summed.)
        start, end = region.offset, region.offset + region.length
        covered = 0
        for r_start, r_end in section_ranges:
            lo, hi = max(start, r_start), min(end, r_end)
            if hi > lo:
                covered += hi - lo
        return (end - start) - covered

    uncovered_bytes = sum(
        _uncovered_length(region) for region in entropy.high_regions
    )
    if uncovered_bytes >= 4096:
        signals.append(
            Signal(
                name="high_entropy_outside_sections",
                severity="medium",
                points=15,
                explanation=(
                    f"{uncovered_bytes:,} bytes of high-entropy "
                    "(packed/encrypted-looking) data sit OUTSIDE every "
                    "declared section — in the overlay or the gaps "
                    "between sections, where the program structure "
                    "does not account for them. Payloads are hidden "
                    "there precisely because section-based checks "
                    "never look."
                ),
            )
        )

    # Attribution requires the window's DOMINANT section (P2): a
    # high-entropy region is charged to a section only when that
    # section holds the MAJORITY of the region's bytes. A window
    # that merely touches or straddles a section boundary — most
    # of it living elsewhere — attributes to nobody; the outside-
    # sections signal above is what covers that data.
    for region in entropy.high_regions:
        region_end = region.offset + region.length
        dominant: Section | None = None
        dominant_overlap = 0
        for sec in pe.sections:
            if sec.raw_size == 0:
                continue
            overlap = min(region_end, sec.raw_offset + sec.raw_size) - max(
                region.offset, sec.raw_offset
            )
            if overlap > dominant_overlap:
                dominant, dominant_overlap = sec, overlap
        if dominant is None or dominant_overlap * 2 <= region.length:
            continue  # no section holds the majority of this window
        sec = dominant
        if not sec.is_executable:
            continue
        if sec.entropy is not None and sec.entropy >= HIGH_ENTROPY_THRESHOLD:
            continue  # the average already told the story above
        signals.append(
            Signal(
                name="high_entropy_window_in_section",
                severity="medium",
                points=15,
                explanation=(
                    f"Section '{sec.name}' looks ordinary on "
                    f"average, but contains a window measuring "
                    f"{region.entropy:.1f} bits of entropy — a packed or "
                    "encrypted pocket hidden inside otherwise "
                    "normal-looking code."
                ),
            )
        )
        break

    if pe.entry_section is not None:
        idx = pe.entry_section_index or 0
        entry = pe.entry_section
        # Layout, not just names: an entry point in a section with
        # no bytes in the file starts in zero-filled memory the
        # program must fill for itself — a hollowing/packing trait
        # whatever the section is called.
        entry_in_vapor = entry.raw_size == 0 and entry.virtual_size > 0
        if (
            idx != 0
            or entry.name.strip().lower() not in _STANDARD_ENTRY_SECTIONS
            or entry_in_vapor
        ):
            signals.append(
                Signal(
                    name="entry_point_unusual",
                    severity="medium",
                    points=15,
                    explanation=(
                        f"The program starts running in section '{entry.name}' "
                        f"(section {idx + 1} of {len(pe.sections)}), not in a "
                        "standard first code section. Packers and modified "
                        "binaries commonly move the starting point like this."
                        + (
                            " The section has no bytes in the file at all — "
                            "the starting code must be produced at runtime."
                            if entry_in_vapor else ""
                        )
                    ),
                )
            )
    elif pe.entry_point_rva != 0:
        signals.append(
            Signal(
                name="entry_point_outside_sections",
                severity="medium",
                points=15,
                explanation=(
                    "The program's starting address does not fall inside "
                    "any declared section. Honest executables always "
                    "start inside a code section; a start in unaccounted "
                    "space is a malformed or tampered structure."
                ),
            )
        )

    packer_names = [s.name for s in pe.sections if s.name.strip().lower() in _PACKER_SECTION_NAMES]
    if packer_names:
        signals.append(
            Signal(
                name="packer_section_name",
                severity="medium",
                points=15,
                explanation=(
                    f"Has a section named '{packer_names[0]}', left by a "
                    "known executable packer. Packing is legal and common, "
                    "but it hides a program's contents from scanners, so "
                    "packed files earn extra scrutiny."
                ),
            )
        )

    wx = [s.name for s in pe.sections if s.is_writable and s.is_executable]
    if wx:
        signals.append(
            Signal(
                name="writable_executable_section",
                severity="high",
                points=25,
                explanation=(
                    f"Section '{wx[0]}' is both writable and executable — "
                    "the program can write code and then run what it wrote. "
                    "Modern security practice forbids this because it is "
                    "how unpacked payloads and injected code execute."
                ),
            )
        )

    for sec in pe.sections:
        # Name-independent: ANY executable section that exists only
        # in memory (zero bytes in the file) must produce its code
        # at runtime — whatever the section calls itself.
        if sec.is_executable and sec.raw_size == 0 and sec.virtual_size > 0:
            signals.append(
                Signal(
                    name="zero_raw_code_section",
                    severity="medium",
                    points=15,
                    explanation=(
                        f"Executable section '{sec.name}' claims {sec.virtual_size:,} "
                        "bytes in memory but occupies zero bytes in the file. "
                        "The real code must appear from somewhere at runtime — "
                        "a hallmark of packed or hollowed executables."
                    ),
                )
            )
            break

    if pe.overlay_size > 64 * 1024 and pe.size > 0 and pe.overlay_size > 0.25 * pe.size:
        signals.append(
            Signal(
                name="huge_overlay",
                severity="medium",
                points=15,
                explanation=(
                    f"Carries {pe.overlay_size:,} extra bytes appended after "
                    "its last section — more than a quarter of the whole "
                    "file is data the program structure does not account "
                    "for. Payloads are often smuggled in this overlay."
                ),
            )
        )

    if not pe.signed and (
        strings.contains("requireadministrator") or strings.contains("highestavailable")
    ):
        signals.append(
            Signal(
                name="unsigned_elevation_request",
                severity="medium",
                points=15,
                explanation=(
                    "Asks Windows to run it with administrator rights "
                    "(its manifest requests elevation) but carries no "
                    "digital signature saying who made it. Unsigned "
                    "software demanding admin rights deserves a hard look."
                ),
            )
        )

    if pe.has_tls:
        signals.append(
            Signal(
                name="tls_callbacks_present",
                severity="medium",
                points=10,
                explanation=(
                    "Registers TLS callbacks — code Windows runs before the "
                    "program's official starting point, even before a "
                    "debugger's first breakpoint. A known hiding place for "
                    "early malware code, though some compilers add these "
                    "honestly."
                ),
            )
        )

    now = int(time.time())
    if pe.timestamp == 0 or pe.timestamp > now + 86_400 or pe.timestamp < 631_152_000:
        signals.append(
            Signal(
                name="timestamp_anomaly",
                severity="low",
                points=5,
                explanation=(
                    "The build timestamp in the file header is missing, in "
                    "the future, or implausibly old. Malware authors often "
                    "forge or zero timestamps to hinder investigation."
                ),
            )
        )

    total_funcs = sum(len(v) for v in pe.imports.values())
    if not pe.is_dll and 0 < total_funcs < 3:
        signals.append(
            Signal(
                name="minimal_imports",
                severity="low",
                points=5,
                explanation=(
                    f"Imports only {total_funcs} function(s). Programs this "
                    "stripped-down often resolve their real APIs secretly "
                    "at runtime to hide what they can do."
                ),
            )
        )

    return signals


# ----------------------------------------------------------------------
# Script signals
# ----------------------------------------------------------------------
_ENCODED_CMD_RE = re.compile(
    r"-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", re.IGNORECASE
)
_LONG_LINE_THRESHOLD = 2000
#: The smuggling shape the long-line signal hunts: one giant
#: WHITESPACE-FREE run (an encoded blob, a minified dropper) —
#: matched against the text as a whole, since a run cannot cross
#: a line break anyway.
_LONG_RUN_RE = re.compile(r"\S{" + str(_LONG_LINE_THRESHOLD + 1) + r",}")


def script_signals(text: str, filename: str) -> list[Signal]:
    """Signals from script content (.ps1/.bat/.vbs/.js/...).

    *text* is the DECODED script (UTF-16 included — see
    :func:`argus.heuristics.analyze._decode_script`), so these
    checks see exactly what the interpreter will see, however the
    bytes were stored.
    """
    signals: list[Signal] = []
    lower = text.lower()

    # ---- download cradles -------------------------------------------
    # The pattern that defines fileless malware delivery: fetch
    # code from the network and execute it in memory. Graded by
    # completeness — a download API alone is common in honest
    # scripts; download + execute + a remote address is the whole
    # weapon.
    has_download = (
        "downloadstring" in lower
        or "downloadfile" in lower
        or "net.webclient" in lower
    )
    has_invoke = "invoke-expression" in lower or bool(
        re.search(r"\biex\b", lower)
    )
    has_url = "http://" in lower or "https://" in lower
    if has_download and has_invoke:
        signals.append(
            Signal(
                name="powershell_download_cradle",
                severity="critical",
                points=50,
                explanation=(
                    "This script downloads code from the network and "
                    "executes it in memory (a 'download cradle': "
                    "WebClient DownloadString/DownloadFile combined "
                    "with Invoke-Expression). Whatever it fetches "
                    "never exists as a file for a scanner to check — "
                    "the defining delivery technique of fileless "
                    "malware."
                ),
            )
        )
    if has_download and has_url:
        signals.append(
            Signal(
                name="script_fetches_remote_content",
                severity="medium",
                points=15,
                explanation=(
                    "The script fetches content from a web address "
                    "(a download API together with an http(s) URL). "
                    "Honest scripts do this too — but combined with "
                    "execution it is a download cradle, and the "
                    "address deserves a hard look."
                ),
            )
        )

    if _ENCODED_CMD_RE.search(text) or "frombase64string" in lower:
        signals.append(
            Signal(
                name="encoded_powershell_command",
                severity="high",
                points=30,
                explanation=(
                    "Runs a PowerShell command hidden inside Base64 "
                    "encoding, so a person reading the file cannot see "
                    "what it actually does. A favorite delivery method "
                    "for fileless malware."
                ),
            )
        )

    if "certutil" in lower and "urlcache" in lower:
        signals.append(
            Signal(
                name="certutil_download",
                severity="high",
                points=25,
                explanation=(
                    "Uses certutil — a Windows certificate tool — to "
                    "download a file. Attackers abuse this trusted tool "
                    "to fetch malware past naive allow-lists."
                ),
            )
        )

    if "mshta" in lower and "http" in lower:
        signals.append(
            Signal(
                name="mshta_remote_script",
                severity="high",
                points=25,
                explanation=(
                    "Launches mshta against a web address, running a "
                    "remote script with a trusted Windows binary. A "
                    "well-known malware delivery trick."
                ),
            )
        )

    if "regsvr32" in lower and ("/i:http" in lower or "scrobj" in lower):
        signals.append(
            Signal(
                name="regsvr32_remote",
                severity="high",
                points=25,
                explanation=(
                    "Uses regsvr32 to pull and run a remote scriptlet — "
                    "the 'Squiblydoo' technique, which abuses a signed "
                    "Windows tool to execute attacker code."
                ),
            )
        )

    if "rundll32" in lower and "javascript:" in lower:
        signals.append(
            Signal(
                name="rundll32_javascript",
                severity="high",
                points=25,
                explanation=(
                    "Runs JavaScript through rundll32's URL handler — an "
                    "abuse of a Windows system tool to execute script "
                    "code that never touches disk as a script file."
                ),
            )
        )

    if text:
        ticks_and_carets = text.count("`") + text.count("^")
        char_construction = lower.count("[char]")
        if ticks_and_carets / len(text) > 0.02 or char_construction > 10:
            signals.append(
                Signal(
                    name="script_obfuscation",
                    severity="medium",
                    points=15,
                    explanation=(
                        "The script is densely obfuscated — heavy escape "
                        "characters and character-code construction that "
                        "make it unreadable to a human while the computer "
                        "runs it fine. Honest scripts rarely hide this hard."
                    ),
                )
            )

    # The threshold measures the longest whitespace-free RUN,
    # not raw line length (fix round 3): what this signal hunts
    # is a payload smuggled as one giant encoded blob. Natural
    # language is never that — a prose paragraph can run to
    # thousands of characters, but its words break it into short
    # runs — so prose (including prose a mixed-encoding decode
    # places next to script content) must not trip a payload
    # signal, while a genuine one-blob line still does.
    if _LONG_RUN_RE.search(text):
        signals.append(
            Signal(
                name="very_long_script_line",
                severity="medium",
                points=10,
                explanation=(
                    "Contains an extremely long unbroken run of text "
                    f"(over {_LONG_LINE_THRESHOLD:,} characters with "
                    "no spaces or line breaks). Payloads are commonly "
                    "smuggled as one giant encoded line so the file "
                    "looks short and innocent at a glance."
                ),
            )
        )

    return signals
