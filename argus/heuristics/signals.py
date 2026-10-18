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
from .pe import PEInfo


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
        """True if *needle* appears anywhere in the extracted text."""
        return needle.lower() in self._blob


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

    if pe.entry_section is not None:
        idx = pe.entry_section_index or 0
        entry = pe.entry_section
        if idx != 0 or entry.name.strip().lower() not in _STANDARD_ENTRY_SECTIONS:
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
        if sec.name.strip().lower() in (".text", ".code") and sec.raw_size == 0 and sec.virtual_size > 0:
            signals.append(
                Signal(
                    name="zero_raw_code_section",
                    severity="medium",
                    points=15,
                    explanation=(
                        f"Code section '{sec.name}' claims {sec.virtual_size:,} "
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


def script_signals(text: str, filename: str) -> list[Signal]:
    """Signals from script content (.ps1/.bat/.vbs/.js/...)."""
    signals: list[Signal] = []
    lower = text.lower()

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

    if any(len(line) > _LONG_LINE_THRESHOLD for line in text.splitlines()):
        signals.append(
            Signal(
                name="very_long_script_line",
                severity="medium",
                points=10,
                explanation=(
                    "Contains an extremely long single line (over "
                    f"{_LONG_LINE_THRESHOLD:,} characters). Payloads are "
                    "commonly smuggled as one giant encoded line so the "
                    "file looks short and innocent at a glance."
                ),
            )
        )

    return signals
