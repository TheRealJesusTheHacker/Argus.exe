"""Display-safety for attacker-controlled text.

File names, archive member names, and error strings that quote
them are data an attacker can choose. When such text is printed
into a line-oriented surface — CLI output, the plain-language
history report, log lines — a name carrying a newline (legal in
a Linux file name, and in archive member names on every
platform) could otherwise forge extra lines that look like
Argus's own output: a fake verdict for a file that was never
scanned, a fake "everything is clean" line, a fake entry in a
report a user may act on.

:func:`display_safe` is the single funnel for that text:
control characters are escaped (``\\x0a`` and friends), so the
text stays on the one line Argus puts it on. Ordinary names —
spaces and printable Unicode included — pass through unchanged.
This is a DISPLAY transformation only: stored paths, history
records, and every filesystem operation keep the true name.
"""

from __future__ import annotations


def display_safe(text: str) -> str:
    """Return *text* made safe to print on a single output line:
    every non-printable character (newlines, carriage returns,
    terminal escape initiators, bidi controls, …) is replaced by
    its ``\\xNN`` escape. Printable text is returned unchanged."""
    return "".join(
        ch if (ch == " " or ch.isprintable()) else f"\\x{ord(ch):02x}"
        for ch in text
    )
