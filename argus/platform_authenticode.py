"""Platform Authenticode verification (v1.1.0 fix round 2, FIX 5).

Argus's Microsoft system-file trust (see
:mod:`argus.heuristics.analyze`) needs to know a file's embedded
signature is *genuinely* valid — chain and signed digest, not just
a well-formed claim. Pure-stdlib DER parsing cannot verify
signature CONTENT (it can parse structure and read the claimed
signer, but it cannot run the certificate-chain engine or check
the message digest against the file). Windows can:
``WinVerifyTrust`` in ``wintrust.dll`` is the operating system's
own Authenticode verifier.

Design:

- On Windows, :func:`verify_authenticode` calls WinVerifyTrust
  (ctypes) with ``WINTRUST_ACTION_GENERIC_VERIFY_V2``, no UI, and
  ``WTD_REVOKE_NONE`` — revocation checking stays OFF so machines
  without network access do not fail genuine files over an
  unreachable revocation endpoint (offline behaviour was an
  explicit requirement; an HRESULT is still logged by the caller
  so field data can revisit the flag choice).
- Any failure — a bad HRESULT, an exception, an unreadable file —
  is ``"failed"``: callers fail CLOSED (no trust), never open.
- Off Windows the verifier is *unavailable* and callers fall back
  to the documented claim-based path (structural validation +
  signer identity + system location), which is the dev /
  non-Windows behaviour only — the shipped product runs on
  Windows and gets the real check.

Verdicts are cached per (resolved path, size, mtime, sampled
content) for the life of the process: a long scan re-verifies
a file only when the file itself changes. The sampled-content
component (the watcher's first+last 64 KiB hash) matters: a
same-size replacement with a restored mtime — the standard
timestomp — must NOT inherit the previous file's "verified"
verdict (fix round 3).
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .watcher import sampled_content_hash

log = logging.getLogger("argus.platform_authenticode")

#: Verification succeeded — Windows vouches for chain + digest.
STATUS_VERIFIED = "verified"
#: Verification ran and did NOT vouch (or could not run cleanly).
STATUS_FAILED = "failed"
#: No platform verifier exists here (non-Windows).
STATUS_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class AuthenticodeResult:
    """The platform verifier's verdict for one file."""

    status: str  # STATUS_VERIFIED | STATUS_FAILED | STATUS_UNAVAILABLE
    #: The raw WinVerifyTrust return code (an HRESULT) when the
    #: platform call ran; None when it never did.
    hresult: int | None = None
    detail: str = ""


#: A verifier maps a path to an AuthenticodeResult. Tests inject
#: fakes; production uses :func:`verify_authenticode`.
AuthenticodeVerifier = Callable[[Path], AuthenticodeResult]

_CACHE_LIMIT = 512
_cache: "OrderedDict[tuple[str, int, int, str], AuthenticodeResult]" = (
    OrderedDict()
)


def platform_verifier() -> AuthenticodeVerifier | None:
    """The default verifier for this platform, or None when the
    platform has none (non-Windows) — the caller then uses its
    documented claim-based fallback. On Windows the verifier is
    always offered; its per-file results fail closed."""
    if sys.platform != "win32":
        return None
    return verify_authenticode


def verify_authenticode(path: Path | str) -> AuthenticodeResult:
    """Verify *path*'s Authenticode signature with WinVerifyTrust.

    Cached per (path, size, mtime, sampled content). Non-Windows
    returns ``STATUS_UNAVAILABLE``. Windows failures of any kind
    return ``STATUS_FAILED`` with the HRESULT recorded — fail
    closed. A file that cannot even be sampled is failed, not
    verified: an unreadable file has no verdict to cache.
    """
    target = Path(path)
    try:
        stat = target.stat()
        key = (
            os.path.normcase(os.path.realpath(str(target))),
            stat.st_size,
            stat.st_mtime_ns,
            sampled_content_hash(target, stat.st_size),
        )
    except OSError as exc:
        return AuthenticodeResult(
            STATUS_FAILED, None, f"could not stat/sample the file: {exc}"
        )
    cached = _cache.get(key)
    if cached is not None:
        _cache.move_to_end(key)
        return cached
    result = _verify_authenticode_uncached(target)
    _cache[key] = result
    while len(_cache) > _CACHE_LIMIT:
        _cache.popitem(last=False)
    return result


def clear_cache() -> None:
    """Forget all cached verdicts (tests)."""
    _cache.clear()


# ----------------------------------------------------------------------
# WinVerifyTrust via ctypes (Windows only)
# ----------------------------------------------------------------------
# WINTRUST_ACTION_GENERIC_VERIFY_V2
_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"

_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 0
_WTD_STATEACTION_CLOSE = 2
# WTD_REVOCATION_CHECK_NONE lives in fdwRevocationChecks; prov
# flags below keep the provider offline-friendly and UI-free.
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000  # do not chase URLs live


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WinTrustFileInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.c_void_p),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WinTrustData(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_ulong),
        ("fdwRevocationChecks", ctypes.c_ulong),
        ("dwUnionChoice", ctypes.c_ulong),
        ("pFile", ctypes.POINTER(_WinTrustFileInfo)),
        ("dwStateAction", ctypes.c_ulong),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_ulong),
        ("dwUIContext", ctypes.c_ulong),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


def _guid_from_string(text: str) -> _GUID:
    import uuid

    raw = uuid.UUID(text).bytes_le
    guid = _GUID()
    ctypes.memmove(ctypes.byref(guid), raw, len(raw))
    return guid


def _verify_authenticode_uncached(target: Path) -> AuthenticodeResult:
    if sys.platform != "win32":
        return AuthenticodeResult(
            STATUS_UNAVAILABLE, None, "WinVerifyTrust is Windows-only"
        )
    try:
        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)  # type: ignore[attr-defined]
    except (OSError, AttributeError) as exc:
        return AuthenticodeResult(
            STATUS_FAILED, None, f"could not load wintrust.dll: {exc}"
        )
    file_info = _WinTrustFileInfo()
    file_info.cbStruct = ctypes.sizeof(_WinTrustFileInfo)
    file_info.pcwszFilePath = str(target)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = _WinTrustData()
    data.cbStruct = ctypes.sizeof(_WinTrustData)
    data.dwUIChoice = _WTD_UI_NONE
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = _WTD_STATEACTION_VERIFY
    data.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL
    data.dwUIContext = 0

    action = _guid_from_string(_GENERIC_VERIFY_V2)
    win_verify_trust = wintrust.WinVerifyTrust
    win_verify_trust.restype = ctypes.c_long
    win_verify_trust.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_GUID),
        ctypes.c_void_p,
    ]
    try:
        status = int(
            win_verify_trust(None, ctypes.byref(action), ctypes.byref(data))
        )
    except Exception as exc:  # ctypes marshalling problems: fail closed
        return AuthenticodeResult(
            STATUS_FAILED, None, f"WinVerifyTrust raised: {exc!r}"
        )
    finally:
        # Always release the state WinVerifyTrust allocated, pass
        # or fail — skipping the CLOSE call leaks provider state.
        try:
            data.dwStateAction = _WTD_STATEACTION_CLOSE
            win_verify_trust(None, ctypes.byref(action), ctypes.byref(data))
        except Exception:
            pass
    if status == 0:
        return AuthenticodeResult(STATUS_VERIFIED, 0, "WinVerifyTrust: OK")
    return AuthenticodeResult(
        STATUS_FAILED,
        status & 0xFFFFFFFF,
        f"WinVerifyTrust returned 0x{status & 0xFFFFFFFF:08X}",
    )
