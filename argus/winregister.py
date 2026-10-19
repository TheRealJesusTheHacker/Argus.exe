"""Windows Security Center registration for ARGUS.EXE (Phase 5).

This is what makes Argus *the machine's antivirus*, not just a
program that scans: registering an ``AntiVirusProduct`` instance in
the ``root\\SecurityCenter2`` WMI namespace is how Windows learns
which product is responsible for antivirus protection. Once
registered, Argus appears by name in **Windows Security → Virus &
threat protection** as the machine's antivirus provider, alongside
its product state (protection on/off, definitions current or not).

Honest scope notes:

- Registration *lists* Argus as the provider and reports its state.
  It is the same mechanism legitimate third-party antivirus products
  use to appear in Windows Security. It does not, by itself, grant
  kernel-level tamper protection or Early Launch Anti-Malware status
  — those need Microsoft's signing programs and are future work.
- ``productState`` follows the SecurityCenter2 convention: a DWORD
  whose high bytes report real-time protection and signature state.
  The exact bit meanings are only loosely documented by Microsoft,
  so the composed values here are the widely-used ones; the composed
  value is isolated in :func:`product_state` so it can be adjusted
  after verification on a real machine without touching callers.

Everything Windows-specific (pywin32 / win32com) is imported lazily,
inside the functions that need it, so this module imports cleanly on
any platform. Off Windows, the register/unregister functions raise
:class:`RegistrationUnavailable` with a plain-language reason; the
pure property-building logic stays testable everywhere.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from typing import Callable

#: Name Windows shows for Argus in the Security Center.
DISPLAY_NAME = "ARGUS.EXE — Sentinel Safeguard"

#: Argus's stable SecurityCenter2 instance GUID — one identity for
#: the product, so re-registering updates the same instance Windows
#: already knows.
INSTANCE_GUID = "{CD12A057-1728-4386-A9B0-C66ACD49E54A}"

#: The WMI namespace Security Center products live in.
WMI_NAMESPACE = r"root\SecurityCenter2"
WMI_CLASS = "AntiVirusProduct"

#: Default instance identifier GUID format Security Center expects.
#: (A stable GUID for the product instance; generated once per
#: installation by the installer/service in practice — callers pass
#: one in, so registration is idempotent across runs.)
PROPERTY_KEYS = (
    "displayName",
    "instanceGuid",
    "pathToSignedProductExe",
    "pathToSignedReportingExe",
    "productState",
    "timestamp",
)


class RegistrationUnavailable(RuntimeError):
    """Registration cannot run here (not Windows, or no WMI access)."""


# ----------------------------------------------------------------------
# Pure logic (testable everywhere)
# ----------------------------------------------------------------------
def product_state(*, realtime_on: bool = True, definitions_current: bool = True) -> int:
    """Compose the SecurityCenter2 ``productState`` DWORD.

    Layout used by registered products: the state byte reports
    real-time protection on/off, and the signature byte reports
    definitions up to date / out of date. See the module docstring —
    the encoding is convention, not a published contract.
    """
    state = 0x0000
    if realtime_on:
        state |= 0x1000  # real-time protection enabled
    if definitions_current:
        state |= 0x0000  # definitions current (absence of the stale flag)
    else:
        state |= 0x0010  # definitions out of date
    if realtime_on:
        state |= 0x010000  # product "on" in the high word
    return state


def _default_timestamp() -> str:
    """Security Center timestamps are local-time strings like
    ``Mon, 01 Jan 2026 00:00:00 GMT+0000``. Best effort formatting —
    WMI accepts the string as-is."""
    now = datetime.now(timezone.utc)
    return now.strftime("%a, %d %b %Y %H:%M:%S GMT+0000")


def antivirus_product_properties(
    *,
    product_exe: PureWindowsPath | str,
    reporting_exe: PureWindowsPath | str,
    instance_guid: str,
    display_name: str = DISPLAY_NAME,
    realtime_on: bool = True,
    definitions_current: bool = True,
    timestamp: str | None = None,
) -> dict:
    """Build the exact property dict for the AntiVirusProduct
    instance. Validates the parts Windows cares about: the display
    name must be present, executable paths must be absolute, and the
    instance GUID must look like one."""
    if not display_name or not display_name.strip():
        raise ValueError("display_name must not be empty")
    # These are paths on the Windows machine being registered, so
    # they are validated with Windows path rules no matter what OS
    # happens to build the dict.
    product_path = PureWindowsPath(str(product_exe))
    reporting_path = PureWindowsPath(str(reporting_exe))
    if not product_path.is_absolute():
        raise ValueError(f"product exe path must be absolute: {product_exe}")
    if not reporting_path.is_absolute():
        raise ValueError(f"reporting exe path must be absolute: {reporting_exe}")
    guid = instance_guid.strip()
    if not (guid.startswith("{") and guid.endswith("}") and len(guid) >= 10):
        raise ValueError(
            f"instance_guid must be a braced GUID like "
            f"'{{12345678-1234-1234-1234-123456789abc}}', got {instance_guid!r}"
        )
    return {
        "displayName": display_name,
        "instanceGuid": guid,
        "pathToSignedProductExe": str(product_path),
        "pathToSignedReportingExe": str(reporting_path),
        "productState": product_state(
            realtime_on=realtime_on,
            definitions_current=definitions_current,
        ),
        "timestamp": timestamp or _default_timestamp(),
    }


# ----------------------------------------------------------------------
# WMI plumbing (Windows only, lazily imported)
# ----------------------------------------------------------------------
def _default_wmi_factory():
    """Connect to root\\SecurityCenter2 via COM. Windows only."""
    if sys.platform != "win32":
        raise RegistrationUnavailable(
            "Windows Security Center registration only works on "
            f"Windows — this machine reports platform '{sys.platform}'."
        )
    try:
        import win32com.client  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RegistrationUnavailable(
            "pywin32 (win32com) is not installed — Argus needs it to "
            "talk to Windows Security Center."
        ) from exc
    locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    return locator.ConnectServer(".", WMI_NAMESPACE)


def register_antivirus(
    properties: dict,
    *,
    wmi_factory: Callable[[], object] | None = None,
    require_existing_exe: bool = False,
) -> dict:
    """Create (or replace) Argus's AntiVirusProduct instance.

    *properties* comes from :func:`antivirus_product_properties`.
    An existing instance with the same display name is removed first
    so re-registration is idempotent. Returns the properties written.
    Raises :class:`RegistrationUnavailable` when WMI cannot be used.

    With ``require_existing_exe=True`` (the real registration path),
    the product executable named in the properties must exist on
    disk first — Windows Security must never be told a missing
    program is the machine's antivirus. Tests injecting a fake WMI
    connection leave it off.
    """
    missing = [key for key in PROPERTY_KEYS if key not in properties]
    if missing:
        raise ValueError(
            f"properties are missing required keys: {', '.join(missing)}"
        )
    if require_existing_exe:
        from pathlib import Path

        product_exe = Path(properties["pathToSignedProductExe"])
        if not product_exe.exists():
            raise RegistrationUnavailable(
                f"cannot register ARGUS.EXE with Windows Security "
                f"Center — the product executable {product_exe} does "
                "not exist on this machine."
            )
    wmi = (wmi_factory or _default_wmi_factory)()
    _delete_existing(wmi, properties["displayName"])
    instance = wmi.Get(WMI_CLASS).SpawnInstance_()
    for key in PROPERTY_KEYS:
        setattr(instance, key, properties[key])
    instance.Put_()
    return dict(properties)


def unregister_antivirus(
    display_name: str = DISPLAY_NAME,
    *,
    wmi_factory: Callable[[], object] | None = None,
) -> int:
    """Remove Argus's AntiVirusProduct instance(s). Returns how many
    instances were removed (0 when Argus was not registered)."""
    wmi = (wmi_factory or _default_wmi_factory)()
    return _delete_existing(wmi, display_name)


def _delete_existing(wmi: object, display_name: str) -> int:
    query = (
        f"SELECT * FROM {WMI_CLASS} WHERE displayName = "
        f"'{display_name.replace(chr(39), chr(39) * 2)}'"
    )
    removed = 0
    for instance in wmi.ExecQuery(query):
        instance.Delete_()
        removed += 1
    return removed
