"""Tests for the Phase 5 Windows Security Center registration
(argus.winregister). The property-building logic is pure and tested
directly; register/unregister are tested against a fake WMI
connection that records every call — no Windows needed."""
import pytest

from argus import winregister
from argus.winregister import (
    DISPLAY_NAME,
    RegistrationUnavailable,
    antivirus_product_properties,
    product_state,
    register_antivirus,
    unregister_antivirus,
)


def _props(**overrides):
    base = dict(
        product_exe=r"C:\Program Files\Sentinel Safeguard\Argus\Argus.exe",
        reporting_exe=r"C:\Program Files\Sentinel Safeguard\Argus\ArgusService.exe",
        instance_guid="{12345678-1234-1234-1234-123456789abc}",
        timestamp="Thu, 01 Jan 2026 00:00:00 GMT+0000",
    )
    base.update(overrides)
    return antivirus_product_properties(**base)


def test_properties_shape():
    props = _props()
    assert props["displayName"] == DISPLAY_NAME
    assert props["instanceGuid"] == "{12345678-1234-1234-1234-123456789abc}"
    assert props["pathToSignedProductExe"].endswith("Argus.exe")
    assert props["pathToSignedReportingExe"].endswith("ArgusService.exe")
    assert props["timestamp"] == "Thu, 01 Jan 2026 00:00:00 GMT+0000"
    assert isinstance(props["productState"], int)
    assert set(props) == set(winregister.PROPERTY_KEYS)


def test_properties_require_absolute_paths():
    with pytest.raises(ValueError):
        _props(product_exe="relative/Argus.exe")
    with pytest.raises(ValueError):
        _props(reporting_exe="ArgusService.exe")


def test_properties_require_guid_and_name():
    with pytest.raises(ValueError):
        _props(instance_guid="not-a-guid")
    with pytest.raises(ValueError):
        _props(display_name="   ")


def test_product_state_encodes_flags():
    on_current = product_state(realtime_on=True, definitions_current=True)
    off = product_state(realtime_on=False, definitions_current=True)
    stale = product_state(realtime_on=True, definitions_current=False)
    assert on_current != off
    assert stale != on_current
    assert off & 0x010000 == 0  # the "product on" high-word bit clears


# ----------------------------------------------------------------------
# Fake WMI
# ----------------------------------------------------------------------
class _FakeInstance:
    def __init__(self, store, props=None):
        self._store = store
        self._props = dict(props or {})
        self.deleted = False

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self._props[name] = value

    def __getattr__(self, name):
        return self._props[name]

    def Put_(self):
        self._store.append(self._props)

    def Delete_(self):
        self.deleted = True
        self._store.remove(self._props)


class _FakeClassObject:
    def __init__(self, store):
        self._store = store

    def SpawnInstance_(self):
        return _FakeInstance(self._store)


class FakeWMI:
    """Records ExecQuery strings; serves instances from a list store."""

    def __init__(self):
        self.store: list[dict] = []
        self.queries: list[str] = []

    def Get(self, class_name):
        assert class_name == "AntiVirusProduct"
        return _FakeClassObject(self.store)

    def ExecQuery(self, query):
        self.queries.append(query)
        results = []
        for props in list(self.store):
            if props.get("displayName") == DISPLAY_NAME:
                instance = _FakeInstance(self.store)
                instance._props = props  # share the stored dict, so Delete_ removes it
                results.append(instance)
        return results


def test_register_writes_instance():
    wmi = FakeWMI()
    written = register_antivirus(_props(), wmi_factory=lambda: wmi)
    assert len(wmi.store) == 1
    assert wmi.store[0]["displayName"] == DISPLAY_NAME
    assert written["displayName"] == DISPLAY_NAME


def test_register_is_idempotent():
    wmi = FakeWMI()
    register_antivirus(_props(), wmi_factory=lambda: wmi)
    register_antivirus(_props(), wmi_factory=lambda: wmi)
    assert len(wmi.store) == 1  # replaced, not duplicated


def test_unregister_removes_and_counts():
    wmi = FakeWMI()
    register_antivirus(_props(), wmi_factory=lambda: wmi)
    assert unregister_antivirus(wmi_factory=lambda: wmi) == 1
    assert wmi.store == []
    assert unregister_antivirus(wmi_factory=lambda: wmi) == 0


def test_register_rejects_incomplete_properties():
    with pytest.raises(ValueError):
        register_antivirus({"displayName": "x"}, wmi_factory=lambda: FakeWMI())


def test_registration_unavailable_off_windows(monkeypatch):
    monkeypatch.setattr("argus.winregister.sys.platform", "linux")
    with pytest.raises(RegistrationUnavailable):
        register_antivirus(_props())  # no factory -> real one refuses
    with pytest.raises(RegistrationUnavailable):
        unregister_antivirus()
