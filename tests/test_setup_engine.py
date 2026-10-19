"""Tests for the v1.1.0 self-install engine (argus.setup_engine).

Everything machine-touching is an injectable seam, so the whole
engine — state detection, step ordering, verification gating,
idempotency, ACL commands, uninstall — is exercised here on any
platform with fakes that record what would have happened.
"""

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from argus import setup_engine
from argus.setup_engine import SetupError, SetupState


# ----------------------------------------------------------------------
# Fakes
# ----------------------------------------------------------------------
class FakeMachine:
    """A recording fake of every setup seam.

    ``scm_states`` is the sequence query_service_state_detailed
    answers with (the last one repeats). ``heartbeat`` is what the
    status-file reader returns.
    """

    def __init__(self, tmp_path, *, scm_states=("not-installed",),
                 heartbeat=None):
        self.tmp_path = tmp_path
        self.calls: list = []
        self.scm_states = list(scm_states)
        self.heartbeat = heartbeat
        self.data_root = tmp_path / "ProgramData" / "Argus"

    # -- seams ------------------------------------------------------
    def scm_state(self):
        self.calls.append("scm_state")
        if len(self.scm_states) > 1:
            return self.scm_states.pop(0)
        return self.scm_states[0]

    def run_command(self, argv):
        self.calls.append(("run", list(argv)))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def install_service(self, exe):
        self.calls.append(("install_service", Path(exe)))

    def remove_service(self):
        self.calls.append("remove_service")

    def stop_service(self):
        self.calls.append("stop_service")

    def start_service(self):
        self.calls.append("start_service")

    def register_av(self, exe):
        self.calls.append(("register_av", Path(exe)))

    def write_uninstall_entry(self, exe):
        self.calls.append(("write_uninstall_entry", Path(exe)))

    def read_heartbeat(self):
        self.calls.append("read_heartbeat")
        return self.heartbeat

    def kwargs(self, **extra):
        base = dict(
            run_command=self.run_command,
            install_service_fn=self.install_service,
            remove_service_fn=self.remove_service,
            stop_service_fn=self.stop_service,
            register_av_fn=self.register_av,
            write_uninstall_entry_fn=self.write_uninstall_entry,
            start_service_fn=self.start_service,
            scm_state_fn=self.scm_state,
            read_heartbeat_fn=self.read_heartbeat,
            data_root=self.data_root,
            sleep=lambda _s: None,
            monotonic=_TickingClock(),
            verify_timeout=5.0,
        )
        base.update(extra)
        return base

    def kinds(self):
        return [
            c[0] if isinstance(c, tuple) else c for c in self.calls
        ]


class _TickingClock:
    """A monotonic clock that advances 1s per call, so verification
    loops terminate deterministically without real waiting."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 1.0
        return self.now


def fresh_heartbeat():
    return {
        "running": True,
        "state": "running",
        "heartbeat_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture(autouse=True)
def _windows_acls(monkeypatch):
    """The ACL step is Windows-gated; these tests exercise it."""
    monkeypatch.setattr(setup_engine, "IS_WINDOWS", True)


@pytest.fixture()
def canonical(tmp_path, monkeypatch):
    """Point the canonical install location into tmp_path."""
    program_files = tmp_path / "Program Files"
    monkeypatch.setenv("ProgramFiles", str(program_files))
    return (
        program_files / "Sentinel Safeguard" / "Argus" / "Argus.exe"
    )


# ----------------------------------------------------------------------
# State detection
# ----------------------------------------------------------------------
def test_detect_state_portable_wins(monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", "/somewhere/portable")
    assert setup_engine.detect_state(scm_state="running") is SetupState.PORTABLE


def test_detect_state_mapping():
    assert (
        setup_engine.detect_state(scm_state="not-installed", portable=False)
        is SetupState.NOT_INSTALLED
    )
    assert (
        setup_engine.detect_state(scm_state="running", portable=False)
        is SetupState.RUNNING
    )
    assert (
        setup_engine.detect_state(scm_state="stopped", portable=False)
        is SetupState.INSTALLED_STOPPED
    )
    # Undeterminable must never claim protection exists.
    assert (
        setup_engine.detect_state(scm_state="unknown", portable=False)
        is SetupState.NOT_INSTALLED
    )


def test_detect_state_uses_detailed_query(monkeypatch):
    """1060 (service does not exist) reaches detect_state as
    NOT_INSTALLED via query_service_state_detailed — not collapsed
    into the same bucket as a stopped service."""
    monkeypatch.setattr(
        setup_engine.winservice,
        "query_service_state_detailed",
        lambda name="ArgusProtection": "not-installed",
    )
    assert (
        setup_engine.detect_state(portable=False) is SetupState.NOT_INSTALLED
    )


# ----------------------------------------------------------------------
# Install: ordering, ACLs, self-placement, verification
# ----------------------------------------------------------------------
def test_install_happy_path_order_and_acls(tmp_path, canonical):
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "stopped", "running"),
        heartbeat=fresh_heartbeat(),
    )
    source = tmp_path / "Downloads" / "Argus.exe"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"fake-exe-bytes")

    result = setup_engine.install(
        source_exe=source, progress=lambda step: None,
        **machine.kwargs(),
    )

    assert result.state is SetupState.RUNNING
    assert result.exe == canonical
    # Self-placement really copied (and the copy is the same bytes).
    assert canonical.read_bytes() == b"fake-exe-bytes"

    kinds = machine.kinds()
    # The service is installed BEFORE recovery is configured, AV is
    # registered BEFORE the start, and the start comes last.
    assert kinds.index("install_service") < kinds.index("register_av")
    assert kinds.index("register_av") < kinds.index("start_service")
    assert kinds.index("start_service") < kinds.index("read_heartbeat")
    # A fresh machine has nothing to stop/remove.
    assert "remove_service" not in kinds

    runs = [c[1] for c in machine.calls if isinstance(c, tuple) and c[0] == "run"]
    icacls = [argv for argv in runs if argv[0] == "icacls.exe"]
    assert len(icacls) == 5
    quarantine_acl = next(a for a in icacls if "quarantine" in a[1])
    assert "/inheritance:r" in quarantine_acl
    assert "SYSTEM:(OI)(CI)F" in quarantine_acl
    assert "Administrators:(OI)(CI)F" in quarantine_acl
    shared_acl = next(a for a in icacls if "shared" in a[1])
    assert "Users:(OI)(CI)M" in shared_acl
    recovery = next(a for a in runs if a[0] == "sc.exe")
    assert recovery[1] == "failure"
    assert "reset=" in recovery and "86400" in recovery
    assert "actions=" in recovery
    assert recovery[-1] == "restart/60000/restart/60000/restart/60000"

    # The data tree exists, in the trust-split shape.
    assert (machine.data_root / "quarantine").is_dir()
    assert (machine.data_root / "shared" / "requests").is_dir()
    assert (machine.data_root / "shared" / "results").is_dir()


def test_install_step_failure_aborts_and_later_steps_never_run(
    tmp_path, canonical
):
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "running"),
        heartbeat=fresh_heartbeat(),
    )

    def bad_register(exe):
        raise RuntimeError("wmi exploded")

    with pytest.raises(SetupError) as excinfo:
        setup_engine.install(
            **machine.kwargs(register_av_fn=bad_register)
        )
    # Plain language for the person, technical record in detail —
    # and the raw jargon stays out of the user message.
    assert "Sentinel Safeguard" in excinfo.value.user_message
    assert "wmi exploded" in excinfo.value.detail
    assert "wmi" not in excinfo.value.user_message.lower()
    kinds = machine.kinds()
    assert "start_service" not in kinds
    assert "read_heartbeat" not in kinds


def test_install_verification_gates_success(tmp_path, canonical):
    """Service starts but never confirms (SCM stuck stopped, no
    heartbeat): setup must FAIL, not declare victory."""
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "stopped"),
        heartbeat=None,
    )
    with pytest.raises(SetupError) as excinfo:
        setup_engine.install(**machine.kwargs())
    assert "didn't confirm" in excinfo.value.user_message
    assert "start_service" in machine.kinds()  # it did try to start


def test_install_verification_needs_fresh_heartbeat(tmp_path, canonical):
    stale = {
        "running": True,
        "state": "running",
        "heartbeat_at": (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat(),
    }
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "running"), heartbeat=stale
    )
    with pytest.raises(SetupError):
        setup_engine.install(**machine.kwargs())


def test_install_acl_failure_is_not_silent(tmp_path, canonical):
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "running"),
        heartbeat=fresh_heartbeat(),
    )

    def failing_run(argv):
        machine.calls.append(("run", list(argv)))
        return subprocess.CompletedProcess(argv, 5, "", "Access denied")

    with pytest.raises(SetupError) as excinfo:
        setup_engine.install(**machine.kwargs(run_command=failing_run))
    assert "secure" in excinfo.value.user_message
    assert "exited 5" in excinfo.value.detail
    assert "install_service" not in machine.kinds()


def test_install_idempotent_over_existing_tree(tmp_path, canonical):
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "running"),
        heartbeat=fresh_heartbeat(),
    )
    sentinel = machine.data_root / "shared" / "keep-me.txt"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("precious user data")

    setup_engine.install(**machine.kwargs())
    # Second run: the service now EXISTS (state sequence says so on
    # its verify poll the machine reports running from the start).
    machine2 = FakeMachine(
        tmp_path, scm_states=("stopped", "stopped", "running"),
        heartbeat=fresh_heartbeat(),
    )
    result = setup_engine.install(**machine2.kwargs())
    assert result.state is SetupState.RUNNING
    # Pre-existing data survived both runs untouched.
    assert sentinel.read_text() == "precious user data"
    # The re-run replaced the registration cleanly: stop + remove
    # happened before the fresh install.
    kinds = machine2.kinds()
    assert kinds.index("remove_service") < kinds.index("install_service")


def test_install_skips_self_place_when_already_canonical(
    tmp_path, canonical
):
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(b"the-real-exe")
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "running"),
        heartbeat=fresh_heartbeat(),
    )
    copied = []
    result = setup_engine.install(
        source_exe=canonical,
        copy_file=lambda s, d: copied.append((s, d)),
        **machine.kwargs(),
    )
    assert result.state is SetupState.RUNNING
    assert copied == []  # already home — no copy attempted


def test_install_self_place_verifies_the_copy(tmp_path, canonical):
    source = tmp_path / "Downloads" / "Argus.exe"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"original-bytes")
    machine = FakeMachine(
        tmp_path, scm_states=("not-installed", "running"),
        heartbeat=fresh_heartbeat(),
    )

    def corrupting_copy(src, dst):
        Path(dst).write_bytes(b"tampered")

    with pytest.raises(SetupError) as excinfo:
        setup_engine.install(
            source_exe=source, copy_file=corrupting_copy,
            **machine.kwargs(),
        )
    assert "copy didn't check out" in excinfo.value.user_message
    assert not canonical.exists()  # the bad copy was removed
    assert "install_service" not in machine.kinds()


def test_install_refuses_in_portable_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "portable"))
    machine = FakeMachine(tmp_path)
    with pytest.raises(SetupError) as excinfo:
        setup_engine.install(**machine.kwargs())
    assert "portable" in excinfo.value.user_message.lower()
    assert machine.calls == []  # nothing was touched at all


# ----------------------------------------------------------------------
# Uninstall
# ----------------------------------------------------------------------
def _uninstall_machine(tmp_path, *, scm="running"):
    states = (scm,) if scm == "not-installed" else (scm, "not-installed")
    machine = FakeMachine(tmp_path, scm_states=states)
    scheduled = []
    kwargs = dict(
        stop_service_fn=machine.stop_service,
        remove_service_fn=machine.remove_service,
        unregister_av_fn=lambda: machine.calls.append("unregister_av"),
        remove_uninstall_entry_fn=lambda: machine.calls.append(
            "remove_uninstall_entry"
        ),
        schedule_delete_on_reboot_fn=lambda p: scheduled.append(Path(p)),
        scm_state_fn=machine.scm_state,
        data_root=machine.data_root,
    )
    return machine, scheduled, kwargs


def test_uninstall_removes_service_and_registration_keeps_data(
    tmp_path, canonical
):
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(b"exe")
    machine, scheduled, kwargs = _uninstall_machine(tmp_path)
    data_file = machine.data_root / "shared" / "history.db"
    data_file.parent.mkdir(parents=True)
    data_file.write_bytes(b"history")

    result = setup_engine.uninstall(**kwargs)

    kinds = machine.kinds()
    assert kinds.index("stop_service") < kinds.index("remove_service")
    assert "unregister_av" in kinds
    assert "remove_uninstall_entry" in kinds
    # Data kept by default — uninstalling by accident must not
    # destroy the record of what Argus caught.
    assert data_file.exists()
    assert result.removed_data is False
    # The exe could be deleted here (this process is not it).
    assert not canonical.exists()


def test_uninstall_remove_data_only_when_asked(tmp_path, canonical):
    machine, scheduled, kwargs = _uninstall_machine(tmp_path)
    data_file = machine.data_root / "quarantine" / "vault.db"
    data_file.parent.mkdir(parents=True)
    data_file.write_bytes(b"vault")

    result = setup_engine.uninstall(remove_data=True, **kwargs)

    assert result.removed_data is True
    assert not machine.data_root.exists()


def test_uninstall_running_exe_is_scheduled_not_hidden(tmp_path, canonical):
    """When the file can't be deleted (this process IS running
    from it on the owner's machine), uninstall schedules the
    deletion for restart and REPORTS it in leftovers."""
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(b"exe")
    machine, scheduled, kwargs = _uninstall_machine(tmp_path)

    real_unlink = Path.unlink

    def locked_unlink(self, *a, **kw):
        if Path(self) == canonical:
            raise PermissionError("in use")
        return real_unlink(self, *a, **kw)

    import unittest.mock as mock

    with mock.patch.object(Path, "unlink", locked_unlink):
        result = setup_engine.uninstall(**kwargs)
    assert scheduled == [canonical]
    assert any("restarts" in note for note in result.leftovers)


def test_uninstall_when_nothing_installed(tmp_path, canonical):
    machine, scheduled, kwargs = _uninstall_machine(
        tmp_path, scm="not-installed"
    )
    result = setup_engine.uninstall(**kwargs)
    assert "remove_service" not in machine.kinds()
    assert "unregister_av" in machine.kinds()


# ----------------------------------------------------------------------
# Setup result hand-off
# ----------------------------------------------------------------------
def test_setup_result_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    setup_engine.write_setup_result({"ok": True, "message": "done"})
    result = setup_engine.read_setup_result()
    assert result["ok"] is True
    assert result["message"] == "done"
    # A stale result is not news.
    assert setup_engine.read_setup_result(max_age_seconds=-1) is None


def test_canonical_location_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    assert setup_engine.canonical_exe_path() == Path(
        r"C:\Program Files"
    ) / "Sentinel Safeguard" / "Argus" / "Argus.exe"
