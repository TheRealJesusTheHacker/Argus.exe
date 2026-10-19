"""Tests for the Linux platform layer (v1.2.0 — the .deb edition
for Debian-based systems: Kali Linux, Parrot OS, Ubuntu, Debian).

The Windows design, translated — every test here pins one leg of
the translation:

- FHS layout + installed-layout detection (argus.paths),
- dpkg system-file trust (argus.platform_dpkg): fixture answers,
  the two-legged decision (dpkg ownership AND a system location),
  the real dpkg-query on this machine, and the analyze gate
  (argus.heuristics.analyze) granting heuristic trust ONLY,
- the systemd unit + service manager (argus.linuxservice):
  the rendered unit, the packaged unit matching it byte for
  byte, systemctl state mapping, setup-state detection,
- the verified Unix-socket channel (argus.socket_channel):
  REAL SO_PEERCRED against a live server, the pipe-identical
  identity proof, the root rule, squatter/stale-socket conduct,
  and a full service-level round trip through ArgusService,
- the inotify watcher (argus.inotify_watcher): factory choice,
  detection behaviour, and the honest polling fallback,
- self-trust at the FHS address (argus.selftrust), the
  verified-channel requirement (argus.action_requests), the
  setup-state delegation (argus.setup_engine), the Linux
  self-check census (argus.entry), and the .deb maintainer
  scripts inspected as shipped text.

Everything is Linux-only; the whole module skips elsewhere.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the Linux platform layer (.deb edition)",
)

from argus import (  # noqa: E402
    action_requests,
    linuxservice,
    paths,
    pipe_channel,
    platform_dpkg,
    selftrust,
    socket_channel,
)
from argus.config import ArgusConfig  # noqa: E402
from argus.heuristics.analyze import analyze_file  # noqa: E402
from argus.setup_engine import SetupState  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
LINUX_PACKAGING = REPO_ROOT / "packaging" / "linux"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ======================================================================
# FHS layout (argus.paths)
# ======================================================================


def test_fhs_layout_constants():
    assert str(paths.LINUX_PROGRAM_PATH) == "/usr/lib/argus/argus"
    assert str(paths.LINUX_DATA_DIR) == "/var/lib/argus"
    assert str(paths.LINUX_CONFIG_PATH) == "/etc/argus/argus-config.json"
    assert str(paths.LINUX_LOG_DIR) == "/var/log/argus"
    assert str(paths.LINUX_RUNTIME_DIR) == "/run/argus"
    assert linuxservice.UNIT_NAME in {
        p.name for p in paths.LINUX_UNIT_PATHS
    }


def test_linux_installed_layout_follows_the_program_file(
    tmp_path, monkeypatch
):
    exe = tmp_path / "usr-lib-argus" / "argus"
    monkeypatch.setattr(paths, "LINUX_PROGRAM_PATH", exe)
    assert paths.linux_installed_layout() is False
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"program")
    assert paths.linux_installed_layout() is True


def test_data_dir_prefers_env_then_installed_layout(
    tmp_path, monkeypatch
):
    env_dir = tmp_path / "env-data"
    monkeypatch.setenv("ARGUS_DATA_DIR", str(env_dir))
    assert paths.data_dir() == env_dir

    monkeypatch.delenv("ARGUS_DATA_DIR")
    exe = tmp_path / "argus"
    exe.write_bytes(b"program")
    installed_data = tmp_path / "var-lib-argus"
    monkeypatch.setattr(paths, "LINUX_PROGRAM_PATH", exe)
    monkeypatch.setattr(paths, "LINUX_DATA_DIR", installed_data)
    assert paths.data_dir() == installed_data


# ======================================================================
# dpkg system-file trust (argus.platform_dpkg)
# ======================================================================


def test_parse_dpkg_search_output_shapes():
    parse = platform_dpkg.parse_dpkg_search_output
    # The normal ownership line.
    assert parse("bash: /usr/bin/bash\n", "", 0, "/usr/bin/bash") == "bash"
    # Comma-joined owners: the first named owns it.
    assert (
        parse("pkg-a, pkg-b: /usr/bin/x\n", "", 0, "/usr/bin/x") == "pkg-a"
    )
    # The :arch qualifier is not part of the package's identity.
    assert (
        parse(
            "libc6:amd64: /lib/x86_64-linux-gnu/libc.so.6\n",
            "",
            0,
            "/lib/x86_64-linux-gnu/libc.so.6",
        )
        == "libc6"
    )
    # Diversion bookkeeping is NOT an ownership claim.
    assert (
        parse(
            "diversion by pkg from: /usr/bin/x\n"
            "diversion by pkg to: /usr/bin/x.distrib\n",
            "",
            0,
            "/usr/bin/x",
        )
        is None
    )
    # A line for a DIFFERENT path proves nothing about this one.
    assert parse("bash: /usr/bin/sh\n", "", 0, "/usr/bin/bash") is None
    # No match at all (rc 1, explanation on stderr).
    assert (
        parse(
            "",
            "dpkg-query: no path found matching pattern /x\n",
            1,
            "/x",
        )
        is None
    )


def test_dpkg_owner_with_fake_runners():
    owned = platform_dpkg.dpkg_owner(
        "/usr/bin/bash",
        runner=lambda argv: (0, "bash: /usr/bin/bash\n", ""),
    )
    assert owned.status == platform_dpkg.STATUS_TRUSTED
    assert owned.package == "bash"

    unowned = platform_dpkg.dpkg_owner(
        "/home/user/x",
        runner=lambda argv: (
            1,
            "",
            "dpkg-query: no path found matching pattern\n",
        ),
    )
    assert unowned.status == platform_dpkg.STATUS_UNTRUSTED

    def _missing(argv):
        raise FileNotFoundError("no dpkg-query")

    unavailable = platform_dpkg.dpkg_owner("/usr/bin/bash", runner=_missing)
    assert unavailable.status == platform_dpkg.STATUS_UNAVAILABLE


def test_is_system_location_legs(tmp_path):
    assert platform_dpkg.is_system_location("/usr/bin/bash") is True
    assert platform_dpkg.is_system_location("/bin/true") is True
    assert platform_dpkg.is_system_location("/lib/x86_64-linux-gnu") is True
    # /usr/local is locally administered — never a system location.
    assert platform_dpkg.is_system_location("/usr/local/bin/tool") is False
    assert platform_dpkg.is_system_location(tmp_path / "tool") is False
    assert platform_dpkg.is_system_location("/home/user/tool") is False


def test_decide_trust_needs_both_legs(tmp_path):
    owned = platform_dpkg.DpkgTrustResult(
        platform_dpkg.STATUS_TRUSTED, "bash", "owned"
    )
    # Ownership alone (a user-folder file a package happens to
    # own) is NOT enough — the location leg must hold too.
    home_file = tmp_path / "bash"
    home_file.write_bytes(b"x")
    assert (
        platform_dpkg.decide_trust(home_file, owned).status
        == platform_dpkg.STATUS_UNTRUSTED
    )
    assert (
        platform_dpkg.decide_trust("/usr/bin/bash", owned).status
        == platform_dpkg.STATUS_TRUSTED
    )
    # An unavailable verifier stays unavailable (fail closed).
    unavailable = platform_dpkg.DpkgTrustResult(
        platform_dpkg.STATUS_UNAVAILABLE, None, "no dpkg"
    )
    assert (
        platform_dpkg.decide_trust("/usr/bin/bash", unavailable).status
        == platform_dpkg.STATUS_UNAVAILABLE
    )


@pytest.mark.skipif(
    shutil.which("dpkg-query") is None, reason="no dpkg on this machine"
)
def test_verify_dpkg_against_the_real_package_database(tmp_path):
    platform_dpkg.clear_cache()
    try:
        # dpkg-query is itself owned by the dpkg package — the
        # safest possible fixture on any Debian-based machine.
        result = platform_dpkg.verify_dpkg("/usr/bin/dpkg-query")
        assert result.status == platform_dpkg.STATUS_TRUSTED
        assert result.package == "dpkg"
        # A file no package owns earns nothing.
        stray = tmp_path / "stray.bin"
        stray.write_bytes(b"nobody owns this")
        assert (
            platform_dpkg.verify_dpkg(stray).status
            == platform_dpkg.STATUS_UNTRUSTED
        )
    finally:
        platform_dpkg.clear_cache()


def test_analyze_gate_grants_heuristic_trust_only(tmp_path):
    script = tmp_path / "update.sh"
    script.write_bytes(b"#!/bin/sh\necho keeping things tidy\n")

    def trusted_verifier(path):
        return platform_dpkg.DpkgTrustResult(
            platform_dpkg.STATUS_TRUSTED, "bash", "fixture"
        )

    report = analyze_file(script, dpkg_verifier=trusted_verifier)
    assert report.trusted_system_file is True
    assert any(
        "package manager" in note and "bash" in note
        for note in report.notes
    )

    def untrusted_verifier(path):
        return platform_dpkg.DpkgTrustResult(
            platform_dpkg.STATUS_UNTRUSTED, None, "fixture"
        )

    report = analyze_file(script, dpkg_verifier=untrusted_verifier)
    assert report.trusted_system_file is False


def test_analyze_gate_fails_closed_on_a_broken_verifier(tmp_path):
    script = tmp_path / "x.sh"
    script.write_bytes(b"#!/bin/sh\necho hi\n")

    def broken_verifier(path):
        raise RuntimeError("verifier exploded")

    report = analyze_file(script, dpkg_verifier=broken_verifier)
    assert report.trusted_system_file is False


@pytest.mark.skipif(
    shutil.which("dpkg-query") is None, reason="no dpkg on this machine"
)
def test_analyze_gate_with_the_real_verifier():
    platform_dpkg.clear_cache()
    try:
        report = analyze_file(Path("/usr/bin/dpkg-query"))
        assert report.trusted_system_file is True
    finally:
        platform_dpkg.clear_cache()


# ======================================================================
# The systemd unit + service manager (argus.linuxservice)
# ======================================================================


def test_render_unit_contents():
    unit = linuxservice.render_unit()
    assert "Type=simple" in unit
    assert "ExecStart=/usr/lib/argus/argus --service" in unit
    # The SCM failure-policy analog in unit terms: restart on
    # failure after a short back-off, enabled at boot.
    assert "Restart=on-failure" in unit
    assert "RestartSec=5" in unit
    assert "Environment=ARGUS_DATA_DIR=/var/lib/argus" in unit
    assert "RuntimeDirectory=argus" in unit
    assert "[Install]" in unit and "WantedBy=multi-user.target" in unit


def test_packaged_unit_matches_rendered_unit_byte_for_byte():
    packaged = LINUX_PACKAGING / "argus-protection.service"
    assert packaged.read_text(encoding="utf-8") == linuxservice.render_unit()


def test_systemd_registered_exe_parses_execstart(tmp_path):
    unit = tmp_path / "argus-protection.service"
    unit.write_text(
        "[Service]\nExecStart=/usr/lib/argus/argus --service\n",
        encoding="utf-8",
    )
    assert linuxservice.systemd_registered_exe(unit) == Path(
        "/usr/lib/argus/argus"
    )
    unit.write_text("[Service]\nType=simple\n", encoding="utf-8")
    assert linuxservice.systemd_registered_exe(unit) is None
    assert (
        linuxservice.systemd_registered_exe(tmp_path / "missing.service")
        is None
    )


def _systemd_runner(is_active: str, load_state: str = "loaded"):
    def run(argv):
        if "is-active" in argv:
            rc = 0 if is_active == "active" else 3
            return rc, is_active + "\n", ""
        return 0, load_state + "\n", ""

    return run


def test_query_service_state_mapping():
    query = linuxservice.query_service_state_detailed
    assert query(runner=_systemd_runner("active")) == "running"
    assert query(runner=_systemd_runner("activating")) == "start_pending"
    assert query(runner=_systemd_runner("failed")) == "stopped"
    assert query(runner=_systemd_runner("inactive")) == "stopped"
    assert (
        query(runner=_systemd_runner("unknown", "not-found"))
        == "not-installed"
    )

    def _missing(argv):
        raise FileNotFoundError("no systemctl")

    assert query(runner=_missing) == "unknown"
    # The heartbeat-gate contract: False = could not be asked.
    assert linuxservice.query_service_state(runner=_missing) is False
    assert (
        linuxservice.query_service_state(runner=_systemd_runner("active"))
        == "running"
    )


@pytest.fixture()
def installed_layout(tmp_path, monkeypatch):
    """A fake .deb install: program file, identity record,
    desktop entry — all in temp space, wired via the paths
    constants the production code reads."""
    exe = tmp_path / "usr-lib-argus" / "argus"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"the genuine argus program")
    data = tmp_path / "var-lib-argus"
    data.mkdir()
    desktop = tmp_path / "argus.desktop"
    desktop.write_text("[Desktop Entry]\n", encoding="utf-8")
    monkeypatch.setattr(paths, "LINUX_PROGRAM_PATH", exe)
    monkeypatch.setattr(paths, "LINUX_DATA_DIR", data)
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data))
    monkeypatch.setattr(linuxservice, "DESKTOP_ENTRY_PATH", desktop)
    selftrust.record_exe_identity(exe, data)
    return {"exe": exe, "data": data, "desktop": desktop}


def test_linux_detect_state_running(installed_layout):
    state = linuxservice.detect_state(runner=_systemd_runner("active"))
    assert state is SetupState.RUNNING


def test_linux_detect_state_stopped(installed_layout):
    state = linuxservice.detect_state(runner=_systemd_runner("inactive"))
    assert state is SetupState.INSTALLED_STOPPED


def test_linux_detect_state_incomplete_without_identity_record(
    installed_layout,
):
    (installed_layout["data"] / selftrust.SELF_IDENTITY_NAME).unlink()
    state = linuxservice.detect_state(runner=_systemd_runner("active"))
    assert state is SetupState.INSTALLED_INCOMPLETE


def test_linux_detect_state_incomplete_without_desktop_entry(
    installed_layout,
):
    installed_layout["desktop"].unlink()
    state = linuxservice.detect_state(runner=_systemd_runner("active"))
    assert state is SetupState.INSTALLED_INCOMPLETE


def test_linux_detect_state_not_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        paths, "LINUX_PROGRAM_PATH", tmp_path / "no" / "argus"
    )
    state = linuxservice.detect_state(
        runner=_systemd_runner("unknown", "not-found")
    )
    assert state is SetupState.NOT_INSTALLED
    # A unit without its program is a broken partial install.
    state = linuxservice.detect_state(runner=_systemd_runner("inactive"))
    assert state is SetupState.INSTALLED_INCOMPLETE


def test_preferred_config_path_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    # Not installed: the data-dir config, as on every platform.
    monkeypatch.setattr(
        paths, "LINUX_PROGRAM_PATH", tmp_path / "no" / "argus"
    )
    assert linuxservice.preferred_config_path() == (
        tmp_path / "data" / "argus-config.json"
    )
    # Installed + an admin config in /etc/argus: the FHS home wins.
    exe = tmp_path / "argus"
    exe.write_bytes(b"program")
    etc_config = tmp_path / "etc-argus.json"
    etc_config.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(paths, "LINUX_PROGRAM_PATH", exe)
    monkeypatch.setattr(paths, "LINUX_CONFIG_PATH", etc_config)
    assert linuxservice.preferred_config_path() == etc_config
    # Installed but no /etc config: data-dir config still.
    etc_config.unlink()
    assert linuxservice.preferred_config_path() == (
        tmp_path / "data" / "argus-config.json"
    )


def test_setup_engine_delegates_when_the_linux_layout_is_present(
    installed_layout, monkeypatch
):
    from argus import setup_engine

    monkeypatch.setattr(
        linuxservice, "detect_state", lambda **kw: SetupState.RUNNING
    )
    monkeypatch.delenv("ARGUS_DATA_DIR", raising=False)
    assert setup_engine.detect_state() is SetupState.RUNNING


def test_setup_engine_never_delegates_without_the_layout(
    tmp_path, monkeypatch
):
    from argus import setup_engine

    monkeypatch.setattr(
        paths, "LINUX_PROGRAM_PATH", tmp_path / "no" / "argus"
    )
    monkeypatch.setattr(
        "argus.paths.LINUX_UNIT_PATHS", (tmp_path / "no.service",)
    )

    def _forbidden(**kwargs):
        raise AssertionError("delegated without an installed layout")

    monkeypatch.setattr(linuxservice, "detect_state", _forbidden)
    monkeypatch.delenv("ARGUS_DATA_DIR", raising=False)
    result = setup_engine.detect_state()
    assert isinstance(result, SetupState)


# ======================================================================
# The verified Unix-socket channel (argus.socket_channel)
# ======================================================================


class _FakeProvider(pipe_channel.ClientIdentityProvider):
    """pid -> ClientIdentity (or None) from a fixed table."""

    def __init__(self, mapping):
        self._mapping = mapping

    def identify(self, pid):
        return self._mapping.get(pid)


def _socket_handler(provider, canonical, recorded, seen=None):
    """A session handler in the service's shape: verdict from
    the kernel credentials first, then the shared pipe session
    core runs the exchange."""

    def handle(stream, creds):
        if seen is not None:
            seen.append(creds)
        verdict = socket_channel.verify_socket_client(
            creds,
            identity_provider=provider,
            canonical_exe=canonical,
            recorded_sha256=recorded,
            allow_root=False,
        )
        return pipe_channel.serve_pipe_stream(
            stream,
            client_pid=creds.pid,
            identity_provider=provider,
            canonical_exe=canonical,
            recorded_sha256=recorded,
            execute=lambda req: {"ok": True, "message": "executed"},
            caller_verdict=verdict,
        )

    return handle


def _roundtrip(server, **overrides):
    payload = {"id": "t1", "kind": "restore", "nonce": "n1"}
    payload.update(overrides)
    return socket_channel.socket_roundtrip(
        payload, timeout=10.0, path=server.path
    )


def test_socket_roundtrip_genuine_client_executes(tmp_path):
    canonical = tmp_path / "argus"
    canonical.write_bytes(b"the genuine argus program")
    recorded = _sha256(b"the genuine argus program")
    provider = _FakeProvider(
        {
            os.getpid(): pipe_channel.ClientIdentity(
                image_path=canonical, sha256=recorded
            )
        }
    )
    seen: list = []
    server = socket_channel.UnixSocketServer(
        _socket_handler(provider, canonical, recorded, seen),
        path=tmp_path / "argus.sock",
    )
    server.start()
    try:
        response = _roundtrip(server)
    finally:
        server.stop()
    assert response["ok"] is True
    assert response["id"] == "t1" and response["nonce"] == "n1"
    # The credentials are the KERNEL's statement, not the
    # client's: they name this very test process and user.
    assert seen and seen[0].pid == os.getpid()
    assert seen[0].uid == os.getuid()


@pytest.mark.parametrize(
    "identity",
    [
        # Right address, wrong bytes (replaced/forged program).
        ("wrong-hash",),
        # Right bytes, wrong address (a copy elsewhere).
        ("wrong-path",),
        # The process cannot be identified at all.
        ("unknown",),
    ],
)
def test_socket_roundtrip_forged_clients_are_refused(tmp_path, identity):
    canonical = tmp_path / "argus"
    canonical.write_bytes(b"the genuine argus program")
    recorded = _sha256(b"the genuine argus program")
    kind = identity[0]
    if kind == "wrong-hash":
        ident = pipe_channel.ClientIdentity(
            image_path=canonical, sha256="f" * 64
        )
    elif kind == "wrong-path":
        elsewhere = tmp_path / "elsewhere" / "argus"
        elsewhere.parent.mkdir()
        elsewhere.write_bytes(b"the genuine argus program")
        ident = pipe_channel.ClientIdentity(
            image_path=elsewhere, sha256=recorded
        )
    else:
        ident = None
    provider = _FakeProvider({os.getpid(): ident} if ident else {})
    server = socket_channel.UnixSocketServer(
        _socket_handler(provider, canonical, recorded),
        path=tmp_path / "argus.sock",
    )
    server.start()
    try:
        response = _roundtrip(server)
    finally:
        server.stop()
    assert response["ok"] is False
    assert response["message"] == pipe_channel.CALLER_REFUSAL_MESSAGE


def test_socket_no_recording_no_execution(tmp_path):
    canonical = tmp_path / "argus"
    canonical.write_bytes(b"the genuine argus program")
    recorded = _sha256(b"the genuine argus program")
    provider = _FakeProvider(
        {
            os.getpid(): pipe_channel.ClientIdentity(
                image_path=canonical, sha256=recorded
            )
        }
    )
    server = socket_channel.UnixSocketServer(
        _socket_handler(provider, canonical, None),
        path=tmp_path / "argus.sock",
    )
    server.start()
    try:
        response = _roundtrip(server)
    finally:
        server.stop()
    assert response["ok"] is False
    assert response["message"] == pipe_channel.CALLER_REFUSAL_MESSAGE


def test_socket_root_rule_is_a_kernel_credential_decision(tmp_path):
    canonical = tmp_path / "argus"
    canonical.write_bytes(b"the genuine argus program")
    nobody = _FakeProvider({})
    root_creds = socket_channel.PeerCredentials(pid=4242, uid=0, gid=0)
    # Root is admitted on the kernel credential alone when
    # allow_root — no identity record needed, none consulted.
    verdict = socket_channel.verify_socket_client(
        root_creds,
        identity_provider=nobody,
        canonical_exe=canonical,
        recorded_sha256=None,
        allow_root=True,
    )
    assert verdict.ok is True
    # With the rule off, root gets no shortcut either.
    verdict = socket_channel.verify_socket_client(
        root_creds,
        identity_provider=nobody,
        canonical_exe=canonical,
        recorded_sha256=None,
        allow_root=False,
    )
    assert verdict.ok is False
    # A non-root stranger is refused under either setting.
    user_creds = socket_channel.PeerCredentials(pid=4242, uid=1000, gid=1000)
    for allow in (True, False):
        verdict = socket_channel.verify_socket_client(
            user_creds,
            identity_provider=nobody,
            canonical_exe=canonical,
            recorded_sha256=None,
            allow_root=allow,
        )
        assert verdict.ok is False


def test_linux_identity_provider_reads_proc():
    provider = socket_channel.LinuxClientIdentityProvider()
    proc = subprocess.Popen(["sleep", "30"])
    try:
        identity = provider.identify(proc.pid)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    assert identity is not None
    assert identity.image_path.name.startswith("sleep")
    assert identity.sha256 == _sha256(identity.image_path.read_bytes())
    assert provider.identify(2**22) is None  # no such process


def test_socket_server_refuses_a_squatter_but_never_steals(
    tmp_path,
):
    canonical = tmp_path / "argus"
    canonical.write_bytes(b"the genuine argus program")
    recorded = _sha256(b"the genuine argus program")
    provider = _FakeProvider(
        {
            os.getpid(): pipe_channel.ClientIdentity(
                image_path=canonical, sha256=recorded
            )
        }
    )
    handler = _socket_handler(provider, canonical, recorded)
    sock_path = tmp_path / "argus.sock"
    first = socket_channel.UnixSocketServer(handler, path=sock_path)
    first.start()
    try:
        assert _roundtrip(first)["ok"] is True
        second = socket_channel.UnixSocketServer(handler, path=sock_path)
        second.start()
        try:
            # A live listener owns the name: the second server
            # refuses to serve rather than displace it…
            assert second.name_taken is True
            # …and stopping the refused server must not unlink
            # the live owner's socket file.
            second.stop()
            assert _roundtrip(first)["ok"] is True
        finally:
            second.stop()
    finally:
        first.stop()
    assert not sock_path.exists()


def test_socket_server_recovers_a_stale_socket_file(tmp_path):
    sock_path = tmp_path / "argus.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(sock_path))
    stale.close()  # the file remains; nothing is listening
    assert sock_path.exists()

    canonical = tmp_path / "argus"
    canonical.write_bytes(b"the genuine argus program")
    recorded = _sha256(b"the genuine argus program")
    provider = _FakeProvider(
        {
            os.getpid(): pipe_channel.ClientIdentity(
                image_path=canonical, sha256=recorded
            )
        }
    )
    server = socket_channel.UnixSocketServer(
        _socket_handler(provider, canonical, recorded), path=sock_path
    )
    server.start()
    try:
        assert server.name_taken is False
        assert _roundtrip(server)["ok"] is True
    finally:
        server.stop()


def test_service_level_socket_roundtrip(tmp_path, monkeypatch):
    """The whole channel as the service runs it: ArgusService's
    own socket session, the REAL /proc identity provider, this
    test process standing in as the genuine installed program
    (its own interpreter image at the 'canonical' address with
    its real hash recorded), and the full proof forced even
    though the suite runs as root (socket_allow_root=False)."""
    from argus.actions import ActionEngine
    from argus.quarantine import Vault
    from argus.service import ArgusService

    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        "argus.service.requests_dir", lambda: tmp_path / "requests"
    )
    monkeypatch.setattr(
        "argus.service.results_dir", lambda: tmp_path / "results"
    )
    exe_image = Path(os.path.realpath(sys.executable))
    recorded = _sha256(exe_image.read_bytes())
    config = ArgusConfig(status_file=str(tmp_path / "status.json"))
    vault = Vault.open(tmp_path / "vault", tmp_path / "trusted" / "pending.db")
    svc = ArgusService(
        config=config,
        pipe_canonical_exe=exe_image,
        pipe_recorded_sha256=recorded,
        socket_allow_root=False,
    )
    svc.vault = vault
    svc.actions = ActionEngine(vault, config, config_path=tmp_path / "c.json")
    svc.state = "running"
    server = socket_channel.UnixSocketServer(
        svc._socket_session, path=tmp_path / "argus.sock"
    )
    server.start()
    try:
        # Genuine: the request EXECUTES — it reaches the vault
        # lookup and gets the honest "no such entry" answer.
        response = socket_channel.socket_roundtrip(
            {
                "id": "q1",
                "kind": "entry-details",
                "entry_id": "missing",
                "nonce": "nq",
            },
            timeout=10.0,
            path=server.path,
        )
        assert response["ok"] is False
        assert "vault entry" in response["message"]
        assert response["nonce"] == "nq"
        # Forged fingerprint: refused before anything executes.
        svc._pipe_recorded_sha256 = "0" * 64
        response = socket_channel.socket_roundtrip(
            {
                "id": "q2",
                "kind": "restore",
                "entry_id": "missing",
                "nonce": "nq2",
            },
            timeout=10.0,
            path=server.path,
        )
        assert response["ok"] is False
        assert response["message"] == pipe_channel.CALLER_REFUSAL_MESSAGE
    finally:
        server.stop()
        vault.close()


# ======================================================================
# The inotify watcher (argus.inotify_watcher)
# ======================================================================


def test_engine_watcher_factory_picks_inotify_on_linux(tmp_path):
    from argus.inotify_watcher import InotifyDirectoryWatcher
    from argus.realtime import _create_watcher

    watcher = _create_watcher([tmp_path])
    assert isinstance(watcher, InotifyDirectoryWatcher)
    assert watcher.backend == "inotify"


def test_inotify_watcher_detects_new_changed_and_nested(tmp_path):
    from argus.inotify_watcher import InotifyDirectoryWatcher

    watched = tmp_path / "watched"
    watched.mkdir()
    ready: list = []
    watcher = InotifyDirectoryWatcher(
        [watched], stable_polls=2, poll_interval=0.05,
        on_ready=ready.append,
    )
    watcher.poll_once()  # baseline (empty folder)
    target = watched / "drop.bin"
    target.write_bytes(b"first version")
    watcher.poll_once()
    watcher.poll_once()
    assert ready == [target]

    # A change re-reports after the same stability wait.
    target.write_bytes(b"second version, longer and different")
    watcher.poll_once()
    watcher.poll_once()
    assert ready == [target, target]

    # Files in a NEW subdirectory are picked up too (structure
    # changes force a full re-walk + fresh watches).
    nested = watched / "sub"
    nested.mkdir()
    inner = nested / "inner.bin"
    inner.write_bytes(b"nested drop")
    watcher.poll_once()
    watcher.poll_once()
    watcher.poll_once()
    assert inner in ready

    # Deletion is quiet: no error, no phantom report.
    inner.unlink()
    watcher.poll_once()


def test_inotify_fallback_is_polling_and_honest(tmp_path, monkeypatch):
    from argus import inotify_watcher

    def _unavailable():
        raise inotify_watcher.InotifyUnavailable("kernel says no")

    monkeypatch.setattr(inotify_watcher, "_Inotify", _unavailable)
    watched = tmp_path / "watched"
    watched.mkdir()
    ready: list = []
    watcher = inotify_watcher.InotifyDirectoryWatcher(
        [watched], stable_polls=1, on_ready=ready.append
    )
    target = watched / "drop.bin"
    target.write_bytes(b"still detected")
    watcher.poll_once()
    watcher.poll_once()
    # Detection still works (same semantics, slower notice)…
    assert ready == [target]
    # …and the backend reports itself truthfully.
    assert watcher.backend == "polling"


def test_engine_status_reports_the_watcher_backend(tmp_path):
    from argus.config import ArgusConfig
    from argus.realtime import RealtimeEngine
    from argus.rules import BUILTIN_RULES
    from argus.signatures import SignatureDB, init_db

    db_path = tmp_path / "sigs.sigdb"
    init_db(db_path)
    db = SignatureDB.open(db_path)
    config = ArgusConfig(
        watch_dirs=[tmp_path],
        process_monitor_enabled=False,
        status_file=str(tmp_path / "status.json"),
    )
    engine = RealtimeEngine(config, db, BUILTIN_RULES)
    try:
        assert engine.status_snapshot()["watcher_backend"] == "inotify"
    finally:
        engine.stop()
        db.close()


# ======================================================================
# Self-trust at the FHS address (argus.selftrust)
# ======================================================================


def test_linux_self_exclusions_follow_the_recording(
    tmp_path, monkeypatch
):
    data = tmp_path / "data"
    data.mkdir()
    install = tmp_path / "usr-lib-argus"
    install.mkdir()
    exe = install / "argus"
    exe.write_bytes(b"the genuine argus program")
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data))
    monkeypatch.setattr(paths, "LINUX_PROGRAM_PATH", exe)
    monkeypatch.setattr(paths, "LINUX_INSTALL_DIR", install)
    selftrust.record_exe_identity(exe, data)
    selftrust.reset_default_cache()
    try:
        exclusions = selftrust.default_self_exclusions()
        # The program itself, proven by the recorded fingerprint.
        assert exclusions.check(exe).excluded is True
        # A file merely NAMED argus somewhere else is not Argus,
        # even with identical bytes — never filename-based trust.
        impostor = tmp_path / "argus"
        impostor.write_bytes(b"the genuine argus program")
        assert exclusions.check(impostor).excluded is False
        # Same address, different bytes: not excluded, and the
        # mismatch is a tamper signal.
        exe.write_bytes(b"a replaced program")
        verdict = exclusions.check(exe)
        assert verdict.excluded is False
        assert verdict.tamper_suspect is True
    finally:
        selftrust.reset_default_cache()


def test_linux_no_recording_no_exclusion(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    install = tmp_path / "usr-lib-argus"
    install.mkdir()
    exe = install / "argus"
    exe.write_bytes(b"an unrecorded program")
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data))
    monkeypatch.setattr(paths, "LINUX_PROGRAM_PATH", exe)
    monkeypatch.setattr(paths, "LINUX_INSTALL_DIR", install)
    selftrust.reset_default_cache()
    try:
        exclusions = selftrust.default_self_exclusions()
        verdict = exclusions.check(exe)
        # No recording: no exclusion — and not tamper evidence
        # either (a portable/dev run records nothing).
        assert verdict.excluded is False
        assert verdict.tamper_suspect is False
    finally:
        selftrust.reset_default_cache()


# ======================================================================
# The verified-channel requirement (argus.action_requests)
# ======================================================================


def test_linux_pipe_channel_required_rules(tmp_path, monkeypatch):
    exe = tmp_path / "argus"
    exe.write_bytes(b"the genuine argus program")
    data = tmp_path / "var-lib-argus"
    data.mkdir()
    monkeypatch.setattr(paths, "LINUX_PROGRAM_PATH", exe)
    monkeypatch.setattr(paths, "LINUX_DATA_DIR", data)
    # Installed + recorded: the verified channel is required.
    selftrust.record_exe_identity(exe, data)
    monkeypatch.delenv("ARGUS_DATA_DIR", raising=False)
    assert action_requests.pipe_channel_required() is True
    # A portable-style override (ARGUS_DATA_DIR) always stands
    # down — caller and service share one trust domain there.
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data))
    assert action_requests.pipe_channel_required() is False
    monkeypatch.delenv("ARGUS_DATA_DIR")
    # Installed but never recorded: the file channel stands (a
    # half-installed package must not lock the user out of the
    # designed error paths).
    (data / selftrust.SELF_IDENTITY_NAME).unlink()
    assert action_requests.pipe_channel_required() is False


# ======================================================================
# The Linux self-check census (argus.entry)
# ======================================================================


def test_linux_self_check_census_contents():
    from argus import entry

    census = entry.SELF_CHECK_MODULES_LINUX
    assert "argus.linuxservice" in census
    assert "argus.socket_channel" in census
    assert "argus.platform_dpkg" in census
    assert "argus.inotify_watcher" in census
    # Nothing Windows-only may appear: pywin32 does not exist
    # on Linux, and the census must be importable there.
    assert not any("win" in name.lower() for name in census)
    # The Windows census is untouched by the addition.
    assert "argus.winservice" in entry.SELF_CHECK_MODULES


def test_run_self_check_with_the_linux_census():
    from argus import entry

    assert (
        entry.run_self_check(modules=["json", "argus.linuxservice"]) == 0
    )
    assert entry.run_self_check(modules=["argus.no_such_module_xyz"]) == 1


# ======================================================================
# The .deb packaging, inspected as shipped (packaging/linux)
# ======================================================================


def test_deb_control_fields():
    control = (LINUX_PACKAGING / "debian" / "control").read_text(
        encoding="utf-8"
    )
    assert "Package: argus" in control
    assert "Architecture: amd64" in control
    assert "Maintainer: Sentinel Safeguard LLC" in control
    # The build substitutes the real version for the token; the
    # source must carry the token, never a stale literal.
    assert "Version: @VERSION@" in control


def test_postinst_creates_the_tree_and_starts_protection():
    postinst = (LINUX_PACKAGING / "debian" / "postinst").read_text(
        encoding="utf-8"
    )
    assert postinst.startswith("#!/bin/sh")
    assert "set -e" in postinst
    assert "configure)" in postinst
    # The data tree with the vault's Windows-ACL analog: the
    # quarantine store is root-only; the request drop is the one
    # sticky, world-writable folder (unprivileged requests).
    assert "DATA_DIR=/var/lib/argus" in postinst
    assert '"$DATA_DIR/quarantine"' in postinst
    assert "0700" in postinst
    assert "1733" in postinst
    # The program proves its own identity to itself.
    assert "self-identity.json" in postinst
    # systemd: the unit is installed, enabled, and started.
    assert "systemctl" in postinst and "enable" in postinst
    assert "start" in postinst
    # Nothing else gets registered — no cron, no shell hooks.
    assert "crontab" not in postinst


def test_prerm_stops_and_disables_only_on_remove():
    prerm = (LINUX_PACKAGING / "debian" / "prerm").read_text(
        encoding="utf-8"
    )
    assert prerm.startswith("#!/bin/sh")
    assert "remove|deconfigure)" in prerm
    remove_at = prerm.index("remove|deconfigure)")
    assert prerm.index("stop", remove_at) > remove_at
    assert prerm.index("disable", remove_at) > remove_at


def test_postrm_removes_data_only_on_purge():
    postrm = (LINUX_PACKAGING / "debian" / "postrm").read_text(
        encoding="utf-8"
    )
    assert postrm.startswith("#!/bin/sh")
    purge_at = postrm.index("purge)")
    # The data tree may only be deleted inside the purge branch:
    # a plain remove/upgrade must leave the vault untouched.
    assert "rm -rf" in postrm
    assert postrm.index("rm -rf") > purge_at
    assert "/var/lib/argus" in postrm[purge_at:]


def test_desktop_entry_is_fhs_and_brand_clean():
    desktop_file = (LINUX_PACKAGING / "argus.desktop").read_text(
        encoding="utf-8"
    )
    assert desktop_file.startswith("[Desktop Entry]")
    assert "Exec=/usr/bin/argus" in desktop_file
    assert "Icon=argus" in desktop_file
    assert "Categories=" in desktop_file
    assert "purple" not in desktop_file.lower()


def test_build_script_produces_argus_deb():
    script = (LINUX_PACKAGING / "build-deb.sh").read_text(encoding="utf-8")
    assert "dpkg-deb" in script
    assert "Argus.deb" in script
    assert "PyInstaller" in script or "pyinstaller" in script
