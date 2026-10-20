"""Regression tests for bug hunt #2 (2026-10-19) — the Linux
edition sweep: dpkg content binding, the inotify fallback loop,
vault claim/key races, the socket stream + session cap, and the
packaging fixes (unit hardening line, postinst upgrade restart).
"""

from __future__ import annotations

import errno
import hashlib
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from argus import inotify_watcher, linuxservice, platform_dpkg, socket_channel
from argus.quarantine import (
    QuarantineError,
    Vault,
    _load_or_create_key,
)

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux-edition hunt fixes"
)

REPO_ROOT = Path(__file__).resolve().parent.parent
LINUX_PACKAGING = REPO_ROOT / "packaging" / "linux"


# ======================================================================
# F1 — dpkg trust binds CONTENT, not just the owned path
# ======================================================================
def test_recorded_content_matches_legs(tmp_path, monkeypatch):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"the genuine payload")
    info = tmp_path / "info"
    info.mkdir()
    rel = str(target).lstrip("/")
    good_md5 = hashlib.md5(b"the genuine payload").hexdigest()
    (info / "bash.md5sums").write_text(f"{good_md5}  {rel}\n")
    (info / "other.md5sums").write_text(f"{'0' * 32}  {rel}\n")
    monkeypatch.setattr(platform_dpkg, "DPKG_INFO_DIR", info)
    # Recorded + matching: intact.
    assert platform_dpkg.recorded_md5("bash", target) == good_md5
    assert platform_dpkg.recorded_content_matches(target, "bash") is True
    # Recorded + different content: NOT intact (replaced in place).
    target.write_bytes(b"a replaced payload!")
    assert platform_dpkg.recorded_content_matches(target, "bash") is False
    # No checksum recorded for the package: no opinion.
    assert platform_dpkg.recorded_content_matches(target, "nosuch") is None
    assert platform_dpkg.recorded_md5("nosuch", target) is None


@pytest.mark.skipif(
    shutil.which("dpkg-query") is None, reason="no dpkg on this machine"
)
def test_verify_dpkg_withdraws_trust_from_a_replaced_payload(
    tmp_path, monkeypatch
):
    info = tmp_path / "info"
    info.mkdir()
    # dpkg-query's own record, but with a checksum the real file
    # does not have — the shape of a payload replaced in place.
    (info / "dpkg.md5sums").write_text(
        f"{'0' * 32}  usr/bin/dpkg-query\n"
    )
    monkeypatch.setattr(platform_dpkg, "DPKG_INFO_DIR", info)
    platform_dpkg.clear_cache()
    try:
        result = platform_dpkg.verify_dpkg("/usr/bin/dpkg-query")
        assert result.status == platform_dpkg.STATUS_UNTRUSTED
        assert "contents do not match the checksum" in result.detail
    finally:
        platform_dpkg.clear_cache()


# ======================================================================
# F5 — the Unix stream consumes each message it returns
# ======================================================================
def test_unix_stream_reads_pipelined_messages_in_order():
    left, right = socket.socketpair()
    try:
        stream = socket_channel._UnixStream(left)
        right.sendall(
            json.dumps({"n": 1}).encode() + b"\n"
            + json.dumps({"n": 2}).encode() + b"\n"
        )
        assert stream.read_message() == {"n": 1}
        assert stream.read_message() == {"n": 2}
    finally:
        left.close()
        right.close()


# ======================================================================
# F6 — the socket listener caps concurrent sessions
# ======================================================================
def test_socket_server_refuses_sessions_past_the_cap(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(socket_channel, "_MAX_CONCURRENT_SESSIONS", 1)
    entered = threading.Event()
    release = threading.Event()

    def handler(stream, creds):
        entered.set()
        release.wait(timeout=10)

    # The cap is read from the module constant at construction,
    # which the monkeypatch above has already lowered to 1.
    server = socket_channel.UnixSocketServer(
        handler, path=tmp_path / "argus.sock"
    )
    server.start()
    first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        first.connect(str(server.path))
        assert entered.wait(timeout=5)
        second.settimeout(5)
        second.connect(str(server.path))
        # The only slot is held: the excess connection is closed
        # on arrival, not queued behind a new thread.
        assert second.recv(1) == b""
    finally:
        release.set()
        first.close()
        second.close()
        server.stop()


# ======================================================================
# F2 — inotify fallback keeps the polling cadence; ENOSPC re-walks
# ======================================================================
def test_inotify_run_fallback_does_not_spin(tmp_path, monkeypatch):
    def _unavailable():
        raise inotify_watcher.InotifyUnavailable("kernel says no")

    monkeypatch.setattr(inotify_watcher, "_Inotify", _unavailable)
    watched = tmp_path / "watched"
    watched.mkdir()
    watcher = inotify_watcher.InotifyDirectoryWatcher(
        [watched], poll_interval=0.2, stable_polls=1
    )
    stop = threading.Event()
    thread = threading.Thread(
        target=watcher.run, args=(stop,), daemon=True
    )
    thread.start()
    time.sleep(1.05)
    stop.set()
    thread.join(timeout=5)
    assert watcher.backend == "polling"
    # ~5 polls at the 0.2s cadence — a hot loop would be thousands.
    assert 2 <= watcher.stats.polls <= 12


def test_inotify_watch_limit_falls_back_to_full_walks(tmp_path):
    class _LimitStub:
        last_add_error = errno.ENOSPC

        def add_watch(self, directory):
            return None

        def dir_for(self, wd):
            return None

        def read_events(self, timeout):
            return []

        def close(self):
            pass

    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "drop.bin"
    target.write_bytes(b"version one")
    watcher = inotify_watcher.InotifyDirectoryWatcher([watched])
    watcher._inotify = _LimitStub()
    snap = watcher.snapshot()
    assert watcher._watches_incomplete is True
    assert target in snap
    # No event can ever report this change (no watch exists):
    # only a full re-walk can see the file vanish.
    target.unlink()
    assert target not in watcher.snapshot()


# ======================================================================
# F3 — a crashed restore's claim is released; a live one is not
# ======================================================================
def _quarantine_one(vault, tmp_path, name="evil.bin"):
    source = tmp_path / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"payload for " + name.encode())
    return vault.quarantine_file(
        source,
        detection_name="Test.Detection",
        severity="high",
        verdict="Malicious",
        reasons=["test"],
    )


def test_stale_restore_claim_is_recovered_on_open(tmp_path):
    vault_dir = tmp_path / "vault"
    vault = Vault.open(vault_dir)
    entry = _quarantine_one(vault, tmp_path)
    # Simulate a restore claimed long ago by a process that died.
    vault._update_entry(
        entry.id,
        status="restoring",
        claimed_at="2000-01-01T00:00:00+00:00",
    )
    vault.close()

    reopened = Vault.open(vault_dir)
    try:
        assert reopened.get_entry(entry.id).status == "quarantined"
        restored = reopened.restore(entry.id)
        assert restored.is_file()
    finally:
        reopened.close()


def test_fresh_restore_claim_is_left_alone_on_open(tmp_path):
    vault_dir = tmp_path / "vault"
    vault = Vault.open(vault_dir)
    entry = _quarantine_one(vault, tmp_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    vault._update_entry(entry.id, status="restoring", claimed_at=now)
    vault.close()

    reopened = Vault.open(vault_dir)
    try:
        # Another live process may be mid-restore: the claim —
        # and its refusal — must survive an open.
        assert reopened.get_entry(entry.id).status == "restoring"
        with pytest.raises(QuarantineError):
            reopened.restore(entry.id)
    finally:
        reopened.close()


# ======================================================================
# F4 — a key still being created is not "damaged"
# ======================================================================
def test_key_creation_race_waits_for_the_writer(tmp_path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    key_material = bytes(range(32))
    (vault_dir / "vault.key").write_bytes(b"")

    def _finish_writing():
        time.sleep(0.3)
        (vault_dir / "vault.key").write_bytes(key_material)

    writer = threading.Thread(target=_finish_writing)
    writer.start()
    try:
        assert _load_or_create_key(vault_dir) == key_material
    finally:
        writer.join(timeout=5)


def test_damaged_key_still_raises(tmp_path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    (vault_dir / "vault.key").write_bytes(b"too short")
    with pytest.raises(QuarantineError):
        _load_or_create_key(vault_dir)


# ======================================================================
# F7 + F9 — packaging: upgrade restarts the service; unit hardening
# ======================================================================
def test_postinst_restarts_the_service_on_upgrade():
    postinst = (LINUX_PACKAGING / "debian" / "postinst").read_text(
        encoding="utf-8"
    )
    assert "systemctl restart" in postinst


def test_unit_carries_no_new_privileges():
    assert "NoNewPrivileges=true" in linuxservice.render_unit()
