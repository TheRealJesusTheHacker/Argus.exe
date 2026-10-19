"""Tests for argus.quarantine: the encrypted vault — round-trip,
tamper evidence, restore collisions, deletion, failure safety."""

import hashlib
import os

import pytest

from argus.quarantine import QuarantineError, Vault

PAYLOAD = bytes(range(256)) * 5000  # ~1.28 MB — spans multiple chunks


@pytest.fixture()
def vault(tmp_path):
    v = Vault.open(tmp_path / "vault")
    yield v
    v.close()


def _make_file(tmp_path, name="evil.exe", data=PAYLOAD):
    target = tmp_path / "downloads" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def _quarantine(vault, path, **kw):
    kw.setdefault("detection_name", "Test.Detection")
    kw.setdefault("severity", "high")
    kw.setdefault("verdict", "Malicious")
    kw.setdefault("reasons", ["It matched a test detection."])
    return vault.quarantine_file(path, **kw)


def test_round_trip(vault, tmp_path):
    target = _make_file(tmp_path)
    expected_sha = hashlib.sha256(PAYLOAD).hexdigest()

    entry = _quarantine(vault, target)

    # Original is gone; the blob is not the original bytes.
    assert not target.exists()
    blob = vault.blobs_dir / entry.blob_name
    assert blob.is_file()
    assert blob.read_bytes() != PAYLOAD
    # Index recorded the facts.
    assert entry.sha256 == expected_sha
    assert entry.size == len(PAYLOAD)
    assert entry.status == "quarantined"
    assert entry.original_path == str(target)
    assert vault.count("quarantined") == 1

    restored = vault.restore(entry.id)
    assert restored == target
    assert target.read_bytes() == PAYLOAD
    assert not blob.exists()
    after = vault.get_entry(entry.id)
    assert after.status == "restored"
    assert after.restored_path == str(target)


def test_empty_file_round_trip(vault, tmp_path):
    target = _make_file(tmp_path, "empty.bin", b"")
    entry = _quarantine(vault, target)
    assert entry.size == 0
    restored = vault.restore(entry.id)
    assert restored.read_bytes() == b""


def test_tampered_blob_refuses_restore(vault, tmp_path):
    target = _make_file(tmp_path)
    entry = _quarantine(vault, target)
    blob = vault.blobs_dir / entry.blob_name
    raw = bytearray(blob.read_bytes())
    raw[len(raw) // 2] ^= 0xFF  # flip a ciphertext byte
    blob.write_bytes(bytes(raw))

    with pytest.raises(QuarantineError):
        vault.restore(entry.id)
    # Nothing was put back, and the entry is still live in the vault.
    assert not target.exists()
    assert vault.get_entry(entry.id).status == "quarantined"


def test_truncated_blob_refuses_restore(vault, tmp_path):
    target = _make_file(tmp_path)
    entry = _quarantine(vault, target)
    blob = vault.blobs_dir / entry.blob_name
    blob.write_bytes(blob.read_bytes()[:40])  # header + almost nothing

    with pytest.raises(QuarantineError):
        vault.restore(entry.id)
    assert not target.exists()


def test_restore_collision_never_overwrites(vault, tmp_path):
    target = _make_file(tmp_path)
    entry = _quarantine(vault, target)
    # Something new now lives at the original location.
    target.write_bytes(b"the user's new, innocent file")

    restored = vault.restore(entry.id)
    assert restored != target
    assert target.read_bytes() == b"the user's new, innocent file"
    assert restored.read_bytes() == PAYLOAD
    assert "restored by Argus" in restored.name


def test_delete_permanent(vault, tmp_path):
    target = _make_file(tmp_path)
    entry = _quarantine(vault, target)
    blob = vault.blobs_dir / entry.blob_name
    assert blob.exists()

    vault.delete_permanent(entry.id)
    assert not blob.exists()
    assert vault.get_entry(entry.id).status == "deleted"
    with pytest.raises(QuarantineError):
        vault.restore(entry.id)


def test_wrong_sha_claim_rejected(vault, tmp_path):
    """If the file changed between scan and quarantine (fingerprint
    mismatch), Argus refuses and leaves the file alone."""
    target = _make_file(tmp_path)
    with pytest.raises(QuarantineError):
        _quarantine(vault, target, sha256="0" * 64)
    assert target.read_bytes() == PAYLOAD
    assert vault.count() == 0


def test_quarantine_missing_file(vault, tmp_path):
    with pytest.raises(QuarantineError):
        _quarantine(vault, tmp_path / "nope.exe")
    assert vault.count() == 0


def test_unknown_entry_ids(vault):
    assert vault.get_entry("deadbeef") is None
    with pytest.raises(QuarantineError):
        vault.restore("deadbeef")
    with pytest.raises(QuarantineError):
        vault.delete_permanent("deadbeef")


def test_double_restore_refused(vault, tmp_path):
    target = _make_file(tmp_path)
    entry = _quarantine(vault, target)
    vault.restore(entry.id)
    with pytest.raises(QuarantineError):
        vault.restore(entry.id)


def test_interrupted_quarantine_leaves_original_intact(vault, tmp_path, monkeypatch):
    """A failure mid-encryption (disk full, crash) must leave the
    original file untouched and record nothing."""
    import argus.quarantine as quarantine_mod

    real_encrypt = quarantine_mod._encrypt_stream

    def exploding_encrypt(source, dest, key, nonce):
        dest.write(b"ARGUSQ1\x00" + nonce + b"partial-ciphertext")
        raise OSError("No space left on device")

    monkeypatch.setattr(quarantine_mod, "_encrypt_stream", exploding_encrypt)
    target = _make_file(tmp_path)
    with pytest.raises(QuarantineError):
        _quarantine(vault, target)
    monkeypatch.setattr(quarantine_mod, "_encrypt_stream", real_encrypt)

    assert target.read_bytes() == PAYLOAD
    assert vault.count() == 0
    assert list(vault.blobs_dir.iterdir()) == []  # no temp or blob left


def test_vault_reopen_keeps_entries(tmp_path, vault):
    target = _make_file(tmp_path)
    entry = _quarantine(vault, target)
    vault.close()

    reopened = Vault.open(tmp_path / "vault")
    try:
        kept = reopened.get_entry(entry.id)
        assert kept is not None
        assert kept.sha256 == entry.sha256
        assert reopened.restore(entry.id) == target
    finally:
        reopened.close()


def test_blob_names_are_opaque(vault, tmp_path):
    target = _make_file(tmp_path, "totally-a-virus.exe")
    entry = _quarantine(vault, target)
    assert "virus" not in entry.blob_name
    assert entry.blob_name.endswith(".blob")
    # The original extension is neutralized inside the vault.
    assert not entry.blob_name.endswith(".exe")


def test_stale_temp_files_swept_on_open(tmp_path):
    vault = Vault.open(tmp_path / "vault")
    stale = vault.blobs_dir / "orphan.encrypt.tmp"
    stale.write_bytes(b"leftover")
    vault.close()

    reopened = Vault.open(tmp_path / "vault")
    try:
        assert not stale.exists()
    finally:
        reopened.close()
