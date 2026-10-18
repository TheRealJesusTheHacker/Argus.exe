"""Tests for the signature database: init, seeding, lookups, integrity."""

import sqlite3

import pytest

from argus.signatures import (
    EICAR_SHA256,
    SCHEMA_VERSION,
    SignatureDB,
    SignatureError,
    init_db,
)


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "test.sigdb"
    init_db(path)
    return path


def test_init_seeds_eicar(db_path):
    with SignatureDB.open(db_path) as db:
        assert db.info.count == 1
        hit = db.lookup(EICAR_SHA256)
        assert hit is not None
        assert hit.name == "EICAR-Test-File"
        assert hit.family == "Test"


def test_init_no_seed_is_empty(tmp_path):
    path = tmp_path / "empty.sigdb"
    info = init_db(path, seed=False)
    assert info.count == 0
    with SignatureDB.open(path) as db:
        assert db.lookup(EICAR_SHA256) is None


def test_lookup_miss_returns_none(db_path):
    with SignatureDB.open(db_path) as db:
        assert db.lookup("0" * 64) is None
        assert ("f" * 64) not in db


def test_info_fields(db_path):
    with SignatureDB.open(db_path) as db:
        assert db.info.schema_version == SCHEMA_VERSION
        assert db.info.version
        assert db.info.built_at


def test_open_missing_file_raises(tmp_path):
    with pytest.raises(SignatureError, match="not found"):
        SignatureDB.open(tmp_path / "does-not-exist.sigdb")


def test_open_corrupt_file_raises(tmp_path):
    path = tmp_path / "garbage.sigdb"
    path.write_bytes(b"this is not a sqlite database at all" * 10)
    with pytest.raises(SignatureError):
        SignatureDB.open(path)


def test_integrity_count_mismatch_detected(tmp_path):
    path = tmp_path / "tampered.sigdb"
    init_db(path)
    # Sneak in a row without updating meta.count.
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO hashes (sha256, name, family, severity) VALUES (?, ?, ?, ?)",
        ("a" * 64, "Sneaky", "Test", "low"),
    )
    conn.commit()
    conn.close()
    with pytest.raises(SignatureError, match="count mismatch"):
        SignatureDB.open(path)


def test_integrity_schema_version_mismatch_detected(tmp_path):
    path = tmp_path / "future.sigdb"
    init_db(path)
    conn = sqlite3.connect(path)
    conn.execute("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
    conn.commit()
    conn.close()
    with pytest.raises(SignatureError, match="schema version"):
        SignatureDB.open(path)


def test_integrity_missing_table_detected(tmp_path):
    path = tmp_path / "broken.sigdb"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.commit()
    conn.close()
    with pytest.raises(SignatureError, match="missing required tables"):
        SignatureDB.open(path)
