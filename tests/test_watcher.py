"""Tests for argus.watcher: stability debounce, re-scan on modify,
symlink safety, vanish tolerance. All driven by poll_once() so they
are deterministic — no sleeps, no threads."""

import os

from argus.watcher import DirectoryWatcher


def _watcher(tmp_path, stable_polls=2):
    ready: list = []
    watcher = DirectoryWatcher(
        [tmp_path], poll_interval=0.05, stable_polls=stable_polls,
        on_ready=ready.append,
    )
    return watcher, ready


def test_new_file_reported_once_stable(tmp_path):
    watcher, ready = _watcher(tmp_path)
    target = tmp_path / "download.bin"
    target.write_bytes(b"payload")

    assert watcher.poll_once() == []  # seen, not yet stable
    assert watcher.poll_once() == [target]
    assert ready == [target]
    # And not reported again while unchanged.
    assert watcher.poll_once() == []


def test_stable_polls_one_reports_immediately(tmp_path):
    watcher, ready = _watcher(tmp_path, stable_polls=1)
    target = tmp_path / "a.txt"
    target.write_text("hi")
    assert watcher.poll_once() == [target]


def test_growing_file_waits_until_stable(tmp_path):
    watcher, ready = _watcher(tmp_path)
    target = tmp_path / "big.iso"
    target.write_bytes(b"chunk-1")

    assert watcher.poll_once() == []
    with open(target, "ab") as fh:  # still downloading...
        fh.write(b"chunk-2")
    assert watcher.poll_once() == []  # changed: wait restarts
    with open(target, "ab") as fh:
        fh.write(b"chunk-3")
    assert watcher.poll_once() == []  # changed again
    assert watcher.poll_once() == [target]  # finally stable
    assert ready == [target]


def test_modified_file_is_reported_again(tmp_path):
    watcher, ready = _watcher(tmp_path)
    target = tmp_path / "doc.txt"
    target.write_text("version 1")
    watcher.poll_once()
    assert watcher.poll_once() == [target]

    target.write_text("version 2 — changed")
    assert watcher.poll_once() == []  # change seen, stabilizing
    assert watcher.poll_once() == [target]
    assert ready == [target, target]


def test_vanished_file_is_forgotten_quietly(tmp_path):
    watcher, ready = _watcher(tmp_path)
    target = tmp_path / "temp.tmp"
    target.write_text("ephemeral")
    watcher.poll_once()
    target.unlink()
    assert watcher.poll_once() == []  # no crash, no report
    assert watcher.stats.files_tracked == 0


def test_nested_directories_are_watched(tmp_path):
    watcher, ready = _watcher(tmp_path)
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    target = nested / "deep.bin"
    target.write_bytes(b"deep")
    watcher.poll_once()
    assert watcher.poll_once() == [target]


def test_symlinks_are_never_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("not watched directly")
    watched = tmp_path / "watched"
    watched.mkdir()
    try:
        os.symlink(outside, watched / "linkdir", target_is_directory=True)
        os.symlink(secret, watched / "linkfile.txt")
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("symlinks not available on this platform")

    ready: list = []
    watcher = DirectoryWatcher(
        [watched], poll_interval=0.05, stable_polls=1, on_ready=ready.append
    )
    watcher.poll_once()
    watcher.poll_once()
    # Neither the link target (through the dir link) nor the file link
    # itself is ever reported.
    assert ready == []
    assert watcher.stats.symlink_files_skipped >= 1


def test_missing_watch_dir_is_tolerated(tmp_path):
    watcher = DirectoryWatcher(
        [tmp_path / "does-not-exist"], poll_interval=0.05, stable_polls=1
    )
    assert watcher.poll_once() == []
    assert watcher.stats.dirs_missing == 1
    # Second poll does not re-count the same missing dir.
    watcher.poll_once()
    assert watcher.stats.dirs_missing == 1


def test_broken_callback_does_not_kill_the_watch(tmp_path):
    def boom(path):
        raise RuntimeError("callback exploded")

    watcher = DirectoryWatcher(
        [tmp_path], poll_interval=0.05, stable_polls=1, on_ready=boom
    )
    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    assert watcher.poll_once() == [target]  # still reported as ready
