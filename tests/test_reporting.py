"""Tests for argus.reporting: history recording, summaries, reports."""

import json

import pytest

from argus.reporting import (
    DetectionRecord,
    History,
    render_text_report,
    report_dict,
)


@pytest.fixture()
def history(tmp_path):
    h = History.open(tmp_path / "history.db")
    yield h
    h.close()


def _record_a_scan(history, *, with_detection=True):
    detections = []
    if with_detection:
        detections.append(
            DetectionRecord(
                path="/downloads/evil.exe",
                verdict="Malicious",
                severity="high",
                score=80,
                name="EICAR-Test-File",
                reasons=["This file is an exact match for known malware."],
                sha256="a" * 64,
                action_taken="quarantined",
            )
        )
    return history.record_scan(
        kind="ondemand",
        root="/downloads",
        files_scanned=10,
        files_skipped=1,
        files_excluded=2,
        bytes_scanned=2048,
        detections=detections,
    )


def test_record_and_read_back(history):
    scan_id = _record_a_scan(history)
    scans = history.recent_scans()
    assert len(scans) == 1
    assert scans[0].id == scan_id
    assert scans[0].files_scanned == 10
    assert scans[0].detections_count == 1

    detections = history.recent_detections()
    assert len(detections) == 1
    det = detections[0]
    assert det.path == "/downloads/evil.exe"
    assert det.verdict == "Malicious"
    assert det.severity == "high"
    assert det.score == 80
    assert det.action_taken == "quarantined"
    assert det.reasons == ["This file is an exact match for known malware."]


def test_summary_aggregates(history):
    _record_a_scan(history)
    _record_a_scan(history, with_detection=False)
    summary = history.summary(days=7)
    assert summary["scans"] == 2
    assert summary["on_demand_scans"] == 2
    assert summary["files_scanned"] == 20
    assert summary["files_excluded"] == 4
    assert summary["detections"] == 1
    assert summary["by_severity"] == {"high": 1}
    assert summary["by_verdict"] == {"Malicious": 1}
    assert summary["by_action"] == {"quarantined": 1}


def test_realtime_recording(history):
    history.record_realtime_detection(
        path="/tmp/drop.exe",
        verdict="Malicious",
        severity="critical",
        name="Real-time detection",
        reasons=["Argus flagged drop.exe as Malicious."],
        sha256="b" * 64,
        action_taken="pending",
    )
    summary = history.summary(days=1)
    assert summary["realtime_events"] == 1
    assert summary["detections"] == 1


def test_update_detection_action(history):
    _record_a_scan(history)
    # The recorded detection starts as quarantined; now simulate the
    # pending-approval flow annotating an earlier 'none' instead.
    history.record_scan(
        kind="ondemand", root="/x", files_scanned=1,
        detections=[DetectionRecord(
            path="/x/f.exe", verdict="Malicious", sha256="c" * 64,
            action_taken="none",
        )],
    )
    history.update_detection_action(
        sha256="c" * 64, path="/x/f.exe", action_taken="quarantined"
    )
    det = [d for d in history.recent_detections() if d.sha256 == "c" * 64][0]
    assert det.action_taken == "quarantined"


def test_text_report_is_plain_language(history):
    _record_a_scan(history)
    text = render_text_report(history, days=7)
    assert "ARGUS report" in text
    assert "evil.exe" in text
    assert "EICAR-Test-File" in text
    assert "quarantine vault" in text  # the action, explained
    assert "Flagged files: 1" in text


def test_text_report_clean_period(history):
    _record_a_scan(history, with_detection=False)
    text = render_text_report(history, days=7)
    assert "Nothing was flagged" in text


def test_report_dict_is_json_safe(history):
    _record_a_scan(history)
    payload = report_dict(history, days=7)
    json.dumps(payload)  # must not raise
    assert payload["summary"]["detections"] == 1
    assert payload["detections"][0]["path"] == "/downloads/evil.exe"
    assert payload["recent_scans"][0]["kind"] == "ondemand"


def test_history_survives_reopen(tmp_path):
    path = tmp_path / "history.db"
    first = History.open(path)
    _record_a_scan(first)
    first.close()

    second = History.open(path)
    try:
        assert len(second.recent_scans()) == 1
        assert len(second.recent_detections()) == 1
    finally:
        second.close()
