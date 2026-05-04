"""TriageOutput schema tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentient_orchestrator.triage.schemas import TriageOutput


def _ok_kwargs() -> dict[str, object]:
    return {
        "severity": "low",
        "confidence": 75,
        "mitre_guesses": ["T1059.001"],
        "entities_to_investigate": ["host-1"],
        "reasoning": "auth burst from known source.",
    }


def test_minimum_valid_construction() -> None:
    out = TriageOutput(**_ok_kwargs())  # type: ignore[arg-type]
    assert out.severity == "low"
    assert out.confidence == 75
    assert out.mitre_guesses == ["T1059.001"]


def test_severity_rejects_unknown_value() -> None:
    kwargs = _ok_kwargs()
    kwargs["severity"] = "fatal"
    with pytest.raises(ValidationError):
        TriageOutput(**kwargs)  # type: ignore[arg-type]


def test_confidence_rejects_below_zero() -> None:
    kwargs = _ok_kwargs()
    kwargs["confidence"] = -1
    with pytest.raises(ValidationError):
        TriageOutput(**kwargs)  # type: ignore[arg-type]


def test_confidence_rejects_above_one_hundred() -> None:
    kwargs = _ok_kwargs()
    kwargs["confidence"] = 101
    with pytest.raises(ValidationError):
        TriageOutput(**kwargs)  # type: ignore[arg-type]


def test_mitre_guesses_drops_invalid_pattern_keeps_valid() -> None:
    """DEFECT-4: drop-and-warn for malformed codes (matches Tier-2 cluster E MED-4).

    Pre-fix: per-element ``Field(pattern=...)`` raised on the LLM's most common
    shapes of bad output (`"TA0002"`, `"T1059.x"`, `" T1059;"`) and the entire
    triage call was bucketed as `validation_fail` → schema-retry → eventually
    fallback-exhausted → investigation marked inconclusive even though the
    severity + reasoning were perfectly usable.
    """
    kwargs = _ok_kwargs()
    kwargs["mitre_guesses"] = ["TA0002", "T1059.001", "T1059.x", "T1071"]
    out = TriageOutput(**kwargs)  # type: ignore[arg-type]
    assert out.mitre_guesses == ["T1059.001", "T1071"]


def test_mitre_guesses_accepts_subtechnique() -> None:
    kwargs = _ok_kwargs()
    kwargs["mitre_guesses"] = ["T1059", "T1059.001"]
    out = TriageOutput(**kwargs)  # type: ignore[arg-type]
    assert out.mitre_guesses == ["T1059", "T1059.001"]


def test_mitre_guesses_dedupes_preserving_order() -> None:
    kwargs = _ok_kwargs()
    kwargs["mitre_guesses"] = ["T1059", "T1071", "T1059", "T1486"]
    out = TriageOutput(**kwargs)  # type: ignore[arg-type]
    assert out.mitre_guesses == ["T1059", "T1071", "T1486"]


def test_mitre_guesses_drops_all_when_all_malformed() -> None:
    """All-bad input degrades to empty list, not exception."""
    kwargs = _ok_kwargs()
    kwargs["mitre_guesses"] = ["bogus", "TA0002", ""]
    out = TriageOutput(**kwargs)  # type: ignore[arg-type]
    assert out.mitre_guesses == []


def test_extra_field_forbidden() -> None:
    kwargs = _ok_kwargs()
    kwargs["bonus"] = "x"
    with pytest.raises(ValidationError):
        TriageOutput(**kwargs)  # type: ignore[arg-type]


def test_reasoning_required_non_empty() -> None:
    kwargs = _ok_kwargs()
    kwargs["reasoning"] = ""
    with pytest.raises(ValidationError):
        TriageOutput(**kwargs)  # type: ignore[arg-type]


def test_validates_from_json_round_trip() -> None:
    payload = {
        "severity": "critical",
        "confidence": 95,
        "mitre_guesses": ["T1486"],
        "entities_to_investigate": ["10.0.0.5"],
        "reasoning": "ransomware kill chain.",
    }
    import json

    out = TriageOutput.model_validate_json(json.dumps(payload))
    assert out.severity == "critical"
    assert out.entities_to_investigate == ["10.0.0.5"]
