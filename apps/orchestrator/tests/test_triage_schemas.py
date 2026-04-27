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


def test_mitre_guesses_rejects_invalid_pattern() -> None:
    kwargs = _ok_kwargs()
    kwargs["mitre_guesses"] = ["TA0002"]  # tactic, not technique
    with pytest.raises(ValidationError):
        TriageOutput(**kwargs)  # type: ignore[arg-type]


def test_mitre_guesses_accepts_subtechnique() -> None:
    kwargs = _ok_kwargs()
    kwargs["mitre_guesses"] = ["T1059", "T1059.001"]
    TriageOutput(**kwargs)  # type: ignore[arg-type]


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
