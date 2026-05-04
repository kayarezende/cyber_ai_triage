"""Unit tests for InvestigationState + InvestigationOutput."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentient_orchestrator.investigation.state import (
    MAX_TOOL_CALLS,
    InvestigationOutput,
    ReviewOutput,
)


def _ok_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "verdict": "true_positive",
        "confidence": 85,
        "severity": "high",
        "mitre_techniques": ["T1059.001", "T1071"],
        "summary": "PowerShell C2 beaconing observed; multiple hosts.",
        "evidence": ["spl: index=main proc=powershell", "src=10.0.0.5 host=DC01"],
        "reasoning": "Two pieces of evidence supporting compromise.",
    }
    base.update(overrides)
    return base


def test_max_tool_calls_constant_is_positive() -> None:
    assert MAX_TOOL_CALLS > 0


def test_investigation_output_happy_path() -> None:
    out = InvestigationOutput(**_ok_kwargs())  # type: ignore[arg-type]
    assert out.verdict == "true_positive"
    assert out.confidence == 85
    assert out.severity == "high"
    assert out.mitre_techniques == ["T1059.001", "T1071"]


def test_invalid_verdict_rejected() -> None:
    with pytest.raises(ValidationError):
        InvestigationOutput(**_ok_kwargs(verdict="malicious"))  # type: ignore[arg-type]


def test_invalid_severity_rejected() -> None:
    with pytest.raises(ValidationError):
        InvestigationOutput(**_ok_kwargs(severity="urgent"))  # type: ignore[arg-type]


@pytest.mark.parametrize("conf", [-1, 101, 200])
def test_confidence_bounds(conf: int) -> None:
    with pytest.raises(ValidationError):
        InvestigationOutput(**_ok_kwargs(confidence=conf))  # type: ignore[arg-type]


def test_mitre_technique_pattern_drops_non_t_codes() -> None:
    """Cluster E MED-4: malformed codes are dropped + warned, not raised.

    Pre-cluster-E this raised ValidationError (per-element ``Field(pattern=...)``).
    Now an ``AfterValidator`` drops malformed codes silently with a warning so
    a single hallucinated technique doesn't burn an LLM schema-retry.
    """
    out = InvestigationOutput(
        **_ok_kwargs(mitre_techniques=["T1059", "S0001"]),  # type: ignore[arg-type]
    )
    assert out.mitre_techniques == ["T1059"]


def test_mitre_technique_pattern_accepts_subtechniques() -> None:
    out = InvestigationOutput(**_ok_kwargs(mitre_techniques=["T1078.004", "T1110"]))  # type: ignore[arg-type]
    assert out.mitre_techniques == ["T1078.004", "T1110"]


def test_evidence_can_be_empty() -> None:
    out = InvestigationOutput(**_ok_kwargs(evidence=[]))  # type: ignore[arg-type]
    assert out.evidence == []


def test_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        InvestigationOutput(
            **_ok_kwargs(unknown_field="foo"),  # type: ignore[arg-type]
        )


def test_summary_must_be_non_empty() -> None:
    with pytest.raises(ValidationError):
        InvestigationOutput(**_ok_kwargs(summary=""))  # type: ignore[arg-type]


def test_reasoning_must_be_non_empty() -> None:
    with pytest.raises(ValidationError):
        InvestigationOutput(**_ok_kwargs(reasoning=""))  # type: ignore[arg-type]


def test_inconclusive_verdict_accepted() -> None:
    out = InvestigationOutput(**_ok_kwargs(verdict="inconclusive"))  # type: ignore[arg-type]
    assert out.verdict == "inconclusive"


def test_round_trip_via_json() -> None:
    out = InvestigationOutput(**_ok_kwargs())  # type: ignore[arg-type]
    payload = out.model_dump_json()
    parsed = InvestigationOutput.model_validate_json(payload)
    assert parsed == out


# ---------------------------------------------------------------- ReviewOutput


def _review_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "status": "approved",
        "hallucination_risk": "low",
        "confidence_assessment": "well_calibrated",
        "notes": "Evidence supports the verdict at the cited confidence.",
        "flagged_claims": [],
    }
    base.update(overrides)
    return base


def test_review_output_happy_path() -> None:
    review = ReviewOutput(**_review_kwargs())  # type: ignore[arg-type]
    assert review.status == "approved"
    assert review.flagged_claims == []


def test_review_output_flagged_with_claims() -> None:
    review = ReviewOutput(
        **_review_kwargs(
            status="flagged",
            hallucination_risk="high",
            confidence_assessment="overconfident",
            notes="claim about lateral movement is not supported.",
            flagged_claims=["lateral movement assertion"],
        )  # type: ignore[arg-type]
    )
    assert review.status == "flagged"
    assert review.flagged_claims == ["lateral movement assertion"]


def test_review_output_rejects_invalid_status() -> None:
    with pytest.raises(ValidationError):
        ReviewOutput(**_review_kwargs(status="rejected"))  # type: ignore[arg-type]


def test_review_output_rejects_empty_notes() -> None:
    with pytest.raises(ValidationError):
        ReviewOutput(**_review_kwargs(notes=""))  # type: ignore[arg-type]


def test_review_output_extra_forbidden() -> None:
    with pytest.raises(ValidationError):
        ReviewOutput(**_review_kwargs(extra_field="x"))  # type: ignore[arg-type]
