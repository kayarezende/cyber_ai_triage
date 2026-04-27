"""Pure-function tests for scoring. Zero IO, zero mocks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evals.harness.scoring import (
    SEVERITY_ORDER,
    score_incident,
    score_mitre,
    score_severity,
    score_verdict,
    summarize,
)


@pytest.fixture
def rubric() -> dict:
    rubric_path = (
        Path(__file__).resolve().parents[1] / "rubrics" / "v1.json"
    )
    return json.loads(rubric_path.read_text())


# ---- score_verdict


@pytest.mark.parametrize(
    "actual,expected,want",
    [
        ("true_positive", "true_positive", True),
        ("false_positive", "true_positive", False),
        (None, "true_positive", False),
        ("benign", "benign", True),
    ],
)
def test_score_verdict(actual, expected, want) -> None:
    assert score_verdict(actual, expected) is want


# ---- score_severity


def test_severity_exact_match() -> None:
    assert score_severity("high", "high") == 1.0


def test_severity_one_step_off() -> None:
    assert score_severity("medium", "high") == 0.5
    assert score_severity("high", "medium") == 0.5


def test_severity_two_step_off() -> None:
    assert score_severity("low", "high") == 0.0


def test_severity_none_actual() -> None:
    assert score_severity(None, "high") == 0.0


def test_severity_invalid_label_returns_zero() -> None:
    assert score_severity("bogus", "high") == 0.0


def test_severity_order_is_5_levels() -> None:
    assert len(SEVERITY_ORDER) == 5


# ---- score_mitre


def test_mitre_exact_match() -> None:
    result = score_mitre(["T1110", "T1110.001"], ["T1110", "T1110.001"])
    assert result.f1 == 1.0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.matched == ("T1110", "T1110.001")
    assert result.missed == ()
    assert result.extra == ()


def test_mitre_both_empty_is_vacuous_match() -> None:
    """A benign event with no expected techniques should not penalize the
    mean F1 across a dataset that includes such events."""
    result = score_mitre([], [])
    assert result.f1 == 1.0
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_mitre_partial_recall() -> None:
    result = score_mitre(["T1110"], ["T1110", "T1110.001"])
    assert result.precision == 1.0
    assert result.recall == 0.5
    # F1 = 2*1*0.5 / 1.5 = 0.6667
    assert round(result.f1, 4) == round(2 / 3, 4)
    assert result.missed == ("T1110.001",)


def test_mitre_extra_predictions_drop_precision() -> None:
    result = score_mitre(["T1110", "T1059"], ["T1110"])
    assert result.precision == 0.5
    assert result.recall == 1.0
    assert result.extra == ("T1059",)


def test_mitre_actual_none_treated_as_empty() -> None:
    result = score_mitre(None, ["T1110"])
    assert result.f1 == 0.0
    assert result.recall == 0.0


# ---- score_incident


def test_score_incident_perfect(rubric) -> None:
    score = score_incident(
        incident_id="x",
        expected_verdict="true_positive",
        expected_severity="high",
        expected_techniques=["T1110"],
        actual_verdict="true_positive",
        actual_severity="high",
        actual_techniques=["T1110"],
        runner_status="completed",
        fail_category=None,
        cost_usd=0.05,
        latency_ms=8000,
        rubric=rubric,
    )
    assert score.verdict_correct is True
    assert score.severity_score == 1.0
    assert score.mitre.f1 == 1.0
    assert score.overall == 1.0  # all weights at 1.0


def test_score_incident_zero(rubric) -> None:
    score = score_incident(
        incident_id="x",
        expected_verdict="true_positive",
        expected_severity="critical",
        expected_techniques=["T1110"],
        actual_verdict="benign",
        actual_severity="info",
        actual_techniques=["T9999"],
        runner_status="completed",
        fail_category="ambiguous_label",
        cost_usd=0.01,
        latency_ms=5000,
        rubric=rubric,
    )
    assert score.verdict_correct is False
    assert score.severity_score == 0.0
    assert score.mitre.f1 == 0.0
    assert score.overall == 0.0


def test_score_incident_partial(rubric) -> None:
    score = score_incident(
        incident_id="x",
        expected_verdict="true_positive",
        expected_severity="high",
        expected_techniques=["T1110", "T1110.001"],
        actual_verdict="true_positive",
        actual_severity="medium",  # one-step off → 0.5
        actual_techniques=["T1110"],  # one of two → F1 ~ 0.667
        runner_status="completed",
        fail_category=None,
        cost_usd=0.02,
        latency_ms=7000,
        rubric=rubric,
    )
    # verdict 0.5 * 1.0 + mitre 0.4 * 0.667 + severity 0.1 * 0.5
    expected = 0.5 + 0.4 * (2 / 3) + 0.1 * 0.5
    assert round(score.overall, 4) == round(expected, 4)


# ---- summarize


def test_summarize_empty_returns_zero(rubric) -> None:
    summary = summarize([], rubric)
    assert summary.total == 0
    assert summary.overall_pass is False


def test_summarize_aggregates_and_thresholds(rubric) -> None:
    perfect = score_incident(
        incident_id="a",
        expected_verdict="true_positive",
        expected_severity="high",
        expected_techniques=["T1110"],
        actual_verdict="true_positive",
        actual_severity="high",
        actual_techniques=["T1110"],
        runner_status="completed",
        fail_category=None,
        cost_usd=0.05,
        latency_ms=8000,
        rubric=rubric,
    )
    failed = score_incident(
        incident_id="b",
        expected_verdict="true_positive",
        expected_severity="high",
        expected_techniques=["T1110"],
        actual_verdict="benign",
        actual_severity="low",
        actual_techniques=[],
        runner_status="completed",
        fail_category="schema",
        cost_usd=0.01,
        latency_ms=5000,
        rubric=rubric,
    )
    summary = summarize([perfect, failed], rubric)
    assert summary.total == 2
    assert summary.verdict_accuracy == 0.5
    assert summary.fail_buckets == {"schema": 1}
    assert summary.total_cost_usd == pytest.approx(0.06)
    assert summary.verdict_pass is False  # 0.5 < 0.85
