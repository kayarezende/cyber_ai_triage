"""Pure scoring functions for eval runs.

No IO, no LLM calls, no DB. Takes a runner output + rubric and returns
per-incident + aggregate scores. Tests at `test_scoring.py` are offline.

Scoring shape:
  - verdict accuracy: exact match (binary).
  - severity accuracy: graded — exact 1.0, ±1 ordinal step 0.5, else 0.0.
  - MITRE F1: precision/recall on the technique-ID set.
  - overall = weighted sum per `rubric.scoring.*_weight`.

Severity is treated ordinally because Tier-1 picks an integer-ish point on a
5-step scale; off-by-one is qualitatively different from off-by-three.
Verdict is categorical so partial credit doesn't apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class MitreF1:
    precision: float
    recall: float
    f1: float
    matched: tuple[str, ...]
    missed: tuple[str, ...]
    extra: tuple[str, ...]


@dataclass(frozen=True)
class IncidentScore:
    incident_id: str
    verdict_actual: str | None
    verdict_expected: str
    verdict_correct: bool
    severity_actual: str | None
    severity_expected: str
    severity_score: float
    mitre: MitreF1
    overall: float
    fail_category: str | None
    runner_status: str
    cost_usd: float | None
    latency_ms: int | None


@dataclass(frozen=True)
class RunSummary:
    total: int
    verdict_accuracy: float
    severity_mean: float
    mitre_f1_mean: float
    overall_mean: float
    verdict_pass: bool
    mitre_pass: bool
    overall_pass: bool
    fail_buckets: dict[str, int] = field(default_factory=dict)
    total_cost_usd: float = 0.0


def score_verdict(actual: str | None, expected: str) -> bool:
    return actual is not None and actual == expected


def score_severity(actual: str | None, expected: str) -> float:
    if actual is None:
        return 0.0
    if actual == expected:
        return 1.0
    if actual not in SEVERITY_ORDER or expected not in SEVERITY_ORDER:
        return 0.0
    distance = abs(SEVERITY_ORDER.index(actual) - SEVERITY_ORDER.index(expected))
    if distance == 1:
        return 0.5
    return 0.0


def score_mitre(actual: list[str] | None, expected: list[str]) -> MitreF1:
    actual_set = set(actual or [])
    expected_set = set(expected or [])
    matched = actual_set & expected_set
    missed = expected_set - actual_set
    extra = actual_set - expected_set

    if not actual_set and not expected_set:
        # Both empty → vacuous match. Treat as F1=1.0 so a benign event
        # with no expected techniques doesn't drag the mean down.
        return MitreF1(
            precision=1.0,
            recall=1.0,
            f1=1.0,
            matched=tuple(sorted(matched)),
            missed=tuple(sorted(missed)),
            extra=tuple(sorted(extra)),
        )

    precision = len(matched) / len(actual_set) if actual_set else 0.0
    recall = len(matched) / len(expected_set) if expected_set else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return MitreF1(
        precision=precision,
        recall=recall,
        f1=f1,
        matched=tuple(sorted(matched)),
        missed=tuple(sorted(missed)),
        extra=tuple(sorted(extra)),
    )


def score_incident(
    *,
    incident_id: str,
    expected_verdict: str,
    expected_severity: str,
    expected_techniques: list[str],
    actual_verdict: str | None,
    actual_severity: str | None,
    actual_techniques: list[str] | None,
    runner_status: str,
    fail_category: str | None,
    cost_usd: float | None,
    latency_ms: int | None,
    rubric: dict[str, Any],
) -> IncidentScore:
    verdict_correct = score_verdict(actual_verdict, expected_verdict)
    severity_score = score_severity(actual_severity, expected_severity)
    mitre = score_mitre(actual_techniques, expected_techniques)

    weights = rubric["scoring"]
    overall = (
        weights["verdict_accuracy_weight"] * (1.0 if verdict_correct else 0.0)
        + weights["mitre_f1_weight"] * mitre.f1
        + weights["severity_accuracy_weight"] * severity_score
    )

    return IncidentScore(
        incident_id=incident_id,
        verdict_actual=actual_verdict,
        verdict_expected=expected_verdict,
        verdict_correct=verdict_correct,
        severity_actual=actual_severity,
        severity_expected=expected_severity,
        severity_score=severity_score,
        mitre=mitre,
        overall=overall,
        fail_category=fail_category,
        runner_status=runner_status,
        cost_usd=cost_usd,
        latency_ms=latency_ms,
    )


def summarize(scores: list[IncidentScore], rubric: dict[str, Any]) -> RunSummary:
    if not scores:
        return RunSummary(
            total=0,
            verdict_accuracy=0.0,
            severity_mean=0.0,
            mitre_f1_mean=0.0,
            overall_mean=0.0,
            verdict_pass=False,
            mitre_pass=False,
            overall_pass=False,
        )

    total = len(scores)
    verdict_acc = sum(1 for s in scores if s.verdict_correct) / total
    sev_mean = sum(s.severity_score for s in scores) / total
    mitre_mean = sum(s.mitre.f1 for s in scores) / total
    overall_mean = sum(s.overall for s in scores) / total
    total_cost = sum(s.cost_usd for s in scores if s.cost_usd is not None)

    fail_buckets: dict[str, int] = {}
    for s in scores:
        if s.fail_category:
            fail_buckets[s.fail_category] = fail_buckets.get(s.fail_category, 0) + 1

    thresholds = rubric["thresholds"]
    return RunSummary(
        total=total,
        verdict_accuracy=verdict_acc,
        severity_mean=sev_mean,
        mitre_f1_mean=mitre_mean,
        overall_mean=overall_mean,
        verdict_pass=verdict_acc >= thresholds["verdict_accuracy_pass"],
        mitre_pass=mitre_mean >= thresholds["mitre_f1_pass"],
        overall_pass=overall_mean >= thresholds["overall_pass"],
        fail_buckets=fail_buckets,
        total_cost_usd=total_cost,
    )


__all__ = [
    "IncidentScore",
    "MitreF1",
    "RunSummary",
    "SEVERITY_ORDER",
    "score_incident",
    "score_mitre",
    "score_severity",
    "score_verdict",
    "summarize",
]
