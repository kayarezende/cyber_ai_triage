"""Wk-8 unit tests for the HITL policy evaluator."""

from __future__ import annotations

from typing import Any

import pytest

from sentient_orchestrator.investigation.hitl_policy import evaluate_policy


def _ctx(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "severity": "high",
        "verdict": "true_positive",
        "confidence": 80,
        "mitre_techniques": ["T1003", "T1059.001"],
        "detection_rule_matches": ["ransomware_kill_chain"],
        "review_status": "approved",
        "review_hallucination_risk": "low",
    }
    base.update(kwargs)
    return base


def test_always_true_returns_true() -> None:
    assert evaluate_policy({"op": "always_true"}, _ctx()) is True


def test_always_false_returns_false() -> None:
    assert evaluate_policy({"op": "always_false"}, _ctx()) is False


def test_eq_operator() -> None:
    assert evaluate_policy({"op": "eq", "field": "severity", "value": "high"}, _ctx())
    assert not evaluate_policy(
        {"op": "eq", "field": "severity", "value": "low"}, _ctx()
    )


def test_gt_lt_operators() -> None:
    assert evaluate_policy(
        {"op": "gt", "field": "confidence", "value": 50}, _ctx()
    )
    assert not evaluate_policy(
        {"op": "lt", "field": "confidence", "value": 50}, _ctx()
    )


def test_gte_lte_operators() -> None:
    assert evaluate_policy(
        {"op": "gte", "field": "confidence", "value": 80}, _ctx()
    )
    assert evaluate_policy(
        {"op": "lte", "field": "confidence", "value": 80}, _ctx()
    )


def test_in_operator() -> None:
    assert evaluate_policy(
        {"op": "in", "field": "severity", "value": ["high", "critical"]}, _ctx()
    )
    assert not evaluate_policy(
        {"op": "in", "field": "severity", "value": ["low", "medium"]}, _ctx()
    )


def test_contains_operator_on_list() -> None:
    assert evaluate_policy(
        {"op": "contains", "field": "mitre_techniques", "value": "T1003"},
        _ctx(),
    )
    assert not evaluate_policy(
        {"op": "contains", "field": "mitre_techniques", "value": "T9999"},
        _ctx(),
    )


def test_contains_operator_on_string() -> None:
    assert evaluate_policy(
        {"op": "contains", "field": "verdict", "value": "true"},
        _ctx(verdict="true_positive"),
    )


def test_and_operator() -> None:
    expr = {
        "op": "and",
        "conditions": [
            {"op": "eq", "field": "severity", "value": "high"},
            {"op": "gte", "field": "confidence", "value": 80},
        ],
    }
    assert evaluate_policy(expr, _ctx())
    assert not evaluate_policy(expr, _ctx(severity="low"))


def test_or_operator() -> None:
    expr = {
        "op": "or",
        "conditions": [
            {"op": "eq", "field": "severity", "value": "critical"},
            {"op": "eq", "field": "severity", "value": "high"},
        ],
    }
    assert evaluate_policy(expr, _ctx())
    assert not evaluate_policy(expr, _ctx(severity="low"))


def test_not_operator() -> None:
    expr = {
        "op": "not",
        "condition": {"op": "eq", "field": "severity", "value": "critical"},
    }
    assert evaluate_policy(expr, _ctx())
    assert not evaluate_policy(expr, _ctx(severity="critical"))


def test_nested_and_or_not() -> None:
    expr = {
        "op": "and",
        "conditions": [
            {
                "op": "or",
                "conditions": [
                    {"op": "eq", "field": "severity", "value": "high"},
                    {"op": "eq", "field": "severity", "value": "critical"},
                ],
            },
            {
                "op": "not",
                "condition": {
                    "op": "eq",
                    "field": "review_status",
                    "value": "flagged",
                },
            },
        ],
    }
    assert evaluate_policy(expr, _ctx())
    assert not evaluate_policy(expr, _ctx(review_status="flagged"))


def test_missing_key_short_circuits_to_false_no_raise() -> None:
    """Missing key in ctx must NOT raise — returns False."""
    expr = {"op": "eq", "field": "nope_not_there", "value": "x"}
    assert evaluate_policy(expr, _ctx()) is False


def test_depth_limit_raises() -> None:
    """Pathologically deep tree raises ValueError."""
    expr: dict[str, Any] = {"op": "always_true"}
    for _ in range(20):
        expr = {"op": "not", "condition": expr}
    with pytest.raises(ValueError, match="depth"):
        evaluate_policy(expr, _ctx())


def test_unknown_op_raises() -> None:
    with pytest.raises(ValueError, match="unknown op"):
        evaluate_policy({"op": "exec_shell"}, _ctx())


def test_non_dict_expr_raises() -> None:
    with pytest.raises(ValueError, match="must be a dict"):
        evaluate_policy("not_a_dict", _ctx())  # type: ignore[arg-type]


def test_not_without_condition_raises() -> None:
    with pytest.raises(ValueError, match="condition"):
        evaluate_policy({"op": "not"}, _ctx())


def test_leaf_op_without_field_raises() -> None:
    with pytest.raises(ValueError, match="field"):
        evaluate_policy({"op": "eq", "value": "x"}, _ctx())


def test_boolean_compare_operands_rejected_softly() -> None:
    """gt/lt with bool operand returns False rather than raising."""
    # ctx field is bool → numeric coerce raises in helper → caught → False.
    ctx = _ctx()
    ctx["confidence"] = True  # type: ignore[assignment]
    assert (
        evaluate_policy({"op": "gt", "field": "confidence", "value": 50}, ctx)
        is False
    )
