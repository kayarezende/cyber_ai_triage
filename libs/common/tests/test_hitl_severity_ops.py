"""HIGH-1: domain-aware severity_* ops + save-time veto on generic compares.

Severity is RANKED, not numeric. A string compare on `'high' >= 'critical'`
is True alphabetically — silently letting a "critical only" gate
auto-approve everything ≥ 'critical' alphabetically (which is just
'critical' itself, but the same trap fires the other way: `severity == 'medium'
GTE 'high'` is also True alphabetically). Domain-aware ops + save-time veto
close both the runtime bug and the misconfig footgun.
"""

from __future__ import annotations

import pytest

from sentient_common.hitl import evaluate_policy, validate_policy_shape

# ---- runtime severity_* op semantics ----


def test_severity_gte_critical_passes_for_critical() -> None:
    assert (
        evaluate_policy(
            {"op": "severity_gte", "field": "severity", "value": "high"},
            {"severity": "critical"},
        )
        is True
    )


def test_severity_gte_high_blocks_medium() -> None:
    assert (
        evaluate_policy(
            {"op": "severity_gte", "field": "severity", "value": "high"},
            {"severity": "medium"},
        )
        is False
    )


def test_severity_lte_inverse() -> None:
    assert (
        evaluate_policy(
            {"op": "severity_lte", "field": "severity", "value": "low"},
            {"severity": "info"},
        )
        is True
    )
    assert (
        evaluate_policy(
            {"op": "severity_lte", "field": "severity", "value": "low"},
            {"severity": "high"},
        )
        is False
    )


def test_severity_gt_strict() -> None:
    assert (
        evaluate_policy(
            {"op": "severity_gt", "field": "severity", "value": "high"},
            {"severity": "critical"},
        )
        is True
    )
    assert (
        evaluate_policy(
            {"op": "severity_gt", "field": "severity", "value": "high"},
            {"severity": "high"},
        )
        is False
    )


def test_severity_lt_strict() -> None:
    assert (
        evaluate_policy(
            {"op": "severity_lt", "field": "severity", "value": "medium"},
            {"severity": "low"},
        )
        is True
    )
    assert (
        evaluate_policy(
            {"op": "severity_lt", "field": "severity", "value": "medium"},
            {"severity": "medium"},
        )
        is False
    )


def test_severity_op_case_insensitive() -> None:
    """Splunk + OCSF emit severity strings inconsistently; lowercase is canonical."""
    assert (
        evaluate_policy(
            {"op": "severity_gte", "field": "severity", "value": "HIGH"},
            {"severity": "Critical"},
        )
        is True
    )


def test_severity_op_missing_field_short_circuits_false() -> None:
    """Consistent with rest of walker — missing-key probe doesn't raise."""
    assert (
        evaluate_policy(
            {"op": "severity_gte", "field": "severity", "value": "high"},
            {},
        )
        is False
    )


def test_severity_op_unknown_severity_raises() -> None:
    """Unknown severity propagates → callsite falls back to needs_human (HIGH-4)."""
    with pytest.raises(ValueError, match="unknown severity"):
        evaluate_policy(
            {"op": "severity_gte", "field": "severity", "value": "bogus"},
            {"severity": "critical"},
        )


def test_severity_op_rejects_bool() -> None:
    with pytest.raises(ValueError, match="boolean"):
        evaluate_policy(
            {"op": "severity_gte", "field": "severity", "value": True},
            {"severity": "critical"},
        )


# ---- save-time veto ----


def test_validate_rejects_generic_gte_on_severity() -> None:
    with pytest.raises(ValueError, match="severity_gte"):
        validate_policy_shape({"op": "gte", "field": "severity", "value": "high"})


def test_validate_rejects_generic_gt_lt_lte_on_severity() -> None:
    for op in ("gt", "lt", "gte", "lte"):
        with pytest.raises(ValueError, match="severity_"):
            validate_policy_shape({"op": op, "field": "severity", "value": "high"})


def test_validate_rejects_severity_misuse_inside_and() -> None:
    """Veto walks into nested logical operators."""
    with pytest.raises(ValueError, match="severity_"):
        validate_policy_shape(
            {
                "op": "and",
                "conditions": [
                    {"op": "eq", "field": "verdict", "value": "true_positive"},
                    {"op": "gte", "field": "severity", "value": "high"},
                ],
            }
        )


def test_validate_rejects_severity_misuse_inside_not() -> None:
    with pytest.raises(ValueError, match="severity_"):
        validate_policy_shape(
            {
                "op": "not",
                "condition": {"op": "lt", "field": "severity", "value": "low"},
            }
        )


def test_validate_accepts_severity_op() -> None:
    validate_policy_shape({"op": "severity_gte", "field": "severity", "value": "high"})


def test_validate_accepts_generic_compares_on_non_severity_fields() -> None:
    """Numeric compares are still legal against `confidence` etc."""
    validate_policy_shape({"op": "gte", "field": "confidence", "value": 80})
    validate_policy_shape({"op": "lt", "field": "confidence", "value": 50})


def test_validate_full_coverage_ctx_surfaces_unknown_severity_value() -> None:
    """A `severity_gte` with a bogus literal value must fail at save time, not
    silently short-circuit on missing-key."""
    with pytest.raises(ValueError, match="unknown severity"):
        validate_policy_shape(
            {
                "op": "severity_gte",
                "field": "severity",
                "value": "fataaaal",  # not in SEVERITY_RANK
            }
        )
