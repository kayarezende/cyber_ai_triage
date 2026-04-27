"""HITL policy expression evaluator (pure, no IO).

Lives in `libs/common` so both the orchestrator (runtime) and the API
(admin-panel validation on save) can use it without the API pulling in
LangGraph/LangChain via the orchestrator package. ADR-0009 + wk-8 details
are in `apps/orchestrator/src/sentient_orchestrator/investigation/hitl_policy.py`,
which re-exports `evaluate_policy` for existing callers.

Operators:

    Logical: and, or, not, always_true, always_false
    Leaf:    eq, gt, lt, gte, lte, in, contains

Leaf operators read `expr["field"]` from the `ctx` dict. Missing keys
short-circuit to `False` (never raise) — this lets policies probe optional
fields like `review_status` without forcing every investigation to populate
them.
"""

from __future__ import annotations

from typing import Any

_LOGICAL_OPS: frozenset[str] = frozenset(
    {"and", "or", "not", "always_true", "always_false"}
)
_LEAF_OPS: frozenset[str] = frozenset({"eq", "gt", "lt", "gte", "lte", "in", "contains"})

#: Hard ceiling on rule-tree nesting depth. Stops a malicious / runaway policy
#: from blowing the stack. 16 levels is generous — real policies are 2-4 deep.
_MAX_DEPTH = 16


def _to_number(value: Any) -> float:
    """Coerce numeric comparison operands. Raises ValueError on non-numerics."""
    if isinstance(value, bool):
        # bool is a subclass of int in Python; reject to avoid 0/1 surprises.
        msg = "boolean operand not allowed for numeric compare"
        raise ValueError(msg)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value)
    msg = f"non-numeric operand: {value!r}"
    raise ValueError(msg)


def evaluate_policy(
    expr: dict[str, Any], ctx: dict[str, Any], *, depth: int = 0
) -> bool:
    """Evaluate a JSONB policy expression against the decision context."""
    if depth > _MAX_DEPTH:
        msg = f"policy depth exceeded ({_MAX_DEPTH})"
        raise ValueError(msg)
    if not isinstance(expr, dict):
        msg = "policy expression must be a dict"
        raise ValueError(msg)

    op = expr.get("op")
    if op == "always_true":
        return True
    if op == "always_false":
        return False
    if op == "and":
        conditions = expr.get("conditions") or []
        return all(
            evaluate_policy(c, ctx, depth=depth + 1) for c in conditions
        )
    if op == "or":
        conditions = expr.get("conditions") or []
        return any(
            evaluate_policy(c, ctx, depth=depth + 1) for c in conditions
        )
    if op == "not":
        inner = expr.get("condition")
        if inner is None:
            msg = "'not' requires 'condition'"
            raise ValueError(msg)
        return not evaluate_policy(inner, ctx, depth=depth + 1)
    if op in _LEAF_OPS:
        field = expr.get("field")
        if not isinstance(field, str):
            msg = f"{op!r} requires string 'field'"
            raise ValueError(msg)
        actual = ctx.get(field)
        # Missing-key short-circuit: never raise on a probe of an absent field.
        if actual is None:
            return False
        value = expr.get("value")
        if op == "eq":
            return bool(actual == value)
        if op in {"gt", "lt", "gte", "lte"}:
            try:
                a, b = _to_number(actual), _to_number(value)
            except ValueError:
                return False
            if op == "gt":
                return a > b
            if op == "lt":
                return a < b
            if op == "gte":
                return a >= b
            if op == "lte":
                return a <= b
        if op == "in":
            return actual in (value or [])
        if op == "contains":
            if isinstance(actual, (list, tuple, set, str)):
                return value in actual
            return False
    msg = f"unknown op: {op!r}"
    raise ValueError(msg)


def validate_policy_shape(expr: dict[str, Any]) -> None:
    """Confirm a policy expression parses without runtime errors.

    Walks the tree once with an empty context. Missing-key short-circuit
    means leaf ops still validate even though no fields are populated.
    Returns on success; raises `ValueError` (with the original parse error
    message) on malformed input. Use from admin-panel save handlers.
    """
    evaluate_policy(expr, ctx={})


__all__ = ["evaluate_policy", "validate_policy_shape"]
