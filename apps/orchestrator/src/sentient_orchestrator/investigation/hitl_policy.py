"""Wk-8 HITL policy evaluator.

JSONB rule-tree walker (~50 lines of evaluation logic). No `eval`, no `exec`,
allowlisted operators only. Default policy `{"op": "always_true"}` per ADR-0009
(MVP requires human approval for every escalation; tenant-specific lower-
priority rules can opt out of approval for narrow conditions).

Operators:

    Logical: and, or, not, always_true, always_false
    Leaf:    eq, gt, lt, gte, lte, in, contains

Leaf operators read `expr["field"]` from the `ctx` dict. Missing keys
short-circuit to `False` (never raise) — this lets policies probe optional
fields like `review_status` without forcing every investigation to populate
them.

`select_active_policy` returns the highest-priority enabled policy visible to
the tenant; on no rows returns the default `always_true` policy.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

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


_DEFAULT_POLICY_NAME = "default_require_approval"
_DEFAULT_POLICY_EXPR: dict[str, Any] = {"op": "always_true"}

_SELECT_SQL = text(
    """
    SELECT id, name, rule_expression
      FROM hitl_policies
     WHERE enabled = TRUE
       AND (tenant_id IS NULL OR tenant_id = :tid)
     ORDER BY priority ASC, tenant_id NULLS LAST
     LIMIT 1
    """
)


def select_active_policy(
    conn: Connection, tenant_id: UUID
) -> tuple[UUID | None, str, dict[str, Any]]:
    """Return (policy_id, policy_name, rule_expression) for highest-priority
    enabled policy. Tenant-specific rules win over globals at the same priority
    (NULLS LAST). When no rule is enabled, returns the default-require-approval
    fall-through.
    """
    row = conn.execute(_SELECT_SQL, {"tid": str(tenant_id)}).first()
    if row is None:
        return None, _DEFAULT_POLICY_NAME, dict(_DEFAULT_POLICY_EXPR)
    policy_id_raw, name, expression = row
    policy_id = UUID(str(policy_id_raw)) if policy_id_raw else None
    if not isinstance(expression, dict):
        # Defensive: a malformed JSONB row shouldn't auto-approve everyone.
        return policy_id, str(name), dict(_DEFAULT_POLICY_EXPR)
    return policy_id, str(name), expression


__all__ = [
    "evaluate_policy",
    "select_active_policy",
]
