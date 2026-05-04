"""HITL policy expression evaluator (pure, no IO).

Lives in `libs/common` so both the orchestrator (runtime) and the API
(admin-panel validation on save) can use it without the API pulling in
LangGraph/LangChain via the orchestrator package. ADR-0009 + wk-8 details
are in `apps/orchestrator/src/sentient_orchestrator/investigation/hitl_policy.py`,
which re-exports `evaluate_policy` for existing callers.

Operators:

    Logical: and, or, not, always_true, always_false
    Leaf:    eq, gt, lt, gte, lte, in, contains
             severity_gt, severity_lt, severity_gte, severity_lte

Leaf operators read `expr["field"]` from the `ctx` dict. Missing keys
short-circuit to `False` (never raise) — this lets policies probe optional
fields like `review_status` without forcing every investigation to populate
them.

Severity is RANKED, not numeric: the natural-language ladder
`info < low < medium < high < critical` doesn't compare correctly via
generic `gt/lt/gte/lte` (a string compare gives `'high' < 'low'`). Use the
domain-aware `severity_*` ops instead. `validate_policy_shape` rejects
generic numeric compares against `field == 'severity'` at save time.
"""

from __future__ import annotations

from typing import Any

_LOGICAL_OPS: frozenset[str] = frozenset({"and", "or", "not", "always_true", "always_false"})
_LEAF_OPS: frozenset[str] = frozenset(
    {
        "eq",
        "gt",
        "lt",
        "gte",
        "lte",
        "in",
        "contains",
        "severity_gt",
        "severity_lt",
        "severity_gte",
        "severity_lte",
    }
)
_SEVERITY_OPS: frozenset[str] = frozenset(
    {"severity_gt", "severity_lt", "severity_gte", "severity_lte"}
)
_GENERIC_NUMERIC_OPS: frozenset[str] = frozenset({"gt", "lt", "gte", "lte"})

#: Hard ceiling on rule-tree nesting depth. Stops a malicious / runaway policy
#: from blowing the stack. 16 levels is generous — real policies are 2-4 deep.
_MAX_DEPTH = 16

#: Severity ladder. Splunk severity_id (info=1..critical=5) and OCSF severity_id
#: (informational=1..fatal=6) both preserve this ordering. Lowercase keys —
#: callers must lower-case before lookup (`_to_severity_rank` does it).
SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


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


def _to_severity_rank(value: Any) -> int:
    """Map a severity name to its rank. Raises ValueError on unknown."""
    if isinstance(value, bool):
        msg = "boolean operand not allowed for severity compare"
        raise ValueError(msg)
    if not isinstance(value, str):
        msg = f"severity operand must be a string, got {type(value).__name__}"
        raise ValueError(msg)
    rank = SEVERITY_RANK.get(value.lower())
    if rank is None:
        msg = f"unknown severity {value!r}"
        raise ValueError(msg)
    return rank


def evaluate_policy(expr: dict[str, Any], ctx: dict[str, Any], *, depth: int = 0) -> bool:
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
        return all(evaluate_policy(c, ctx, depth=depth + 1) for c in conditions)
    if op == "or":
        conditions = expr.get("conditions") or []
        return any(evaluate_policy(c, ctx, depth=depth + 1) for c in conditions)
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
        if op in _GENERIC_NUMERIC_OPS:
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
        if op in _SEVERITY_OPS:
            # Unknown severity raises ValueError → propagates to caller fallback
            # (HIGH-4: runtime callsite catches and falls back to needs_human).
            a_rank = _to_severity_rank(actual)
            b_rank = _to_severity_rank(value)
            if op == "severity_gt":
                return a_rank > b_rank
            if op == "severity_lt":
                return a_rank < b_rank
            if op == "severity_gte":
                return a_rank >= b_rank
            if op == "severity_lte":
                return a_rank <= b_rank
        if op == "in":
            return actual in (value or [])
        if op == "contains":
            if isinstance(actual, (list, tuple, set, str)):
                return value in actual
            return False
    msg = f"unknown op: {op!r}"
    raise ValueError(msg)


#: Synthetic ctx with every leaf field a real-world policy could probe. Walked
#: by `validate_policy_shape` so leaf ops don't short-circuit to False on
#: missing-key — that short-circuit hides bugs like an unknown severity name
#: passed as `value`. A populated ctx forces every leaf to evaluate.
_VALIDATION_CTX: dict[str, Any] = {
    "severity": "critical",
    "confidence": 50,
    "verdict": "true_positive",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "mitre_techniques": ["T1059"],
    "review_status": "approved",
    "writeback_mode": "dual",
    "approval_status": "auto",
}


def _walk_for_severity_misuse(expr: Any, depth: int = 0) -> None:
    """Recursively scan for `gt/lt/gte/lte` against `field == 'severity'`.

    Generic numeric compares CAN'T rank severity strings — `'high' >= 'critical'`
    is True alphabetically, which silently lets a "critical only" gate
    auto-approve high-severity. Reject at save time with a helpful pointer.
    """
    if depth > _MAX_DEPTH:
        msg = f"policy depth exceeded ({_MAX_DEPTH})"
        raise ValueError(msg)
    if not isinstance(expr, dict):
        return
    op = expr.get("op")
    if op in _GENERIC_NUMERIC_OPS and expr.get("field") == "severity":
        msg = (
            f"op {op!r} cannot compare severity strings — use "
            "severity_gt/severity_lt/severity_gte/severity_lte against "
            "field='severity'. Generic numeric compares give incorrect "
            "alphabetic ordering on severity names."
        )
        raise ValueError(msg)
    for child in expr.get("conditions") or []:
        _walk_for_severity_misuse(child, depth=depth + 1)
    inner = expr.get("condition")
    if inner is not None:
        _walk_for_severity_misuse(inner, depth=depth + 1)


def validate_policy_shape(expr: dict[str, Any]) -> None:
    """Confirm a policy expression parses without runtime errors.

    Two passes:
      1. Veto generic numeric compares against `field == 'severity'` — they
         silently produce alphabetic ordering, never severity ordering.
      2. Walk with a fully-populated synthetic ctx so leaf ops actually
         evaluate (and surface ValueError on bad shape) rather than
         short-circuiting on missing keys.

    Returns on success; raises `ValueError` on malformed input. Use from
    admin-panel save handlers.
    """
    _walk_for_severity_misuse(expr)
    evaluate_policy(expr, ctx=dict(_VALIDATION_CTX))


__all__ = [
    "SEVERITY_RANK",
    "evaluate_policy",
    "validate_policy_shape",
]
