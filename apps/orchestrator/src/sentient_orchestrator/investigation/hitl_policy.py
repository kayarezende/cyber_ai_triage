"""Wk-8 HITL policy: tenant policy selection + evaluator re-export.

The pure evaluator (`evaluate_policy`) lives in `sentient_common.hitl` so
the API admin panel can validate rule expressions on save without pulling
LangGraph/LangChain through the orchestrator. Wk-10 move; behaviour
unchanged.

`select_active_policy` returns the highest-priority enabled policy visible to
the tenant; on no rows returns the default `always_true` policy.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.hitl import evaluate_policy

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
