"""Admin: per-tenant LLM + concurrency budgets.

Four scalars on `tenants`:
  - `max_concurrent_investigations`  (Tier-2 dispatch fan-out cap)
  - `monthly_llm_budget_usd`         (soft limit, dashboard signal)
  - `per_investigation_budget_usd`   (hard cap; LLMRouter enforces, see ADR-0015)
  - `per_investigation_token_cap`    (companion token cap; ADR-0019 / wk-7)

The runtime checks both per-investigation caps inside `LLMRouter._check_budget`
on every call. Setting either to NULL disables that gate; the admin UI
should make the disable affordance explicit (empty input, not "0").
"""

from __future__ import annotations

from decimal import Decimal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from sentient_api.deps import RequireAdmin, TenantId
from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session

router = APIRouter(prefix="/api/admin", tags=["admin"])


class TenantBudgets(BaseModel):
    max_concurrent_investigations: int | None
    monthly_llm_budget_usd: float | None
    per_investigation_budget_usd: float | None
    per_investigation_token_cap: int | None

    model_config = ConfigDict(extra="forbid")


class TenantBudgetsUpdate(BaseModel):
    max_concurrent_investigations: int | None = Field(default=None, ge=1, le=1000)
    monthly_llm_budget_usd: float | None = Field(default=None, ge=0.0)
    per_investigation_budget_usd: float | None = Field(default=None, ge=0.0)
    per_investigation_token_cap: int | None = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid")


@router.get("/budgets", response_model=TenantBudgets)
def get_budgets(
    tenant_id: TenantId,
    _admin: RequireAdmin,
) -> TenantBudgets:
    with tenant_session(tenant_id) as conn:
        # tenants table doesn't have RLS (it's the source of tenancy). Filter
        # explicitly by tenant_id so multi-tenant deployments still scope.
        row = conn.execute(
            text(
                """
                SELECT max_concurrent_investigations,
                       monthly_llm_budget_usd,
                       per_investigation_budget_usd,
                       per_investigation_token_cap
                  FROM tenants
                 WHERE id = :tenant_id
                """
            ),
            {"tenant_id": str(tenant_id)},
        ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    return TenantBudgets(
        max_concurrent_investigations=int(row[0]) if row[0] is not None else None,
        monthly_llm_budget_usd=_to_float(row[1]),
        per_investigation_budget_usd=_to_float(row[2]),
        per_investigation_token_cap=int(row[3]) if row[3] is not None else None,
    )


@router.put("/budgets", response_model=TenantBudgets)
def update_budgets(
    body: TenantBudgetsUpdate,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> TenantBudgets:
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                UPDATE tenants
                   SET max_concurrent_investigations = :max_concurrent,
                       monthly_llm_budget_usd = :monthly_budget,
                       per_investigation_budget_usd = :per_inv_budget,
                       per_investigation_token_cap = :per_inv_token_cap
                 WHERE id = :tenant_id
                RETURNING max_concurrent_investigations,
                          monthly_llm_budget_usd,
                          per_investigation_budget_usd,
                          per_investigation_token_cap
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "max_concurrent": body.max_concurrent_investigations,
                "monthly_budget": body.monthly_llm_budget_usd,
                "per_inv_budget": body.per_investigation_budget_usd,
                "per_inv_token_cap": body.per_investigation_token_cap,
            },
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_budgets_updated",
            details={
                "max_concurrent_investigations": body.max_concurrent_investigations,
                "monthly_llm_budget_usd": body.monthly_llm_budget_usd,
                "per_investigation_budget_usd": body.per_investigation_budget_usd,
                "per_investigation_token_cap": body.per_investigation_token_cap,
            },
        )
    return TenantBudgets(
        max_concurrent_investigations=int(row[0]) if row[0] is not None else None,
        monthly_llm_budget_usd=_to_float(row[1]),
        per_investigation_budget_usd=_to_float(row[2]),
        per_investigation_token_cap=int(row[3]) if row[3] is not None else None,
    )


def _to_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    return float(value)  # type: ignore[arg-type]


__all__ = ["TenantBudgets", "TenantBudgetsUpdate", "router"]
