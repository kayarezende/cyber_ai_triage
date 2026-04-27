"""Admin: per-tenant LLM usage aggregates.

Read-only roll-up over the `usage` table — every LLM call is logged there
by `LLMRouter._log_failure`/`log_usage_attempt` (ADR-0015 audit ledger).
Admin sees: tokens + cost + attempt counts grouped by month/role/model,
plus a status breakdown (success / timeout / 5xx / validation_fail /
rate_limited) so blowback patterns surface (e.g. one model 5xx-ing
chronically while another succeeds).

No charts on the wire — that's a frontend choice; the API ships rows.
The cap-versus-spend signal lives next to the budget config so admins
adjusting `monthly_llm_budget_usd` see the trailing month inline.

Slipped from wk-10 to wk-11 by user pre-auth so the wk-10 calendar
could focus on the five config surfaces.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from sentient_api.deps import RequireAdmin, TenantId
from sentient_common.db import tenant_session

router = APIRouter(prefix="/api/admin", tags=["admin"])


class UsageRow(BaseModel):
    month: str = Field(description="ISO-8601 month bucket (`YYYY-MM-01`).")
    role: str
    model_requested: str
    attempts: int
    successes: int
    failures: int
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost_usd: float

    model_config = ConfigDict(extra="forbid")


class UsageStatusBreakdown(BaseModel):
    status: str
    count: int

    model_config = ConfigDict(extra="forbid")


class UsageSummary(BaseModel):
    months_back: int
    total_attempts: int
    total_successes: int
    total_input_tokens: int
    total_output_tokens: int
    total_cached_tokens: int
    total_cost_usd: float
    rows: list[UsageRow]
    by_status: list[UsageStatusBreakdown]

    model_config = ConfigDict(extra="forbid")


@router.get("/usage", response_model=UsageSummary)
def get_usage(
    tenant_id: TenantId,
    _admin: RequireAdmin,
    months_back: Annotated[int, Query(ge=1, le=24)] = 3,
) -> UsageSummary:
    """Return monthly usage aggregates + status breakdown for the tenant.

    `months_back` defaults to 3 (the trailing-quarter view); cap is 24
    to keep the rollup query bounded — usage rolls into a separate
    long-term archive post-MVP.
    """
    with tenant_session(tenant_id) as conn:
        rows = conn.execute(
            text(
                """
                SELECT to_char(date_trunc('month', created_at), 'YYYY-MM-01') AS month,
                       role,
                       COALESCE(model_requested, '<unknown>') AS model_requested,
                       COUNT(*)::int AS attempts,
                       COUNT(*) FILTER (WHERE status = 'success')::int AS successes,
                       COUNT(*) FILTER (WHERE status <> 'success')::int AS failures,
                       COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
                       COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
                       COALESCE(SUM(cached_tokens), 0)::bigint AS cached_tokens,
                       COALESCE(SUM(cost_usd), 0)::numeric AS cost_usd
                  FROM usage
                 WHERE created_at >= date_trunc('month', NOW())
                                     - (:months_back || ' months')::interval
                 GROUP BY 1, 2, 3
                 ORDER BY 1 DESC, 2, 3
                """
            ),
            {"months_back": months_back},
        ).all()

        status_rows = conn.execute(
            text(
                """
                SELECT status, COUNT(*)::int AS count
                  FROM usage
                 WHERE created_at >= date_trunc('month', NOW())
                                     - (:months_back || ' months')::interval
                 GROUP BY status
                 ORDER BY count DESC
                """
            ),
            {"months_back": months_back},
        ).all()

    items = [
        UsageRow(
            month=row[0],
            role=row[1],
            model_requested=row[2],
            attempts=int(row[3]),
            successes=int(row[4]),
            failures=int(row[5]),
            input_tokens=int(row[6]),
            output_tokens=int(row[7]),
            cached_tokens=int(row[8]),
            cost_usd=_to_float(row[9]),
        )
        for row in rows
    ]
    by_status = [
        UsageStatusBreakdown(status=row[0] or "unknown", count=int(row[1]))
        for row in status_rows
    ]

    return UsageSummary(
        months_back=months_back,
        total_attempts=sum(r.attempts for r in items),
        total_successes=sum(r.successes for r in items),
        total_input_tokens=sum(r.input_tokens for r in items),
        total_output_tokens=sum(r.output_tokens for r in items),
        total_cached_tokens=sum(r.cached_tokens for r in items),
        total_cost_usd=sum(r.cost_usd for r in items),
        rows=items,
        by_status=by_status,
    )


def _to_float(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, Decimal):
        return float(value)
    return float(value)  # type: ignore[arg-type]


__all__ = ["UsageRow", "UsageStatusBreakdown", "UsageSummary", "router"]
