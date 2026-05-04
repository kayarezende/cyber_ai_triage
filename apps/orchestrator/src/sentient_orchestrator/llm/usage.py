"""`usage` table INSERT helper + per-investigation accumulator.

Per ADR-0015, every LLM attempt — success or failure — writes one row.
Caller is the LLMRouter; it wraps the call in the same `tenant_session`
that owns the surrounding investigation transaction so RLS holds + the
audit trail is atomic with the investigation row.

Wk-7: `update_investigation_totals` mirrors each successful attempt's
counters onto the `investigations` row so the per-investigation cost-cap
gate inside `LLMRouter.call()` can read a single row instead of SUM-ing
the whole `usage` table on every call.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

UsageStatus = Literal[
    "success",
    "timeout",
    "5xx",
    "validation_fail",
    "rate_limited",
]


def log_usage_attempt(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID | None,
    role: str,
    attempt_num: int,
    model_requested: str,
    model_used: str | None,
    status: UsageStatus,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cached_tokens: int | None = None,
    cost_usd: Decimal | None = None,
    openrouter_generation_id: str | None = None,
    latency_ms: int | None = None,
    retry_seq: int = 0,
) -> None:
    """INSERT one row into `usage`. RLS scoped via the caller's tenant_session.

    ``retry_seq`` (cluster C / CRIT-5) — 0 = primary HTTP call, 1 = first
    schema-retry within the same ``attempt_num``. Composite identity
    ``(investigation_id, attempt_num, retry_seq)`` distinguishes the retry
    sub-event per ADR-0015 §"Retry semantics".
    """
    conn.execute(
        text("""
            INSERT INTO usage
                (tenant_id, investigation_id, role, attempt_num,
                 model_requested, model_used, status,
                 input_tokens, output_tokens, cached_tokens,
                 cost_usd, openrouter_generation_id, latency_ms,
                 retry_seq)
            VALUES
                (:tenant_id, :investigation_id, :role, :attempt_num,
                 :model_requested, :model_used, :status,
                 :input_tokens, :output_tokens, :cached_tokens,
                 :cost_usd, :openrouter_generation_id, :latency_ms,
                 :retry_seq)
            """),
        {
            "tenant_id": str(tenant_id),
            "investigation_id": str(investigation_id) if investigation_id else None,
            "role": role,
            "attempt_num": attempt_num,
            "model_requested": model_requested,
            "model_used": model_used,
            "status": status,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "cost_usd": cost_usd,
            "openrouter_generation_id": openrouter_generation_id,
            "latency_ms": latency_ms,
            "retry_seq": retry_seq,
        },
    )


def update_investigation_totals(
    conn: Connection,
    *,
    investigation_id: UUID,
    input_tokens: int | None,
    output_tokens: int | None,
    cost_usd: Decimal | None,
) -> None:
    """Atomically increment per-investigation cost + token totals.

    Called from `LLMRouter._attempt` after each `log_usage_attempt` (success
    AND failures-with-response per wk-7 round-2 R-2 fix).

    `COALESCE(:val, 0)` handles NULL — OpenRouter omits `usage.cost` for some
    providers + may report missing tokens. `GREATEST(:val, 0)` clamps any
    negative value (Byzantine response from a compromised proxy / malformed
    JSON / future bug) to zero so the running total can never be DECREMENTED
    out from under the cap gate. See round-2 review fix R-3.
    """
    conn.execute(
        text("""
            UPDATE investigations
               SET total_input_tokens  = total_input_tokens
                                       + COALESCE(GREATEST(:in_tok, 0), 0),
                   total_output_tokens = total_output_tokens
                                       + COALESCE(GREATEST(:out_tok, 0), 0),
                   total_cost_usd      = total_cost_usd
                                       + COALESCE(GREATEST(:cost, 0), 0)
             WHERE id = :id
            """),
        {
            "id": str(investigation_id),
            "in_tok": input_tokens,
            "out_tok": output_tokens,
            "cost": cost_usd,
        },
    )


__all__ = ["UsageStatus", "log_usage_attempt", "update_investigation_totals"]
