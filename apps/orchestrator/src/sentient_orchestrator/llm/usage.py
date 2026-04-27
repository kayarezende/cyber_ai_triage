"""`usage` table INSERT helper.

Per ADR-0015, every LLM attempt — success or failure — writes one row.
Caller is the LLMRouter; it wraps the call in the same `tenant_session`
that owns the surrounding investigation transaction so RLS holds + the
audit trail is atomic with the investigation row.
"""

from __future__ import annotations

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
    cost_usd: float | None = None,
    openrouter_generation_id: str | None = None,
    latency_ms: int | None = None,
) -> None:
    """INSERT one row into `usage`. RLS scoped via the caller's tenant_session."""
    conn.execute(
        text(
            """
            INSERT INTO usage
                (tenant_id, investigation_id, role, attempt_num,
                 model_requested, model_used, status,
                 input_tokens, output_tokens, cached_tokens,
                 cost_usd, openrouter_generation_id, latency_ms)
            VALUES
                (:tenant_id, :investigation_id, :role, :attempt_num,
                 :model_requested, :model_used, :status,
                 :input_tokens, :output_tokens, :cached_tokens,
                 :cost_usd, :openrouter_generation_id, :latency_ms)
            """
        ),
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
        },
    )


__all__ = ["UsageStatus", "log_usage_attempt"]
