"""Admin: per-role LLM config (`llm_role_config`).

Surfaces exactly the six fields the runtime honours
(`apps/orchestrator/src/sentient_orchestrator/llm/router.py:_RoleConfig`):
`primary_model`, `fallback_chain`, `max_tokens`, `temperature`,
`timeout_seconds`, `enabled`. Adding more here without a runtime change
gives the false impression they're configurable; surfacing fewer leaves
operators unable to tune the chain.

Only the five `ACTIVE_ROLES` from the LLMRouter are accepted on PUT.
Disabled roles (`summarize`, `entity_extraction`) are seeded but excluded
from MVP write paths to prevent accidentally enabling them.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from sentient_api.deps import RequireAdmin, TenantId
from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session
from sentient_common.logging import get_logger

router = APIRouter(prefix="/api/admin", tags=["admin"])
log = get_logger(__name__)


# Keep in sync with `sentient_orchestrator.llm.router.ACTIVE_ROLES` —
# duplicating the literal here so the API doesn't import the orchestrator.
LlmRole = Literal["triage", "investigation", "review", "summarize", "entity_extraction"]


class LlmRoleConfig(BaseModel):
    role: LlmRole
    primary_model: str = Field(min_length=1, max_length=200)
    fallback_chain: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=10
    )
    max_tokens: int = Field(ge=1, le=200_000)
    temperature: float = Field(ge=0.0, le=2.0)
    timeout_seconds: int = Field(ge=1, le=600)
    enabled: bool

    model_config = ConfigDict(extra="forbid")


class LlmRoleListResponse(BaseModel):
    items: list[LlmRoleConfig]


class LlmRoleUpdate(BaseModel):
    primary_model: str = Field(min_length=1, max_length=200)
    fallback_chain: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=10
    )
    max_tokens: int = Field(ge=1, le=200_000)
    temperature: float = Field(ge=0.0, le=2.0)
    timeout_seconds: int = Field(ge=1, le=600)
    enabled: bool

    model_config = ConfigDict(extra="forbid")


@router.get("/llm-roles", response_model=LlmRoleListResponse)
def list_llm_roles(
    tenant_id: TenantId,
    _admin: RequireAdmin,
) -> LlmRoleListResponse:
    with tenant_session(tenant_id) as conn:
        rows = conn.execute(
            text(
                """
                SELECT role, primary_model, fallback_chain,
                       max_tokens, temperature, timeout_seconds, enabled
                  FROM llm_role_config
                 ORDER BY role
                """
            )
        ).all()
    return LlmRoleListResponse(
        items=[
            LlmRoleConfig(
                role=row[0],
                primary_model=row[1],
                fallback_chain=list(row[2] or []),
                max_tokens=int(row[3]),
                temperature=float(_decimal_to_float(row[4])),
                timeout_seconds=int(row[5]),
                enabled=bool(row[6]),
            )
            for row in rows
        ]
    )


@router.put("/llm-roles/{role}", response_model=LlmRoleConfig)
def update_llm_role(
    role: LlmRole,
    body: LlmRoleUpdate,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> LlmRoleConfig:
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                UPDATE llm_role_config
                   SET primary_model     = :primary_model,
                       fallback_chain    = CAST(:fallback_chain AS TEXT[]),
                       max_tokens        = :max_tokens,
                       temperature       = :temperature,
                       timeout_seconds   = :timeout_seconds,
                       enabled           = :enabled
                 WHERE tenant_id = :tenant_id AND role = :role
                RETURNING role, primary_model, fallback_chain,
                          max_tokens, temperature, timeout_seconds, enabled
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "role": role,
                "primary_model": body.primary_model,
                "fallback_chain": "{" + ",".join(body.fallback_chain) + "}",
                "max_tokens": body.max_tokens,
                "temperature": body.temperature,
                "timeout_seconds": body.timeout_seconds,
                "enabled": body.enabled,
            },
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="llm_role_not_found")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_llm_role_updated",
            details={
                "role": role,
                "primary_model": body.primary_model,
                "fallback_chain": list(body.fallback_chain),
                "enabled": body.enabled,
            },
        )

    return LlmRoleConfig(
        role=row[0],
        primary_model=row[1],
        fallback_chain=list(row[2] or []),
        max_tokens=int(row[3]),
        temperature=float(_decimal_to_float(row[4])),
        timeout_seconds=int(row[5]),
        enabled=bool(row[6]),
    )


def _decimal_to_float(value: object) -> float:
    if isinstance(value, Decimal):
        return float(value)
    return float(value)  # type: ignore[arg-type]


__all__ = ["LlmRoleConfig", "LlmRoleUpdate", "router"]
