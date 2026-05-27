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
from pydantic import BaseModel, ConfigDict, Field, field_validator
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

# --- Provider/capability validation -----------------------------------------
# Mirrors `sentient_orchestrator.llm.catalog` (kept minimal + duplicated so the
# API need not import the orchestrator). A model ref is `provider:model`; a bare
# slug means OpenRouter. Roles in STRUCTURED_ROLES require a model that can
# produce schema-conforming JSON — the orchestrator depends on it.
_ALLOWED_PROVIDERS: frozenset[str] = frozenset(
    {"openrouter", "groq", "gemini", "anthropic"}
)
STRUCTURED_ROLES: frozenset[str] = frozenset({"triage", "investigation", "review"})
def _parse_provider(model_ref: str) -> tuple[str, str]:
    head, sep, tail = model_ref.partition(":")
    if sep and head in _ALLOWED_PROVIDERS:
        return head, tail
    return "openrouter", model_ref


def _validate_provider_prefix(model_ref: str) -> str:
    """Reject an explicit-but-unknown provider prefix (e.g. `grok:`).

    A `/` in the head (OpenRouter org slugs like `anthropic/claude-...`) is not
    a provider prefix and is left alone.
    """
    head, sep, _tail = model_ref.partition(":")
    if sep and head not in _ALLOWED_PROVIDERS and "/" not in head:
        raise ValueError(
            f"unknown LLM provider prefix {head!r}; "
            f"allowed: {sorted(_ALLOWED_PROVIDERS)}"
        )
    return model_ref


def _can_produce_structured(model_ref: str) -> bool:
    """Whether the resolved model can emit JSON for a structured role.

    Only providers whose structured-output capability is `none` are rejected.
    Today that's Anthropic-direct (its OpenAI-compat endpoint ignores
    `response_format`). Groq `json_object` models are accepted — the router's
    schema-injection + validate-and-retry path handles them.
    """
    provider, _model = _parse_provider(model_ref)
    return provider != "anthropic"


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

    @field_validator("primary_model")
    @classmethod
    def _check_primary_prefix(cls, v: str) -> str:
        return _validate_provider_prefix(v)

    @field_validator("fallback_chain")
    @classmethod
    def _check_fallback_prefixes(cls, v: list[str]) -> list[str]:
        for entry in v:
            _validate_provider_prefix(entry)
        return v


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
    # Capability guard: structured roles need a model that can emit JSON.
    # Checked here (not in the schema) because it depends on the path `role`.
    if role in STRUCTURED_ROLES:
        for model_ref in (body.primary_model, *body.fallback_chain):
            if not _can_produce_structured(model_ref):
                provider, _ = _parse_provider(model_ref)
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "model_cannot_produce_structured_output",
                        "message": (
                            f"Provider {provider!r} (model {model_ref!r}) cannot "
                            f"produce structured JSON, which role {role!r} "
                            "requires. Route this model through OpenRouter, or "
                            "pick a structured-capable provider/model."
                        ),
                    },
                )
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
