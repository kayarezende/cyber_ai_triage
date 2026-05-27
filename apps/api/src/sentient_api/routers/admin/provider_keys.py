"""Admin: per-provider LLM API keys (`provider_credentials`).

Keys are stored Fernet-encrypted (`sentient_common.crypto.encrypt`, ADR-0012)
and are **write-only** over the API: GET returns only whether a key is set plus
a non-sensitive last-4 hint — never the plaintext or ciphertext. PUT encrypts
and upserts; DELETE removes. Every mutation is audited.

This replaces putting Groq/Gemini/Anthropic keys in `.env`. The orchestrator's
LLMRouter reads these rows at call time (decrypting in memory) for whichever
provider a role's model resolves to.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from sentient_api.deps import RequireAdmin, TenantId
from sentient_common.audit import insert_audit_log
from sentient_common.crypto import encrypt
from sentient_common.db import tenant_session
from sentient_common.logging import get_logger

router = APIRouter(prefix="/api/admin", tags=["admin"])
log = get_logger(__name__)

# Keep in sync with `sentient_orchestrator.llm.catalog.ALLOWED_PROVIDERS` —
# duplicated here so the API does not import the orchestrator (mirrors the
# `LlmRole` duplication in llm_roles.py).
Provider = Literal["openrouter", "groq", "gemini", "anthropic"]
_PROVIDERS: tuple[str, ...] = ("openrouter", "groq", "gemini", "anthropic")


class ProviderKeyStatus(BaseModel):
    provider: Provider
    is_set: bool
    key_last4: str | None
    updated_at: str | None

    model_config = ConfigDict(extra="forbid")


class ProviderKeyListResponse(BaseModel):
    items: list[ProviderKeyStatus]


class ProviderKeyUpdate(BaseModel):
    api_key: str = Field(min_length=8, max_length=4096)

    model_config = ConfigDict(extra="forbid")


@router.get("/provider-keys", response_model=ProviderKeyListResponse)
def list_provider_keys(
    tenant_id: TenantId,
    _admin: RequireAdmin,
) -> ProviderKeyListResponse:
    with tenant_session(tenant_id) as conn:
        rows = conn.execute(
            text(
                """
                SELECT provider, key_last4, updated_at
                  FROM provider_credentials
                """
            )
        ).all()
    by_provider = {row[0]: (row[1], row[2]) for row in rows}
    items = [
        ProviderKeyStatus(
            provider=provider,  # type: ignore[arg-type]
            is_set=provider in by_provider,
            key_last4=by_provider.get(provider, (None, None))[0],
            updated_at=(
                by_provider[provider][1].isoformat()
                if provider in by_provider and by_provider[provider][1] is not None
                else None
            ),
        )
        for provider in _PROVIDERS
    ]
    return ProviderKeyListResponse(items=items)


@router.put("/provider-keys/{provider}", response_model=ProviderKeyStatus)
def set_provider_key(
    provider: Provider,
    body: ProviderKeyUpdate,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> ProviderKeyStatus:
    api_key = body.api_key.strip()
    if not api_key:
        raise HTTPException(status_code=422, detail="api_key_empty")
    last4 = api_key[-4:]
    encrypted = encrypt(api_key)

    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO provider_credentials
                    (tenant_id, provider, key_encrypted, key_last4, updated_at)
                VALUES (:tenant_id, :provider, :key_encrypted, :key_last4, NOW())
                ON CONFLICT (tenant_id, provider) DO UPDATE
                    SET key_encrypted = EXCLUDED.key_encrypted,
                        key_last4     = EXCLUDED.key_last4,
                        updated_at    = NOW()
                RETURNING key_last4, updated_at
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "provider": provider,
                "key_encrypted": encrypted,
                "key_last4": last4,
            },
        ).first()
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_provider_key_set",
            # Never log the key. last4 is a recognisability hint only.
            details={"provider": provider, "key_last4": last4},
        )

    return ProviderKeyStatus(
        provider=provider,
        is_set=True,
        key_last4=row[0] if row else last4,
        updated_at=row[1].isoformat() if row and row[1] is not None else None,
    )


@router.delete("/provider-keys/{provider}", status_code=204)
def delete_provider_key(
    provider: Provider,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> None:
    with tenant_session(tenant_id) as conn:
        result = conn.execute(
            text(
                """
                DELETE FROM provider_credentials
                 WHERE tenant_id = :tenant_id AND provider = :provider
                """
            ),
            {"tenant_id": str(tenant_id), "provider": provider},
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="provider_key_not_found")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_provider_key_deleted",
            details={"provider": provider},
        )


__all__ = ["ProviderKeyListResponse", "ProviderKeyStatus", "ProviderKeyUpdate", "router"]
