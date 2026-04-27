"""Admin: Splunk connection config.

GET returns host + writeback_mode + flags showing whether each token is
populated; never returns the plaintext (or ciphertext) token.

PUT runs a probe against `https://{host}:8089/services/server/info` with
the new management token before persisting. A typo or revoked token gets
caught at save time, not at the next ingest webhook. When `splunk_token`
is omitted, the existing token stays in place — supports updating just the
host or writeback_mode without re-supplying secrets.

Token storage: Fernet via `sentient_common.crypto.encrypt` (ADR-0012).
HEC token has no probe (HEC `/services/collector/health` is unauth, so a
200 doesn't prove the token is valid — the first real writeback attempt
is the validation).
"""

from __future__ import annotations

from typing import Literal

import httpx
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

WritebackMode = Literal["dual", "hec_only"]

DEFAULT_MGMT_PORT = 8089
PROBE_TIMEOUT_SECONDS = 5.0


class SplunkConfig(BaseModel):
    splunk_host: str | None
    writeback_mode: WritebackMode
    has_management_token: bool
    has_hec_token: bool

    model_config = ConfigDict(extra="forbid")


class SplunkConfigUpdate(BaseModel):
    splunk_host: str = Field(min_length=1, max_length=512)
    writeback_mode: WritebackMode = "hec_only"
    splunk_token: str | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description=(
            "Splunk management token. When omitted, the existing token is "
            "preserved and the probe runs against it."
        ),
    )
    splunk_hec_token: str | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description="HEC token. When omitted, the existing HEC token is preserved.",
    )
    skip_probe: bool = Field(
        default=False,
        description=(
            "Bypass the connection probe. Useful when the founder box is "
            "offline at config-edit time. Off by default."
        ),
    )

    model_config = ConfigDict(extra="forbid")


@router.get("/splunk", response_model=SplunkConfig)
def get_splunk_config(
    tenant_id: TenantId,
    _admin: RequireAdmin,
) -> SplunkConfig:
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                SELECT splunk_host, writeback_mode,
                       splunk_token_encrypted IS NOT NULL,
                       splunk_hec_token_encrypted IS NOT NULL
                  FROM tenants
                 WHERE id = :tenant_id
                """
            ),
            {"tenant_id": str(tenant_id)},
        ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    return SplunkConfig(
        splunk_host=row[0],
        writeback_mode=row[1] or "hec_only",
        has_management_token=bool(row[2]),
        has_hec_token=bool(row[3]),
    )


@router.put("/splunk", response_model=SplunkConfig)
def update_splunk_config(
    body: SplunkConfigUpdate,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> SplunkConfig:
    if not body.skip_probe:
        if body.splunk_token is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "probe_requires_token",
                    "message": (
                        "Set `skip_probe=true` to update host without re-"
                        "supplying the management token, or include "
                        "`splunk_token` so the probe can run."
                    ),
                },
            )
        _probe_or_400(body.splunk_host, body.splunk_token)

    encrypted_token = encrypt(body.splunk_token) if body.splunk_token else None
    encrypted_hec = encrypt(body.splunk_hec_token) if body.splunk_hec_token else None

    # COALESCE keeps the existing ciphertext when the admin did not supply
    # a fresh secret; supplying a value rotates it. NULL is reserved for
    # "tenant has no token configured" rather than "preserve current".
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                UPDATE tenants
                   SET splunk_host = :host,
                       writeback_mode = :writeback_mode,
                       splunk_token_encrypted = COALESCE(
                         :token_new, splunk_token_encrypted
                       ),
                       splunk_hec_token_encrypted = COALESCE(
                         :hec_new, splunk_hec_token_encrypted
                       )
                 WHERE id = :tenant_id
                RETURNING splunk_host, writeback_mode,
                          splunk_token_encrypted IS NOT NULL,
                          splunk_hec_token_encrypted IS NOT NULL
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "host": body.splunk_host,
                "writeback_mode": body.writeback_mode,
                "token_new": encrypted_token,
                "hec_new": encrypted_hec,
            },
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_splunk_config_updated",
            details={
                "splunk_host": body.splunk_host,
                "writeback_mode": body.writeback_mode,
                "token_rotated": body.splunk_token is not None,
                "hec_rotated": body.splunk_hec_token is not None,
                "probe_skipped": body.skip_probe,
            },
        )

    return SplunkConfig(
        splunk_host=row[0],
        writeback_mode=row[1] or "hec_only",
        has_management_token=bool(row[2]),
        has_hec_token=bool(row[3]),
    )


def _probe_or_400(host: str, token: str) -> None:
    """Hit `/services/server/info` to verify host reachable + token valid.

    Returns silently on success. On any failure raises a 400 with the
    underlying transport error message so the operator gets a single
    actionable response (`connection refused`, `401 invalid token`, etc.)
    rather than a deferred runtime surprise.
    """
    url = f"https://{host}:{DEFAULT_MGMT_PORT}/services/server/info?output_mode=json"
    try:
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=PROBE_TIMEOUT_SECONDS,
            verify=False,  # noqa: S501 — founder box uses self-signed by default
        )
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "probe_timeout", "message": str(exc)},
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "probe_failed", "message": str(exc)},
        ) from exc
    if resp.status_code == 401:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "probe_unauthorized",
                "message": "Splunk management token rejected (401).",
            },
        )
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "probe_http_error",
                "message": f"Splunk returned {resp.status_code}.",
            },
        )


__all__ = ["SplunkConfig", "SplunkConfigUpdate", "router"]
