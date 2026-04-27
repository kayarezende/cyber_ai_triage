"""Admin: HITL policy CRUD.

`rule_expression` (JSONB) is validated via `sentient_common.hitl.validate_policy_shape`
before each write so an unparseable rule never reaches the runtime selector.
The default `{"op": "always_true"}` (require approval) is the fallback when
no policy matches; a malformed JSONB row used to be defensive-defaulted at
read time, but rejecting on write keeps the bug contained at its source.

Tenant scoping mirrors the rest of the API: rows live behind RLS, scope is
the requesting tenant. Globals (`tenant_id IS NULL`) are read-only here —
the seed-row platform policies are not editable from a tenant-admin
session.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from sentient_api.deps import RequireAdmin, TenantId
from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session
from sentient_common.hitl import validate_policy_shape
from sentient_common.logging import get_logger

router = APIRouter(prefix="/api/admin", tags=["admin"])
log = get_logger(__name__)


class HitlPolicy(BaseModel):
    id: UUID
    tenant_id: UUID | None
    name: str
    rule_expression: dict[str, Any]
    priority: int
    enabled: bool

    model_config = ConfigDict(extra="forbid")


class HitlPolicyListResponse(BaseModel):
    items: list[HitlPolicy]


class HitlPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    rule_expression: dict[str, Any]
    priority: int = Field(ge=1, le=10_000, default=100)
    enabled: bool = True

    model_config = ConfigDict(extra="forbid")


class HitlPolicyUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    rule_expression: dict[str, Any]
    priority: int = Field(ge=1, le=10_000)
    enabled: bool

    model_config = ConfigDict(extra="forbid")


def _validate_or_400(expr: dict[str, Any]) -> None:
    try:
        validate_policy_shape(expr)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_rule_expression", "message": str(exc)},
        ) from exc


@router.get("/hitl-policies", response_model=HitlPolicyListResponse)
def list_policies(
    tenant_id: TenantId,
    _admin: RequireAdmin,
) -> HitlPolicyListResponse:
    """Return tenant-scoped + global policies, ordered by priority asc."""
    with tenant_session(tenant_id) as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, tenant_id, name, rule_expression, priority, enabled
                  FROM hitl_policies
                 ORDER BY priority ASC, tenant_id NULLS LAST
                """
            )
        ).all()
    return HitlPolicyListResponse(
        items=[
            HitlPolicy(
                id=UUID(str(row[0])),
                tenant_id=UUID(str(row[1])) if row[1] else None,
                name=row[2],
                rule_expression=row[3] or {},
                priority=int(row[4]),
                enabled=bool(row[5]),
            )
            for row in rows
        ]
    )


@router.post("/hitl-policies", response_model=HitlPolicy, status_code=201)
def create_policy(
    body: HitlPolicyCreate,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> HitlPolicy:
    _validate_or_400(body.rule_expression)
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO hitl_policies (tenant_id, name, rule_expression, priority, enabled)
                VALUES (:tenant_id, :name, CAST(:expr AS jsonb), :priority, :enabled)
                RETURNING id, tenant_id, name, rule_expression, priority, enabled
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "name": body.name,
                "expr": _json_dump(body.rule_expression),
                "priority": body.priority,
                "enabled": body.enabled,
            },
        ).first()
        if row is None:
            raise HTTPException(status_code=500, detail="insert_returning_empty")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_hitl_policy_created",
            details={"policy_id": str(row[0]), "name": body.name},
        )
    return _row_to_policy(row)


@router.put("/hitl-policies/{policy_id}", response_model=HitlPolicy)
def update_policy(
    policy_id: UUID,
    body: HitlPolicyUpdate,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> HitlPolicy:
    _validate_or_400(body.rule_expression)
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                UPDATE hitl_policies
                   SET name = :name,
                       rule_expression = CAST(:expr AS jsonb),
                       priority = :priority,
                       enabled = :enabled
                 WHERE id = :id AND tenant_id = :tenant_id
                RETURNING id, tenant_id, name, rule_expression, priority, enabled
                """
            ),
            {
                "id": str(policy_id),
                "tenant_id": str(tenant_id),
                "name": body.name,
                "expr": _json_dump(body.rule_expression),
                "priority": body.priority,
                "enabled": body.enabled,
            },
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="hitl_policy_not_found")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_hitl_policy_updated",
            details={"policy_id": str(policy_id), "name": body.name},
        )
    return _row_to_policy(row)


@router.delete("/hitl-policies/{policy_id}", status_code=204)
def delete_policy(
    policy_id: UUID,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> None:
    with tenant_session(tenant_id) as conn:
        result = conn.execute(
            text(
                "DELETE FROM hitl_policies WHERE id = :id AND tenant_id = :tenant_id"
            ),
            {"id": str(policy_id), "tenant_id": str(tenant_id)},
        )
        if getattr(result, "rowcount", 0) == 0:
            raise HTTPException(status_code=404, detail="hitl_policy_not_found")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_hitl_policy_deleted",
            details={"policy_id": str(policy_id)},
        )


def _row_to_policy(row: Any) -> HitlPolicy:
    return HitlPolicy(
        id=UUID(str(row[0])),
        tenant_id=UUID(str(row[1])) if row[1] else None,
        name=row[2],
        rule_expression=row[3] or {},
        priority=int(row[4]),
        enabled=bool(row[5]),
    )


def _json_dump(value: dict[str, Any]) -> str:
    import json
    return json.dumps(value)


__all__ = ["HitlPolicy", "HitlPolicyCreate", "HitlPolicyUpdate", "router"]
