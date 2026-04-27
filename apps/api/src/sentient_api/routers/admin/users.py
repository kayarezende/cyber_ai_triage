"""Admin: tenant users.

List + invite + role-change. Inviting a user creates a `users` row with no
`entra_oid` — the row is "pending" until that user logs in via Entra (wk
11) at which point the OIDC handler binds the OID to the email match.

Until SSO ships, "invite" is essentially a placeholder seed that lets the
admin expose a role to a future login. Email is the natural identity key.

Role values: `analyst` (default) or `admin` (CHECK constraint matches
`users.role` column).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from sentient_api.deps import RequireAdmin, TenantId
from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session

router = APIRouter(prefix="/api/admin", tags=["admin"])

UserRole = Literal["analyst", "admin"]


class TenantUser(BaseModel):
    id: UUID
    email: str
    role: UserRole
    entra_oid: str | None
    created_at: datetime | None

    model_config = ConfigDict(extra="forbid")


class TenantUserListResponse(BaseModel):
    items: list[TenantUser]


class UserInvite(BaseModel):
    # Plain `str` + a relaxed regex to avoid pulling `pydantic[email]` into
    # the API container; an "@" + a "." after the "@" is enough validation
    # for an admin-curated invite list.
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: UserRole = "analyst"

    model_config = ConfigDict(extra="forbid")


class UserRoleUpdate(BaseModel):
    role: UserRole

    model_config = ConfigDict(extra="forbid")


@router.get("/users", response_model=TenantUserListResponse)
def list_users(
    tenant_id: TenantId,
    _admin: RequireAdmin,
) -> TenantUserListResponse:
    with tenant_session(tenant_id) as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, email, role, entra_oid, created_at
                  FROM users
                 ORDER BY created_at ASC NULLS LAST, email ASC
                """
            )
        ).all()
    return TenantUserListResponse(
        items=[
            TenantUser(
                id=UUID(str(row[0])),
                email=row[1] or "",
                role=row[2],
                entra_oid=row[3],
                created_at=row[4],
            )
            for row in rows
        ]
    )


@router.post("/users", response_model=TenantUser, status_code=201)
def invite_user(
    body: UserInvite,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> TenantUser:
    with tenant_session(tenant_id) as conn:
        try:
            row = conn.execute(
                text(
                    """
                    INSERT INTO users (tenant_id, email, role)
                    VALUES (:tenant_id, :email, :role)
                    RETURNING id, email, role, entra_oid, created_at
                    """
                ),
                {
                    "tenant_id": str(tenant_id),
                    "email": str(body.email).lower(),
                    "role": body.role,
                },
            ).first()
        except IntegrityError as exc:
            raise HTTPException(
                status_code=409, detail="email_already_exists"
            ) from exc
        if row is None:
            raise HTTPException(status_code=500, detail="insert_returning_empty")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_user_invited",
            details={"user_id": str(row[0]), "email": str(body.email).lower(), "role": body.role},
        )
    return _row_to_user(row)


@router.patch("/users/{user_id}", response_model=TenantUser)
def update_user_role(
    user_id: UUID,
    body: UserRoleUpdate,
    tenant_id: TenantId,
    admin: RequireAdmin,
) -> TenantUser:
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                UPDATE users
                   SET role = :role
                 WHERE id = :id AND tenant_id = :tenant_id
                RETURNING id, email, role, entra_oid, created_at
                """
            ),
            {
                "id": str(user_id),
                "tenant_id": str(tenant_id),
                "role": body.role,
            },
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="user_not_found")
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor=admin.get("email", "unknown"),
            action="admin_user_role_changed",
            details={"user_id": str(user_id), "role": body.role},
        )
    return _row_to_user(row)


def _row_to_user(row: object) -> TenantUser:
    r = list(row)  # type: ignore[call-overload]
    return TenantUser(
        id=UUID(str(r[0])),
        email=r[1] or "",
        role=r[2],
        entra_oid=r[3],
        created_at=r[4],
    )


__all__ = ["TenantUser", "UserInvite", "UserRoleUpdate", "router"]
