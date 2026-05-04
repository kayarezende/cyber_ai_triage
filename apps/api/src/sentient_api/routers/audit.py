"""Wk-9 audit explorer — drives `/audit` page + per-row chain-integrity badge.

GET `/api/audit`                            paginated, filterable timeline
GET `/api/audit/verify/{investigation_id}`  full chain walk + integrity report

Hash recomputation uses Postgres-side text casts (uuid::text, jsonb::text,
created_at::text) fed into `compute_audit_row_hash` so formatting drift
between Python and Postgres can never break verification.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text

from sentient_api.deps import (
    PageParams,
    TenantId,
    decode_int_cursor,
    encode_int_cursor,
)
from sentient_common.audit import (
    ChainVerification,
    verify_chain,
)
from sentient_common.db import tenant_session
from sentient_common.logging import get_logger

router = APIRouter(tags=["audit"])
log = get_logger(__name__)


class AuditEntry(BaseModel):
    id: int
    investigation_id: UUID | None
    actor: str | None
    action: str | None
    details: dict[str, Any] | None
    content_hash: str | None
    previous_hash: str | None
    hash_scope: str | None
    created_at: datetime | None
    chain_ok: bool

    model_config = ConfigDict(extra="forbid")


class AuditPage(BaseModel):
    items: list[AuditEntry]
    next_cursor: str | None = None


class AuditChainRow(BaseModel):
    row_id: int
    expected_hash: str
    stored_hash: str
    expected_previous: str
    stored_previous: str
    ok: bool


class AuditVerifyResponse(BaseModel):
    investigation_id: UUID
    hash_scope: str
    total_rows: int
    valid: bool
    first_invalid_row_id: int | None
    rows: list[AuditChainRow]


_LIST_SQL = """
    SELECT id, investigation_id, actor, action, details,
           content_hash, previous_hash, hash_scope, created_at,
           tenant_id::text       AS tenant_id_text,
           investigation_id::text AS investigation_id_text,
           details::text         AS details_text,
           created_at::text      AS created_at_text
      FROM audit_log
     {where}
     ORDER BY id ASC
     LIMIT :limit
"""


@router.get("/api/audit", response_model=AuditPage)
def list_audit(
    tenant_id: TenantId,
    page: PageParams,
    investigation_id: Annotated[UUID | None, Query()] = None,
    action: Annotated[str | None, Query()] = None,
    actor: Annotated[str | None, Query()] = None,
) -> AuditPage:
    cursor = decode_int_cursor(page.cursor)
    where_clauses: list[str] = []
    params: dict[str, Any] = {"limit": page.limit + 1}

    if investigation_id is not None:
        where_clauses.append("investigation_id = :iid")
        params["iid"] = str(investigation_id)
    if action:
        where_clauses.append("action = :action")
        params["action"] = action
    if actor:
        where_clauses.append("actor = :actor")
        params["actor"] = actor
    if cursor is not None:
        where_clauses.append("id > :cursor_id")
        params["cursor_id"] = cursor

    where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    with tenant_session(tenant_id) as conn:
        rows = list(conn.execute(text(_LIST_SQL.format(where=where)), params))

    # Group by hash_scope to walk integrity inline. Page boundaries can split
    # a chain — chain verification is best-effort within the page (the
    # `/api/audit/verify/{id}` endpoint walks the full chain on demand).
    by_scope: dict[str, list[dict[str, Any]]] = {}
    raw_rows: list[dict[str, Any]] = []
    for r in rows[: page.limit]:
        record = {
            "id": int(r[0]),
            "investigation_id": r[1],
            "actor": r[2],
            "action": r[3],
            "details": r[4],
            "content_hash": r[5],
            "previous_hash": r[6],
            "hash_scope": r[7],
            "created_at": r[8],
            "tenant_id_text": r[9],
            "investigation_id_text": r[10],
            "details_text": r[11],
            "created_at_text": r[12],
        }
        raw_rows.append(record)
        by_scope.setdefault(record["hash_scope"] or "", []).append(record)

    chain_ok_by_id: dict[int, bool] = {}
    for scope_rows in by_scope.values():
        scope_rows_sorted = sorted(scope_rows, key=lambda r: r["id"])
        verification = verify_chain(scope_rows_sorted)
        for vrow in verification.rows:
            chain_ok_by_id[vrow.row_id] = vrow.ok

    items = [
        AuditEntry(
            id=r["id"],
            investigation_id=UUID(str(r["investigation_id"])) if r["investigation_id"] else None,
            actor=r["actor"],
            action=r["action"],
            details=r["details"],
            content_hash=r["content_hash"],
            previous_hash=r["previous_hash"],
            hash_scope=r["hash_scope"],
            created_at=r["created_at"],
            chain_ok=chain_ok_by_id.get(r["id"], False),
        )
        for r in raw_rows
    ]

    next_cursor = (
        encode_int_cursor(int(rows[page.limit - 1][0])) if len(rows) > page.limit else None
    )

    return AuditPage(items=items, next_cursor=next_cursor)


_VERIFY_SQL = """
    SELECT id, content_hash, previous_hash, hash_scope,
           tenant_id::text         AS tenant_id_text,
           investigation_id::text  AS investigation_id_text,
           actor, action,
           details::text           AS details_text,
           created_at::text        AS created_at_text
      FROM audit_log
     WHERE hash_scope = :scope
     ORDER BY id ASC
     LIMIT 5000
"""


@router.get("/api/audit/verify/{investigation_id}", response_model=AuditVerifyResponse)
def verify_audit_chain(
    investigation_id: UUID,
    tenant_id: TenantId,
) -> AuditVerifyResponse:
    scope = f"investigation:{investigation_id}"
    with tenant_session(tenant_id) as conn:
        # Existence + tenancy check (RLS already scopes audit_log).
        exists = conn.execute(
            text("SELECT 1 FROM investigations WHERE id = :id"),
            {"id": str(investigation_id)},
        ).first()
        if exists is None:
            raise HTTPException(status_code=404, detail="investigation_not_found")
        rows = list(conn.execute(text(_VERIFY_SQL), {"scope": scope}))

    payload = [
        {
            "id": int(r[0]),
            "content_hash": r[1],
            "previous_hash": r[2],
            "hash_scope": r[3],
            "tenant_id_text": r[4],
            "investigation_id_text": r[5],
            "actor": r[6],
            "action": r[7],
            "details_text": r[8],
            "created_at_text": r[9],
        }
        for r in rows
    ]
    verification: ChainVerification = verify_chain(payload)
    return AuditVerifyResponse(
        investigation_id=investigation_id,
        hash_scope=scope,
        total_rows=verification.total_rows,
        valid=verification.valid,
        first_invalid_row_id=verification.first_invalid_row_id,
        rows=[
            AuditChainRow(
                row_id=v.row_id,
                expected_hash=v.expected_hash,
                stored_hash=v.stored_hash,
                expected_previous=v.expected_previous,
                stored_previous=v.stored_previous,
                ok=v.ok,
            )
            for v in verification.rows
        ],
    )


__all__ = ["router"]
