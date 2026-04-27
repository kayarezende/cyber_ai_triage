"""Shared FastAPI dependencies for wk-9 routers.

`TenantId` reads `request.state.tenant_id` (set by `DevBypassAuthMiddleware`)
and returns a UUID. `Pagination` parses `?limit=` + `?cursor=` into a typed
struct; cursors are opaque base64 of the last seen `(int_id)` (audit) or
`(timestamp_iso, uuid)` (investigations).

Routers should depend on these via `Annotated[..., Depends(...)]` to keep
endpoint signatures clean.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Query, Request


def get_request_tenant(request: Request) -> UUID:
    """Pull tenant_id off request.state. Middleware guarantees it is set
    when auth has run; bypassed routes (health, ingest webhook) don't use this.
    """
    raw = getattr(request.state, "tenant_id", None)
    if not raw:
        raise HTTPException(status_code=401, detail="tenant_unresolved")
    try:
        return UUID(str(raw))
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="tenant_id_invalid") from exc


TenantId = Annotated[UUID, Depends(get_request_tenant)]


@dataclass(frozen=True)
class Pagination:
    """Forward-cursor pagination params. Cursor is opaque to clients."""

    limit: int
    cursor: str | None


def parse_pagination(
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> Pagination:
    return Pagination(limit=limit, cursor=cursor)


PageParams = Annotated[Pagination, Depends(parse_pagination)]


def encode_int_cursor(value: int) -> str:
    """For BIGSERIAL-keyed tables (audit_log)."""
    return base64.urlsafe_b64encode(str(value).encode("ascii")).decode("ascii")


def decode_int_cursor(cursor: str | None) -> int | None:
    """Reverse of `encode_int_cursor`. Bad input → 400."""
    if cursor is None:
        return None
    try:
        return int(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid_cursor") from exc


def encode_uuid_ts_cursor(ts_iso: str, row_id: UUID) -> str:
    """For (started_at DESC, id DESC) pagination on investigations."""
    raw = f"{ts_iso}|{row_id}".encode()
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_uuid_ts_cursor(cursor: str | None) -> tuple[str, UUID] | None:
    if cursor is None:
        return None
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        ts_iso, raw_uuid = decoded.split("|", 1)
        return ts_iso, UUID(raw_uuid)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid_cursor") from exc


__all__ = [
    "PageParams",
    "Pagination",
    "TenantId",
    "decode_int_cursor",
    "decode_uuid_ts_cursor",
    "encode_int_cursor",
    "encode_uuid_ts_cursor",
    "get_request_tenant",
    "parse_pagination",
]
