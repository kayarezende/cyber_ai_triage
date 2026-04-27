"""Audit log INSERT helper + Python-side hash chain verifier.

The `audit_log` BEFORE INSERT trigger (migration `b7c4e9a2f1d8`) computes
`content_hash` + `previous_hash` from the prior row in the same `hash_scope`.
Callers supply the row payload + scope; the trigger handles the chain.

Scope rule:
    investigation_id is not None  →  f'investigation:{investigation_id}'
    else                          →  f'tenant:{tenant_id}'

Use within an active `tenant_session(tenant_id)` so RLS + transaction
atomicity hold.

Wk-9 adds `compute_audit_row_hash` + `verify_chain` so the API can render
chain integrity inline without re-running the plpgsql trigger. The Python
helper expects the row's column values as their Postgres-cast text form
(uuid::text, jsonb::text, created_at::text); the audit router queries
those casts so formatting drift between Python and Postgres can't break
verification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection


def insert_audit_log(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID | None,
    actor: str,
    action: str,
    details: dict[str, Any],
) -> None:
    """INSERT one row into audit_log; trigger fills content_hash + previous_hash."""
    scope = (
        f"investigation:{investigation_id}"
        if investigation_id is not None
        else f"tenant:{tenant_id}"
    )
    conn.execute(
        text(
            """
            INSERT INTO audit_log
                (tenant_id, investigation_id, actor, action, details, hash_scope)
            VALUES
                (:tenant_id, :investigation_id, :actor, :action,
                 CAST(:details AS jsonb), :hash_scope)
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "investigation_id": str(investigation_id) if investigation_id else None,
            "actor": actor,
            "action": action,
            "details": json.dumps(details),
            "hash_scope": scope,
        },
    )


def compute_audit_row_hash(
    *,
    tenant_id_text: str | None,
    investigation_id_text: str | None,
    actor: str | None,
    action: str | None,
    details_text: str | None,
    created_at_text: str | None,
    previous_hash: str | None,
) -> str:
    """Recompute SHA-256 over the same digest scope as the plpgsql trigger.

    The trigger (migration `b7c4e9a2f1d8`) formats:

        encode(
          digest(
            COALESCE(NEW.tenant_id::text, '') || '|' ||
            COALESCE(NEW.investigation_id::text, '') || '|' ||
            COALESCE(NEW.actor, '') || '|' ||
            COALESCE(NEW.action, '') || '|' ||
            COALESCE(NEW.details::text, '') || '|' ||
            COALESCE(NEW.created_at::text, '') || '|' ||
            NEW.previous_hash,
            'sha256'
          ), 'hex'
        )

    Inputs MUST be the Postgres-side text casts (uuid::text, jsonb::text,
    timestamptz::text) — Python's `str(uuid)` / `json.dumps()` /
    `datetime.isoformat()` differ from Postgres in casing, key ordering,
    and timezone notation. The audit-router fetch SQL is responsible for
    feeding the right casts.
    """
    payload = (
        (tenant_id_text or "")
        + "|"
        + (investigation_id_text or "")
        + "|"
        + (actor or "")
        + "|"
        + (action or "")
        + "|"
        + (details_text or "")
        + "|"
        + (created_at_text or "")
        + "|"
        + (previous_hash or "")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRowVerification:
    """One row's verification result."""

    row_id: int
    expected_hash: str
    stored_hash: str
    expected_previous: str
    stored_previous: str
    ok: bool


@dataclass(frozen=True)
class ChainVerification:
    """Aggregate result of walking one hash_scope's chain."""

    total_rows: int
    valid: bool
    first_invalid_row_id: int | None
    rows: list[AuditRowVerification]


def verify_chain(
    rows: list[dict[str, Any]],
) -> ChainVerification:
    """Walk an ordered list of rows (id ASC) within one `hash_scope`.

    Each row dict MUST carry the Postgres-side text casts:
        id (int), tenant_id_text, investigation_id_text, actor, action,
        details_text, created_at_text, content_hash, previous_hash.

    For row N: `previous_hash` must equal row N-1's `content_hash` (or
    empty string for the first row), and `content_hash` must match the
    recomputed digest. First mismatch sets `first_invalid_row_id` and
    `valid=False`.
    """
    results: list[AuditRowVerification] = []
    prior_hash = ""
    valid = True
    first_invalid: int | None = None

    for row in rows:
        expected_prev = prior_hash
        stored_prev = row.get("previous_hash") or ""
        expected = compute_audit_row_hash(
            tenant_id_text=row.get("tenant_id_text"),
            investigation_id_text=row.get("investigation_id_text"),
            actor=row.get("actor"),
            action=row.get("action"),
            details_text=row.get("details_text"),
            created_at_text=row.get("created_at_text"),
            previous_hash=stored_prev,
        )
        stored = row.get("content_hash") or ""
        row_ok = expected == stored and stored_prev == expected_prev
        if not row_ok and first_invalid is None:
            valid = False
            first_invalid = int(row["id"])
        results.append(
            AuditRowVerification(
                row_id=int(row["id"]),
                expected_hash=expected,
                stored_hash=stored,
                expected_previous=expected_prev,
                stored_previous=stored_prev,
                ok=row_ok,
            )
        )
        prior_hash = stored

    return ChainVerification(
        total_rows=len(rows),
        valid=valid,
        first_invalid_row_id=first_invalid,
        rows=results,
    )


__all__ = [
    "AuditRowVerification",
    "ChainVerification",
    "compute_audit_row_hash",
    "insert_audit_log",
    "verify_chain",
]
