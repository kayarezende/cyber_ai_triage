"""Audit log INSERT helper.

The `audit_log` BEFORE INSERT trigger (migration `b7c4e9a2f1d8`) computes
`content_hash` + `previous_hash` from the prior row in the same `hash_scope`.
Callers supply the row payload + scope; the trigger handles the chain.

Scope rule:
    investigation_id is not None  →  f'investigation:{investigation_id}'
    else                          →  f'tenant:{tenant_id}'

Use within an active `tenant_session(tenant_id)` so RLS + transaction
atomicity hold.
"""

from __future__ import annotations

import json
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


__all__ = ["insert_audit_log"]
