"""Cluster D HIGH-13: shared resume-intent dedup.

The wk-9 web UI submits an analyst decision via `POST /api/approvals/{id}`
which enqueues a ResumeJob; the worker drains the queue and calls
`resume_investigation`. The wk-8 dev hack `cli_resume.py` calls
`resume_investigation` directly. Both entry points must record the
analyst's intent on the audit chain BEFORE the resume runs — the audit
row is the source of truth for "this decision is in-flight" and is what
makes a second submission a 409 (or CLI exit 3).

Lives in `libs/common` so the API container (which does NOT depend on
the orchestrator package) can call it without dragging LangGraph +
checkpointer wiring into its dependency graph.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text

from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session


class ResumeAlreadySubmitted(Exception):  # noqa: N818 — spec-named (cluster D HIGH-13)
    """A `human_decision_submitted` audit row already exists.

    The API maps this to HTTP 409. The CLI exits with status 3.
    """

    def __init__(self, investigation_id: UUID) -> None:
        super().__init__(f"resume already submitted for {investigation_id}")
        self.investigation_id = investigation_id


def claim_resume_intent(
    *,
    investigation_id: UUID,
    tenant_id: UUID,
    approved: bool,
    analyst_id: str | None,
    notes: str,
    actor: str,
    trace_id: str,
) -> None:
    """Atomic dedup + intent-recording for a resume.

    Runs inside one tenant_session txn:
      1. `SELECT … FOR UPDATE` row-locks the investigation row.
      2. EXISTS check on `audit_log` for action='human_decision_submitted'.
         If found → raise `ResumeAlreadySubmitted`.
      3. Insert the `human_decision_submitted` audit row.

    Both the API submit handler and the CLI resume call this BEFORE
    invoking `resume_investigation`. `resume_investigation` itself does
    NOT re-claim — its caller is contractually required to have done so.
    Otherwise the second call from API → worker would always raise.

    Raises:
        ResumeAlreadySubmitted: another decision already on the audit
            chain for this investigation.
        RuntimeError: investigation row not found (caller maps to 404).
    """
    details: dict[str, Any] = {
        "approved": approved,
        "analyst_id": analyst_id,
        "notes_length": len(notes),
        "trace_id": trace_id,
    }
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                "SELECT id FROM investigations WHERE id = :id "
                "AND tenant_id = :tenant FOR UPDATE"
            ),
            {"id": str(investigation_id), "tenant": str(tenant_id)},
        ).first()
        if row is None:
            msg = f"investigation {investigation_id} not found"
            raise RuntimeError(msg)
        already = conn.execute(
            text(
                "SELECT 1 FROM audit_log "
                "WHERE investigation_id = :id "
                "AND action = 'human_decision_submitted' LIMIT 1"
            ),
            {"id": str(investigation_id)},
        ).first()
        if already is not None:
            raise ResumeAlreadySubmitted(investigation_id)
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            actor=actor,
            action="human_decision_submitted",
            details=details,
        )


__all__ = ["ResumeAlreadySubmitted", "claim_resume_intent"]
