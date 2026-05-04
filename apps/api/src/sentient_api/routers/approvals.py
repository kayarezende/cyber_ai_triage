"""Wk-9 approval surface — drives the Approval UI on the investigation page.

POST `/api/approvals/{investigation_id}` — analyst submits decision.
GET  `/api/approvals/pending`            — analyst inbox (paused threads).

The POST endpoint does NOT resume the LangGraph thread inline. Resuming
re-enters MCP tool calls + writeback + possibly a final LLM pass; that's
seconds-to-minutes — wrong place for an HTTP handler. Instead it:

  1. validates the investigation belongs to the caller's tenant + is
     `approval_status='pending'` via an atomic UPDATE...RETURNING (idempotent
     guard against double-submit by two analysts);
  2. writes a `human_decision_submitted` audit row (records intent on the
     hash-chain before the worker re-enters the graph);
  3. enqueues a ResumeJob on QUEUE_RESUMES.

The worker BLPOPs that queue and calls `resume_investigation(job)`, which
is the same code path the wk-8 CLI hack drives (see ADR-0008 / wk-9 plan).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

import redis as redis_lib
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from sentient_api.deps import TenantId
from sentient_api.settings import Settings, get_settings
from sentient_common.db import tenant_session
from sentient_common.jobs import ResumeJob, enqueue_resume
from sentient_common.logging import get_logger
from sentient_common.resume import ResumeAlreadySubmitted, claim_resume_intent

router = APIRouter(tags=["approvals"])
log = get_logger(__name__)


class ApprovalRequest(BaseModel):
    approved: bool
    analyst_id: UUID | None = None
    notes: str = Field(default="", max_length=1024)

    model_config = ConfigDict(extra="forbid")


class ApprovalResponse(BaseModel):
    investigation_id: UUID
    queued: bool
    trace_id: str
    status: str = "resume_enqueued"


class PendingApproval(BaseModel):
    investigation_id: UUID
    incident_id: UUID
    started_at: datetime | None
    severity: str | None
    verdict: str | None
    summary_excerpt: str | None
    review_status: str | None


class PendingApprovalsResponse(BaseModel):
    items: list[PendingApproval]


def _summary_excerpt(summary: str | None, max_len: int = 160) -> str | None:
    if not summary:
        return None
    if len(summary) <= max_len:
        return summary
    return summary[: max_len - 1] + "…"


@router.post(
    "/api/approvals/{investigation_id}",
    response_model=ApprovalResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def submit_approval(
    investigation_id: UUID,
    body: ApprovalRequest,
    tenant_id: TenantId,
    settings: Annotated[Settings, Depends(get_settings)],
    x_user_id: Annotated[str | None, Header(alias="x-user-id")] = None,
) -> ApprovalResponse:
    trace_id = uuid4().hex
    # Fall back to the auth middleware's `x-user-id` header when the body
    # doesn't carry `analyst_id`. Without this, dev-bypass approvals (Web UI
    # → server-action → apiFetch propagates x-user-id) record NULL approver,
    # leaving `investigations.human_approved_by` perpetually unset. When
    # wk-11 Entra SSO lands, the OIDC middleware sets the same header from
    # the verified token — same fallback shape, no router change needed.
    analyst_id_str: str | None = None
    if body.analyst_id is not None:
        analyst_id_str = str(body.analyst_id)
    elif x_user_id:
        try:
            analyst_id_str = str(UUID(x_user_id))
        except ValueError:
            log.warning("ignoring malformed x-user-id header", value=x_user_id)

    # Cluster D HIGH-13: dedup + audit-row insert live in
    # `claim_resume_intent` so the CLI resume path goes through the same
    # gate. Pre-flight `approval_status` check stays here for clear 409s
    # (`not_pending_approval` vs `decision_already_submitted`); the full
    # row-locked dedup happens inside the helper.
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                "SELECT approval_status FROM investigations "
                "WHERE id = :id AND tenant_id = :tenant_id"
            ),
            {"id": str(investigation_id), "tenant_id": str(tenant_id)},
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="investigation_not_found")
        if row[0] != "pending":
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "not_pending_approval",
                    "approval_status": row[0],
                },
            )
    try:
        claim_resume_intent(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            approved=body.approved,
            analyst_id=analyst_id_str,
            notes=body.notes,
            actor="api:approvals",
            trace_id=trace_id,
        )
    except ResumeAlreadySubmitted as exc:
        raise HTTPException(status_code=409, detail="decision_already_submitted") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=404, detail="investigation_not_found") from exc

    job = ResumeJob(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        approved=body.approved,
        analyst_id=analyst_id_str,
        notes=body.notes,
        enqueued_at=datetime.now(UTC),
        trace_id=trace_id,
    )
    redis_client = redis_lib.Redis.from_url(settings.redis_url)
    enqueue_resume(redis_client, job)

    log.info(
        "approval submitted",
        investigation_id=str(investigation_id),
        tenant_id=str(tenant_id),
        approved=body.approved,
        trace_id=trace_id,
    )
    return ApprovalResponse(investigation_id=investigation_id, queued=True, trace_id=trace_id)


@router.get("/api/approvals/pending", response_model=PendingApprovalsResponse)
def list_pending(
    tenant_id: TenantId,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> PendingApprovalsResponse:
    with tenant_session(tenant_id) as conn:
        rows = conn.execute(
            text("""
                SELECT inv.id, inv.incident_id, inv.started_at, inv.severity,
                       inv.verdict, inv.summary, inv.review_status
                  FROM investigations inv
                 WHERE inv.approval_status = 'pending'
                 ORDER BY inv.started_at DESC NULLS LAST, inv.id DESC
                 LIMIT :limit
                """),
            {"limit": limit},
        ).all()
    return PendingApprovalsResponse(
        items=[
            PendingApproval(
                investigation_id=UUID(str(r[0])),
                incident_id=UUID(str(r[1])),
                started_at=r[2],
                severity=r[3],
                verdict=r[4],
                summary_excerpt=_summary_excerpt(r[5]),
                review_status=r[6],
            )
            for r in rows
        ]
    )


__all__ = ["router"]
