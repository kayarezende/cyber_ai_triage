"""Wk-9 GET endpoints for the web UI investigation views.

- GET `/api/investigations`              list + filter + paginate
- GET `/api/investigations/{id}`         detail + joined incident OCSF + MITRE
- GET `/api/investigations/{id}/manifest` evidence manifest JSON (proxied)
- GET `/api/investigations/{id}/timeline` per-investigation audit slice

All read paths run inside `tenant_session(tenant_id)` so RLS policies
(migration `b7c4e9a2f1d8`) are enforced; every row that comes back is
already tenant-scoped.
"""

from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text

from sentient_api.deps import (
    PageParams,
    TenantId,
    decode_uuid_ts_cursor,
    encode_uuid_ts_cursor,
)
from sentient_api.settings import Settings, get_settings
from sentient_common.db import tenant_session
from sentient_common.logging import get_logger
from sentient_common.storage import (
    ObjectNotFoundError,
    StorageError,
    download_evidence,
)

router = APIRouter(tags=["investigations"])
log = get_logger(__name__)


# ---------- response schemas


class InvestigationSummary(BaseModel):
    id: UUID
    incident_id: UUID
    started_at: datetime | None
    completed_at: datetime | None
    incident_status: str | None
    verdict: str | None
    confidence: float | None
    severity: str | None
    mitre_techniques: list[str]
    summary_excerpt: str | None
    approval_status: str | None
    review_status: str | None
    writeback_status: str | None
    inconclusive_reason: str | None
    total_cost_usd: float | None

    model_config = ConfigDict(extra="forbid")


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummary]
    next_cursor: str | None = None


class MitreTechnique(BaseModel):
    technique_id: str
    name: str | None
    tactic_ids: list[str]


class InvestigationDetail(BaseModel):
    id: UUID
    tenant_id: UUID
    incident_id: UUID
    incident_status: str | None
    siem_notable_id: str | None
    siem_source: str | None
    ocsf_normalized: dict[str, Any] | None
    langgraph_thread_id: str | None
    started_at: datetime | None
    completed_at: datetime | None
    verdict: str | None
    confidence: float | None
    severity: str | None
    mitre_techniques: list[str]
    mitre_resolved: list[MitreTechnique]
    summary: str | None
    review_notes: str | None
    review_status: str | None
    review_metadata: dict[str, Any] | None
    approval_status: str | None
    approver_id: UUID | None
    approval_notes: str | None
    human_approved_by: UUID | None
    human_approved_at: datetime | None
    writeback_status: str | None
    writeback_attempts: list[dict[str, Any]]
    detection_rule_matches: list[dict[str, Any]]
    inconclusive_reason: str | None
    evidence_s3_key: str | None
    total_input_tokens: int | None
    total_output_tokens: int | None
    total_cost_usd: float | None
    ocsf_output: dict[str, Any] | None
    # Wk-9 UX gate. The API writes `human_decision_submitted` to the audit
    # chain, then enqueues a `ResumeJob` on Redis. The DB `approval_status`
    # stays `pending` until the worker resumes the graph + finalizes — so
    # the UI cannot tell from `approval_status` alone whether a decision
    # is already in flight. This flag closes that gap.
    decision_submitted: bool

    model_config = ConfigDict(extra="forbid")


class TimelineEntry(BaseModel):
    id: int
    actor: str | None
    action: str | None
    details: dict[str, Any] | None
    created_at: datetime | None


class TimelineResponse(BaseModel):
    items: list[TimelineEntry]


# ---------- helpers


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    return float(value)


def _summary_excerpt(summary: str | None, max_len: int = 200) -> str | None:
    if not summary:
        return None
    if len(summary) <= max_len:
        return summary
    return summary[: max_len - 1] + "…"


def _coerce_jsonb(value: Any) -> Any:
    """Postgres returns JSONB as a python dict/list already; normalise None."""
    return value


# ---------- list


@router.get("/api/investigations", response_model=InvestigationListResponse)
def list_investigations(
    tenant_id: TenantId,
    page: PageParams,
    status: Annotated[str | None, Query()] = None,
    verdict: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    approval_status: Annotated[str | None, Query()] = None,
    review_status: Annotated[str | None, Query()] = None,
) -> InvestigationListResponse:
    cursor = decode_uuid_ts_cursor(page.cursor)
    # NULL started_at would short-circuit the cursor predicate (Postgres
    # tuple comparison returns NULL when any component is NULL → excluded
    # from results). The runner always sets started_at on insert, but
    # filter explicitly so a malformed write path can't break pagination.
    where_clauses: list[str] = ["inv.started_at IS NOT NULL"]
    params: dict[str, Any] = {"limit": page.limit + 1}

    if status:
        where_clauses.append("i.status = :status")
        params["status"] = status
    if verdict:
        where_clauses.append("inv.verdict = :verdict")
        params["verdict"] = verdict
    if severity:
        where_clauses.append("inv.severity = :severity")
        params["severity"] = severity
    if approval_status:
        where_clauses.append("inv.approval_status = :approval_status")
        params["approval_status"] = approval_status
    if review_status:
        where_clauses.append("inv.review_status = :review_status")
        params["review_status"] = review_status
    if cursor:
        ts_iso, last_id = cursor
        where_clauses.append(
            "(inv.started_at, inv.id) < (CAST(:cur_ts AS TIMESTAMPTZ), :cur_id)"
        )
        params["cur_ts"] = ts_iso
        params["cur_id"] = str(last_id)

    where = "WHERE " + " AND ".join(where_clauses)
    sql = f"""
        SELECT inv.id, inv.incident_id, inv.started_at, inv.completed_at,
               i.status AS incident_status,
               inv.verdict, inv.confidence, inv.severity,
               inv.mitre_techniques, inv.summary,
               inv.approval_status, inv.review_status, inv.writeback_status,
               inv.inconclusive_reason, inv.total_cost_usd
          FROM investigations inv
          JOIN incidents i ON i.id = inv.incident_id
        {where}
        ORDER BY inv.started_at DESC, inv.id DESC
        LIMIT :limit
    """

    with tenant_session(tenant_id) as conn:
        rows = list(conn.execute(text(sql), params))

    items: list[InvestigationSummary] = []
    for row in rows[: page.limit]:
        items.append(
            InvestigationSummary(
                id=UUID(str(row[0])),
                incident_id=UUID(str(row[1])),
                started_at=row[2],
                completed_at=row[3],
                incident_status=row[4],
                verdict=row[5],
                confidence=_to_float(row[6]),
                severity=row[7],
                mitre_techniques=list(row[8] or []),
                summary_excerpt=_summary_excerpt(row[9]),
                approval_status=row[10],
                review_status=row[11],
                writeback_status=row[12],
                inconclusive_reason=row[13],
                total_cost_usd=_to_float(row[14]),
            )
        )

    next_cursor: str | None = None
    if len(rows) > page.limit:
        last = rows[page.limit - 1]
        # `started_at IS NOT NULL` is enforced in WHERE, so last[2] is set.
        next_cursor = encode_uuid_ts_cursor(
            last[2].isoformat(), UUID(str(last[0]))
        )

    return InvestigationListResponse(items=items, next_cursor=next_cursor)


# ---------- detail


def _resolve_mitre(conn: Any, technique_ids: list[str]) -> list[MitreTechnique]:
    if not technique_ids:
        return []
    rows = conn.execute(
        text(
            """
            SELECT technique_id, name, tactic_ids
              FROM mitre_techniques
             WHERE technique_id = ANY(CAST(:ids AS TEXT[]))
            """
        ),
        {"ids": "{" + ",".join(technique_ids) + "}"},
    ).all()
    by_id = {row[0]: row for row in rows}
    out: list[MitreTechnique] = []
    for tid in technique_ids:
        row = by_id.get(tid)
        if row is None:
            out.append(MitreTechnique(technique_id=tid, name=None, tactic_ids=[]))
            continue
        out.append(
            MitreTechnique(
                technique_id=row[0],
                name=row[1],
                tactic_ids=list(row[2] or []),
            )
        )
    return out


@router.get(
    "/api/investigations/{investigation_id}", response_model=InvestigationDetail
)
def get_investigation(
    investigation_id: UUID,
    tenant_id: TenantId,
) -> InvestigationDetail:
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                """
                SELECT inv.id, inv.tenant_id, inv.incident_id,
                       i.status AS incident_status,
                       i.siem_notable_id, i.siem_source, i.ocsf_normalized,
                       inv.langgraph_thread_id, inv.started_at, inv.completed_at,
                       inv.verdict, inv.confidence, inv.severity,
                       inv.mitre_techniques, inv.summary,
                       inv.review_notes, inv.review_status, inv.review_metadata,
                       inv.approval_status, inv.approver_id, inv.approval_notes,
                       inv.human_approved_by, inv.human_approved_at,
                       inv.writeback_status, inv.writeback_attempts,
                       inv.detection_rule_matches, inv.inconclusive_reason,
                       inv.evidence_s3_key,
                       inv.total_input_tokens, inv.total_output_tokens,
                       inv.total_cost_usd, inv.ocsf_output,
                       EXISTS (
                         SELECT 1 FROM audit_log
                          WHERE investigation_id = inv.id
                            AND action = 'human_decision_submitted'
                       ) AS decision_submitted
                  FROM investigations inv
                  JOIN incidents i ON i.id = inv.incident_id
                 WHERE inv.id = :id
                """
            ),
            {"id": str(investigation_id)},
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="investigation_not_found")
        techniques = list(row[13] or [])
        resolved = _resolve_mitre(conn, techniques)

    return InvestigationDetail(
        id=UUID(str(row[0])),
        tenant_id=UUID(str(row[1])),
        incident_id=UUID(str(row[2])),
        incident_status=row[3],
        siem_notable_id=row[4],
        siem_source=row[5],
        ocsf_normalized=_coerce_jsonb(row[6]),
        langgraph_thread_id=row[7],
        started_at=row[8],
        completed_at=row[9],
        verdict=row[10],
        confidence=_to_float(row[11]),
        severity=row[12],
        mitre_techniques=techniques,
        mitre_resolved=resolved,
        summary=row[14],
        review_notes=row[15],
        review_status=row[16],
        review_metadata=_coerce_jsonb(row[17]),
        approval_status=row[18],
        approver_id=UUID(str(row[19])) if row[19] else None,
        approval_notes=row[20],
        human_approved_by=UUID(str(row[21])) if row[21] else None,
        human_approved_at=row[22],
        writeback_status=row[23],
        writeback_attempts=list(_coerce_jsonb(row[24]) or []),
        detection_rule_matches=list(_coerce_jsonb(row[25]) or []),
        inconclusive_reason=row[26],
        evidence_s3_key=row[27],
        total_input_tokens=row[28],
        total_output_tokens=row[29],
        total_cost_usd=_to_float(row[30]),
        ocsf_output=_coerce_jsonb(row[31]),
        decision_submitted=bool(row[32]),
    )


# ---------- manifest


@router.get("/api/investigations/{investigation_id}/manifest")
def get_investigation_manifest(
    investigation_id: UUID,
    tenant_id: TenantId,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return the evidence manifest JSON proxied from MinIO.

    RLS lives here in the API; presigned MinIO URLs would leak bucket layout
    + bypass tenant scoping. Manifests are tens of KB so the proxy cost is
    negligible.
    """
    with tenant_session(tenant_id) as conn:
        row = conn.execute(
            text(
                "SELECT evidence_s3_key FROM investigations WHERE id = :id"
            ),
            {"id": str(investigation_id)},
        ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="investigation_not_found")
    key = row[0]
    if not key:
        raise HTTPException(status_code=404, detail="manifest_not_uploaded")
    try:
        body = download_evidence(bucket=settings.minio_bucket_evidence, key=key)
    except ObjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="manifest_object_missing") from exc
    except StorageError as exc:
        log.exception(
            "manifest download failed",
            investigation_id=str(investigation_id),
        )
        raise HTTPException(status_code=502, detail="manifest_download_failed") from exc
    try:
        parsed: dict[str, Any] = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.exception(
            "manifest is not valid utf-8 json",
            investigation_id=str(investigation_id),
        )
        raise HTTPException(status_code=502, detail="manifest_invalid") from exc
    return parsed


# ---------- timeline


@router.get(
    "/api/investigations/{investigation_id}/timeline",
    response_model=TimelineResponse,
)
def get_investigation_timeline(
    investigation_id: UUID,
    tenant_id: TenantId,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> TimelineResponse:
    """Audit rows scoped to one investigation, oldest-first.

    Drives the reasoning trace + MITRE matrix on the detail page. Bounded
    at 500 rows by default because the full chain for one Tier-2 run is
    typically <100 entries; multi-step heavy investigations top out
    around ~200.
    """
    with tenant_session(tenant_id) as conn:
        # Cheap existence + tenancy check first so 404 vs empty timeline differ.
        exists = conn.execute(
            text("SELECT 1 FROM investigations WHERE id = :id"),
            {"id": str(investigation_id)},
        ).first()
        if exists is None:
            raise HTTPException(
                status_code=404, detail="investigation_not_found"
            )
        rows = conn.execute(
            text(
                """
                SELECT id, actor, action, details, created_at
                  FROM audit_log
                 WHERE investigation_id = :iid
                 ORDER BY id ASC
                 LIMIT :limit
                """
            ),
            {"iid": str(investigation_id), "limit": limit},
        ).all()
    return TimelineResponse(
        items=[
            TimelineEntry(
                id=int(r[0]),
                actor=r[1],
                action=r[2],
                details=_coerce_jsonb(r[3]),
                created_at=r[4],
            )
            for r in rows
        ]
    )


__all__ = ["router"]
