"""POST /api/incidents/ingest — Splunk saved-search webhook.

Auth: body field `secret`, constant-time compared against `INGEST_WEBHOOK_SECRET`.
Stock Splunk Enterprise's webhook alert action does not support custom headers,
so the secret travels in the body (ADR-0021 supersedes ADR-0014 §header carrier).

Tenant routing: single dev tenant for MVP. Per-tenant slugs land wk-11 alongside
Entra SSO.

Flow per request:
    1. compare secret
    2. resolve tenant_id (DEV_TENANT_ID)
    3. extract notable_dict from `req.result` (Splunk wraps each row) or flat body
    4. upload raw payload to MinIO under raw/<tenant>/<incident>.json
    5. validate notable + map to OCSF Detection Finding (wk-3 mapper)
    6. INSERT incidents row + audit_log row inside tenant_session
    7. enqueue investigation job on Redis
    8. return 202 with incident_id
"""

from __future__ import annotations

import hmac
import json
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

import redis as redis_lib
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import text

from sentient_api.settings import DEV_TENANT_ID, Settings, get_settings
from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session
from sentient_common.jobs import IngestJob, enqueue_investigation
from sentient_common.logging import get_logger
from sentient_common.storage import StorageError, upload_evidence
from sentient_ocsf.splunk_mapper import SplunkNotable, map_notable_to_ocsf

router = APIRouter(tags=["incidents"])
log = get_logger(__name__)


class IngestRequest(BaseModel):
    """Splunk webhook payload.

    Splunk's built-in webhook action wraps each result row as
    `{search_name, sid, result, results_link, ...}`. The saved-search alert
    action templates an additional `secret` field (per ADR-0021 / `splunk-setup.md`
    §5.3). We accept both wrapped (`result` populated) and flat shapes — the flat
    form is convenient for curl smoke tests.
    """

    secret: str
    result: dict[str, Any] | None = None

    model_config = ConfigDict(extra="allow")


class IngestResponse(BaseModel):
    incident_id: UUID
    status: Literal["accepted"] = "accepted"


def _resolve_notable_dict(req: IngestRequest) -> dict[str, Any]:
    if req.result:
        return req.result
    # Flat body — strip transport-only fields, keep the rest as the notable.
    return req.model_dump(exclude={"secret", "result"})


@router.post(
    "/api/incidents/ingest",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestResponse,
)
async def ingest(
    req: IngestRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> IngestResponse:
    if not settings.ingest_webhook_secret:
        log.error("ingest webhook secret not configured")
        raise HTTPException(status_code=503, detail="ingest_secret_not_configured")
    if not hmac.compare_digest(req.secret, settings.ingest_webhook_secret):
        raise HTTPException(status_code=401, detail="invalid_webhook_secret")

    tenant_id = UUID(DEV_TENANT_ID)
    incident_id = uuid4()
    notable_dict = _resolve_notable_dict(req)

    raw_key = f"raw/{tenant_id}/{incident_id}.json"
    try:
        upload_evidence(
            bucket=settings.minio_bucket_evidence,
            key=raw_key,
            body=json.dumps(notable_dict).encode("utf-8"),
            content_type="application/json",
        )
    except StorageError as exc:
        log.exception("evidence upload failed", incident_id=str(incident_id))
        raise HTTPException(status_code=502, detail="evidence_upload_failed") from exc

    try:
        notable = SplunkNotable.model_validate(notable_dict)
    except ValidationError as exc:
        log.warning("notable validation failed", errors=exc.errors())
        raise HTTPException(status_code=400, detail="invalid_notable") from exc

    try:
        finding = map_notable_to_ocsf(
            notable,
            finding_uid=str(incident_id),
            received_at_ms=int(time.time() * 1000),
        )
    except ValueError as exc:
        # `_time` parser raises ValueError on unparseable inputs — mapper is the
        # only call that can hit this (other fields are typed by Pydantic).
        log.warning("ocsf mapping failed", reason=str(exc))
        raise HTTPException(status_code=400, detail="invalid_notable_time") from exc

    ocsf_payload = finding.model_dump(exclude_none=True, mode="json")

    with tenant_session(tenant_id) as conn:
        conn.execute(
            text(
                """
                INSERT INTO incidents
                    (id, tenant_id, siem_source, siem_notable_id,
                     raw_payload_s3_key, ocsf_normalized, status)
                VALUES
                    (:id, :tenant_id, 'splunk', :siem_notable_id,
                     :raw_key, CAST(:ocsf AS jsonb), 'new')
                """
            ),
            {
                "id": str(incident_id),
                "tenant_id": str(tenant_id),
                "siem_notable_id": notable.rid,
                "raw_key": raw_key,
                "ocsf": json.dumps(ocsf_payload),
            },
        )
        insert_audit_log(
            conn,
            tenant_id=tenant_id,
            investigation_id=None,
            actor="webhook",
            action="incident_ingested",
            details={
                "siem_notable_id": notable.rid,
                "ocsf_uid": str(incident_id),
                "raw_payload_s3_key": raw_key,
            },
        )

    redis_client = redis_lib.Redis.from_url(settings.redis_url)
    job = IngestJob(
        incident_id=incident_id,
        tenant_id=tenant_id,
        enqueued_at=datetime.now(UTC),
        trace_id=uuid4().hex,
    )
    enqueue_investigation(redis_client, job)

    log.info(
        "incident ingested",
        incident_id=str(incident_id),
        tenant_id=str(tenant_id),
        trace_id=job.trace_id,
        siem_notable_id=notable.rid,
    )
    return IngestResponse(incident_id=incident_id)


__all__ = ["router"]
