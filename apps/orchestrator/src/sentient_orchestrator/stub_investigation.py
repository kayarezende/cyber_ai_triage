"""Wk-4 stub investigation handler.

Worker calls `run_stub_investigation(job)` after popping an `IngestJob` from
Redis. Inserts a placeholder `investigations` row with verdict `inconclusive`,
flips the corresponding `incidents.status` to `done`, and writes an audit log
entry. No LLM, no MCP tools — `LLMRouter` lands wk-5, real LangGraph wk-6.

The function lives in the orchestrator package so the import path is stable
when wk-6 swaps the body for the real runner — workers + tests don't move.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import text

from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session
from sentient_common.jobs import IngestJob
from sentient_common.logging import get_logger

_STUB_SUMMARY = "wk-4 stub — LLM pipeline lands wk-5"
log = get_logger(__name__)


def run_stub_investigation(job: IngestJob) -> UUID:
    """Insert investigation + audit row, mark incident done, return investigation_id.

    Idempotency: out of scope for wk-4 — at-most-once via Redis BLPOP. Reliable
    queue + retry guard land wk-6.
    """
    investigation_id = uuid4()
    now = datetime.now(UTC)

    with tenant_session(job.tenant_id) as conn:
        conn.execute(
            text(
                """
                INSERT INTO investigations
                    (id, tenant_id, incident_id, started_at, completed_at,
                     verdict, confidence, severity, mitre_techniques, summary)
                VALUES
                    (:id, :tenant_id, :incident_id, :started_at, :completed_at,
                     'inconclusive', 0.0, 'info', CAST(:techniques AS text[]), :summary)
                """
            ),
            {
                "id": str(investigation_id),
                "tenant_id": str(job.tenant_id),
                "incident_id": str(job.incident_id),
                "started_at": now,
                "completed_at": now,
                "techniques": "{}",
                "summary": _STUB_SUMMARY,
            },
        )
        conn.execute(
            text("UPDATE incidents SET status = 'done' WHERE id = :id"),
            {"id": str(job.incident_id)},
        )
        insert_audit_log(
            conn,
            tenant_id=job.tenant_id,
            investigation_id=investigation_id,
            actor="worker",
            action="stub_investigation_completed",
            details={
                "verdict": "inconclusive",
                "reason": "wk-4 stub",
                "incident_id": str(job.incident_id),
                "trace_id": job.trace_id,
            },
        )

    log.info(
        "stub investigation written",
        investigation_id=str(investigation_id),
        incident_id=str(job.incident_id),
        tenant_id=str(job.tenant_id),
        trace_id=job.trace_id,
    )
    return investigation_id


__all__ = ["run_stub_investigation"]
