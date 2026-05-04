"""Investigation runner — Tier-1 triage today, Tier-2 LangGraph wk-6.

Worker calls `await run_investigation(job)` after popping an `IngestJob`
from Redis. Loads the OCSF Detection Finding from the incident row, runs
the Tier-1 triage role via `LLMRouter`, branches on severity:

- `info` / `low`  → verdict `benign`, `incidents.status='done'`, auto-close.
- `medium`+      → verdict `inconclusive`, `inconclusive_reason='tier_2_pending_wk6'`,
                   `incidents.status` stays `triaging`. Wk-6 LangGraph claims
                   `triaging` rows + transitions `triaging → investigating → done`.
- All-fail        → verdict `inconclusive`, `inconclusive_reason` populated with
                   the model attempts, `incidents.status='inconclusive'`.

Audit trail: one row per state transition (triage_started, triage_auto_close
| triage_escalated | triage_failed_fallback_exhausted). Per-attempt LLM rows
land in `usage` via the `LLMRouter` itself.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session
from sentient_common.jobs import IngestJob
from sentient_common.logging import get_logger
from sentient_ocsf.detection_finding import (
    DetectionFinding,
    validate_detection_finding,
)
from sentient_orchestrator.investigation import run_tier2_investigation
from sentient_orchestrator.llm.exceptions import FallbackChainExhausted
from sentient_orchestrator.llm.router import LLMRouter
from sentient_orchestrator.mitre_lookup import fetch_technique_descriptions
from sentient_orchestrator.triage.role import run_triage
from sentient_orchestrator.triage.schemas import TriageOutput

log = get_logger(__name__)


async def run_investigation(job: IngestJob) -> UUID:
    """Run Tier-1 triage and (on escalation) Tier-2 investigation.

    Returns the `investigations.id` for the row created by triage. When triage
    escalates, Tier-2 runs in-process after the triage txn commits — the
    investigation state continues advancing without a second worker dispatch.
    """
    investigation_id = uuid4()
    now = datetime.now(UTC)
    was_escalated = False

    with tenant_session(job.tenant_id) as conn:
        finding = _load_finding(conn, job.incident_id)

        # Status guard: only transition `new → triaging`. A re-delivered job
        # against an already-claimed incident is a no-op signal.
        result = conn.execute(
            text("""
                UPDATE incidents SET status = 'triaging'
                WHERE id = :id AND status = 'new'
                """),
            {"id": str(job.incident_id)},
        )
        if result.rowcount == 0:
            log.warning(
                "incident not in 'new' state; skipping (re-delivered or already claimed)",
                incident_id=str(job.incident_id),
                trace_id=job.trace_id,
            )
            return investigation_id

        _insert_investigation_row(
            conn,
            investigation_id=investigation_id,
            tenant_id=job.tenant_id,
            incident_id=job.incident_id,
            started_at=now,
        )
        insert_audit_log(
            conn,
            tenant_id=job.tenant_id,
            investigation_id=investigation_id,
            actor="orchestrator:triage",
            action="triage_started",
            details={
                "incident_id": str(job.incident_id),
                "trace_id": job.trace_id,
            },
        )

        router = LLMRouter(job.tenant_id, conn)
        mitre_descs = fetch_technique_descriptions(conn, finding.mitre_techniques)

        try:
            triage = await run_triage(
                router=router,
                finding=finding,
                mitre_descs=mitre_descs,
                investigation_id=investigation_id,
            )
        except FallbackChainExhausted as exc:
            _finalize_fallback_exhausted(
                conn,
                investigation_id=investigation_id,
                incident_id=job.incident_id,
                tenant_id=job.tenant_id,
                reason=f"triage_fallback_chain_exhausted: {','.join(exc.attempts)}",
                details={"attempts": exc.attempts},
                completed_at=datetime.now(UTC),
            )
            log.warning(
                "triage fallback exhausted",
                investigation_id=str(investigation_id),
                incident_id=str(job.incident_id),
                attempts=exc.attempts,
            )
            return investigation_id
        except Exception as exc:  # noqa: BLE001 — preserve audit trail
            # Auth failures, network errors mid-call, etc. ADR-0017 demands
            # an audit row for every triage attempt; finalize as inconclusive
            # so the txn commits with the trail intact.
            _finalize_fallback_exhausted(
                conn,
                investigation_id=investigation_id,
                incident_id=job.incident_id,
                tenant_id=job.tenant_id,
                reason=f"triage_unexpected_error: {type(exc).__name__}",
                details={"error_type": type(exc).__name__, "error": str(exc)[:500]},
                completed_at=datetime.now(UTC),
            )
            log.exception(
                "triage failed with unexpected error",
                investigation_id=str(investigation_id),
                incident_id=str(job.incident_id),
            )
            return investigation_id

        completed_at = datetime.now(UTC)
        if triage.severity in ("info", "low"):
            _finalize_auto_close(
                conn,
                investigation_id=investigation_id,
                incident_id=job.incident_id,
                tenant_id=job.tenant_id,
                triage=triage,
                completed_at=completed_at,
            )
            log.info(
                "triage auto-closed benign",
                investigation_id=str(investigation_id),
                incident_id=str(job.incident_id),
                severity=triage.severity,
                confidence=triage.confidence,
            )
        else:
            _finalize_escalated(
                conn,
                investigation_id=investigation_id,
                incident_id=job.incident_id,
                tenant_id=job.tenant_id,
                triage=triage,
            )
            was_escalated = True
            log.info(
                "triage escalated to tier-2",
                investigation_id=str(investigation_id),
                incident_id=str(job.incident_id),
                severity=triage.severity,
                confidence=triage.confidence,
            )

    # Tier-2 runs OUTSIDE the triage txn so the escalation row + audit are
    # already durable when the long-running graph starts. Crash mid-graph
    # leaves the row in `triaging`/`investigating` for the wk-12 reaper to
    # pick up — same-process resume covered by the smoke test.
    if was_escalated:
        await run_tier2_investigation(
            investigation_id=investigation_id,
            tenant_id=job.tenant_id,
            incident_id=job.incident_id,
        )

    return investigation_id


# --------------------------------------------------------------------- helpers


def _load_finding(conn: Connection, incident_id: UUID) -> DetectionFinding:
    row = conn.execute(
        text("SELECT ocsf_normalized FROM incidents WHERE id = :id"),
        {"id": str(incident_id)},
    ).first()
    if row is None:
        msg = f"incident {incident_id} not found"
        raise RuntimeError(msg)
    payload = row[0]
    if not payload:
        msg = f"incident {incident_id} has no ocsf_normalized payload"
        raise RuntimeError(msg)
    return validate_detection_finding(payload)


def _insert_investigation_row(
    conn: Connection,
    *,
    investigation_id: UUID,
    tenant_id: UUID,
    incident_id: UUID,
    started_at: datetime,
) -> None:
    conn.execute(
        text("""
            INSERT INTO investigations
                (id, tenant_id, incident_id, started_at, severity, mitre_techniques)
            VALUES
                (:id, :tenant_id, :incident_id, :started_at,
                 'info', CAST(:techniques AS text[]))
            """),
        {
            "id": str(investigation_id),
            "tenant_id": str(tenant_id),
            "incident_id": str(incident_id),
            "started_at": started_at,
            "techniques": "{}",
        },
    )


def _finalize_auto_close(
    conn: Connection,
    *,
    investigation_id: UUID,
    incident_id: UUID,
    tenant_id: UUID,
    triage: TriageOutput,
    completed_at: datetime,
) -> None:
    _update_investigation_with_triage(
        conn,
        investigation_id=investigation_id,
        triage=triage,
        verdict="benign",
        inconclusive_reason=None,
        completed_at=completed_at,
    )
    conn.execute(
        text("UPDATE incidents SET status = 'done' WHERE id = :id"),
        {"id": str(incident_id)},
    )
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor="orchestrator:triage",
        action="triage_auto_close",
        details=_triage_audit_details(triage),
    )


def _finalize_escalated(
    conn: Connection,
    *,
    investigation_id: UUID,
    incident_id: UUID,
    tenant_id: UUID,
    triage: TriageOutput,
) -> None:
    """Persist triage placeholder + emit audit row for the escalated path.

    Does NOT set ``completed_at`` — Tier-2 owns it via ``_claim_finalize``.
    Setting it here would make Tier-2's atomic claim short-circuit on the
    happy path, leaving the LLM verdict + manifest unwritten and the audit
    chain missing its closing ``investigation_complete`` row.
    """
    _update_investigation_with_triage(
        conn,
        investigation_id=investigation_id,
        triage=triage,
        verdict="inconclusive",
        inconclusive_reason="tier_2_pending_wk6",
        completed_at=None,
    )
    # incidents.status stays 'triaging' — wk-6 Tier-2 claims triaging rows.
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor="orchestrator:triage",
        action="triage_escalated",
        details=_triage_audit_details(triage),
    )


def _finalize_fallback_exhausted(
    conn: Connection,
    *,
    investigation_id: UUID,
    incident_id: UUID,
    tenant_id: UUID,
    reason: str,
    details: dict[str, Any],
    completed_at: datetime,
) -> None:
    conn.execute(
        text("""
            UPDATE investigations
            SET verdict = 'inconclusive',
                severity = 'info',
                confidence = 0.0,
                summary = :summary,
                inconclusive_reason = :reason,
                completed_at = :completed_at
            WHERE id = :id
            """),
        {
            "id": str(investigation_id),
            "summary": "triage failed — analyst review needed",
            "reason": reason,
            "completed_at": completed_at,
        },
    )
    conn.execute(
        text("UPDATE incidents SET status = 'inconclusive' WHERE id = :id"),
        {"id": str(incident_id)},
    )
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor="orchestrator:triage",
        action="triage_failed_fallback_exhausted",
        details=details,
    )


def _update_investigation_with_triage(
    conn: Connection,
    *,
    investigation_id: UUID,
    triage: TriageOutput,
    verdict: str,
    inconclusive_reason: str | None,
    completed_at: datetime | None,
) -> None:
    """Persist triage output to the investigations row.

    ``completed_at`` is set ONLY for terminal triage outcomes (auto-benign,
    fallback-exhausted, unexpected error). For the escalated path, callers
    pass None — Tier-2 owns ``completed_at`` via cluster D's
    ``_claim_finalize`` (atomic NULL→NOW() flip), and any pre-set value
    silently breaks Tier-2 finalization (`_finalize_done` short-circuits,
    the LLM verdict + manifest never persist).
    """
    if completed_at is None:
        conn.execute(
            text("""
                UPDATE investigations
                SET verdict = :verdict,
                    severity = :severity,
                    confidence = :confidence,
                    summary = :summary,
                    mitre_techniques = CAST(:techniques AS text[]),
                    inconclusive_reason = :reason
                WHERE id = :id
                """),
            {
                "id": str(investigation_id),
                "verdict": verdict,
                "severity": triage.severity,
                "confidence": round(triage.confidence / 100.0, 2),
                "summary": triage.reasoning,
                "techniques": _pg_text_array(triage.mitre_guesses),
                "reason": inconclusive_reason,
            },
        )
        return
    conn.execute(
        text("""
            UPDATE investigations
            SET verdict = :verdict,
                severity = :severity,
                confidence = :confidence,
                summary = :summary,
                mitre_techniques = CAST(:techniques AS text[]),
                inconclusive_reason = :reason,
                completed_at = :completed_at
            WHERE id = :id
            """),
        {
            "id": str(investigation_id),
            "verdict": verdict,
            "severity": triage.severity,
            "confidence": round(triage.confidence / 100.0, 2),
            "summary": triage.reasoning,
            "techniques": _pg_text_array(triage.mitre_guesses),
            "reason": inconclusive_reason,
            "completed_at": completed_at,
        },
    )


def _triage_audit_details(triage: TriageOutput) -> dict[str, Any]:
    return {
        "severity": triage.severity,
        "confidence": triage.confidence,
        "mitre_guesses": triage.mitre_guesses,
        "entities_to_investigate": triage.entities_to_investigate,
        "reasoning": triage.reasoning,
    }


def _pg_text_array(items: list[str]) -> str:
    """Render a list of T-codes as a Postgres TEXT[] literal.

    `mitre_guesses` is constrained to `^T\\d+(\\.\\d+)?$` by the Pydantic
    schema, so values are safe to interpolate without quoting.
    """
    return "{" + ",".join(items) + "}"


__all__ = ["run_investigation"]
