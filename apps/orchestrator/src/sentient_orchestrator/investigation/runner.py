"""Tier-2 investigation entry point.

`run_tier2_investigation` is invoked in-process by the main `runner.py` after
Tier-1 escalation commits. It:

  1. Claims the `triaging` incident (atomic UPDATE → `investigating`).
  2. Loads the OCSF Detection Finding + triage context.
  3. Opens an MCP client + AsyncPostgresSaver checkpointer.
  4. Builds + runs the LangGraph investigation skeleton.
  5. Finalizes the investigation row + incident status.

Crash-resume: if the worker dies mid-graph, the checkpoint is still on disk.
A separate poll-based reaper (wk-12 hardening) is responsible for re-claiming
`investigating` rows whose Redis job was already consumed; wk-6 only proves
SAME-process resume via `ainvoke(None, config)`.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast
from uuid import UUID

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.types import Command
from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.db import tenant_session
from sentient_common.jobs import ResumeJob
from sentient_common.logging import get_logger
from sentient_ocsf.detection_finding import (
    DetectionFinding,
    validate_detection_finding,
)
from sentient_orchestrator.investigation.audit import (
    emit_budget_exceeded,
    emit_investigation_complete,
    emit_investigation_failed,
    emit_investigation_started,
    emit_manifest_upload_failed,
    emit_manifest_uploaded,
)
from sentient_orchestrator.investigation.evidence import (
    build_evidence_manifest,
    upload_manifest,
)
from sentient_orchestrator.investigation.graph import build_investigation_graph
from sentient_orchestrator.investigation.mcp_client import build_mcp_client
from sentient_orchestrator.investigation.state import (
    InvestigationOutput,
    InvestigationState,
)
from sentient_orchestrator.llm.exceptions import (
    BudgetExceeded,
    FallbackChainExhausted,
)
from sentient_orchestrator.mitre_lookup import fetch_technique_descriptions

log = get_logger(__name__)


def _strip_psycopg_dsn(database_url: str) -> str:
    """Same pattern as verify/runner — AsyncPostgresSaver wants native form."""
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def _make_thread_id(tenant_id: UUID, investigation_id: UUID) -> str:
    """Build the LangGraph thread_id binding tenant + investigation.

    Tenant prefix prevents the (theoretical) cross-tenant checkpoint mix-up
    where two tenants happen to mint colliding investigation UUIDs and
    LangGraph's checkpointer hands one tenant's state to another. Resume
    paths read `langgraph_thread_id` straight off the row, so old in-flight
    investigations keep finalizing under their stored shape — no parser
    needed.
    """
    return f"{tenant_id.hex}:{investigation_id.hex}"


async def run_tier2_investigation(
    *,
    investigation_id: UUID,
    tenant_id: UUID,
    incident_id: UUID,
) -> None:
    """Drive the Tier-2 investigation graph end-to-end for one incident.

    Idempotent claim: the atomic `status='triaging' → 'investigating'` UPDATE
    fails silently (rowcount==0) when the row is already claimed by another
    worker or no longer triaging. No retry — the redis pop already
    serialized the trigger.
    """
    # 1. Claim txn.
    claim = _claim_investigation(investigation_id, tenant_id, incident_id)
    if claim is None:
        log.warning(
            "investigation not in 'triaging' state; skipping (already claimed?)",
            investigation_id=str(investigation_id),
            incident_id=str(incident_id),
        )
        return
    finding, triage_ctx, thread_id = claim
    log.info(
        "tier-2 investigation claimed",
        investigation_id=str(investigation_id),
        incident_id=str(incident_id),
        thread_id=thread_id,
    )

    # 2. MITRE descriptions for the techniques flagged by triage.
    mitre_ids = list(triage_ctx.get("mitre_guesses", []) or [])
    with tenant_session(tenant_id) as conn:
        mitre_descs = fetch_technique_descriptions(conn, mitre_ids) if mitre_ids else {}

    # 3. Run the graph under MCP + AsyncPostgresSaver lifecycles.
    db_url = _strip_psycopg_dsn(os.environ.get("DATABASE_URL", ""))
    if not db_url:
        await _finalize_inconclusive(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            error_type="ConfigError",
            error_message="DATABASE_URL not configured",
            reason="config_missing_database_url",
        )
        return

    initial_state: InvestigationState = {
        "messages": [],
        "investigation_id": str(investigation_id),
        "tenant_id": str(tenant_id),
        "incident_id": str(incident_id),
        "triage_severity": triage_ctx.get("severity", "unknown"),
        "triage_confidence": int(triage_ctx.get("confidence", 0)),
        "triage_mitre_guesses": list(triage_ctx.get("mitre_guesses", []) or []),
        "triage_entities": list(triage_ctx.get("entities", []) or []),
        "triage_reasoning": triage_ctx.get("reasoning", "") or "",
        "tool_call_count": 0,
        "draft_verdict": None,
    }

    try:
        # MultiServerMCPClient is not an async context manager — sessions
        # are opened per `get_tools()` / per tool invocation under the hood.
        # Mirrors the verify/runner.py pattern.
        mcp_client = build_mcp_client()
        tools = await mcp_client.get_tools()
        log.info(
            "tier-2 mcp tools loaded",
            count=len(tools),
            names=[t.name for t in tools],
        )
        async with AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
            graph = build_investigation_graph().compile(checkpointer=checkpointer)
            config: RunnableConfig = {
                "configurable": {
                    "thread_id": thread_id,
                    "tenant_id": str(tenant_id),
                    "investigation_id": str(investigation_id),
                    "finding": finding,
                    "tools": tools,
                    "mitre_descs": mitre_descs,
                }
            }
            final_state = await graph.ainvoke(initial_state, config=config)
    except FallbackChainExhausted as exc:
        await _finalize_inconclusive(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            error_type="FallbackChainExhausted",
            error_message=f"role={exc.role} attempts={exc.attempts}",
            reason="fallback_chain_exhausted",
        )
        return
    except BudgetExceeded as exc:
        with tenant_session(tenant_id) as conn:
            emit_budget_exceeded(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                role=exc.role,
                total_cost_usd=exc.total_cost_usd,
                cap_usd=exc.cap_usd,
                total_tokens=exc.total_tokens,
                token_cap=exc.token_cap,
            )
        # Wk-7 round-2 fix R-1: keep this string generic — cap config + running
        # totals already flow through `emit_budget_exceeded` above with structured
        # fields. Including them here would duplicate the leak into
        # `audit_log.details.error_message`, which is a separate (RLS-scoped, but
        # eventually UI-surfaced) channel.
        await _finalize_inconclusive(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            error_type="BudgetExceeded",
            error_message=f"per-investigation budget exceeded for role={exc.role}",
            reason="budget_cap_exceeded",
        )
        return
    except Exception as exc:  # noqa: BLE001 — preserve audit chain
        await _finalize_inconclusive(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            error_type=type(exc).__name__,
            error_message=str(exc)[:500],
            reason="graph_unhandled_exception",
        )
        log.exception(
            "tier-2 graph raised unhandled exception",
            investigation_id=str(investigation_id),
        )
        return

    # 4. Detect HITL interrupt — graph paused at `await_approval_node`.
    #    incidents.status='awaiting_approval' + investigations.approval_status=
    #    'pending' already written by the node. The resumer (cli_resume.py for
    #    wk-8; web UI for wk-9) will re-enter via `Command(resume=...)` and
    #    eventually call `_finalize_after_graph`. We do nothing else here.
    if _is_interrupted(final_state):
        log.info(
            "tier-2 interrupted at await_approval; pending analyst",
            investigation_id=str(investigation_id),
        )
        return

    # 5. Finalize success / inconclusive.
    await _finalize_after_graph(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        finding=finding,
        final_state=cast(InvestigationState, final_state),
    )


def _is_interrupted(final_state: Any) -> bool:
    """Detect a LangGraph `interrupt()` pause across minor-version API shifts.

    1.x sets `__interrupt__` in state; defence-in-depth: also treat
    `approval_status == 'pending'` as an interrupt indicator (the node sets
    this before calling `interrupt()` and `writeback_status` is unset because
    the writeback node never ran).
    """
    if not isinstance(final_state, dict):
        return False
    if "__interrupt__" in final_state:
        return True
    if (
        final_state.get("approval_status") == "pending"
        and final_state.get("writeback_status") is None
    ):
        return True
    return False


async def _finalize_after_graph(
    *,
    investigation_id: UUID,
    tenant_id: UUID,
    incident_id: UUID,
    finding: DetectionFinding,
    final_state: InvestigationState,
) -> None:
    """Finalize after the graph has run to completion (no interrupt).

    Called from both `run_tier2_investigation` (initial) and `cli_resume.py`
    (after `Command(resume=...)`).
    """
    draft = final_state.get("draft_verdict") if final_state else None
    if not draft:
        await _finalize_inconclusive(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            error_type="MissingVerdict",
            error_message="graph completed without a draft verdict",
            reason="no_verdict_emitted",
        )
        return

    verdict = InvestigationOutput.model_validate(draft)
    review_output = final_state.get("review_output") if final_state else None
    await _finalize_done(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        verdict=verdict,
        review=review_output,
        approval_status=final_state.get("approval_status"),
        approver_id=final_state.get("approver_id"),
        approval_notes=final_state.get("approval_notes"),
        writeback_status=final_state.get("writeback_status"),
        writeback_attempts=list(final_state.get("writeback_attempts") or []),
        detection_rule_matches=list(final_state.get("detection_rule_matches") or []),
    )
    log.info(
        "tier-2 investigation complete",
        investigation_id=str(investigation_id),
        verdict=verdict.verdict,
        confidence=verdict.confidence,
        writeback_status=final_state.get("writeback_status"),
    )

    # Manifest upload is best-effort. The verdict is already finalized + the
    # `investigation_complete` audit row is in the chain — a MinIO outage must
    # not roll any of that back.
    _try_upload_manifest(
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        incident_id=incident_id,
        finding=finding,
        final_state=final_state,
        verdict=verdict,
        review=review_output,
    )


# ------------------------------------------------------------------ helpers


def _claim_investigation(
    investigation_id: UUID, tenant_id: UUID, incident_id: UUID
) -> tuple[DetectionFinding, dict[str, Any], str] | None:
    """Atomic claim. Returns (finding, triage_ctx, thread_id) or None if not claimable."""
    thread_id = _make_thread_id(tenant_id, investigation_id)
    with tenant_session(tenant_id) as conn:
        # Pull triage context off the investigation row (wk-5 wrote these).
        inv_row = conn.execute(
            text("""
                SELECT severity, confidence, mitre_techniques, summary,
                       inconclusive_reason
                  FROM investigations
                 WHERE id = :id
                """),
            {"id": str(investigation_id)},
        ).first()
        if inv_row is None:
            return None
        if (inv_row[4] or "") != "tier_2_pending_wk6":
            # Either already processed, or not Tier-2 work.
            return None

        # Atomic claim of the incident row.
        result = conn.execute(
            text("""
                UPDATE incidents SET status = 'investigating'
                 WHERE id = :id AND status = 'triaging'
                """),
            {"id": str(incident_id)},
        )
        if result.rowcount == 0:
            return None

        # Load the OCSF finding off the incident.
        ocsf_row = conn.execute(
            text("SELECT ocsf_normalized FROM incidents WHERE id = :id"),
            {"id": str(incident_id)},
        ).first()
        if ocsf_row is None or not ocsf_row[0]:
            msg = f"incident {incident_id} missing ocsf_normalized payload"
            raise RuntimeError(msg)
        finding = validate_detection_finding(ocsf_row[0])

        # Mark thread id + clear the pending flag.
        conn.execute(
            text("""
                UPDATE investigations
                   SET langgraph_thread_id = :tid,
                       inconclusive_reason = NULL
                 WHERE id = :id
                """),
            {"id": str(investigation_id), "tid": thread_id},
        )

        confidence = inv_row[1]
        if isinstance(confidence, Decimal):
            confidence_int = int(confidence * 100)
        else:
            confidence_int = int((confidence or 0) * 100)
        triage_ctx = {
            "severity": inv_row[0] or "unknown",
            "confidence": confidence_int,
            "mitre_guesses": list(inv_row[2] or []),
            "entities": [],  # Not currently round-tripped through DB; wk-7 may add.
            "reasoning": inv_row[3] or "",
        }

        emit_investigation_started(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            thread_id=thread_id,
            triage_summary=triage_ctx,
        )

    return finding, triage_ctx, thread_id


async def _finalize_done(
    *,
    investigation_id: UUID,
    tenant_id: UUID,
    incident_id: UUID,
    verdict: InvestigationOutput,
    review: dict[str, Any] | None,
    approval_status: str | None = None,
    approver_id: str | None = None,
    approval_notes: str | None = None,
    writeback_status: str | None = None,
    writeback_attempts: list[dict[str, Any]] | None = None,
    detection_rule_matches: list[dict[str, Any]] | None = None,
) -> None:
    completed_at = datetime.now(UTC)
    with tenant_session(tenant_id) as conn:
        _update_investigation_with_verdict(
            conn,
            investigation_id=investigation_id,
            verdict=verdict,
            completed_at=completed_at,
        )
        if review is not None:
            _update_investigation_with_review(
                conn,
                investigation_id=investigation_id,
                review=review,
            )
        _update_investigation_wk8_surface(
            conn,
            investigation_id=investigation_id,
            approval_status=approval_status,
            approver_id=approver_id,
            approval_notes=approval_notes,
            writeback_status=writeback_status,
            writeback_attempts=writeback_attempts or [],
            detection_rule_matches=detection_rule_matches or [],
        )
        conn.execute(
            text("UPDATE incidents SET status = 'done' WHERE id = :id"),
            {"id": str(incident_id)},
        )
        emit_investigation_complete(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            verdict=verdict.verdict,
            status_after="done",
        )


async def _finalize_inconclusive(
    *,
    investigation_id: UUID,
    tenant_id: UUID,
    incident_id: UUID,
    error_type: str,
    error_message: str,
    reason: str,
) -> None:
    completed_at = datetime.now(UTC)
    with tenant_session(tenant_id) as conn:
        conn.execute(
            text("""
                UPDATE investigations
                   SET verdict = 'inconclusive',
                       inconclusive_reason = :reason,
                       completed_at = :completed_at
                 WHERE id = :id
                """),
            {
                "id": str(investigation_id),
                "reason": reason,
                "completed_at": completed_at,
            },
        )
        conn.execute(
            text("UPDATE incidents SET status = 'inconclusive' WHERE id = :id"),
            {"id": str(incident_id)},
        )
        emit_investigation_failed(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            error_type=error_type,
            error_message=error_message,
            reason=reason,
        )


def _update_investigation_with_verdict(
    conn: Connection,
    *,
    investigation_id: UUID,
    verdict: InvestigationOutput,
    completed_at: datetime,
) -> None:
    conn.execute(
        text("""
            UPDATE investigations
               SET verdict = :verdict,
                   confidence = :confidence,
                   severity = :severity,
                   mitre_techniques = CAST(:techniques AS text[]),
                   summary = :summary,
                   ocsf_output = CAST(:ocsf AS jsonb),
                   inconclusive_reason = NULL,
                   completed_at = :completed_at
             WHERE id = :id
            """),
        {
            "id": str(investigation_id),
            "verdict": verdict.verdict,
            "confidence": round(verdict.confidence / 100.0, 2),
            "severity": verdict.severity,
            "techniques": _pg_text_array(verdict.mitre_techniques),
            "summary": verdict.summary,
            "ocsf": json.dumps(verdict.model_dump()),
            "completed_at": completed_at,
        },
    )


def _update_investigation_wk8_surface(
    conn: Connection,
    *,
    investigation_id: UUID,
    approval_status: str | None,
    approver_id: str | None,
    approval_notes: str | None,
    writeback_status: str | None,
    writeback_attempts: list[dict[str, Any]],
    detection_rule_matches: list[dict[str, Any]],
) -> None:
    """Wk-8. Persist HITL + writeback + detection-rule fields.

    The `approver_id` column is the application-level mirror — always set when
    an analyst-supplied identifier was provided (string form, UUID-validated).
    `human_approved_by` is the FK to `users.id`. To avoid a FK-violation
    rollback when the analyst's UUID isn't a real user (CLI dev hack;
    misconfigured wk-9 UI), we resolve it via a subquery `(SELECT id FROM
    users WHERE id = :candidate)` — missing user → NULL → `COALESCE` preserves
    the existing FK column.
    """
    candidate_uuid = None
    if approver_id:
        try:
            candidate_uuid = str(UUID(approver_id))
        except ValueError:
            candidate_uuid = None
    conn.execute(
        text("""
            WITH resolved AS (
                SELECT id AS user_id
                  FROM users
                 WHERE id = CAST(:candidate AS UUID)
            )
            UPDATE investigations
               SET approval_status = :approval_status,
                   approver_id = :approver_id,
                   approval_notes = :approval_notes,
                   writeback_status = :writeback_status,
                   writeback_attempts = CAST(:writeback_attempts AS jsonb),
                   detection_rule_matches = CAST(:detection_rule_matches AS jsonb),
                   human_approved_by = COALESCE(
                       (SELECT user_id FROM resolved),
                       human_approved_by
                   ),
                   human_approved_at = CASE
                       WHEN (SELECT user_id FROM resolved) IS NOT NULL
                            AND human_approved_at IS NULL
                            THEN NOW()
                       ELSE human_approved_at
                   END
             WHERE id = :id
            """),
        {
            "id": str(investigation_id),
            "approval_status": approval_status,
            "approver_id": candidate_uuid,
            "approval_notes": approval_notes,
            "writeback_status": writeback_status,
            "writeback_attempts": json.dumps(writeback_attempts),
            "detection_rule_matches": json.dumps(detection_rule_matches),
            "candidate": candidate_uuid,
        },
    )


def _update_investigation_with_review(
    conn: Connection,
    *,
    investigation_id: UUID,
    review: dict[str, Any],
) -> None:
    """Wk-7. Persist review_status / notes / metadata. `review_notes` already
    exists from initial schema (line 118 of 81e2d43b3ec0); `review_status` +
    `review_metadata` arrive in `c1d8e3f4a9b2_wk7_cost_cap_review.py`.
    """
    conn.execute(
        text("""
            UPDATE investigations
               SET review_status = :status,
                   review_notes = :notes,
                   review_metadata = CAST(:meta AS jsonb)
             WHERE id = :id
            """),
        {
            "id": str(investigation_id),
            "status": review.get("status"),
            "notes": review.get("notes"),
            "meta": json.dumps(review),
        },
    )


def _try_upload_manifest(
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    incident_id: UUID,
    finding: DetectionFinding,
    final_state: InvestigationState,
    verdict: InvestigationOutput,
    review: dict[str, Any] | None,
) -> None:
    """Wk-7. Best-effort manifest upload. Never raises.

    Verdict is already finalized + `investigation_complete` is in the audit
    chain by the time this runs. MinIO down → log + emit
    `manifest_upload_failed`, leave `evidence_s3_key` NULL, move on.
    """
    try:
        with tenant_session(tenant_id) as conn:
            manifest = build_evidence_manifest(
                conn=conn,
                investigation_id=investigation_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                finding=finding,
                final_state=final_state,
                verdict=verdict,
                review=review,
            )
        bucket, key, size_bytes = upload_manifest(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            manifest=manifest,
        )
        with tenant_session(tenant_id) as conn:
            conn.execute(
                text("UPDATE investigations SET evidence_s3_key = :k WHERE id = :id"),
                {"k": key, "id": str(investigation_id)},
            )
            emit_manifest_uploaded(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                bucket=bucket,
                key=key,
                size_bytes=size_bytes,
            )
        log.info(
            "evidence manifest uploaded",
            investigation_id=str(investigation_id),
            bucket=bucket,
            key=key,
            size_bytes=size_bytes,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; verdict already done
        log.exception(
            "evidence manifest upload failed; verdict still finalized",
            investigation_id=str(investigation_id),
        )
        try:
            with tenant_session(tenant_id) as conn:
                emit_manifest_upload_failed(
                    conn,
                    tenant_id=tenant_id,
                    investigation_id=investigation_id,
                    error_type=type(exc).__name__,
                    error_message=str(exc)[:500],
                )
        except Exception:  # noqa: BLE001 — ledger write failed too; just log.
            log.exception(
                "manifest_upload_failed audit emit also failed",
                investigation_id=str(investigation_id),
            )


def _pg_text_array(items: list[str]) -> str:
    """Render T-codes as a Postgres TEXT[] literal. Pattern-validated upstream."""
    return "{" + ",".join(items) + "}"


# ---------------------------------------------------------------- resume entry


def _load_resume_context(
    investigation_id: UUID, tenant_id: UUID
) -> tuple[UUID, str, DetectionFinding, list[str]]:
    """Pull incident_id, thread_id, OCSF finding, MITRE technique IDs.

    Reads under `tenant_session(tenant_id)` so RLS is in effect (the API
    has already authenticated the analyst against the tenant; the worker
    inherits that authority via the ResumeJob).
    """
    with tenant_session(tenant_id) as conn:
        inv_row = conn.execute(
            text("""
                SELECT incident_id, langgraph_thread_id, mitre_techniques
                  FROM investigations WHERE id = :id
                """),
            {"id": str(investigation_id)},
        ).first()
        if inv_row is None:
            msg = f"investigation {investigation_id} not found"
            raise RuntimeError(msg)
        incident_id = UUID(str(inv_row[0]))
        thread_id = str(inv_row[1]) if inv_row[1] else ""
        if not thread_id:
            msg = (
                f"investigation {investigation_id} has no langgraph_thread_id; " "not interruptable"
            )
            raise RuntimeError(msg)
        mitre_ids = list(inv_row[2] or [])

        ocsf_row = conn.execute(
            text("SELECT ocsf_normalized FROM incidents WHERE id = :id"),
            {"id": str(incident_id)},
        ).first()
        if ocsf_row is None or not ocsf_row[0]:
            msg = f"incident {incident_id} missing ocsf_normalized"
            raise RuntimeError(msg)
    finding = validate_detection_finding(ocsf_row[0])
    return incident_id, thread_id, finding, mitre_ids


async def resume_investigation(job: ResumeJob) -> int:
    """Resume a paused LangGraph thread with the analyst's decision.

    Called by both the wk-9 worker (`QUEUE_RESUMES`) and the wk-8 CLI hack
    (`cli_resume.py`). Re-attaches the same MCP toolset + AsyncPostgresSaver
    the original run used, then `Command(resume=...)`s the graph past
    `await_approval_node`. After completion calls `_finalize_after_graph`
    so the verdict + writeback + approval surface lands on the
    investigations row.

    Returns 0 on clean completion, 2 if the graph re-entered an interrupted
    state (shouldn't happen with a single approval node — defensive log).
    """
    investigation_id = job.investigation_id
    tenant_id = job.tenant_id
    incident_id, thread_id, finding, mitre_ids = _load_resume_context(investigation_id, tenant_id)

    with tenant_session(tenant_id) as conn:
        mitre_descs = fetch_technique_descriptions(conn, mitre_ids) if mitre_ids else {}

    mcp_client = build_mcp_client()
    tools = await mcp_client.get_tools()

    db_url = _strip_psycopg_dsn(os.environ.get("DATABASE_URL", ""))
    if not db_url:
        msg = "DATABASE_URL not configured"
        raise RuntimeError(msg)

    async with AsyncPostgresSaver.from_conn_string(db_url) as checkpointer:
        graph = build_investigation_graph().compile(checkpointer=checkpointer)
        config: RunnableConfig = {
            "configurable": {
                "thread_id": thread_id,
                "tenant_id": str(tenant_id),
                "investigation_id": str(investigation_id),
                "finding": finding,
                "tools": tools,
                "mitre_descs": mitre_descs,
            }
        }
        resume_payload: dict[str, Any] = {
            "approved": job.approved,
            "analyst_id": job.analyst_id,
            "notes": job.notes,
        }
        log.info(
            "resuming investigation",
            investigation_id=str(investigation_id),
            thread_id=thread_id,
            approved=job.approved,
            trace_id=job.trace_id,
        )
        final_state = await graph.ainvoke(Command(resume=resume_payload), config=config)

    if _is_interrupted(final_state):
        log.warning(
            "graph re-entered interrupted state after resume",
            investigation_id=str(investigation_id),
        )
        return 2

    await _finalize_after_graph(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        finding=finding,
        final_state=cast(InvestigationState, final_state),
    )
    return 0


__all__ = ["resume_investigation", "run_tier2_investigation"]
