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
from typing import Any
from uuid import UUID

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.db import tenant_session
from sentient_common.logging import get_logger
from sentient_ocsf.detection_finding import (
    DetectionFinding,
    validate_detection_finding,
)
from sentient_orchestrator.investigation.audit import (
    emit_investigation_complete,
    emit_investigation_failed,
    emit_investigation_started,
)
from sentient_orchestrator.investigation.graph import build_investigation_graph
from sentient_orchestrator.investigation.mcp_client import build_mcp_client
from sentient_orchestrator.investigation.state import (
    InvestigationOutput,
    InvestigationState,
)
from sentient_orchestrator.llm.exceptions import FallbackChainExhausted
from sentient_orchestrator.mitre_lookup import fetch_technique_descriptions

log = get_logger(__name__)


def _strip_psycopg_dsn(database_url: str) -> str:
    """Same pattern as verify/runner — AsyncPostgresSaver wants native form."""
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def _make_thread_id(investigation_id: UUID) -> str:
    return f"inv-{investigation_id.hex[:12]}"


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
        mitre_descs = (
            fetch_technique_descriptions(conn, mitre_ids) if mitre_ids else {}
        )

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

    # 4. Finalize success.
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
    await _finalize_done(
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        incident_id=incident_id,
        verdict=verdict,
    )
    log.info(
        "tier-2 investigation complete",
        investigation_id=str(investigation_id),
        verdict=verdict.verdict,
        confidence=verdict.confidence,
    )


# ------------------------------------------------------------------ helpers


def _claim_investigation(
    investigation_id: UUID, tenant_id: UUID, incident_id: UUID
) -> tuple[DetectionFinding, dict[str, Any], str] | None:
    """Atomic claim. Returns (finding, triage_ctx, thread_id) or None if not claimable."""
    thread_id = _make_thread_id(investigation_id)
    with tenant_session(tenant_id) as conn:
        # Pull triage context off the investigation row (wk-5 wrote these).
        inv_row = conn.execute(
            text(
                """
                SELECT severity, confidence, mitre_techniques, summary,
                       inconclusive_reason
                  FROM investigations
                 WHERE id = :id
                """
            ),
            {"id": str(investigation_id)},
        ).first()
        if inv_row is None:
            return None
        if (inv_row[4] or "") != "tier_2_pending_wk6":
            # Either already processed, or not Tier-2 work.
            return None

        # Atomic claim of the incident row.
        result = conn.execute(
            text(
                """
                UPDATE incidents SET status = 'investigating'
                 WHERE id = :id AND status = 'triaging'
                """
            ),
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
            text(
                """
                UPDATE investigations
                   SET langgraph_thread_id = :tid,
                       inconclusive_reason = NULL
                 WHERE id = :id
                """
            ),
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
) -> None:
    completed_at = datetime.now(UTC)
    with tenant_session(tenant_id) as conn:
        _update_investigation_with_verdict(
            conn,
            investigation_id=investigation_id,
            verdict=verdict,
            completed_at=completed_at,
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
            text(
                """
                UPDATE investigations
                   SET verdict = 'inconclusive',
                       inconclusive_reason = :reason,
                       completed_at = :completed_at
                 WHERE id = :id
                """
            ),
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
        text(
            """
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
            """
        ),
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


def _pg_text_array(items: list[str]) -> str:
    """Render T-codes as a Postgres TEXT[] literal. Pattern-validated upstream."""
    return "{" + ",".join(items) + "}"


__all__ = ["run_tier2_investigation"]
