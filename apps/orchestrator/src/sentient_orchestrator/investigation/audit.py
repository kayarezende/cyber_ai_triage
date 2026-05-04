"""Audit log emit helpers for Tier-2 investigation.

Thin wrappers over `sentient_common.audit.insert_audit_log` so node code
doesn't have to spell out `actor='orchestrator:investigation'` + scope at
each call site. Each function records one row; per-attempt LLM `usage` rows
land separately via `LLMRouter` itself.

Args + result snippets pass through `walk_and_sanitize` before insert so
attacker-controlled tool output can't smuggle control chars / huge blobs into
the audit chain.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.audit import insert_audit_log
from sentient_common.db import tenant_session
from sentient_common.logging import get_logger
from sentient_orchestrator.investigation.sanitizer import walk_and_sanitize

log = get_logger(__name__)

#: Per-field cap on audit detail summaries. Tighter than the LLM-context
#: cap (4KB) so a noisy tool blob doesn't dominate the audit row.
_AUDIT_FIELD_CHARS = 1024

ACTOR = "orchestrator:investigation"


def emit_investigation_started(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    thread_id: str,
    triage_summary: dict[str, Any],
) -> None:
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="investigation_started",
        details=walk_and_sanitize(
            {"thread_id": thread_id, "triage": triage_summary},
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_llm_call(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    phase: str,
    model_used: str,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int,
    latency_ms: int,
) -> None:
    """Per-LLM-call audit row. Per-attempt token cost lives in `usage`."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="llm_call",
        details={
            "phase": phase,
            "model_used": model_used,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "latency_ms": latency_ms,
        },
    )


def emit_tool_call(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    tool_name: str,
    args: dict[str, Any],
    result_text: str,
    latency_ms: int,
) -> None:
    """One row per tool invocation. Args + result are sanitized + capped."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="tool_call",
        details=walk_and_sanitize(
            {
                "tool_name": tool_name,
                "args": args,
                "result_summary": result_text,
                "latency_ms": latency_ms,
            },
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_verdict_drafted(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    verdict: str,
    confidence: int,
    severity: str,
    mitre_techniques: list[str],
) -> None:
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="verdict_drafted",
        details={
            "verdict": verdict,
            "confidence": confidence,
            "severity": severity,
            "mitre_techniques": mitre_techniques,
        },
    )


def emit_investigation_complete(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    verdict: str,
    status_after: str,
) -> None:
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="investigation_complete",
        details={"verdict": verdict, "status_after": status_after},
    )


def emit_investigation_failed(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    error_type: str,
    error_message: str,
    reason: str,
) -> None:
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="investigation_failed",
        details=walk_and_sanitize(
            {
                "error_type": error_type,
                "error_message": error_message,
                "reason": reason,
            },
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_budget_exceeded(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    role: str,
    total_cost_usd: Any,
    cap_usd: Any,
    total_tokens: int | None,
    token_cap: int | None,
) -> None:
    """Wk-7. One row when `LLMRouter._check_budget` raises pre-call."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="budget_exceeded",
        details={
            "role": role,
            "total_cost_usd": str(total_cost_usd) if total_cost_usd is not None else None,
            "cap_usd": str(cap_usd) if cap_usd is not None else None,
            "total_tokens": total_tokens,
            "token_cap": token_cap,
        },
    )


def emit_review_started(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    model_used: str,
) -> None:
    """Wk-7. Review-role node entry."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="review_started",
        details={"model_used": model_used},
    )


def emit_review_complete(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    status: str,
    hallucination_risk: str,
    confidence_assessment: str,
    flagged_claim_count: int,
) -> None:
    """Wk-7. Review-role node exit (approved or flagged)."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="review_complete",
        details={
            "status": status,
            "hallucination_risk": hallucination_risk,
            "confidence_assessment": confidence_assessment,
            "flagged_claim_count": flagged_claim_count,
        },
    )


def emit_review_skipped(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    reason: str,
) -> None:
    """Wk-7. Review-role best-effort failure (FallbackChainExhausted etc)."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="review_skipped",
        details=walk_and_sanitize({"reason": reason}, max_chars=_AUDIT_FIELD_CHARS),
    )


def emit_manifest_uploaded(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    bucket: str,
    key: str,
    size_bytes: int,
) -> None:
    """Wk-7. Evidence manifest landed in MinIO."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="manifest_uploaded",
        details={"bucket": bucket, "key": key, "size_bytes": size_bytes},
    )


def emit_manifest_upload_failed(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    error_type: str,
    error_message: str,
) -> None:
    """Wk-7. MinIO upload failed; verdict already finalized — best-effort."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="manifest_upload_failed",
        details=walk_and_sanitize(
            {"error_type": error_type, "error_message": error_message},
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_detection_rules_evaluated(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    evaluated_count: int,
    matched_count: int,
    matched_rules: list[str],
    agent_severity: str,
    effective_severity: str,
    severity_overridden: bool,
) -> None:
    """Wk-8. Deterministic detection-rule pass output."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="detection_rules_evaluated",
        details=walk_and_sanitize(
            {
                "evaluated_count": evaluated_count,
                "matched_count": matched_count,
                "matched_rules": matched_rules,
                "agent_severity": agent_severity,
                "effective_severity": effective_severity,
                "severity_overridden": severity_overridden,
            },
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_awaiting_approval(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    policy_id: UUID | None,
    policy_name: str,
    decision_ctx: dict[str, Any],
) -> None:
    """Wk-8. HITL gate fired; investigation is interrupted pending analyst."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="awaiting_approval",
        details=walk_and_sanitize(
            {
                "policy_id": str(policy_id) if policy_id else None,
                "policy_name": policy_name,
                "decision_ctx": decision_ctx,
            },
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_approval_received(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    approver_id: str | None,
    approved: bool,
    notes: str,
    policy_id: UUID | None,
    policy_name: str,
) -> None:
    """Wk-8. Analyst approved or rejected (or HITL auto-approved)."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="approval_received",
        details=walk_and_sanitize(
            {
                "approver_id": approver_id,
                "approved": approved,
                "notes": notes,
                "policy_id": str(policy_id) if policy_id else None,
                "policy_name": policy_name,
            },
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_hitl_policy_evaluation_failed(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    policy_id: UUID | None,
    policy_name: str | None,
    error_message: str,
    decision_ctx: dict[str, Any],
) -> None:
    """Cluster B HIGH-4. Policy walker raised at runtime; await_approval fell
    back to needs_human=True. The audit row names the broken policy so admins
    can fix it without trawling logs."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="hitl_policy_evaluation_failed",
        details=walk_and_sanitize(
            {
                "policy_id": str(policy_id) if policy_id else None,
                "policy_name": policy_name,
                "error_message": error_message,
                "decision_ctx": decision_ctx,
            },
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_writeback_tenant_missing(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
) -> None:
    """Cluster B HIGH-2. `_load_writeback_mode` couldn't find the tenant row.
    Distinct signal from `writeback_failed` so admins can tell a tenant-config
    bug apart from a Splunk transport failure."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="writeback_tenant_missing",
        details={"tenant_id": str(tenant_id)},
    )


def emit_writeback_attempted(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    mode: str,
    hec_index: str | None,
    notable_update_target: str | None,
) -> None:
    """Wk-8. About to push the verdict back to Splunk."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="writeback_attempted",
        details=walk_and_sanitize(
            {
                "mode": mode,
                "hec_index": hec_index,
                "notable_update_target": notable_update_target,
            },
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_writeback_succeeded(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    mode: str,
    attempts: list[dict[str, Any]],
) -> None:
    """Wk-8. All writeback paths succeeded."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="writeback_succeeded",
        details=walk_and_sanitize(
            {"mode": mode, "attempts": attempts},
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_writeback_failed(
    conn: Connection,
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    mode: str,
    attempts: list[dict[str, Any]],
    error: str,
) -> None:
    """Wk-8. At least one writeback path failed; verdict still committed."""
    insert_audit_log(
        conn,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        actor=ACTOR,
        action="writeback_failed",
        details=walk_and_sanitize(
            {"mode": mode, "attempts": attempts, "error": error},
            max_chars=_AUDIT_FIELD_CHARS,
        ),
    )


def emit_with_fallback(
    emit_fn: Callable[..., None],
    *,
    tenant_id: UUID,
    investigation_id: UUID | None,
    fallback_action: str,
    **kwargs: Any,
) -> None:
    """Wrap an audit emit with an ``audit_chain_gap`` fallback.

    Cluster E HIGH-12: bare ``try/except: log.exception(...)`` swallowed audit
    emit failures silently. ``verify_chain`` then accepted the partial chain
    as intact — the dropped row was invisible. This wrapper opens its own
    ``tenant_session`` so callers don't have to manage one, then on emit
    failure logs structured + INSERTs an ``audit_chain_gap`` row recording
    the action + the error. If THAT also fails, log and continue
    (best-effort — we are already on the failure path).

    Args:
      emit_fn: One of the ``emit_*`` helpers in this module. Called as
        ``emit_fn(conn, tenant_id=..., investigation_id=..., **kwargs)``.
      tenant_id: Required for ``tenant_session`` and the gap row.
      investigation_id: ``None`` for tenant-scope audits (allowed).
      fallback_action: Short name of the action that was being emitted.
        Used as the gap row's ``attempted_action`` so admins can grep.
      **kwargs: Forwarded to ``emit_fn``.
    """
    try:
        with tenant_session(tenant_id) as conn:
            emit_fn(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                **kwargs,
            )
        return
    except Exception as exc:  # noqa: BLE001 — audit must not propagate
        error_message = f"{type(exc).__name__}: {exc!s}"[:500]
        log.exception(
            "audit emit failed; recording in audit_chain_gap",
            attempted_action=fallback_action,
            tenant_id=str(tenant_id),
            investigation_id=str(investigation_id) if investigation_id else None,
        )
        try:
            with tenant_session(tenant_id) as conn:
                conn.execute(
                    text("""
                        INSERT INTO audit_chain_gap
                            (tenant_id, investigation_id,
                             attempted_action, error_message)
                        VALUES
                            (:tenant_id, :investigation_id,
                             :attempted_action, :error_message)
                        """),
                    {
                        "tenant_id": str(tenant_id),
                        "investigation_id": (str(investigation_id) if investigation_id else None),
                        "attempted_action": fallback_action,
                        "error_message": error_message,
                    },
                )
        except Exception:  # noqa: BLE001 — gap insert also best-effort
            log.exception(
                "audit_chain_gap insert also failed; surface lost",
                attempted_action=fallback_action,
                tenant_id=str(tenant_id),
            )


__all__ = [
    "ACTOR",
    "emit_approval_received",
    "emit_awaiting_approval",
    "emit_budget_exceeded",
    "emit_detection_rules_evaluated",
    "emit_investigation_complete",
    "emit_investigation_failed",
    "emit_investigation_started",
    "emit_llm_call",
    "emit_manifest_upload_failed",
    "emit_manifest_uploaded",
    "emit_review_complete",
    "emit_review_skipped",
    "emit_review_started",
    "emit_tool_call",
    "emit_verdict_drafted",
    "emit_with_fallback",
    "emit_writeback_attempted",
    "emit_writeback_failed",
    "emit_writeback_succeeded",
]
