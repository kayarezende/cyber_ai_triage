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

from typing import Any
from uuid import UUID

from sqlalchemy.engine import Connection

from sentient_common.audit import insert_audit_log
from sentient_orchestrator.investigation.sanitizer import walk_and_sanitize

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


__all__ = [
    "ACTOR",
    "emit_investigation_complete",
    "emit_investigation_failed",
    "emit_investigation_started",
    "emit_llm_call",
    "emit_tool_call",
    "emit_verdict_drafted",
]
