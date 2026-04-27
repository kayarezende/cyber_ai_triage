"""Evidence manifest — per-investigation provenance bundle to MinIO.

Wk-7. After `_finalize_done` lands the verdict, the runner calls
`build_and_upload_manifest` which:

  1. Pulls the chat history out of `final_state["messages"]` (LangGraph
     StateGraph state — round-tripped through PostgresSaver).
  2. Pulls `tool_call` rows out of `audit_log` (single source of truth — the
     LangGraph state can be replayed but the audit chain is the contractual
     surface).
  3. Aggregates per-attempt token + cost rows out of `usage`.
  4. Assembles the manifest dict matching `tasks/todo.md` lines 357-380.
  5. Uploads as `manifests/{tenant_id}/{investigation_id}.json` to the
     `MINIO_BUCKET_EVIDENCE` bucket. Deterministic key — idempotent overwrite
     on resume.

Failure of the upload step does NOT roll back the verdict. The caller wraps
this in a try/except and emits `manifest_upload_failed` as best-effort audit.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from sentient_common.storage import upload_evidence
from sentient_ocsf.detection_finding import DetectionFinding
from sentient_orchestrator.investigation.state import (
    InvestigationOutput,
    InvestigationState,
)

DEFAULT_BUCKET = "evidence"


def _bucket() -> str:
    return os.environ.get("MINIO_BUCKET_EVIDENCE", DEFAULT_BUCKET)


def manifest_key(*, tenant_id: UUID, investigation_id: UUID) -> str:
    """Deterministic MinIO key. Idempotent on resume — overwrite is acceptable."""
    return f"manifests/{tenant_id}/{investigation_id}.json"


def _sha256_text(text_in: str) -> str:
    return "sha256:" + hashlib.sha256(text_in.encode("utf-8")).hexdigest()


def _filter_agent_turns(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop system + initial-user; keep assistant + tool turns (the trace)."""
    out: list[dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role in ("assistant", "tool"):
            # Strip the cacheable flag if it leaked here (it shouldn't — flag
            # only ever lives on system + initial user).
            out.append({k: v for k, v in msg.items() if k != "cacheable"})
    return out


def _load_tool_calls(conn: Connection, *, investigation_id: UUID) -> list[dict[str, Any]]:
    """Read tool_call audit rows; SHA256 each result_summary."""
    rows = conn.execute(
        text("""
            SELECT details
              FROM audit_log
             WHERE investigation_id = :id
               AND action = 'tool_call'
             ORDER BY id
            """),
        {"id": str(investigation_id)},
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        details = row[0] if row else None
        if not isinstance(details, dict):
            continue
        result_summary = str(details.get("result_summary") or "")
        out.append(
            {
                "tool": details.get("tool_name"),
                "args": details.get("args") or {},
                "result_hash": _sha256_text(result_summary) if result_summary else None,
                # wk-7 ships hash + audit-row excerpt only; per-result MinIO
                # upload is wk-8/9 work when the analyst UI consumes it.
                "result_s3_key": None,
                "latency_ms": details.get("latency_ms"),
            }
        )
    return out


def _load_usage_summary(
    conn: Connection, *, investigation_id: UUID
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Aggregate token + cost totals + per-attempt entries from `usage`."""
    rows = conn.execute(
        text("""
            SELECT role, model_requested, model_used, status,
                   attempt_num, input_tokens, output_tokens, cached_tokens,
                   cost_usd
              FROM usage
             WHERE investigation_id = :id
             ORDER BY id
            """),
        {"id": str(investigation_id)},
    ).fetchall()
    total_in = total_out = total_cached = 0
    total_cost = 0.0
    attempts: list[dict[str, Any]] = []
    for row in rows:
        (
            role,
            model_req,
            model_used,
            status,
            attempt_num,
            in_tok,
            out_tok,
            cached_tok,
            cost,
        ) = row
        if status == "success":
            total_in += int(in_tok or 0)
            total_out += int(out_tok or 0)
            total_cached += int(cached_tok or 0)
            if cost is not None:
                total_cost += float(cost)
        attempts.append(
            {
                "role": role,
                "model_requested": model_req,
                "model_used": model_used,
                "status": status,
                "attempt_num": attempt_num,
                "cost_usd": float(cost) if cost is not None else None,
            }
        )
    cache_hit_rate = (total_cached / total_in) if total_in else 0.0
    token_usage = {
        "input": total_in,
        "output": total_out,
        "cached": total_cached,
        "cost_usd": round(total_cost, 6),
        "cache_hit_rate": round(cache_hit_rate, 4),
    }
    return token_usage, attempts


def build_evidence_manifest(
    *,
    conn: Connection,
    investigation_id: UUID,
    tenant_id: UUID,
    incident_id: UUID,
    finding: DetectionFinding,
    final_state: InvestigationState,
    verdict: InvestigationOutput,
    review: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assemble the manifest dict per `tasks/todo.md` lines 357-380."""
    triage_result = {
        "severity": final_state.get("triage_severity"),
        "confidence": final_state.get("triage_confidence"),
        "mitre_guesses": list(final_state.get("triage_mitre_guesses", []) or []),
        "entities": list(final_state.get("triage_entities", []) or []),
        "reasoning": final_state.get("triage_reasoning"),
    }
    agent_turns = _filter_agent_turns(list(final_state.get("messages") or []))
    tool_calls = _load_tool_calls(conn, investigation_id=investigation_id)
    token_usage, attempts = _load_usage_summary(conn, investigation_id=investigation_id)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "investigation_id": str(investigation_id),
        "tenant_id": str(tenant_id),
        "incident_id": str(incident_id),
        "incident": {"ocsf": finding.model_dump(mode="json", exclude_none=True)},
        "triage_result": triage_result,
        "agent_turns": agent_turns,
        "tool_calls": tool_calls,
        "draft_verdict": final_state.get("draft_verdict"),
        "review": review,
        "review_notes": (review or {}).get("notes") if review else None,
        "mitre_techniques": list(verdict.mitre_techniques),
        "rule_matches": list(final_state.get("detection_rule_matches") or []),
        "final_output": {"ocsf": verdict.model_dump(mode="json")},
        "token_usage": token_usage,
        "attempts": attempts,
    }


def upload_manifest(
    *,
    tenant_id: UUID,
    investigation_id: UUID,
    manifest: dict[str, Any],
) -> tuple[str, str, int]:
    """Serialize + upload. Returns (bucket, key, size_bytes)."""
    body = json.dumps(manifest, default=str, separators=(",", ":")).encode("utf-8")
    bucket = _bucket()
    key = manifest_key(tenant_id=tenant_id, investigation_id=investigation_id)
    upload_evidence(bucket=bucket, key=key, body=body)
    return bucket, key, len(body)


__all__ = [
    "build_evidence_manifest",
    "manifest_key",
    "upload_manifest",
]
