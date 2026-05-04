"""Tier-2 investigation graph nodes.

Each node is `async def <name>(state, *, config) -> dict` returning a state
delta. The `messages` key uses the `operator.add` reducer so per-node returns
APPEND to history rather than replacing.

Node responsibilities:
  * `plan_node` — single LLM call with system + initial user message.
    No tools bound; the model just states hypotheses.
  * `agent_node` — LLM call with tools bound. May emit tool_calls or
    final reasoning. Routes to `tools_node` when tool_calls present (and
    cap not hit), else `correlate_node`.
  * `tools_node` — dispatches each tool_call manually, sanitizes results,
    appends ToolMessages, increments `tool_call_count`. Loops back to agent.
  * `correlate_node` — single LLM call to summarize evidence + cross-
    reference triage techniques. No tools.
  * `draft_verdict_node` — single LLM call with `response_schema`. No tools.

LLMRouter is constructed PER NODE inside a fresh `tenant_session` so the
per-attempt usage ledger commits independently of the graph run — checkpoint
crash semantics don't roll back already-recorded LLM costs.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, cast
from uuid import UUID

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.types import interrupt
from sqlalchemy import text

from sentient_common.db import tenant_session
from sentient_common.logging import get_logger
from sentient_orchestrator.investigation import audit
from sentient_orchestrator.investigation.detection_rules import (
    effective_severity,
    evaluate_rules,
    load_enabled_rules_for_tenant,
)
from sentient_orchestrator.investigation.hitl_policy import (
    evaluate_policy,
    select_active_policy,
)
from sentient_orchestrator.investigation.prompt import (
    build_initial_user_message,
    build_review_system_prompt,
    build_review_user_message,
    build_system_prompt,
)
from sentient_orchestrator.investigation.sanitizer import sanitize_untrusted
from sentient_orchestrator.investigation.state import (
    MAX_TOOL_CALLS,
    InvestigationOutput,
    InvestigationState,
    ReviewOutput,
)
from sentient_orchestrator.llm.exceptions import (
    BudgetExceeded,
    FallbackChainExhausted,
)
from sentient_orchestrator.llm.router import LLMResult, LLMRouter
from sentient_orchestrator.triage.schemas import Severity

log = get_logger(__name__)

#: Per-process node entry counter — used by the crash-resume smoke test to
#: prove that resumed runs don't re-fire already-checkpointed nodes.
node_call_counts: dict[str, int] = {
    "plan": 0,
    "agent": 0,
    "tools": 0,
    "correlate": 0,
    "draft_verdict": 0,
    "review": 0,
    "apply_detection_rules": 0,
    "await_approval": 0,
    "writeback": 0,
}

#: Env var that triggers a synthetic failure inside a named node. Used by
#: `test_investigation_smoke.py` to exercise checkpoint resume; never set
#: in production.
INVESTIGATION_INJECT_FAILURE_ENV = "INVESTIGATION_INJECT_FAILURE"


def reset_node_call_counts() -> None:
    for k in node_call_counts:
        node_call_counts[k] = 0


# --------------------------------------------------------------- helpers


def _ids_from_config(config: RunnableConfig) -> tuple[UUID, UUID]:
    """Pull tenant_id + investigation_id out of the LangGraph config."""
    configurable = config.get("configurable") or {}
    tenant_id = UUID(configurable["tenant_id"])
    investigation_id = UUID(configurable["investigation_id"])
    return tenant_id, investigation_id


def _maybe_inject_failure(node_name: str) -> None:
    """Raise RuntimeError if INVESTIGATION_INJECT_FAILURE matches this node."""
    target = os.environ.get(INVESTIGATION_INJECT_FAILURE_ENV, "").strip()
    if target and target == node_name:
        msg = f"INVESTIGATION_INJECT_FAILURE={target} — simulated failure in {node_name}"
        raise RuntimeError(msg)


def tools_to_openai_schema(tools: list[BaseTool]) -> list[dict[str, Any]]:
    """Convert LangChain BaseTool list → OpenAI tools[] wire format."""
    return [convert_to_openai_tool(t) for t in tools]


def find_tool(tools: list[BaseTool], name: str) -> BaseTool:
    for t in tools:
        if t.name == name:
            return t
    msg = f"tool {name!r} not in {[t.name for t in tools]!r}"
    raise LookupError(msg)


def extract_tool_text(result: Any) -> str:
    """Pull the text payload out of an MCP tool's content-block result.

    Mirrors `verify/graph.py::_extract_tool_text`. `langchain-mcp-adapters`
    returns the raw MCP content blocks (`[{"type":"text","text":"..."}]`)
    from `BaseTool.ainvoke`. We want a plain string for the ToolMessage
    content + audit log.
    """
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        parts: list[str] = []
        for block in result:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        if parts:
            return "".join(parts)
    return str(result)


def _serialize_assistant_message(content: str, result: LLMResult) -> dict[str, Any]:
    """Render an assistant message dict for the messages history.

    OpenAI/OpenRouter wire format: tool_calls have `function.arguments` as a
    JSON STRING (not a dict). We emit that shape so subsequent calls
    re-using `messages` go straight back over the wire without re-encoding.
    """
    msg: dict[str, Any] = {"role": "assistant", "content": content}
    if result.tool_calls:
        msg["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.name,
                    "arguments": json.dumps(tc.arguments),
                },
            }
            for tc in result.tool_calls
        ]
    return msg


# ----------------------------------------------------------------- nodes


async def plan_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """First LLM call: ingest finding + state hypotheses to test."""
    node_call_counts["plan"] += 1
    _maybe_inject_failure("plan")

    tenant_id, investigation_id = _ids_from_config(config)
    configurable = config.get("configurable") or {}
    finding = configurable["finding"]
    triage_ctx = {
        "severity": state.get("triage_severity", "unknown"),
        "confidence": state.get("triage_confidence", 0),
        "mitre_guesses": list(state.get("triage_mitre_guesses", [])),
        "entities": list(state.get("triage_entities", [])),
        "reasoning": state.get("triage_reasoning", ""),
    }
    mitre_descs: dict[str, str] = configurable.get("mitre_descs") or {}

    system = build_system_prompt(mitre_descs)
    user = build_initial_user_message(
        finding=finding, triage_ctx=triage_ctx, mitre_descs=mitre_descs
    )
    # Wk-7: cache the system prompt only — it carries the static methodology
    # + tool descriptions + MITRE block (the latter resolves to the same
    # T-codes within a session for repeat findings of the same class) so a
    # cache hit on it is the high-value breakpoint. The initial user message
    # embeds the per-investigation OCSF finding + triage hand-off — those
    # fields vary per investigation, so caching that block burns one of
    # Anthropic's 4 cache breakpoints for ~0% hit rate.
    # The `cacheable` field is consumed by
    # `call_chat_completion._apply_cache_markers` which rewrites string
    # content into the Anthropic ephemeral cache-block wire shape and
    # strips the flag before sending. Non-Anthropic backends (Gemini,
    # OpenAI) ignore the marker.
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system, "cacheable": True},
        {"role": "user", "content": user},
    ]

    with tenant_session(tenant_id) as conn:
        router = LLMRouter(tenant_id, conn)
        start = time.monotonic()
        result = await router.call(
            role="investigation",
            messages=messages,
            investigation_id=investigation_id,
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        audit.emit_llm_call(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            phase="plan",
            model_used=result.model_used,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cached_tokens=result.cached_tokens,
            latency_ms=latency_ms,
        )

    assistant = _serialize_assistant_message(result.content, result)
    return {
        "messages": [*messages, assistant],
        "tool_call_count": 0,
    }


async def agent_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """Tool-using LLM call: may emit tool_calls or final reasoning.

    `tool_choice="auto"` (default) — never `tool_choice="<name>"` per wk-2
    lessons (Gemini-via-OpenRouter rejects named tool_choice).
    """
    node_call_counts["agent"] += 1
    _maybe_inject_failure("agent")

    tenant_id, investigation_id = _ids_from_config(config)
    configurable = config.get("configurable") or {}
    tools: list[BaseTool] = configurable["tools"]
    tools_schema = tools_to_openai_schema(tools)

    messages = list(state.get("messages") or [])

    with tenant_session(tenant_id) as conn:
        router = LLMRouter(tenant_id, conn)
        start = time.monotonic()
        result = await router.call(
            role="investigation",
            messages=messages,
            investigation_id=investigation_id,
            tools=tools_schema,
            tool_choice="auto",
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        audit.emit_llm_call(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            phase="agent",
            model_used=result.model_used,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cached_tokens=result.cached_tokens,
            latency_ms=latency_ms,
        )

    assistant = _serialize_assistant_message(result.content, result)
    new_count = state.get("tool_call_count", 0) + len(result.tool_calls)
    return {"messages": [assistant], "tool_call_count": new_count}


async def tools_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """Dispatch each tool_call from the last assistant message.

    Sanitizes results before appending ToolMessages. Audits one row per call.
    Increments `tool_call_count` (already incremented by agent_node, so this
    is a no-op for the count — kept for symmetry).

    Cluster D MED-5: skip any `tool_call_id` already in
    `state.completed_tool_call_ids` — LangGraph re-invokes this node when
    the graph resumes from a checkpoint; without the skip the same MCP
    call + audit row fires twice. The id is appended (reducer
    `operator.add`) only after a successful invoke + audit emit.
    """
    node_call_counts["tools"] += 1
    _maybe_inject_failure("tools")

    tenant_id, investigation_id = _ids_from_config(config)
    configurable = config.get("configurable") or {}
    tools: list[BaseTool] = configurable["tools"]

    messages = list(state.get("messages") or [])
    if not messages:
        return {"messages": []}
    last = messages[-1]
    raw_calls = last.get("tool_calls") or [] if isinstance(last, dict) else []

    done = set(state.get("completed_tool_call_ids") or [])
    newly_completed: list[str] = []

    new_messages: list[dict[str, Any]] = []
    for tc in raw_calls:
        tc_id = tc.get("id") or ""
        if tc_id and tc_id in done:
            log.debug(
                "tools_node skipping already-completed tool_call",
                investigation_id=str(investigation_id),
                tool_call_id=tc_id,
            )
            continue
        function = tc.get("function") or {}
        name = function.get("name") or ""
        args_raw = function.get("arguments")
        try:
            args: dict[str, Any] = (
                json.loads(args_raw)
                if isinstance(args_raw, str) and args_raw
                else (args_raw if isinstance(args_raw, dict) else {})
            )
        except json.JSONDecodeError:
            args = {}

        try:
            tool = find_tool(tools, name)
        except LookupError:
            # Sanitize the model-emitted name before echoing it back into the
            # LLM context — defence-in-depth against control-char / prompt-
            # injection payloads in synthesized tool names.
            safe_name = sanitize_untrusted(name) if name else "(empty)"
            text = f"error: tool {safe_name!r} not found"
            new_messages.append(
                {"role": "tool", "tool_call_id": tc.get("id") or "", "content": text}
            )
            with tenant_session(tenant_id) as conn:
                audit.emit_tool_call(
                    conn,
                    tenant_id=tenant_id,
                    investigation_id=investigation_id,
                    tool_name=name,
                    args=args,
                    result_text=text,
                    latency_ms=0,
                )
            if tc_id:
                newly_completed.append(tc_id)
            continue

        start = time.monotonic()
        try:
            result = await tool.ainvoke(args)
            text_raw = extract_tool_text(result)
        except Exception as exc:  # noqa: BLE001 — surface tool error as ToolMessage
            text_raw = f"error: {type(exc).__name__}: {exc}"
        latency_ms = int((time.monotonic() - start) * 1000)
        text = sanitize_untrusted(text_raw)

        new_messages.append(
            {
                "role": "tool",
                "tool_call_id": tc.get("id") or "",
                "content": text,
            }
        )
        with tenant_session(tenant_id) as conn:
            audit.emit_tool_call(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                tool_name=name,
                args=args,
                result_text=text,
                latency_ms=latency_ms,
            )
        if tc_id:
            newly_completed.append(tc_id)

    return {
        "messages": new_messages,
        "completed_tool_call_ids": newly_completed,
    }


async def correlate_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """LLM call: summarize evidence + cross-reference triage techniques."""
    node_call_counts["correlate"] += 1
    _maybe_inject_failure("correlate")

    tenant_id, investigation_id = _ids_from_config(config)
    messages = list(state.get("messages") or [])
    messages.append(
        {
            "role": "user",
            "content": (
                "Summarize the evidence you have so far. Cross-reference each "
                "MITRE technique you can confirm against the Tier-1 guesses. "
                "Note gaps. This is your last reasoning step before drafting "
                "the final verdict."
            ),
        }
    )

    with tenant_session(tenant_id) as conn:
        router = LLMRouter(tenant_id, conn)
        start = time.monotonic()
        result = await router.call(
            role="investigation",
            messages=messages,
            investigation_id=investigation_id,
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        audit.emit_llm_call(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            phase="correlate",
            model_used=result.model_used,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cached_tokens=result.cached_tokens,
            latency_ms=latency_ms,
        )

    assistant = _serialize_assistant_message(result.content, result)
    # Append the prompt + assistant response (the prompt was a synthetic user
    # turn we added locally; persist it so checkpoints can replay).
    return {"messages": [messages[-1], assistant]}


async def draft_verdict_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """Final LLM call with `response_schema=InvestigationOutput`."""
    node_call_counts["draft_verdict"] += 1
    _maybe_inject_failure("draft_verdict")

    tenant_id, investigation_id = _ids_from_config(config)
    messages = list(state.get("messages") or [])
    messages.append(
        {
            "role": "user",
            "content": (
                "Emit ONLY the InvestigationOutput JSON now. No prose, no "
                "markdown, no code fences. Conform exactly to the schema."
            ),
        }
    )

    with tenant_session(tenant_id) as conn:
        router = LLMRouter(tenant_id, conn)
        start = time.monotonic()
        result = await router.call(
            role="investigation",
            messages=messages,
            investigation_id=investigation_id,
            response_schema=InvestigationOutput,
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        audit.emit_llm_call(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            phase="draft_verdict",
            model_used=result.model_used,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cached_tokens=result.cached_tokens,
            latency_ms=latency_ms,
        )

        if not isinstance(result.parsed, InvestigationOutput):
            msg = "draft_verdict_node expected parsed InvestigationOutput"
            raise RuntimeError(msg)
        verdict = result.parsed
        audit.emit_verdict_drafted(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            verdict=verdict.verdict,
            confidence=verdict.confidence,
            severity=verdict.severity,
            mitre_techniques=list(verdict.mitre_techniques),
        )

    return {"draft_verdict": verdict.model_dump(), "messages": [messages[-1]]}


async def review_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """Wk-7. Critic LLM call: audit the draft verdict.

    Best-effort: if the review LLM call fails (FallbackChainExhausted /
    BudgetExceeded / unhandled exception), DO NOT propagate. The verdict is
    already drafted; review is annotation. Emit `review_skipped` and return
    a skipped-shape `review_output` so downstream persistence has a value.

    Does NOT mutate the draft verdict; returns only `review_output`.
    """
    node_call_counts["review"] += 1
    _maybe_inject_failure("review")

    tenant_id, investigation_id = _ids_from_config(config)
    configurable = config.get("configurable") or {}
    finding = configurable["finding"]

    draft = state.get("draft_verdict")
    if not draft:
        log.warning(
            "review_node invoked without draft_verdict; skipping",
            investigation_id=str(investigation_id),
        )
        return {
            "review_output": {
                "status": "skipped",
                "notes": "no_draft_verdict_to_review",
            }
        }

    system = build_review_system_prompt()
    user = build_review_user_message(finding=finding, draft_verdict=draft)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system, "cacheable": True},
        {"role": "user", "content": user},
    ]

    try:
        with tenant_session(tenant_id) as conn:
            router = LLMRouter(tenant_id, conn)
            audit.emit_review_started(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                model_used="(router-resolved)",
            )
            start = time.monotonic()
            result = await router.call(
                role="review",
                messages=messages,
                investigation_id=investigation_id,
                response_schema=ReviewOutput,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            audit.emit_llm_call(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                phase="review",
                model_used=result.model_used,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                cached_tokens=result.cached_tokens,
                latency_ms=latency_ms,
            )
            if not isinstance(result.parsed, ReviewOutput):
                msg = "review_node expected parsed ReviewOutput"
                raise RuntimeError(msg)
            review = result.parsed
            audit.emit_review_complete(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                status=review.status,
                hallucination_risk=review.hallucination_risk,
                confidence_assessment=review.confidence_assessment,
                flagged_claim_count=len(review.flagged_claims),
            )
        return {"review_output": review.model_dump()}
    except (FallbackChainExhausted, BudgetExceeded) as exc:
        # Best-effort: review failure does not fail the investigation.
        reason = type(exc).__name__
        log.warning(
            "review_node skipped due to LLM failure",
            investigation_id=str(investigation_id),
            reason=reason,
        )
        try:
            with tenant_session(tenant_id) as conn:
                audit.emit_review_skipped(
                    conn,
                    tenant_id=tenant_id,
                    investigation_id=investigation_id,
                    reason=reason,
                )
        except Exception:  # noqa: BLE001 — audit failure also best-effort
            log.exception(
                "review_skipped audit emit failed",
                investigation_id=str(investigation_id),
            )
        return {
            "review_output": {
                "status": "skipped",
                "notes": f"review_role_unavailable:{reason}",
            }
        }
    except Exception as exc:  # noqa: BLE001 — unhandled review failure
        log.exception(
            "review_node unhandled exception; skipping review",
            investigation_id=str(investigation_id),
        )
        try:
            with tenant_session(tenant_id) as conn:
                audit.emit_review_skipped(
                    conn,
                    tenant_id=tenant_id,
                    investigation_id=investigation_id,
                    reason=f"{type(exc).__name__}: {exc!s:.200}",
                )
        except Exception:  # noqa: BLE001
            log.exception(
                "review_skipped audit emit failed",
                investigation_id=str(investigation_id),
            )
        return {
            "review_output": {
                "status": "skipped",
                "notes": f"review_unhandled:{type(exc).__name__}",
            }
        }


# ----------------------------------------------------------- wk-8 nodes


def _build_decision_ctx(
    draft: dict[str, Any],
    review: dict[str, Any] | None,
    matches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the field map consumed by HITL policy evaluation."""
    return {
        "severity": draft.get("severity"),
        "verdict": draft.get("verdict"),
        "confidence": int(draft.get("confidence") or 0),
        "mitre_techniques": list(draft.get("mitre_techniques") or []),
        "detection_rule_matches": [m.get("rule_name") for m in matches],
        "review_status": (review or {}).get("status"),
        "review_hallucination_risk": (review or {}).get("hallucination_risk"),
    }


async def apply_detection_rules_node(
    state: InvestigationState, config: RunnableConfig
) -> dict[str, Any]:
    """Wk-8. Deterministic post-pass over the agent's draft verdict.

    Loads enabled detection rules visible to the tenant (own + global),
    matches against `draft_verdict.mitre_techniques`, computes
    `effective_severity = max(agent, *rule_overrides)`, and writes the
    matches back to state for the manifest + HITL policy + writeback comment.

    Mutates `draft_verdict.severity` only when a matching rule's override is
    higher than the agent's draft.
    """
    node_call_counts["apply_detection_rules"] += 1
    _maybe_inject_failure("apply_detection_rules")

    tenant_id, investigation_id = _ids_from_config(config)
    draft = state.get("draft_verdict") or {}
    techniques = list(draft.get("mitre_techniques") or [])
    agent_sev: Severity = cast(Severity, draft.get("severity") or "info")

    with tenant_session(tenant_id) as conn:
        rules = load_enabled_rules_for_tenant(conn, tenant_id)
        matches = evaluate_rules(rules, mitre_techniques=techniques)
        new_sev = effective_severity(agent_sev, matches)
        audit.emit_detection_rules_evaluated(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            evaluated_count=len(rules),
            matched_count=len(matches),
            matched_rules=[m.rule_name for m in matches],
            agent_severity=agent_sev,
            effective_severity=new_sev,
            severity_overridden=(new_sev != agent_sev),
        )

    matches_dict = [
        {
            "rule_id": m.rule_id,
            "rule_name": m.rule_name,
            "matched_required": list(m.matched_required),
            "matched_any": list(m.matched_any),
            "severity_override": m.severity_override,
        }
        for m in matches
    ]
    return {
        "draft_verdict": {**draft, "severity": new_sev},
        "detection_rule_matches": matches_dict,
    }


async def await_approval_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """Wk-8. HITL gate. Either auto-approves or fires `interrupt()`.

    The active HITL policy decides. `{"op":"always_true"}` (the MVP default
    per ADR-0009) means every Tier-2 escalation goes through human approval.
    Tenant-specific lower-priority rules can opt out of approval for narrow
    conditions.

    If interrupted, the resumer (CLI hack for wk-8; web UI in wk-9) must
    `Command(resume={"approved": bool, "analyst_id": str | None,
    "notes": str})`. Resume payload is treated as untrusted ingress and
    coerced defensively before persistence.
    """
    node_call_counts["await_approval"] += 1
    _maybe_inject_failure("await_approval")

    tenant_id, investigation_id = _ids_from_config(config)
    incident_id = UUID(state["incident_id"])
    draft = state.get("draft_verdict") or {}
    review = state.get("review_output")
    matches = state.get("detection_rule_matches") or []
    ctx = _build_decision_ctx(draft, review, matches)

    with tenant_session(tenant_id) as conn:
        policy_id, policy_name, expression = select_active_policy(conn, tenant_id)
        try:
            needs_human = evaluate_policy(expression, ctx)
        except (ValueError, TypeError, RecursionError) as exc:
            # HIGH-4: malformed policy must NEVER auto-approve. Fall back to
            # the conservative default + emit a structured audit row so the
            # admin panel can surface the broken policy. Per ADR-0009.
            log.warning(
                "hitl_policy_evaluation_failed",
                policy_id=str(policy_id) if policy_id else None,
                policy_name=policy_name,
                error=str(exc),
            )
            audit.emit_hitl_policy_evaluation_failed(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                policy_id=policy_id,
                policy_name=policy_name,
                error_message=str(exc),
                decision_ctx=ctx,
            )
            needs_human = True

    if not needs_human:
        with tenant_session(tenant_id) as conn:
            audit.emit_approval_received(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                approver_id=None,
                approved=True,
                notes="auto_approved",
                policy_id=policy_id,
                policy_name=policy_name,
            )
        return {
            "approval_status": "auto",
            "approver_id": None,
            "approval_notes": "auto_approved",
        }

    # Human approval required. Flip incident status BEFORE interrupt so the
    # checkpoint captures post-flip state. Cluster D HIGH-14: gate UPDATEs on
    # transition (status != 'awaiting_approval') and only emit the
    # `awaiting_approval` audit on rowcount==1 — replay safety. Without the
    # gate, every interrupt resume would re-emit the audit row.
    with tenant_session(tenant_id) as conn:
        incidents_result = conn.execute(
            text(
                "UPDATE incidents SET status = 'awaiting_approval' "
                "WHERE id = :id AND status IS DISTINCT FROM 'awaiting_approval'"
            ),
            {"id": str(incident_id)},
        )
        conn.execute(
            text(
                "UPDATE investigations SET approval_status = 'pending' "
                "WHERE id = :id AND approval_status IS DISTINCT FROM 'pending'"
            ),
            {"id": str(investigation_id)},
        )
        if incidents_result.rowcount == 1:
            audit.emit_awaiting_approval(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                policy_id=policy_id,
                policy_name=policy_name,
                decision_ctx=ctx,
            )

    resume_payload = interrupt(
        {
            "reason": "human_approval_required",
            "policy_name": policy_name,
            "policy_id": str(policy_id) if policy_id else None,
            "draft_verdict": draft,
            "review": review,
            "detection_rule_matches": matches,
        }
    )

    if not isinstance(resume_payload, dict):
        resume_payload = {}
    approved = bool(resume_payload.get("approved"))
    approver_id_raw = resume_payload.get("analyst_id")
    approver_id = str(approver_id_raw) if approver_id_raw else None
    notes_raw = resume_payload.get("notes") or ""
    notes = sanitize_untrusted(str(notes_raw))[:1024]

    with tenant_session(tenant_id) as conn:
        audit.emit_approval_received(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            approver_id=approver_id,
            approved=approved,
            notes=notes,
            policy_id=policy_id,
            policy_name=policy_name,
        )

    return {
        "approval_status": "approved" if approved else "rejected",
        "approver_id": approver_id,
        "approval_notes": notes,
    }


def _build_writeback_comment(
    draft: dict[str, Any], investigation_id: UUID, evidence_url: str | None
) -> str:
    techniques = ",".join(list(draft.get("mitre_techniques") or [])[:8]) or "none"
    summary = (draft.get("summary") or "").strip()[:500]
    evidence_part = evidence_url or "pending"
    return (
        f"Sentient Layer verdict: {draft.get('verdict')} "
        f"(confidence {int(draft.get('confidence') or 0)}%). "
        f"MITRE: {techniques}. Summary: {summary} "
        f"Evidence: {evidence_part}. inv_id={investigation_id.hex[:12]}"
    )


def _build_writeback_event(
    finding: Any,
    draft: dict[str, Any],
    investigation_id: UUID,
    verdict_revision: int,
) -> dict[str, Any]:
    """Render the OCSF Detection Finding HEC event payload.

    Uses `finding.to_hec_dict()` for the OCSF-namespaced base, then overlays
    Sentient verdict fields (already namespaced in `to_hec_dict()` via wk-2's
    `to_hec_dict` method, but we re-emit current draft values in case the
    review/detection-rules pass mutated severity).

    Cluster D HIGH-9: `sentient_dedup_id = "{investigation_id}:{verdict_revision}"`
    rides on every HEC event so future Splunk-side dedup transforms (or the
    wk-12 reaper) can collapse re-fires onto a stable key. Today every
    `verdict_revision` is 1; column exists for verdict-correction flows.
    """
    base = finding.to_hec_dict() if hasattr(finding, "to_hec_dict") else dict(finding)
    base["sentient_verdict"] = draft.get("verdict")
    base["sentient_confidence"] = int(draft.get("confidence") or 0)
    base["sentient_severity"] = draft.get("severity")
    base["sentient_summary"] = (draft.get("summary") or "")[:1024]
    base["sentient_mitre_techniques"] = list(draft.get("mitre_techniques") or [])
    base["sentient_investigation_id"] = str(investigation_id)
    base["sentient_dedup_id"] = f"{investigation_id}:{verdict_revision}"
    return base


class WritebackTenantMissingError(LookupError):
    """HIGH-2: tenant row for writeback_mode lookup doesn't exist.

    Distinct from a NULL `writeback_mode` value (which is a legitimate
    "default to hec_only"). A missing row means the tenant_id is invalid —
    likely a misconfig — and the silent downgrade was masking it. Caller
    in `writeback_node` traps this, emits a structured audit row, then
    returns the writeback as failed (best-effort path: doesn't roll back
    the verdict, but admin sees a clear signal).
    """


def _load_writeback_mode(conn: Any, tenant_id: UUID) -> str:
    row = conn.execute(
        text("SELECT writeback_mode FROM tenants WHERE id = :id"),
        {"id": str(tenant_id)},
    ).first()
    if row is None:
        raise WritebackTenantMissingError(str(tenant_id))
    mode = row[0]
    if not mode:
        return "hec_only"  # NULL = legitimate default per ADR-0018
    return str(mode)


def _load_siem_notable_id(conn: Any, incident_id: UUID) -> str | None:
    row = conn.execute(
        text("SELECT siem_notable_id FROM incidents WHERE id = :id"),
        {"id": str(incident_id)},
    ).first()
    if row is None or not row[0]:
        return None
    return str(row[0])


async def _invoke_writeback_tool(
    tool: BaseTool, payload: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    """Wrap a writeback MCP tool call. Catches every exception → (False, detail).

    Best-effort: writeback_node treats all failures as non-fatal so the verdict
    stays committed. The detail dict is sanitized + capped at the audit emit.

    Soft-failure detection: a tool may return `success=false` / `degraded=true`
    structurally without raising (e.g. siem_notable_update on plain Splunk
    returns `degraded=true`). Parse the JSON response and inspect the fields
    rather than substring-matching — Pydantic v2's compact JSON shape
    (`"success":false`, no space) breaks naïve substring checks.
    """
    try:
        result = await tool.ainvoke(payload)
        text_payload = extract_tool_text(result)
        soft_failed = False
        try:
            parsed = json.loads(text_payload)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            if parsed.get("success") is False:
                soft_failed = True
            if parsed.get("degraded") is True:
                soft_failed = True
        return (not soft_failed, {"response": text_payload[:500]})
    except Exception as exc:  # noqa: BLE001 — best-effort writeback
        return (
            False,
            {
                "error_type": type(exc).__name__,
                "error_message": str(exc)[:500],
            },
        )


async def writeback_node(state: InvestigationState, config: RunnableConfig) -> dict[str, Any]:
    """Wk-8. Push the verdict back to Splunk.

    Always: HEC POST to `triage_verdicts` index (works on plain Splunk).
    Conditional: when tenant.writeback_mode='dual' AND we have the upstream
    notable id, also call `siem_notable_update` to pin the verdict comment to
    the original ES notable.

    Best-effort failure: a HEC or notable_update error does NOT roll back the
    verdict (already committed by `_finalize_done` after this returns).
    `writeback_status='failed'` is recorded on the investigation row instead.

    Skipped path: when the analyst rejected the writeback
    (`approval_status='rejected'`), the verdict stays committed but neither
    Splunk surface is touched.

    Cluster D HIGH-9 idempotency: read `writeback_status` first. If it's
    already `'succeeded'` we short-circuit BEFORE any HEC / notable_update
    side effect — wk-12 reaper can re-fire a finalize on a successful run
    without double-posting. The `sentient_dedup_id` field on the HEC event
    is a stable key for Splunk-side dedup transforms (deferred).
    """
    node_call_counts["writeback"] += 1
    _maybe_inject_failure("writeback")

    tenant_id, investigation_id = _ids_from_config(config)
    incident_id = UUID(state["incident_id"])
    configurable = config.get("configurable") or {}
    tools: list[BaseTool] = configurable["tools"]
    finding = configurable["finding"]
    draft = state.get("draft_verdict") or {}

    # Cluster D HIGH-9: idempotency guard + verdict_revision lookup. Read
    # both in one round-trip; row missing here is treated like other
    # writeback misconfig — let downstream loader raise.
    with tenant_session(tenant_id) as conn:
        inv_row = conn.execute(
            text("SELECT writeback_status, verdict_revision " "FROM investigations WHERE id = :id"),
            {"id": str(investigation_id)},
        ).first()
    prior_writeback_status = inv_row[0] if inv_row else None
    verdict_revision = int(inv_row[1]) if inv_row and inv_row[1] is not None else 1
    if prior_writeback_status == "succeeded":
        log.info(
            "writeback already succeeded; short-circuit",
            investigation_id=str(investigation_id),
        )
        return {"writeback_status": "succeeded"}

    if state.get("approval_status") == "rejected":
        with tenant_session(tenant_id) as conn:
            audit.emit_writeback_attempted(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                mode="skipped_rejected",
                hec_index=None,
                notable_update_target=None,
            )
        return {"writeback_status": "skipped", "writeback_attempts": []}

    try:
        with tenant_session(tenant_id) as conn:
            wb_mode = _load_writeback_mode(conn, tenant_id)
            siem_notable_id = _load_siem_notable_id(conn, incident_id)
    except WritebackTenantMissingError as exc:
        # HIGH-2: tenant row absent. Pre-fix this returned 'hec_only' silently;
        # writeback would attempt HEC against a tenant that doesn't exist and
        # surface no signal in the audit chain. Now: emit dedicated audit row
        # + writeback_failed + return failed shape (best-effort: verdict still
        # ships in DB, but admin sees the misconfig).
        miss_attempt = {
            "tool": "writeback_mode_loader",
            "ok": False,
            "detail": {"error_message": f"tenant_missing: {exc}"},
        }
        with tenant_session(tenant_id) as conn:
            audit.emit_writeback_tenant_missing(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
            )
            audit.emit_writeback_failed(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                mode="unknown",
                attempts=[miss_attempt],
                error="tenant_missing",
            )
        return {
            "writeback_status": "failed",
            "writeback_attempts": [miss_attempt],
        }

    event = _build_writeback_event(finding, draft, investigation_id, verdict_revision)

    with tenant_session(tenant_id) as conn:
        audit.emit_writeback_attempted(
            conn,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            mode=wb_mode,
            hec_index="triage_verdicts",
            notable_update_target=(siem_notable_id if wb_mode == "dual" else None),
        )

    attempts: list[dict[str, Any]] = []

    try:
        hec_tool = find_tool(tools, "siem_hec_post")
    except LookupError as exc:
        miss_attempt = {
            "tool": "siem_hec_post",
            "ok": False,
            "detail": {"error_message": str(exc)},
        }
        with tenant_session(tenant_id) as conn:
            audit.emit_writeback_failed(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                mode=wb_mode,
                attempts=[miss_attempt],
                error="hec_tool_unavailable",
            )
        return {
            "writeback_status": "failed",
            "writeback_attempts": [miss_attempt],
        }

    hec_ok, hec_detail = await _invoke_writeback_tool(
        hec_tool, {"event": event, "index": "triage_verdicts"}
    )
    attempts.append({"tool": "siem_hec_post", "ok": hec_ok, "detail": hec_detail})

    nu_ok = True
    if wb_mode == "dual" and siem_notable_id:
        try:
            nu_tool = find_tool(tools, "siem_notable_update")
        except LookupError as exc:
            attempts.append(
                {
                    "tool": "siem_notable_update",
                    "ok": False,
                    "detail": {"error_message": str(exc)},
                }
            )
            nu_ok = False
        else:
            evidence_url_raw = state.get("evidence_s3_key")
            evidence_url = str(evidence_url_raw) if evidence_url_raw else None
            comment = _build_writeback_comment(draft, investigation_id, evidence_url=evidence_url)
            nu_ok, nu_detail = await _invoke_writeback_tool(
                nu_tool,
                {
                    "notable_id": siem_notable_id,
                    "comment": comment,
                    "status": "in_progress",
                },
            )
            attempts.append({"tool": "siem_notable_update", "ok": nu_ok, "detail": nu_detail})

    overall_ok = hec_ok and nu_ok
    with tenant_session(tenant_id) as conn:
        if overall_ok:
            audit.emit_writeback_succeeded(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                mode=wb_mode,
                attempts=attempts,
            )
        else:
            audit.emit_writeback_failed(
                conn,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                mode=wb_mode,
                attempts=attempts,
                error=("hec_failed" if not hec_ok else "notable_update_failed"),
            )

    return {
        "writeback_status": "succeeded" if overall_ok else "failed",
        "writeback_attempts": attempts,
    }


# ------------------------------------------------------------- routing


def route_after_agent(state: InvestigationState) -> str:
    """Conditional edge: tools loop until cap, then correlate."""
    messages = state.get("messages") or []
    if not messages:
        return "correlate"
    last = messages[-1]
    if not isinstance(last, dict):
        return "correlate"
    tool_calls = last.get("tool_calls") or []
    if tool_calls and state.get("tool_call_count", 0) < MAX_TOOL_CALLS:
        return "tools"
    return "correlate"


__all__ = [
    "INVESTIGATION_INJECT_FAILURE_ENV",
    "agent_node",
    "apply_detection_rules_node",
    "await_approval_node",
    "correlate_node",
    "draft_verdict_node",
    "extract_tool_text",
    "find_tool",
    "node_call_counts",
    "plan_node",
    "reset_node_call_counts",
    "review_node",
    "route_after_agent",
    "tools_node",
    "tools_to_openai_schema",
    "writeback_node",
]
