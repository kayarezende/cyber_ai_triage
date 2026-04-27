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
from typing import Any
from uuid import UUID

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool

from sentient_common.db import tenant_session
from sentient_common.logging import get_logger
from sentient_orchestrator.investigation import audit
from sentient_orchestrator.investigation.prompt import (
    build_initial_user_message,
    build_system_prompt,
)
from sentient_orchestrator.investigation.sanitizer import sanitize_untrusted
from sentient_orchestrator.investigation.state import (
    MAX_TOOL_CALLS,
    InvestigationOutput,
    InvestigationState,
)
from sentient_orchestrator.llm.router import LLMResult, LLMRouter

log = get_logger(__name__)

#: Per-process node entry counter — used by the crash-resume smoke test to
#: prove that resumed runs don't re-fire already-checkpointed nodes.
node_call_counts: dict[str, int] = {
    "plan": 0,
    "agent": 0,
    "tools": 0,
    "correlate": 0,
    "draft_verdict": 0,
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


async def plan_node(
    state: InvestigationState, config: RunnableConfig
) -> dict[str, Any]:
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
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
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


async def agent_node(
    state: InvestigationState, config: RunnableConfig
) -> dict[str, Any]:
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


async def tools_node(
    state: InvestigationState, config: RunnableConfig
) -> dict[str, Any]:
    """Dispatch each tool_call from the last assistant message.

    Sanitizes results before appending ToolMessages. Audits one row per call.
    Increments `tool_call_count` (already incremented by agent_node, so this
    is a no-op for the count — kept for symmetry).
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

    new_messages: list[dict[str, Any]] = []
    for tc in raw_calls:
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

    return {"messages": new_messages}


async def correlate_node(
    state: InvestigationState, config: RunnableConfig
) -> dict[str, Any]:
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


async def draft_verdict_node(
    state: InvestigationState, config: RunnableConfig
) -> dict[str, Any]:
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
    "correlate_node",
    "draft_verdict_node",
    "extract_tool_text",
    "find_tool",
    "node_call_counts",
    "plan_node",
    "reset_node_call_counts",
    "route_after_agent",
    "tools_node",
    "tools_to_openai_schema",
]
