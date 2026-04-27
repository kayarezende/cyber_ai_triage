"""Three-node StateGraph that exercises the framework stack end-to-end.

Node 1 `extract_ip` — `with_structured_output(ExtractedIP)` against OpenRouter.
Node 2 `call_echo_tool` — `bind_tools(echo_tool)` + manual ToolMessage dispatch.
Node 3 `done` — terminal.

Linear: START → extract_ip → call_echo_tool → done → END. Each transition
writes a checkpoint via PostgresSaver, so a 3-node run produces ≥3 rows in
`checkpoints` for that thread_id.

The `extract_ip` node also writes a synthetic AIMessage so `messages` is
non-empty entering `call_echo_tool` (LangChain's `bind_tools` path expects a
human/system message context).

Resume invariant — proven by `node_call_counts`:
    `node_call_counts["extract_ip"]` increments on each entry. After a
    successful run + a same-`thread_id` resume (`ainvoke(None, config)`), the
    counter equals 1 — LangGraph reads the post-`extract_ip` checkpoint and
    re-enters at `call_echo_tool`, not from START. The pytest smoke asserts
    this directly.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph

from sentient_orchestrator.verify.schemas import ExtractedIP, VerifyState

SAMPLE_EVENT = "src=10.0.0.42 dest=10.0.0.1 action=allowed proto=tcp dport=443"
EXPECTED_SRC_IP = "10.0.0.42"

_INJECT_FAILURE_ENV = "VERIFY_INJECT_FAILURE"

# Per-process node-entry counter. Tests inspect this to prove the resume
# semantics: after a same-thread `ainvoke(None, ...)` the failed node should
# re-run but already-checkpointed nodes should NOT.
node_call_counts: dict[str, int] = {"extract_ip": 0, "call_echo_tool": 0, "done": 0}


def reset_node_call_counts() -> None:
    """Reset the entry counter — pytest fixture between tests."""
    for k in node_call_counts:
        node_call_counts[k] = 0


def _should_inject_failure() -> bool:
    return os.environ.get(_INJECT_FAILURE_ENV, "").lower() in {"1", "true", "yes"}


def build_verify_graph(
    llm: BaseChatModel,
    tools: list[BaseTool],
) -> Any:
    """Compile the 3-node verify graph (caller wraps with checkpointer).

    Returns the StateGraph builder pre-`compile`. Caller passes the
    PostgresSaver to `.compile(checkpointer=...)`.
    """
    echo_tool = _find_tool(tools, "echo")

    async def extract_ip(state: VerifyState) -> dict[str, Any]:
        node_call_counts["extract_ip"] += 1
        prompt = (
            "Extract the source IP from this Splunk event. Respond with the "
            f"exact IP, no extra commentary.\n\nEvent: {SAMPLE_EVENT}"
        )
        structured = llm.with_structured_output(ExtractedIP)
        result: ExtractedIP = await structured.ainvoke(prompt)  # type: ignore[assignment]
        return {
            "src_ip": result.src_ip,
            "messages": [
                HumanMessage(content=prompt),
                AIMessage(content=f"src_ip={result.src_ip}"),
            ],
        }

    async def call_echo_tool(state: VerifyState) -> dict[str, Any]:
        node_call_counts["call_echo_tool"] += 1
        if _should_inject_failure():
            msg = "VERIFY_INJECT_FAILURE=1 — simulated mid-run failure"
            raise RuntimeError(msg)

        src_ip = state.get("src_ip", "<unknown>")
        prompt = (
            f"Call the `echo` tool with msg='ip={src_ip}'. Use the tool, "
            "do not answer directly."
        )
        # `tool_choice="any"` forces a tool call without naming a specific
        # tool — broader provider compatibility than `tool_choice="<name>"`,
        # which Gemini-via-OpenRouter has been known to reject. With one
        # tool bound this is equivalent to "must call echo".
        bound = llm.bind_tools([echo_tool], tool_choice="any")
        ai_msg = await bound.ainvoke([HumanMessage(content=prompt)])
        if not isinstance(ai_msg, AIMessage) or not ai_msg.tool_calls:
            msg = (
                "model did not emit a tool_call — OpenRouter tool_use "
                f"passthrough may be broken. Got: {ai_msg!r}"
            )
            raise RuntimeError(msg)

        tc = ai_msg.tool_calls[0]
        tool_result = await echo_tool.ainvoke(tc["args"])
        text = _extract_tool_text(tool_result)
        return {
            "echo_result": text,
            "messages": [
                ai_msg,
                ToolMessage(content=text, tool_call_id=tc["id"]),
            ],
        }

    async def done(state: VerifyState) -> dict[str, Any]:
        node_call_counts["done"] += 1
        return {}

    builder: StateGraph[VerifyState] = StateGraph(VerifyState)
    builder.add_node("extract_ip", extract_ip)
    builder.add_node("call_echo_tool", call_echo_tool)
    builder.add_node("done", done)
    builder.add_edge(START, "extract_ip")
    builder.add_edge("extract_ip", "call_echo_tool")
    builder.add_edge("call_echo_tool", "done")
    builder.add_edge("done", END)
    return builder


def _find_tool(tools: list[BaseTool], name: str) -> BaseTool:
    for t in tools:
        if t.name == name:
            return t
    msg = f"tool {name!r} not found in {[t.name for t in tools]!r}"
    raise LookupError(msg)


def _extract_tool_text(result: Any) -> str:
    """Pull the text payload out of an MCP tool's content-block result.

    `langchain-mcp-adapters` returns the raw MCP content blocks (list of
    `{"type": "text", "text": ...}` dicts) from `BaseTool.ainvoke`. We want a
    plain string for the ToolMessage content + the verify summary.
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
