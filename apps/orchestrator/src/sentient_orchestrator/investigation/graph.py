"""Tier-2 investigation StateGraph builder.

Topology:

    START → plan → agent ┬──(tool_calls)──→ tools ──┐
                          │                         │
                          │                  (back to agent)
                          │
                          └──(no tool_calls / cap)──→ correlate → draft_verdict → review →
                              apply_detection_rules → await_approval → writeback → END

`tools` node loops back to `agent` so the model can iterate (observe tool
result → reason → call again). `route_after_agent` force-routes to
`correlate` once `state.tool_call_count >= MAX_TOOL_CALLS`, preventing
runaway loops.

Wk-7: `review` is the second LLM pass — annotation only, never overrides
the verdict. Failures inside `review_node` are absorbed (skipped), the
verdict is already drafted by the time we get here.

Wk-8 closes the loop:
  * `apply_detection_rules` is the deterministic post-pass — may raise
    `draft_verdict.severity` to a rule's `severity_override` (never lowers).
  * `await_approval` evaluates the active HITL policy. `interrupt()` fires
    when a human is required (default policy is `always_true`); resume via
    `Command(resume={...})` from CLI/UI.
  * `writeback` always pushes HEC + (when tenant.writeback_mode='dual')
    `siem_notable_update`. Best-effort — never rolls back the verdict.

`build_investigation_graph` returns the uncompiled StateGraph builder. Caller
wraps with the PostgresSaver checkpointer:

    builder = build_investigation_graph()
    graph = builder.compile(checkpointer=async_postgres_saver)
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from sentient_orchestrator.investigation.nodes import (
    agent_node,
    apply_detection_rules_node,
    await_approval_node,
    correlate_node,
    draft_verdict_node,
    plan_node,
    review_node,
    route_after_agent,
    tools_node,
    writeback_node,
)
from sentient_orchestrator.investigation.state import InvestigationState


def build_investigation_graph() -> StateGraph[InvestigationState]:
    """Construct the StateGraph builder. Caller compiles with checkpointer."""
    builder: StateGraph[InvestigationState] = StateGraph(InvestigationState)
    builder.add_node("plan", plan_node)
    builder.add_node("agent", agent_node)
    builder.add_node("tools", tools_node)
    builder.add_node("correlate", correlate_node)
    builder.add_node("draft_verdict", draft_verdict_node)
    builder.add_node("review", review_node)
    builder.add_node("apply_detection_rules", apply_detection_rules_node)
    builder.add_node("await_approval", await_approval_node)
    builder.add_node("writeback", writeback_node)

    builder.add_edge(START, "plan")
    builder.add_edge("plan", "agent")
    builder.add_conditional_edges(
        "agent",
        route_after_agent,
        {"tools": "tools", "correlate": "correlate"},
    )
    builder.add_edge("tools", "agent")
    builder.add_edge("correlate", "draft_verdict")
    builder.add_edge("draft_verdict", "review")
    builder.add_edge("review", "apply_detection_rules")
    builder.add_edge("apply_detection_rules", "await_approval")
    builder.add_edge("await_approval", "writeback")
    builder.add_edge("writeback", END)
    return builder


__all__ = ["build_investigation_graph"]
