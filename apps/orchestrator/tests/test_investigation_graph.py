"""Tier-2 investigation graph topology tests."""

from __future__ import annotations

from langgraph.graph import END, START
from langgraph.graph.state import CompiledStateGraph

from sentient_orchestrator.investigation.graph import build_investigation_graph


def test_builder_registers_all_nodes() -> None:
    builder = build_investigation_graph()
    expected = {
        "plan",
        "agent",
        "tools",
        "correlate",
        "draft_verdict",
        "review",
        "apply_detection_rules",
        "await_approval",
        "writeback",
    }
    assert expected.issubset(builder.nodes.keys())


def test_compiles_without_checkpointer() -> None:
    """Graph must compile in-memory for unit-level inspection."""
    graph = build_investigation_graph().compile()
    assert isinstance(graph, CompiledStateGraph)


def test_static_edges_present() -> None:
    builder = build_investigation_graph()
    edges = {(src, dst) for src, dst in builder.edges}
    assert (START, "plan") in edges
    assert ("plan", "agent") in edges
    assert ("tools", "agent") in edges
    assert ("correlate", "draft_verdict") in edges
    # Wk-7: draft_verdict → review.
    assert ("draft_verdict", "review") in edges
    # Wk-8: review → apply_detection_rules → await_approval → writeback → END.
    assert ("review", "apply_detection_rules") in edges
    assert ("apply_detection_rules", "await_approval") in edges
    assert ("await_approval", "writeback") in edges
    assert ("writeback", END) in edges
    # Earlier-week terminal edges no longer present.
    assert ("draft_verdict", END) not in edges
    assert ("review", END) not in edges


def test_agent_has_conditional_routing() -> None:
    """`agent` node must have a conditional edge (route_after_agent), not a static edge."""
    builder = build_investigation_graph()
    branches = builder.branches
    assert "agent" in branches
