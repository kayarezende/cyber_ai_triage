"""Cluster D MED-5: `tools_node` skips tool_call ids it has already
invoked + audited.

LangGraph re-invokes `tools_node` from a checkpointed prior state on
crash-resume. Without the skip, every tool_call in the replayed
assistant message would re-fire its MCP call AND its `tool_call` audit
row. The reducer-merged `completed_tool_call_ids` field carries the
idempotency key set across checkpoints.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from langchain_core.tools import tool

from sentient_orchestrator.investigation import nodes
from sentient_orchestrator.investigation.nodes import (
    reset_node_call_counts,
    tools_node,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")
INC = UUID("33333333-3333-3333-3333-333333333333")


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


@contextmanager
def _fake_session(_tenant_id: UUID) -> Any:
    yield MagicMock()


def _config(tools: list[Any]) -> dict[str, Any]:
    return {
        "configurable": {
            "tenant_id": str(TENANT),
            "investigation_id": str(INV),
            "finding": None,
            "tools": tools,
            "mitre_descs": {},
        }
    }


def _state(
    *,
    completed: list[str],
    tool_calls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a state where the last assistant message carries the given tool_calls."""
    return {
        "incident_id": str(INC),
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": tool_calls,
            }
        ],
        "completed_tool_call_ids": completed,
    }


def _make_search_tool(invocations: list[dict[str, Any]]) -> Any:
    @tool
    async def siem_query(query: str) -> str:
        """Splunk search."""
        invocations.append({"query": query})
        return '{"results":[]}'

    return siem_query


@pytest.mark.asyncio
async def test_skips_already_completed_tool_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """call_a is in `completed_tool_call_ids` → only call_b invokes + audits."""
    invocations: list[dict[str, Any]] = []
    audit_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(nodes, "tenant_session", _fake_session)

    def _audit(_conn: object, **kwargs: Any) -> None:
        audit_calls.append(kwargs)

    monkeypatch.setattr(nodes.audit, "emit_tool_call", _audit)

    siem_query = _make_search_tool(invocations)
    tool_calls = [
        {
            "id": "call_a",
            "function": {"name": "siem_query", "arguments": '{"query":"a"}'},
        },
        {
            "id": "call_b",
            "function": {"name": "siem_query", "arguments": '{"query":"b"}'},
        },
    ]

    delta = await tools_node(  # type: ignore[arg-type]
        _state(completed=["call_a"], tool_calls=tool_calls),
        _config(tools=[siem_query]),
    )

    # Only call_b invoked.
    assert len(invocations) == 1
    assert invocations[0]["query"] == "b"
    # Only call_b audited.
    assert len(audit_calls) == 1
    # Only call_b's ToolMessage appended.
    assert len(delta["messages"]) == 1
    assert delta["messages"][0]["tool_call_id"] == "call_b"
    # State delta records the new id only (call_a was already in the set).
    assert delta["completed_tool_call_ids"] == ["call_b"]


@pytest.mark.asyncio
async def test_empty_completed_set_invokes_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First-run sanity: empty `completed_tool_call_ids` → both invoke."""
    invocations: list[dict[str, Any]] = []
    audit_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(nodes, "tenant_session", _fake_session)
    monkeypatch.setattr(nodes.audit, "emit_tool_call", lambda _c, **kw: audit_calls.append(kw))

    siem_query = _make_search_tool(invocations)
    tool_calls = [
        {
            "id": "call_a",
            "function": {"name": "siem_query", "arguments": '{"query":"a"}'},
        },
        {
            "id": "call_b",
            "function": {"name": "siem_query", "arguments": '{"query":"b"}'},
        },
    ]

    delta = await tools_node(  # type: ignore[arg-type]
        _state(completed=[], tool_calls=tool_calls),
        _config(tools=[siem_query]),
    )

    assert len(invocations) == 2
    assert len(audit_calls) == 2
    assert delta["completed_tool_call_ids"] == ["call_a", "call_b"]


@pytest.mark.asyncio
async def test_unknown_tool_audit_also_records_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LookupError branch (unknown tool) still emits an audit + records the
    id — replay must NOT re-emit the "tool not found" audit row."""
    audit_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)
    monkeypatch.setattr(nodes.audit, "emit_tool_call", lambda _c, **kw: audit_calls.append(kw))

    siem_query = _make_search_tool([])
    tool_calls = [
        {
            "id": "call_x",
            "function": {"name": "nonexistent", "arguments": "{}"},
        },
    ]

    delta = await tools_node(  # type: ignore[arg-type]
        _state(completed=[], tool_calls=tool_calls),
        _config(tools=[siem_query]),
    )
    assert delta["completed_tool_call_ids"] == ["call_x"]
    assert len(audit_calls) == 1
