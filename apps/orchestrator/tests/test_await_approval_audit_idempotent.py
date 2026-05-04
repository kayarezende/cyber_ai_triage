"""Cluster D HIGH-14: `await_approval_node` audit emits only on real
state transition, not on replay.

The wk-12 reaper (and any same-process retry) re-enters the graph from
its prior checkpoint; if `incidents.status` is already
`'awaiting_approval'`, the UPDATE rowcount is 0 and the audit row must
NOT fire a second time. Hash-chain integrity for "human-visible
transition" depends on this.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from uuid import UUID

import pytest

from sentient_orchestrator.investigation import nodes
from sentient_orchestrator.investigation.nodes import (
    await_approval_node,
    reset_node_call_counts,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")
INC = UUID("33333333-3333-3333-3333-333333333333")
POLICY_ID = UUID("44444444-4444-4444-4444-444444444444")


class _Result:
    def __init__(self, rowcount: int = 1) -> None:
        self.rowcount = rowcount


class _Conn:
    """Returns rowcount=1 on the first gated UPDATE for incidents.status,
    rowcount=0 thereafter — the row is already in the target state."""

    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self._first_incidents_seen = False

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _Result:
        sql = str(getattr(stmt, "text", stmt))
        self.queries.append((sql, params or {}))
        if "UPDATE incidents" in sql and "awaiting_approval" in sql:
            if not self._first_incidents_seen:
                self._first_incidents_seen = True
                return _Result(rowcount=1)
            return _Result(rowcount=0)
        return _Result(rowcount=1)


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {
        "audit_calls": [],
        "interrupt_resume": {"approved": True, "analyst_id": None, "notes": ""},
    }
    conn = _Conn()
    captured["conn"] = conn

    @contextmanager
    def session(_tid: UUID) -> Any:
        yield conn

    monkeypatch.setattr(nodes, "tenant_session", session)
    monkeypatch.setattr(
        nodes,
        "select_active_policy",
        lambda *_a, **_k: (POLICY_ID, "default_require_approval", {"op": "always_true"}),
    )
    monkeypatch.setattr(nodes, "evaluate_policy", lambda *_a, **_k: True)
    monkeypatch.setattr(nodes, "interrupt", lambda _payload: captured["interrupt_resume"])

    def _track(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            captured["audit_calls"].append((name, kwargs))

        return _f

    monkeypatch.setattr(nodes.audit, "emit_awaiting_approval", _track("awaiting_approval"))
    monkeypatch.setattr(nodes.audit, "emit_approval_received", _track("approval_received"))
    return captured


def _state() -> dict[str, Any]:
    return {
        "incident_id": str(INC),
        "draft_verdict": {
            "verdict": "true_positive",
            "confidence": 88,
            "severity": "high",
            "mitre_techniques": ["T1003"],
        },
        "review_output": {"status": "approved"},
        "detection_rule_matches": [],
    }


def _config() -> dict[str, Any]:
    return {
        "configurable": {
            "tenant_id": str(TENANT),
            "investigation_id": str(INV),
            "finding": None,
            "tools": [],
            "mitre_descs": {},
        }
    }


@pytest.mark.asyncio
async def test_repeated_invocations_emit_awaiting_approval_only_once(
    wired: dict[str, Any],
) -> None:
    """Run `await_approval_node` 3× — only the first transition audits."""
    for _ in range(3):
        await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    awaiting_count = sum(1 for name, _ in wired["audit_calls"] if name == "awaiting_approval")
    received_count = sum(1 for name, _ in wired["audit_calls"] if name == "approval_received")
    assert awaiting_count == 1, "awaiting_approval audit must fire exactly once across replays"
    # `approval_received` fires every call (records the resume's analyst
    # decision; idempotency is the API/CLI dedup's job, not the node's).
    assert received_count == 3


def test_update_sql_uses_distinct_from_guard(wired: dict[str, Any]) -> None:
    """The gated UPDATE SQL form is what makes the audit emit replay-safe."""
    import asyncio

    asyncio.run(await_approval_node(_state(), _config()))  # type: ignore[arg-type]
    sqls = " ".join(q[0] for q in wired["conn"].queries)
    assert "incidents" in sqls and "IS DISTINCT FROM 'awaiting_approval'" in sqls
    assert "investigations" in sqls and "IS DISTINCT FROM 'pending'" in sqls
