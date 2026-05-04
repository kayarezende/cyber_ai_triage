"""Cluster D HIGH-9: writeback_node short-circuits on prior success +
HEC payload carries `sentient_dedup_id = "{investigation_id}:{verdict_revision}"`.

Two `writeback_node` calls (e.g., wk-12 reaper firing a stale finalize
alongside the fresh resume path) must NOT double-post to HEC. The DB row
already carries `writeback_status='succeeded'` after the first call;
the second `writeback_node` invocation reads that and returns immediately.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from uuid import UUID

import pytest
from langchain_core.tools import tool

from sentient_orchestrator.investigation import nodes
from sentient_orchestrator.investigation.nodes import (
    _build_writeback_event,
    reset_node_call_counts,
    writeback_node,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")
INC = UUID("33333333-3333-3333-3333-333333333333")


class _Result:
    def __init__(self, *, first: tuple[Any, ...] | None = None, rowcount: int = 1) -> None:
        self._first = first
        self.rowcount = rowcount

    def first(self) -> tuple[Any, ...] | None:
        return self._first


class _Conn:
    def __init__(
        self,
        *,
        prior_writeback_status: str | None = None,
        verdict_revision: int = 1,
    ) -> None:
        self._prior = prior_writeback_status
        self._rev = verdict_revision
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _Result:
        sql = str(getattr(stmt, "text", stmt))
        self.queries.append((sql, params or {}))
        if "writeback_status" in sql and "verdict_revision" in sql:
            return _Result(first=(self._prior, self._rev))
        return _Result(rowcount=1)


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


class _FakeFinding:
    def to_hec_dict(self) -> dict[str, Any]:
        return {"class_uid": 2004, "ocsf_field": "x"}


def _draft() -> dict[str, Any]:
    return {
        "verdict": "true_positive",
        "confidence": 88,
        "severity": "high",
        "summary": "lateral movement",
        "mitre_techniques": ["T1003", "T1059.001"],
    }


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "incident_id": str(INC),
        "draft_verdict": _draft(),
        "approval_status": "approved",
    }
    base.update(overrides)
    return base


def _config(tools: list[Any]) -> dict[str, Any]:
    return {
        "configurable": {
            "tenant_id": str(TENANT),
            "investigation_id": str(INV),
            "finding": _FakeFinding(),
            "tools": tools,
            "mitre_descs": {},
        }
    }


# ----------------------------------------------------------------- short-circuit


@pytest.mark.asyncio
async def test_short_circuits_when_prior_writeback_status_succeeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cluster D HIGH-9: prior `succeeded` row → no HEC tool call, no
    `writeback_attempted` audit, return shape `{"writeback_status":"succeeded"}`."""
    conn = _Conn(prior_writeback_status="succeeded")

    @contextmanager
    def session(_tid: UUID) -> Any:
        yield conn

    audit_emits: list[str] = []

    def _track(name: str) -> Any:
        def _f(_conn: object, **_kwargs: Any) -> None:
            audit_emits.append(name)

        return _f

    monkeypatch.setattr(nodes, "tenant_session", session)
    monkeypatch.setattr(nodes.audit, "emit_writeback_attempted", _track("writeback_attempted"))
    monkeypatch.setattr(nodes.audit, "emit_writeback_succeeded", _track("writeback_succeeded"))
    monkeypatch.setattr(nodes.audit, "emit_writeback_failed", _track("writeback_failed"))

    hec_calls: list[dict[str, Any]] = []

    @tool
    async def siem_hec_post(event: dict, index: str = "triage_verdicts") -> str:
        """HEC post."""
        hec_calls.append({"event": event, "index": index})
        return '{"success":true}'

    delta = await writeback_node(_state(), _config(tools=[siem_hec_post]))  # type: ignore[arg-type]
    assert delta == {"writeback_status": "succeeded"}
    assert hec_calls == []
    assert audit_emits == [], "no audit emits on short-circuit"


@pytest.mark.asyncio
async def test_pending_status_proceeds_to_hec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: `prior_writeback_status='pending'` does NOT short-circuit."""
    conn = _Conn(prior_writeback_status="pending")

    @contextmanager
    def session(_tid: UUID) -> Any:
        yield conn

    monkeypatch.setattr(nodes, "tenant_session", session)
    monkeypatch.setattr(nodes, "_load_writeback_mode", lambda _c, _t: "hec_only")
    monkeypatch.setattr(nodes, "_load_siem_notable_id", lambda _c, _i: None)
    monkeypatch.setattr(nodes.audit, "emit_writeback_attempted", lambda *_a, **_k: None)
    monkeypatch.setattr(nodes.audit, "emit_writeback_succeeded", lambda *_a, **_k: None)
    monkeypatch.setattr(nodes.audit, "emit_writeback_failed", lambda *_a, **_k: None)

    hec_calls: list[dict[str, Any]] = []

    @tool
    async def siem_hec_post(event: dict, index: str = "triage_verdicts") -> str:
        """HEC post."""
        hec_calls.append({"event": event, "index": index})
        return '{"success":true}'

    delta = await writeback_node(_state(), _config(tools=[siem_hec_post]))  # type: ignore[arg-type]
    assert delta["writeback_status"] == "succeeded"
    assert len(hec_calls) == 1


# ----------------------------------------------------------------- dedup_id


def test_build_writeback_event_includes_sentient_dedup_id() -> None:
    event = _build_writeback_event(_FakeFinding(), _draft(), INV, verdict_revision=1)
    assert event["sentient_dedup_id"] == f"{INV}:1"
    assert event["sentient_investigation_id"] == str(INV)


def test_build_writeback_event_dedup_id_uses_revision() -> None:
    """Future verdict-correction flow bumps the revision; dedup_id reflects it."""
    event = _build_writeback_event(_FakeFinding(), _draft(), INV, verdict_revision=4)
    assert event["sentient_dedup_id"] == f"{INV}:4"
