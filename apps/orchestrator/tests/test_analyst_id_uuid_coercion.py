"""Cluster E MED-3: await_approval_node coerces analyst_id to UUID.

The resume payload is untrusted ingress (CLI dev tool, web UI, future API).
Free-form strings flowed unchanged into ``audit_log.details.approver_id``,
breaking analytics + downstream FK resolution. The fix tries
``UUID(str(raw))`` and on ValueError sets the field to None + emits a warning.
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
VALID_USER = UUID("55555555-5555-5555-5555-555555555555")


class _Result:
    def __init__(self, rowcount: int = 1) -> None:
        self.rowcount = rowcount

    def first(self) -> tuple[Any, ...] | None:
        return None


class _Conn:
    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _Result:
        sql = str(getattr(stmt, "text", stmt))
        self.queries.append((sql, params or {}))
        return _Result(1)


@contextmanager
def _fake_session(_tenant_id: UUID) -> Any:
    yield _Conn()


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {
        "audit_calls": [],
        "interrupt_resume": {"approved": True, "analyst_id": None, "notes": ""},
    }

    def _select_active_policy(_conn: object, _tid: UUID) -> tuple[UUID, str, dict]:
        return (POLICY_ID, "default_require_approval", {"op": "always_true"})

    def _check_policy(_expr: dict, _ctx: dict) -> bool:
        return True

    def _interrupt(_payload: Any) -> Any:
        return captured["interrupt_resume"]

    def _track_audit(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            captured["audit_calls"].append((name, kwargs))

        return _f

    monkeypatch.setattr(nodes, "select_active_policy", _select_active_policy)
    monkeypatch.setattr(nodes, "evaluate_policy", _check_policy)
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)
    monkeypatch.setattr(nodes, "interrupt", _interrupt)
    monkeypatch.setattr(nodes.audit, "emit_awaiting_approval", _track_audit("awaiting"))
    monkeypatch.setattr(nodes.audit, "emit_approval_received", _track_audit("approval_received"))
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
async def test_non_uuid_analyst_id_dropped_to_none(
    patched: dict[str, Any],
) -> None:
    patched["interrupt_resume"] = {
        "approved": True,
        "analyst_id": "kaya@sentientlayer.ai",
        "notes": "approving",
    }
    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]
    assert delta["approver_id"] is None
    received = next(kw for name, kw in patched["audit_calls"] if name == "approval_received")
    assert received["approver_id"] is None
    assert received["approved"] is True


@pytest.mark.asyncio
async def test_valid_uuid_passes_through(patched: dict[str, Any]) -> None:
    patched["interrupt_resume"] = {
        "approved": True,
        "analyst_id": str(VALID_USER),
        "notes": "ok",
    }
    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]
    assert delta["approver_id"] == str(VALID_USER)


@pytest.mark.asyncio
async def test_uuid_with_braces_normalized(patched: dict[str, Any]) -> None:
    """uuid.UUID() accepts braced + hyphenated forms — normalize to canonical."""
    patched["interrupt_resume"] = {
        "approved": True,
        "analyst_id": "{55555555-5555-5555-5555-555555555555}",
        "notes": "",
    }
    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]
    assert delta["approver_id"] == "55555555-5555-5555-5555-555555555555"


@pytest.mark.asyncio
async def test_empty_analyst_id_is_none(patched: dict[str, Any]) -> None:
    patched["interrupt_resume"] = {
        "approved": True,
        "analyst_id": "",
        "notes": "",
    }
    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]
    assert delta["approver_id"] is None
