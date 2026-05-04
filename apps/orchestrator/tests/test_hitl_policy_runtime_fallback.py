"""Cluster B HIGH-4: malformed policy at runtime falls back to needs_human.

If a policy row in the DB is corrupt (unknown op, mistyped operand, recursion
overflow), `evaluate_policy` raises. Pre-fix the exception propagated up
through `await_approval_node` and crashed the LangGraph node — investigation
ends `inconclusive`, no audit signal naming the broken policy, no analyst
review. Post-fix: the callsite catches `ValueError`/`TypeError`/`RecursionError`,
emits a structured audit row, and falls back to `needs_human=True` (the
conservative MVP default per ADR-0009).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
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


@contextmanager
def _fake_session(_tenant_id: UUID) -> Any:
    yield MagicMock()


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {
        "policy": (
            POLICY_ID,
            "broken_policy",
            {"op": "unknown_op", "field": "severity", "value": "high"},
        ),
        "policy_exception": ValueError("unknown op: 'unknown_op'"),
        "audit_calls": [],
        "interrupt_payload": None,
        "interrupt_resume": {"approved": True, "analyst_id": None, "notes": ""},
    }

    def _select_active_policy(_conn: object, _tid: UUID) -> tuple[UUID | None, str, dict]:
        return captured["policy"]

    def _raise_policy(_expr: dict, _ctx: dict) -> bool:
        exc = captured["policy_exception"]
        if exc is None:
            return True
        raise exc

    def _interrupt(payload: Any) -> Any:
        captured["interrupt_payload"] = payload
        return captured["interrupt_resume"]

    def _track_audit(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            captured["audit_calls"].append((name, kwargs))

        return _f

    monkeypatch.setattr(nodes, "select_active_policy", _select_active_policy)
    monkeypatch.setattr(nodes, "evaluate_policy", _raise_policy)
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)
    monkeypatch.setattr(nodes, "interrupt", _interrupt)
    monkeypatch.setattr(nodes.audit, "emit_awaiting_approval", _track_audit("awaiting_approval"))
    monkeypatch.setattr(nodes.audit, "emit_approval_received", _track_audit("approval_received"))
    monkeypatch.setattr(
        nodes.audit,
        "emit_hitl_policy_evaluation_failed",
        _track_audit("hitl_policy_evaluation_failed"),
    )
    return captured


def _state() -> dict[str, Any]:
    return {
        "incident_id": str(INC),
        "draft_verdict": {
            "verdict": "true_positive",
            "confidence": 88,
            "severity": "high",
            "mitre_techniques": ["T1059"],
        },
        "review_output": {"status": "approved", "hallucination_risk": "low"},
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
async def test_value_error_in_policy_falls_back_to_needs_human(
    patched: dict[str, Any],
) -> None:
    patched["policy_exception"] = ValueError("unknown op: 'unknown_op'")

    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    # Conservative default: human approval required, interrupt fires.
    assert delta["approval_status"] == "approved"
    assert patched["interrupt_payload"] is not None
    assert patched["interrupt_payload"]["reason"] == "human_approval_required"


@pytest.mark.asyncio
async def test_value_error_emits_hitl_policy_evaluation_failed_audit(
    patched: dict[str, Any],
) -> None:
    patched["policy_exception"] = ValueError("unknown op: 'unknown_op'")

    await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    audit_names = [name for name, _ in patched["audit_calls"]]
    assert "hitl_policy_evaluation_failed" in audit_names

    failure = next(
        kwargs for name, kwargs in patched["audit_calls"] if name == "hitl_policy_evaluation_failed"
    )
    assert failure["policy_id"] == POLICY_ID
    assert failure["policy_name"] == "broken_policy"
    assert "unknown_op" in failure["error_message"]
    assert failure["decision_ctx"]["severity"] == "high"


@pytest.mark.asyncio
async def test_type_error_also_falls_back(patched: dict[str, Any]) -> None:
    patched["policy_exception"] = TypeError("not subscriptable")

    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    audit_names = [name for name, _ in patched["audit_calls"]]
    assert "hitl_policy_evaluation_failed" in audit_names
    assert delta["approval_status"] == "approved"  # via the resume path


@pytest.mark.asyncio
async def test_recursion_error_also_falls_back(
    patched: dict[str, Any],
) -> None:
    patched["policy_exception"] = RecursionError("policy depth exceeded")

    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    audit_names = [name for name, _ in patched["audit_calls"]]
    assert "hitl_policy_evaluation_failed" in audit_names
    assert delta["approval_status"] == "approved"


@pytest.mark.asyncio
async def test_clean_policy_does_not_emit_failure_audit(
    patched: dict[str, Any],
) -> None:
    patched["policy_exception"] = None  # policy returns True cleanly

    await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    audit_names = [name for name, _ in patched["audit_calls"]]
    assert "hitl_policy_evaluation_failed" not in audit_names
