"""Wk-8 unit tests for `await_approval_node`.

Mocks `select_active_policy` + `evaluate_policy` so we can exercise both the
auto-approve path and the interrupt path without a live DB. Audit emitters
are tracked.
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
        "policy": (POLICY_ID, "default_require_approval", {"op": "always_true"}),
        "policy_decision": True,
        "audit_calls": [],
        "interrupt_payload": None,
        "interrupt_resume": {"approved": True, "analyst_id": None, "notes": ""},
    }

    def _select_active_policy(_conn: object, _tid: UUID) -> tuple[UUID | None, str, dict]:
        return captured["policy"]

    def _check_policy(_expr: dict, _ctx: dict) -> bool:
        return captured["policy_decision"]

    def _interrupt(payload: Any) -> Any:
        captured["interrupt_payload"] = payload
        return captured["interrupt_resume"]

    def _track_audit(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            captured["audit_calls"].append((name, kwargs))

        return _f

    monkeypatch.setattr(nodes, "select_active_policy", _select_active_policy)
    monkeypatch.setattr(nodes, "evaluate_policy", _check_policy)
    monkeypatch.setattr(nodes, "tenant_session", _fake_session)
    monkeypatch.setattr(nodes, "interrupt", _interrupt)
    monkeypatch.setattr(
        nodes.audit, "emit_awaiting_approval", _track_audit("awaiting_approval")
    )
    monkeypatch.setattr(
        nodes.audit, "emit_approval_received", _track_audit("approval_received")
    )
    return captured


def _state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "incident_id": str(INC),
        "draft_verdict": {
            "verdict": "true_positive",
            "confidence": 88,
            "severity": "high",
            "mitre_techniques": ["T1003", "T1059.001"],
        },
        "review_output": {"status": "approved", "hallucination_risk": "low"},
        "detection_rule_matches": [{"rule_name": "ransomware_kill_chain"}],
    }
    base.update(overrides)
    return base


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


# --- auto-approve path ---------------------------------------------------


@pytest.mark.asyncio
async def test_auto_approves_when_policy_returns_false(
    patched: dict[str, Any],
) -> None:
    patched["policy_decision"] = False
    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]
    assert delta == {
        "approval_status": "auto",
        "approver_id": None,
        "approval_notes": "auto_approved",
    }
    assert patched["interrupt_payload"] is None
    names = [n for n, _ in patched["audit_calls"]]
    assert names == ["approval_received"]
    received = patched["audit_calls"][-1][1]
    assert received["approved"] is True
    assert received["notes"] == "auto_approved"


# --- interrupt path ------------------------------------------------------


@pytest.mark.asyncio
async def test_interrupts_when_policy_returns_true_and_resumes_approved(
    patched: dict[str, Any],
) -> None:
    patched["policy_decision"] = True
    patched["interrupt_resume"] = {
        "approved": True,
        "analyst_id": "55555555-5555-5555-5555-555555555555",
        "notes": "looks good",
    }

    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    assert delta["approval_status"] == "approved"
    assert delta["approver_id"] == "55555555-5555-5555-5555-555555555555"
    assert delta["approval_notes"] == "looks good"

    payload = patched["interrupt_payload"]
    assert payload is not None
    assert payload["reason"] == "human_approval_required"
    assert payload["policy_name"] == "default_require_approval"
    assert payload["draft_verdict"]["verdict"] == "true_positive"

    names = [n for n, _ in patched["audit_calls"]]
    assert names == ["awaiting_approval", "approval_received"]


@pytest.mark.asyncio
async def test_rejected_resume_persists_rejected_status(
    patched: dict[str, Any],
) -> None:
    patched["policy_decision"] = True
    patched["interrupt_resume"] = {
        "approved": False,
        "analyst_id": None,
        "notes": "false positive",
    }

    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    assert delta["approval_status"] == "rejected"
    assert delta["approver_id"] is None


@pytest.mark.asyncio
async def test_resume_payload_notes_are_sanitized_and_capped(
    patched: dict[str, Any],
) -> None:
    patched["policy_decision"] = True
    payload_notes = "approve\x00with\x07nulls" + "x" * 5000
    patched["interrupt_resume"] = {
        "approved": True,
        "analyst_id": None,
        "notes": payload_notes,
    }

    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    assert "\x00" not in delta["approval_notes"]
    assert "\x07" not in delta["approval_notes"]
    assert len(delta["approval_notes"]) <= 1024


@pytest.mark.asyncio
async def test_non_dict_resume_payload_treated_as_rejection(
    patched: dict[str, Any],
) -> None:
    patched["policy_decision"] = True
    patched["interrupt_resume"] = "garbage-not-a-dict"

    delta = await await_approval_node(_state(), _config())  # type: ignore[arg-type]
    assert delta["approval_status"] == "rejected"
    assert delta["approver_id"] is None
    assert delta["approval_notes"] == ""


@pytest.mark.asyncio
async def test_decision_ctx_carries_review_status_and_severity(
    patched: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    captured_ctx: list[dict[str, Any]] = []

    def _capture(_expr: dict, ctx: dict) -> bool:
        captured_ctx.append(ctx)
        return True

    monkeypatch.setattr(nodes, "evaluate_policy", _capture)
    patched["interrupt_resume"] = {"approved": True}
    await await_approval_node(_state(), _config())  # type: ignore[arg-type]

    assert captured_ctx, "policy not evaluated"
    ctx = captured_ctx[0]
    assert ctx["severity"] == "high"
    assert ctx["confidence"] == 88
    assert "T1003" in ctx["mitre_techniques"]
    assert ctx["review_status"] == "approved"
    assert ctx["detection_rule_matches"] == ["ransomware_kill_chain"]
