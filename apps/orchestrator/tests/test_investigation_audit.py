"""Unit tests for investigation audit emit helpers."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from sentient_orchestrator.investigation import audit as audit_module
from sentient_orchestrator.investigation.audit import (
    ACTOR,
    emit_investigation_complete,
    emit_investigation_failed,
    emit_investigation_started,
    emit_llm_call,
    emit_tool_call,
    emit_verdict_drafted,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture every insert_audit_log call's kwargs."""
    calls: list[dict[str, Any]] = []

    def _capture(_conn: object, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(audit_module, "insert_audit_log", _capture)
    return calls


def test_actor_constant() -> None:
    assert ACTOR == "orchestrator:investigation"


def test_investigation_started_emits_thread_id_and_summary(
    captured: list[dict[str, Any]],
) -> None:
    emit_investigation_started(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        thread_id="inv-abc123",
        triage_summary={"severity": "high", "confidence": 80},
    )
    assert len(captured) == 1
    call = captured[0]
    assert call["tenant_id"] == TENANT
    assert call["investigation_id"] == INV
    assert call["actor"] == ACTOR
    assert call["action"] == "investigation_started"
    assert call["details"]["thread_id"] == "inv-abc123"
    assert call["details"]["triage"]["severity"] == "high"


def test_llm_call_emits_phase_and_metrics(captured: list[dict[str, Any]]) -> None:
    emit_llm_call(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        phase="agent",
        model_used="google/gemini-3-flash-preview-20251217",
        input_tokens=100,
        output_tokens=50,
        cached_tokens=20,
        latency_ms=1500,
    )
    call = captured[0]
    assert call["action"] == "llm_call"
    assert call["details"] == {
        "phase": "agent",
        "model_used": "google/gemini-3-flash-preview-20251217",
        "input_tokens": 100,
        "output_tokens": 50,
        "cached_tokens": 20,
        "latency_ms": 1500,
    }


def test_tool_call_sanitizes_args_and_result(captured: list[dict[str, Any]]) -> None:
    """Args + result blobs pass through walk_and_sanitize before insert."""
    emit_tool_call(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        tool_name="siem_query",
        args={"spl": "index=main\x00DROP", "earliest": "-1h"},
        result_text="event\x07line",
        latency_ms=200,
    )
    call = captured[0]
    assert call["action"] == "tool_call"
    # Control chars stripped from both args + result.
    assert call["details"]["args"]["spl"] == "index=mainDROP"
    assert call["details"]["result_summary"] == "eventline"
    assert call["details"]["tool_name"] == "siem_query"
    assert call["details"]["latency_ms"] == 200


def test_tool_call_truncates_huge_result(captured: list[dict[str, Any]]) -> None:
    """Audit field cap is 1KB; result blobs over that are truncated."""
    big = "x" * 5000
    emit_tool_call(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        tool_name="siem_query",
        args={},
        result_text=big,
        latency_ms=10,
    )
    summary = captured[0]["details"]["result_summary"]
    assert summary.endswith("…[truncated]")
    # Cap is 1024 + marker length.
    assert len(summary) < 5000


def test_verdict_drafted_emits_full_verdict(captured: list[dict[str, Any]]) -> None:
    emit_verdict_drafted(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        verdict="true_positive",
        confidence=85,
        severity="high",
        mitre_techniques=["T1059.001", "T1071"],
    )
    call = captured[0]
    assert call["action"] == "verdict_drafted"
    assert call["details"]["verdict"] == "true_positive"
    assert call["details"]["mitre_techniques"] == ["T1059.001", "T1071"]


def test_investigation_complete_emits_status(captured: list[dict[str, Any]]) -> None:
    emit_investigation_complete(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        verdict="benign",
        status_after="done",
    )
    call = captured[0]
    assert call["action"] == "investigation_complete"
    assert call["details"] == {"verdict": "benign", "status_after": "done"}


def test_investigation_failed_sanitizes_error(captured: list[dict[str, Any]]) -> None:
    """Error message + reason flow through sanitizer (control chars stripped)."""
    emit_investigation_failed(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        error_type="FallbackChainExhausted",
        error_message="all attempts failed\x00",
        reason="timeout_chain",
    )
    call = captured[0]
    assert call["action"] == "investigation_failed"
    assert call["details"]["error_type"] == "FallbackChainExhausted"
    assert call["details"]["error_message"] == "all attempts failed"
    assert call["details"]["reason"] == "timeout_chain"
