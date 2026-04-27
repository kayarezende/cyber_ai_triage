"""Unit tests for investigation audit emit helpers."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from sentient_orchestrator.investigation import audit as audit_module
from sentient_orchestrator.investigation.audit import (
    ACTOR,
    emit_approval_received,
    emit_awaiting_approval,
    emit_detection_rules_evaluated,
    emit_investigation_complete,
    emit_investigation_failed,
    emit_investigation_started,
    emit_llm_call,
    emit_tool_call,
    emit_verdict_drafted,
    emit_writeback_attempted,
    emit_writeback_failed,
    emit_writeback_succeeded,
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


# --- wk-8 emitters -------------------------------------------------------


def test_detection_rules_evaluated_emits_match_summary(
    captured: list[dict[str, Any]],
) -> None:
    emit_detection_rules_evaluated(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        evaluated_count=10,
        matched_count=2,
        matched_rules=["ransomware_kill_chain", "data_exfil_over_c2"],
        agent_severity="medium",
        effective_severity="critical",
        severity_overridden=True,
    )
    call = captured[0]
    assert call["action"] == "detection_rules_evaluated"
    assert call["actor"] == ACTOR
    details = call["details"]
    assert details["matched_count"] == 2
    assert "ransomware_kill_chain" in details["matched_rules"]
    assert details["severity_overridden"] is True
    assert details["agent_severity"] == "medium"
    assert details["effective_severity"] == "critical"


def test_awaiting_approval_emits_policy_and_decision_ctx(
    captured: list[dict[str, Any]],
) -> None:
    pid = UUID("44444444-4444-4444-4444-444444444444")
    emit_awaiting_approval(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        policy_id=pid,
        policy_name="default_require_approval",
        decision_ctx={"severity": "high", "verdict": "true_positive"},
    )
    call = captured[0]
    assert call["action"] == "awaiting_approval"
    details = call["details"]
    assert details["policy_id"] == str(pid)
    assert details["policy_name"] == "default_require_approval"
    assert details["decision_ctx"]["severity"] == "high"


def test_approval_received_emits_decision_and_approver(
    captured: list[dict[str, Any]],
) -> None:
    emit_approval_received(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        approver_id="55555555-5555-5555-5555-555555555555",
        approved=True,
        notes="looks good\x00",
        policy_id=None,
        policy_name="default_require_approval",
    )
    call = captured[0]
    assert call["action"] == "approval_received"
    details = call["details"]
    assert details["approved"] is True
    assert details["approver_id"] == "55555555-5555-5555-5555-555555555555"
    assert "\x00" not in details["notes"]
    assert details["policy_id"] is None


def test_writeback_attempted_emits_mode_and_targets(
    captured: list[dict[str, Any]],
) -> None:
    emit_writeback_attempted(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        mode="dual",
        hec_index="triage_verdicts",
        notable_update_target="notable-abc",
    )
    call = captured[0]
    assert call["action"] == "writeback_attempted"
    details = call["details"]
    assert details["mode"] == "dual"
    assert details["hec_index"] == "triage_verdicts"
    assert details["notable_update_target"] == "notable-abc"


def test_writeback_succeeded_emits_attempts_payload(
    captured: list[dict[str, Any]],
) -> None:
    emit_writeback_succeeded(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        mode="hec_only",
        attempts=[{"tool": "siem_hec_post", "ok": True, "detail": {"response": "ok"}}],
    )
    call = captured[0]
    assert call["action"] == "writeback_succeeded"
    assert call["details"]["mode"] == "hec_only"
    assert call["details"]["attempts"][0]["tool"] == "siem_hec_post"


def test_writeback_failed_emits_error_and_attempts(
    captured: list[dict[str, Any]],
) -> None:
    emit_writeback_failed(
        MagicMock(),
        tenant_id=TENANT,
        investigation_id=INV,
        mode="dual",
        attempts=[
            {"tool": "siem_hec_post", "ok": False, "detail": {"error_type": "RuntimeError"}}
        ],
        error="hec_failed",
    )
    call = captured[0]
    assert call["action"] == "writeback_failed"
    assert call["details"]["error"] == "hec_failed"
    assert call["details"]["attempts"][0]["ok"] is False
