"""Wk-8 unit tests for `writeback_node`.

Mocks the MCP tool surface + DB-load helpers so the node can be exercised
without live Splunk or Postgres. Audit emitters tracked.
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
    _build_writeback_comment,
    reset_node_call_counts,
    writeback_node,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INV = UUID("22222222-2222-2222-2222-222222222222")
INC = UUID("33333333-3333-3333-3333-333333333333")


@contextmanager
def _fake_session(_tenant_id: UUID) -> Any:
    yield MagicMock()


@pytest.fixture(autouse=True)
def _reset_counts() -> None:
    reset_node_call_counts()


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {
        "writeback_mode": "hec_only",
        "siem_notable_id": None,
        "audit_calls": [],
    }

    monkeypatch.setattr(nodes, "tenant_session", _fake_session)
    monkeypatch.setattr(
        nodes,
        "_load_writeback_mode",
        lambda _conn, _tid: captured["writeback_mode"],
    )
    monkeypatch.setattr(
        nodes,
        "_load_siem_notable_id",
        lambda _conn, _iid: captured["siem_notable_id"],
    )

    def _track(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            captured["audit_calls"].append((name, kwargs))

        return _f

    monkeypatch.setattr(
        nodes.audit, "emit_writeback_attempted", _track("writeback_attempted")
    )
    monkeypatch.setattr(
        nodes.audit, "emit_writeback_succeeded", _track("writeback_succeeded")
    )
    monkeypatch.setattr(
        nodes.audit, "emit_writeback_failed", _track("writeback_failed")
    )
    return captured


class _FakeFinding:
    """Minimal stand-in for DetectionFinding — `to_hec_dict` is the only call."""

    def to_hec_dict(self) -> dict[str, Any]:
        return {"class_uid": 2004, "ocsf_field": "x"}


def _draft() -> dict[str, Any]:
    return {
        "verdict": "true_positive",
        "confidence": 88,
        "severity": "high",
        "summary": "user pivoted lateral",
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


def _hec_tool(*, fail: bool = False) -> Any:
    # Compact JSON to mirror Pydantic v2's `model_dump_json()` shape — naïve
    # substring detection in the writeback wrapper would silently misclassify
    # the spaced form, so tests use the wire shape.
    @tool
    async def siem_hec_post(event: dict, index: str = "triage_verdicts") -> str:
        """HEC post."""
        if fail:
            raise RuntimeError("hec down")
        return '{"success":true,"status_code":200}'

    return siem_hec_post


def _notable_update_tool(*, fail: bool = False, degraded: bool = False) -> Any:
    @tool
    async def siem_notable_update(
        notable_id: str, comment: str, status: str | None = None
    ) -> str:
        """ES notable update."""
        if fail:
            raise RuntimeError("notable_update down")
        if degraded:
            return '{"success":false,"degraded":true,"notable_id":"n-1"}'
        return '{"success":true,"degraded":false,"notable_id":"n-1"}'

    return siem_notable_update


# --- hec_only path -------------------------------------------------------


@pytest.mark.asyncio
async def test_hec_only_calls_only_hec(patched: dict[str, Any]) -> None:
    patched["writeback_mode"] = "hec_only"
    delta = await writeback_node(  # type: ignore[arg-type]
        _state(), _config(tools=[_hec_tool(), _notable_update_tool()])
    )
    assert delta["writeback_status"] == "succeeded"
    assert len(delta["writeback_attempts"]) == 1
    assert delta["writeback_attempts"][0]["tool"] == "siem_hec_post"
    names = [n for n, _ in patched["audit_calls"]]
    assert names == ["writeback_attempted", "writeback_succeeded"]


@pytest.mark.asyncio
async def test_dual_calls_both_when_notable_id_present(
    patched: dict[str, Any],
) -> None:
    patched["writeback_mode"] = "dual"
    patched["siem_notable_id"] = "notable-abc"
    delta = await writeback_node(  # type: ignore[arg-type]
        _state(), _config(tools=[_hec_tool(), _notable_update_tool()])
    )
    assert delta["writeback_status"] == "succeeded"
    tools_called = [a["tool"] for a in delta["writeback_attempts"]]
    assert tools_called == ["siem_hec_post", "siem_notable_update"]


@pytest.mark.asyncio
async def test_dual_without_notable_id_falls_back_to_hec_only(
    patched: dict[str, Any],
) -> None:
    patched["writeback_mode"] = "dual"
    patched["siem_notable_id"] = None
    delta = await writeback_node(  # type: ignore[arg-type]
        _state(), _config(tools=[_hec_tool(), _notable_update_tool()])
    )
    assert delta["writeback_status"] == "succeeded"
    tools_called = [a["tool"] for a in delta["writeback_attempts"]]
    assert tools_called == ["siem_hec_post"]


# --- failure paths -------------------------------------------------------


@pytest.mark.asyncio
async def test_hec_failure_marks_failed_does_not_raise(
    patched: dict[str, Any],
) -> None:
    delta = await writeback_node(  # type: ignore[arg-type]
        _state(),
        _config(tools=[_hec_tool(fail=True), _notable_update_tool()]),
    )
    assert delta["writeback_status"] == "failed"
    assert delta["writeback_attempts"][0]["ok"] is False
    detail = delta["writeback_attempts"][0]["detail"]
    assert detail["error_type"] == "RuntimeError"
    failed_emits = [
        kwargs for name, kwargs in patched["audit_calls"] if name == "writeback_failed"
    ]
    assert failed_emits[0]["error"] == "hec_failed"


@pytest.mark.asyncio
async def test_notable_update_failure_marks_failed(
    patched: dict[str, Any],
) -> None:
    patched["writeback_mode"] = "dual"
    patched["siem_notable_id"] = "n-1"
    delta = await writeback_node(  # type: ignore[arg-type]
        _state(),
        _config(tools=[_hec_tool(), _notable_update_tool(fail=True)]),
    )
    assert delta["writeback_status"] == "failed"
    failed_emits = [
        kwargs for name, kwargs in patched["audit_calls"] if name == "writeback_failed"
    ]
    assert failed_emits[0]["error"] == "notable_update_failed"


@pytest.mark.asyncio
async def test_rejected_approval_skips_writeback(
    patched: dict[str, Any],
) -> None:
    patched["writeback_mode"] = "dual"
    patched["siem_notable_id"] = "n-1"
    delta = await writeback_node(  # type: ignore[arg-type]
        _state(approval_status="rejected"),
        _config(tools=[_hec_tool(), _notable_update_tool()]),
    )
    assert delta["writeback_status"] == "skipped"
    assert delta["writeback_attempts"] == []
    names = [n for n, _ in patched["audit_calls"]]
    assert names == ["writeback_attempted"]
    attempted_kw = patched["audit_calls"][0][1]
    assert attempted_kw["mode"] == "skipped_rejected"


# --- comment / event helpers --------------------------------------------


@pytest.mark.asyncio
async def test_dual_with_degraded_notable_update_marks_failed(
    patched: dict[str, Any],
) -> None:
    """Soft failure: notable_update returns degraded=true (plain Splunk, no ES).

    Regression test — Pydantic v2 emits compact JSON `"success":false`, naïve
    substring detection that requires `"success": false` (with space) silently
    misclassified this as success.
    """
    patched["writeback_mode"] = "dual"
    patched["siem_notable_id"] = "n-1"
    delta = await writeback_node(  # type: ignore[arg-type]
        _state(),
        _config(tools=[_hec_tool(), _notable_update_tool(degraded=True)]),
    )
    assert delta["writeback_status"] == "failed"
    assert delta["writeback_attempts"][1]["tool"] == "siem_notable_update"
    assert delta["writeback_attempts"][1]["ok"] is False
    failed_emits = [
        kwargs for name, kwargs in patched["audit_calls"] if name == "writeback_failed"
    ]
    assert failed_emits[0]["error"] == "notable_update_failed"


def test_build_writeback_comment_truncates_summary() -> None:
    long_summary = "x" * 2000
    draft = {
        "verdict": "true_positive",
        "confidence": 80,
        "severity": "high",
        "mitre_techniques": ["T1003"],
        "summary": long_summary,
    }
    comment = _build_writeback_comment(draft, INV, evidence_url="s3://k")
    assert "Sentient Layer verdict: true_positive" in comment
    assert "T1003" in comment
    assert "x" * 600 not in comment  # summary trimmed to 500
    assert "Evidence: s3://k" in comment
    assert INV.hex[:12] in comment
