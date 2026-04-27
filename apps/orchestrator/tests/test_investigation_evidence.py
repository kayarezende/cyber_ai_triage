"""Unit tests for the wk-7 evidence manifest module."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from sentient_ocsf.detection_finding import (
    Analytic,
    DetectionFinding,
    FindingInfo,
    Metadata,
    Product,
)
from sentient_orchestrator.investigation.evidence import (
    DEFAULT_BUCKET,
    _filter_agent_turns,
    _load_tool_calls,
    _load_usage_summary,
    _sha256_text,
    build_evidence_manifest,
    manifest_key,
    upload_manifest,
)
from sentient_orchestrator.investigation.state import InvestigationOutput

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INC = UUID("22222222-2222-2222-2222-222222222222")
INV = UUID("33333333-3333-3333-3333-333333333333")


def _finding() -> DetectionFinding:
    return DetectionFinding(
        category_uid=2,
        class_uid=2004,
        activity_id=1,
        type_uid=200401,
        severity_id=4,
        time=1700000000000,
        metadata=Metadata(
            version="1.3.0",
            log_provider="splunk",
            product=Product(name="Splunk", vendor_name="Splunk Inc."),
        ),
        finding_info=FindingInfo(
            uid="fid-evidence",
            title="Evidence Test",
            analytic=Analytic(name="t", type_id=2, uid="a", version="1"),
        ),
        mitre_techniques=[],
        attacks=[],
    )


def _verdict() -> InvestigationOutput:
    return InvestigationOutput(
        verdict="true_positive",
        confidence=85,
        severity="high",
        mitre_techniques=["T1059.001", "T1071"],
        summary="Confirmed PowerShell C2.",
        evidence=["spl: search"],
        reasoning="evidence chain.",
    )


# ------------------------------------------------------------ manifest_key


def test_manifest_key_deterministic() -> None:
    a = manifest_key(tenant_id=TENANT, investigation_id=INV)
    b = manifest_key(tenant_id=TENANT, investigation_id=INV)
    assert a == b
    assert a == f"manifests/{TENANT}/{INV}.json"


# ------------------------------------------------------------ filter agent turns


def test_filter_agent_turns_drops_system_and_user() -> None:
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "incident"},
        {"role": "assistant", "content": "plan"},
        {"role": "tool", "tool_call_id": "t1", "content": "result"},
        {"role": "assistant", "content": "verdict"},
    ]
    out = _filter_agent_turns(msgs)
    assert len(out) == 3
    assert [m["role"] for m in out] == ["assistant", "tool", "assistant"]


def test_filter_agent_turns_strips_cacheable() -> None:
    """Defensive: cacheable shouldn't appear on assistant/tool turns, but if it
    does, drop it before persisting to manifest."""
    out = _filter_agent_turns([{"role": "assistant", "content": "x", "cacheable": True}])
    assert "cacheable" not in out[0]


# ------------------------------------------------------------ tool calls + sha256


def test_sha256_text_format() -> None:
    h = _sha256_text("hello")
    assert h.startswith("sha256:")
    expected = hashlib.sha256(b"hello").hexdigest()
    assert h.split(":", 1)[1] == expected


def test_load_tool_calls_hashes_results() -> None:
    rows = [
        (
            {
                "tool_name": "siem_query",
                "args": {"spl": "index=main"},
                "result_summary": "10 events",
                "latency_ms": 150,
            },
        ),
        (
            {
                "tool_name": "siem_get_notable",
                "args": {"id": "abc"},
                "result_summary": "",
                "latency_ms": 5,
            },
        ),
    ]
    conn = MagicMock()
    conn.execute.return_value.fetchall.return_value = rows

    calls = _load_tool_calls(conn, investigation_id=INV)
    assert len(calls) == 2
    assert calls[0]["tool"] == "siem_query"
    assert calls[0]["args"] == {"spl": "index=main"}
    assert calls[0]["result_hash"] == _sha256_text("10 events")
    assert calls[0]["result_s3_key"] is None
    # Empty result_summary → result_hash is None (don't hash empty string)
    assert calls[1]["result_hash"] is None


# ------------------------------------------------------------ usage summary


def test_load_usage_summary_aggregates_success_rows_only() -> None:
    rows = [
        ("triage", "model-a", "model-a", "success", 1, 100, 50, 20, 0.0010),
        ("investigation", "model-b", "model-b", "5xx", 1, None, None, None, None),
        ("investigation", "model-b", "model-b", "success", 2, 200, 80, 60, 0.0030),
        ("review", "model-c", "model-c", "success", 1, 50, 25, 10, 0.0005),
    ]
    conn = MagicMock()
    conn.execute.return_value.fetchall.return_value = rows

    token_usage, attempts = _load_usage_summary(conn, investigation_id=INV)

    # Only success rows aggregate.
    assert token_usage["input"] == 100 + 200 + 50
    assert token_usage["output"] == 50 + 80 + 25
    assert token_usage["cached"] == 20 + 60 + 10
    assert token_usage["cost_usd"] == pytest.approx(0.0010 + 0.0030 + 0.0005, rel=1e-6)
    # cache_hit_rate = 90 / 350
    assert token_usage["cache_hit_rate"] == pytest.approx(round(90 / 350, 4))
    # All rows (incl failure) present in attempts list.
    assert len(attempts) == 4
    assert [a["status"] for a in attempts] == ["success", "5xx", "success", "success"]


def test_load_usage_summary_empty_no_div_zero() -> None:
    """No usage rows yet (e.g. graph crashed before any LLM call)."""
    conn = MagicMock()
    conn.execute.return_value.fetchall.return_value = []
    token_usage, attempts = _load_usage_summary(conn, investigation_id=INV)
    assert token_usage["input"] == 0
    assert token_usage["cache_hit_rate"] == 0.0
    assert attempts == []


# ------------------------------------------------------------ build_evidence_manifest


def _conn_for_manifest() -> MagicMock:
    """Mock conn whose execute().fetchall() routes by SQL keyword."""
    conn = MagicMock()

    def _execute(stmt: Any, _params: Any = None) -> MagicMock:
        result = MagicMock()
        sql = str(getattr(stmt, "text", stmt))
        if "audit_log" in sql:
            result.fetchall.return_value = [
                (
                    {
                        "tool_name": "siem_query",
                        "args": {"spl": "index=main"},
                        "result_summary": "5 events",
                        "latency_ms": 100,
                    },
                ),
            ]
        elif "FROM usage" in sql:
            result.fetchall.return_value = [
                ("investigation", "m", "m", "success", 1, 100, 30, 10, 0.001),
            ]
        else:
            result.fetchall.return_value = []
        return result

    conn.execute.side_effect = _execute
    return conn


def test_build_evidence_manifest_shape() -> None:
    final_state: dict[str, Any] = {
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "incident"},
            {"role": "assistant", "content": "plan"},
            {"role": "tool", "tool_call_id": "t1", "content": "result"},
        ],
        "triage_severity": "high",
        "triage_confidence": 80,
        "triage_mitre_guesses": ["T1110"],
        "triage_entities": ["alice"],
        "triage_reasoning": "brute force",
        "draft_verdict": _verdict().model_dump(),
    }
    review = {"status": "approved", "notes": "looks good"}

    manifest = build_evidence_manifest(
        conn=_conn_for_manifest(),
        investigation_id=INV,
        tenant_id=TENANT,
        incident_id=INC,
        finding=_finding(),
        final_state=final_state,  # type: ignore[arg-type]
        verdict=_verdict(),
        review=review,
    )

    # Required top-level keys per tasks/todo.md lines 357-380.
    for key in (
        "investigation_id",
        "tenant_id",
        "incident",
        "triage_result",
        "agent_turns",
        "tool_calls",
        "draft_verdict",
        "mitre_techniques",
        "rule_matches",
        "final_output",
        "token_usage",
        "attempts",
    ):
        assert key in manifest, f"missing top-level key: {key!r}"

    assert manifest["investigation_id"] == str(INV)
    assert manifest["tenant_id"] == str(TENANT)
    assert manifest["incident"]["ocsf"]["class_uid"] == 2004
    assert manifest["triage_result"]["severity"] == "high"
    assert manifest["mitre_techniques"] == ["T1059.001", "T1071"]
    assert manifest["rule_matches"] == []
    assert manifest["review"] == review
    assert manifest["review_notes"] == "looks good"
    # Agent turns dropped system + user.
    assert [m["role"] for m in manifest["agent_turns"]] == ["assistant", "tool"]
    # Tool calls hashed.
    assert manifest["tool_calls"][0]["result_hash"].startswith("sha256:")
    # Token usage came through.
    assert manifest["token_usage"]["input"] == 100


def test_build_evidence_manifest_review_none() -> None:
    """Review still under construction (Phase D not yet wired) → None passes."""
    final_state: dict[str, Any] = {
        "messages": [],
        "triage_severity": "low",
        "triage_confidence": 50,
        "triage_mitre_guesses": [],
        "triage_entities": [],
        "triage_reasoning": "",
        "draft_verdict": _verdict().model_dump(),
    }
    manifest = build_evidence_manifest(
        conn=_conn_for_manifest(),
        investigation_id=INV,
        tenant_id=TENANT,
        incident_id=INC,
        finding=_finding(),
        final_state=final_state,  # type: ignore[arg-type]
        verdict=_verdict(),
        review=None,
    )
    assert manifest["review"] is None
    assert manifest["review_notes"] is None


# ------------------------------------------------------------ upload_manifest


def test_upload_manifest_calls_storage_with_serialized_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_upload(
        *,
        bucket: str,
        key: str,
        body: bytes,
        content_type: str = "application/json",
    ) -> str:
        captured["bucket"] = bucket
        captured["key"] = key
        captured["body"] = body
        captured["content_type"] = content_type
        return key

    monkeypatch.setattr(
        "sentient_orchestrator.investigation.evidence.upload_evidence",
        fake_upload,
    )
    manifest = {"investigation_id": str(INV), "x": 1}
    bucket, key, size_bytes = upload_manifest(
        tenant_id=TENANT,
        investigation_id=INV,
        manifest=manifest,
    )
    assert bucket == DEFAULT_BUCKET
    assert key == manifest_key(tenant_id=TENANT, investigation_id=INV)
    assert size_bytes > 0
    parsed = json.loads(captured["body"].decode("utf-8"))
    assert parsed["investigation_id"] == str(INV)


def test_upload_manifest_uses_env_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MINIO_BUCKET_EVIDENCE", "evidence-test")
    captured: dict[str, Any] = {}

    def fake_upload(
        *,
        bucket: str,
        key: str,
        body: bytes,
        content_type: str = "application/json",
    ) -> str:
        captured["bucket"] = bucket
        return key

    monkeypatch.setattr(
        "sentient_orchestrator.investigation.evidence.upload_evidence",
        fake_upload,
    )
    upload_manifest(tenant_id=TENANT, investigation_id=INV, manifest={})
    assert captured["bucket"] == "evidence-test"
