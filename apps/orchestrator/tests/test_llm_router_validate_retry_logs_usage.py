"""Cluster C / CRIT-5 — schema-retry HTTP call writes its own usage row + accumulator UPDATE.

Pre-cluster-C, ``_validate_with_retry`` made a second OpenRouter call inside
the same logical attempt without any ledger row or accumulator UPDATE — the
per-investigation cap could be evaded indefinitely by triggering schema
validation failures. Cluster C threads ``attempt_num`` + ``investigation_id``
into the method and writes the retry sub-event under
``(attempt_num, retry_seq=1)``. ADR-0015 §"Retry semantics" defines the
contract.

Five scenarios covered (the Section 3 matrix from
``tasks/bug-fixes-2026-05-04/cluster-c-cost-cap.md`` plan derivation):

1. Primary validates first try — caller logs, no retry-side rows.
2. Primary fails validation → retry succeeds — 2 rows: (seq=0, fail) + (seq=1, success).
3. Primary fails → retry validates, fails — 2 rows: (seq=0, fail) + (seq=1, fail).
4. Primary fails → retry HTTP fails (transport) — 2 rows: (seq=0, fail) + (seq=1, classified).
5. Primary fails → retry hits 401/403 — 1 row: (seq=0, fail) then propagate.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import BaseModel, Field

from sentient_orchestrator.llm import router as router_module
from sentient_orchestrator.llm.openrouter import OpenRouterResponse
from sentient_orchestrator.llm.router import LLMRouter, _RoleConfig, _TenantConfig

TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")


class _Out(BaseModel):
    severity: str = Field(...)


def _ok_body(*, model: str = "model-a") -> OpenRouterResponse:
    return OpenRouterResponse(
        content='{"severity": "low"}',
        model_used=model,
        generation_id="gen-ok",
        input_tokens=20,
        output_tokens=8,
        cached_tokens=0,
        cost_usd=Decimal("0.0010"),
        latency_ms=42,
    )


def _bad_body(*, model: str = "model-a") -> OpenRouterResponse:
    """Token-counted response that fails schema validation."""
    return OpenRouterResponse(
        content="not-json",
        model_used=model,
        generation_id="gen-bad",
        input_tokens=15,
        output_tokens=4,
        cached_tokens=0,
        cost_usd=Decimal("0.0006"),
        latency_ms=20,
    )


def _patch_loaders(
    monkeypatch: pytest.MonkeyPatch,
    *,
    tenant_cfg: _TenantConfig,
    role_cfg: _RoleConfig,
) -> None:
    monkeypatch.setattr(
        LLMRouter, "_load_tenant_config", staticmethod(lambda _conn, _tid: tenant_cfg)
    )
    monkeypatch.setattr(
        LLMRouter,
        "_load_role_config",
        staticmethod(lambda _conn, _tid, _role: role_cfg),
    )


def _tenant_cfg() -> _TenantConfig:
    return _TenantConfig(
        api_key="sk-test",
        region_constraint=None,
        langsmith_enabled=True,
        per_investigation_budget_usd=None,
        per_investigation_token_cap=None,
    )


def _role_cfg() -> _RoleConfig:
    return _RoleConfig(
        primary_model="model-a",
        fallback_chain=[],
        max_tokens=512,
        temperature=0.0,
        timeout_seconds=30,
        enabled=True,
    )


@pytest.fixture
def usage_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        router_module,
        "log_usage_attempt",
        lambda _conn, **kwargs: calls.append(kwargs),
    )
    return calls


@pytest.fixture
def accumulator_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        router_module,
        "update_investigation_totals",
        lambda _conn, **kwargs: calls.append(kwargs),
    )
    return calls


# ----------------------------------------------------- Scenario 1: primary OK


@pytest.mark.asyncio
async def test_primary_validates_writes_one_row_retry_seq_zero(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg())
    monkeypatch.setattr(router_module, "call_chat_completion", lambda **_kw: _ok_body())

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_body()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    inv_id = uuid4()
    result = await router.call(
        role="triage", messages=[], response_schema=_Out, investigation_id=inv_id
    )

    assert result.parsed is not None
    assert len(usage_calls) == 1
    assert usage_calls[0]["status"] == "success"
    assert usage_calls[0]["retry_seq"] == 0
    assert len(accumulator_calls) == 1


# ----------------------------------------------------- Scenario 2: retry wins


@pytest.mark.asyncio
async def test_primary_fails_retry_succeeds_two_rows(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Primary returns bad JSON → schema fail → retry returns valid JSON →
    success. Ledger has TWO rows for attempt_num=1: (retry_seq=0, fail) +
    (retry_seq=1, success). Both accumulate."""
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg())

    call_seq = {"n": 0}

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        call_seq["n"] += 1
        if call_seq["n"] == 1:
            return _bad_body()  # primary
        return _ok_body()  # retry

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    inv_id = uuid4()
    result = await router.call(
        role="triage", messages=[], response_schema=_Out, investigation_id=inv_id
    )

    assert result.parsed is not None
    assert result.input_tokens == 20  # winning_response = retry
    assert result.cost_usd == Decimal("0.0010")
    assert len(usage_calls) == 2
    assert usage_calls[0]["status"] == "validation_fail"
    assert usage_calls[0]["retry_seq"] == 0
    assert usage_calls[0]["input_tokens"] == 15  # primary tokens
    assert usage_calls[1]["status"] == "success"
    assert usage_calls[1]["retry_seq"] == 1
    assert usage_calls[1]["input_tokens"] == 20  # retry tokens
    # Both calls share the same attempt_num (the schema-retry is a sub-event).
    assert usage_calls[0]["attempt_num"] == usage_calls[1]["attempt_num"] == 1
    assert len(accumulator_calls) == 2


# ----------------------------------------------------- Scenario 3: both fail validation


@pytest.mark.asyncio
async def test_primary_fails_retry_fails_two_rows(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Both primary and retry return bad JSON. Ledger gets two
    (validation_fail, retry_seq=0/1) rows; both accumulate; outer
    _AttemptFailedError advances the fallback chain (which is empty here)
    so FallbackChainExhausted raises."""
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg())

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _bad_body()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    inv_id = uuid4()
    with pytest.raises(router_module.FallbackChainExhausted):
        await router.call(
            role="triage",
            messages=[],
            response_schema=_Out,
            investigation_id=inv_id,
        )

    assert len(usage_calls) == 2
    assert [c["status"] for c in usage_calls] == ["validation_fail", "validation_fail"]
    assert [c["retry_seq"] for c in usage_calls] == [0, 1]
    # Both rows have a token-counted response → both accumulate.
    assert len(accumulator_calls) == 2


# ----------------------------------------------------- Scenario 4: retry transport fails


@pytest.mark.asyncio
async def test_primary_fails_retry_transport_fails_two_rows_one_accum(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Primary fails validation → retry HTTP times out (no response). Two
    usage rows: primary (validation_fail with response) + retry
    (timeout, no response). Only the primary accumulates (retry has no
    token count)."""
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg())

    call_seq = {"n": 0}

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        call_seq["n"] += 1
        if call_seq["n"] == 1:
            return _bad_body()
        raise httpx.TimeoutException("retry timed out")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    inv_id = uuid4()
    with pytest.raises(router_module.FallbackChainExhausted):
        await router.call(
            role="triage",
            messages=[],
            response_schema=_Out,
            investigation_id=inv_id,
        )

    assert len(usage_calls) == 2
    assert usage_calls[0]["status"] == "validation_fail"
    assert usage_calls[0]["retry_seq"] == 0
    assert usage_calls[0]["input_tokens"] == 15  # primary tokens captured
    assert usage_calls[1]["status"] == "timeout"
    assert usage_calls[1]["retry_seq"] == 1
    assert usage_calls[1]["input_tokens"] is None  # no response
    # Only primary accumulates — retry had no token-counted response.
    assert len(accumulator_calls) == 1
    assert accumulator_calls[0]["input_tokens"] == 15


# ----------------------------------------------------- Scenario 5: retry 401 propagates


@pytest.mark.asyncio
async def test_primary_fails_retry_auth_propagates(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Primary fails validation → retry HTTP 401. Primary failure row IS
    written + accumulated; the 401 propagates out (matches primary auth
    policy — no retry row in this case, no swallowing)."""
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg())

    call_seq = {"n": 0}

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        call_seq["n"] += 1
        if call_seq["n"] == 1:
            return _bad_body()
        request = httpx.Request("POST", "https://openrouter.ai/x")
        raise httpx.HTTPStatusError(
            "auth", request=request, response=httpx.Response(401, request=request)
        )

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    inv_id = uuid4()
    with pytest.raises(httpx.HTTPStatusError):
        await router.call(
            role="triage",
            messages=[],
            response_schema=_Out,
            investigation_id=inv_id,
        )

    # Only the primary failure row is in the ledger. The 401 retry does not
    # write a row (matches the primary attempt's auth-failure policy).
    assert len(usage_calls) == 1
    assert usage_calls[0]["status"] == "validation_fail"
    assert usage_calls[0]["retry_seq"] == 0
    assert len(accumulator_calls) == 1
