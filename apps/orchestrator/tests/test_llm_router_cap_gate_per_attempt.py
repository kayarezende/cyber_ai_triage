"""Cluster C / HIGH-6 — cap gate re-checks before every fallback attempt.

Pre-cluster-C the cap gate ran ONCE before the for-loop. A primary attempt
that failed-with-response and pushed the running total past the cap would
NOT block the next iteration's HTTP call — the gate wasn't re-evaluated.
Cluster C moves the call into the loop body so each iteration's pre-flight
sees the just-written totals from the prior iteration.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import BaseModel, Field

from sentient_orchestrator.llm import router as router_module
from sentient_orchestrator.llm.exceptions import BudgetExceeded
from sentient_orchestrator.llm.openrouter import OpenRouterResponse
from sentient_orchestrator.llm.router import LLMRouter, _RoleConfig, _TenantConfig

TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")


class _Out(BaseModel):
    severity: str = Field(...)


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


@pytest.mark.asyncio
async def test_cap_breached_after_first_attempt_blocks_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First fallback iteration runs (primary + schema-retry both fail with
    token-counted response). Both accumulate. Second iteration's pre-flight
    cap gate reads the over-cap totals and raises BudgetExceeded BEFORE
    making any HTTP call to model-b. Confirms HIGH-6 per-attempt re-check.
    """
    tenant_cfg = _TenantConfig(
        byo_keys={"openrouter": "sk-test"},
        region_constraint=None,
        langsmith_enabled=True,
        per_investigation_budget_usd=Decimal("0.50"),
        per_investigation_token_cap=None,
    )
    role_cfg = _RoleConfig(
        primary_model="model-a",
        fallback_chain=["model-b"],
        max_tokens=512,
        temperature=0.0,
        timeout_seconds=30,
        enabled=True,
    )
    _patch_loaders(monkeypatch, tenant_cfg=tenant_cfg, role_cfg=role_cfg)

    # Mock conn: each gate SELECT returns a row reflecting the "current"
    # accumulator state. iter 1 reads under-cap; iter 2 reads over-cap.
    gate_reads = {"n": 0}

    def _execute(_stmt: Any, _params: Any = None) -> MagicMock:
        result = MagicMock()
        sql = str(getattr(_stmt, "text", _stmt))
        if "FROM investigations" in sql:
            gate_reads["n"] += 1
            if gate_reads["n"] == 1:
                # Under cap on first iteration's pre-flight.
                result.first.return_value = (10, 5, Decimal("0.10"))
            else:
                # Cap breached after model-a's primary + retry accumulators ran.
                result.first.return_value = (200, 100, Decimal("0.55"))
        else:
            result.first.return_value = None
        return result

    conn = MagicMock()
    conn.execute.side_effect = _execute

    fake_call_models: list[str] = []

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        fake_call_models.append(model)
        # model-a returns bad JSON to trigger schema-fail path; the retry
        # also gets bad JSON (same fake_call mock). model-b would return OK
        # but should never be reached.
        if model == "model-a":
            return OpenRouterResponse(
                content="not-json",
                model_used=model,
                generation_id="gen-bad",
                input_tokens=200,
                output_tokens=100,
                cached_tokens=0,
                cost_usd=Decimal("0.55"),
                latency_ms=20,
            )
        return OpenRouterResponse(
            content='{"severity": "low"}',
            model_used=model,
            generation_id="gen-ok",
            input_tokens=10,
            output_tokens=5,
            cached_tokens=0,
            cost_usd=Decimal("0.001"),
            latency_ms=20,
        )

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)

    router = LLMRouter(TENANT_ID, conn)
    inv_id = uuid4()
    with pytest.raises(BudgetExceeded) as info:
        await router.call(
            role="triage",
            messages=[],
            response_schema=_Out,
            investigation_id=inv_id,
        )

    # model-a was called twice (primary + schema-retry inside _validate_with_retry).
    # model-b was never called — the per-attempt gate caught the over-cap state.
    assert fake_call_models == ["model-a", "model-a"]
    assert "model-b" not in fake_call_models
    assert info.value.role == "triage"
    # 2 gate SELECTs: iter 1 (under), iter 2 (over → raise).
    assert gate_reads["n"] == 2


@pytest.mark.asyncio
async def test_cap_disabled_outer_gate_no_per_attempt_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both caps None — outer-gate skips the per-attempt _check_budget call
    entirely. Verified by counting SELECTs against `investigations`."""
    tenant_cfg = _TenantConfig(
        byo_keys={"openrouter": "k"},
        region_constraint=None,
        langsmith_enabled=True,
        per_investigation_budget_usd=None,
        per_investigation_token_cap=None,
    )
    role_cfg = _RoleConfig(
        primary_model="model-a",
        fallback_chain=[],
        max_tokens=512,
        temperature=0.0,
        timeout_seconds=30,
        enabled=True,
    )
    _patch_loaders(monkeypatch, tenant_cfg=tenant_cfg, role_cfg=role_cfg)

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return OpenRouterResponse(
            content='{"severity": "low"}',
            model_used="model-a",
            generation_id="gen",
            input_tokens=10,
            output_tokens=5,
            cached_tokens=0,
            cost_usd=Decimal("0.0001"),
            latency_ms=20,
        )

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)

    conn = MagicMock()
    router = LLMRouter(TENANT_ID, conn)
    await router.call(role="triage", messages=[], investigation_id=uuid4())

    select_against_investigations = [
        c for c in conn.execute.call_args_list if c.args and "FROM investigations" in str(c.args[0])
    ]
    assert select_against_investigations == []
