"""Cluster C / MED-1 — ``cap_usd == 0`` and ``token_cap == 0`` mean "disabled".

Pre-cluster-C, ``cap_usd == 0`` raised BudgetExceeded on cost == 0 because the
comparison is ``>=``. The fix treats 0 as a "no limit" sentinel matching the
project convention (admins setting "no cap" via the UI default to 0, not NULL).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from sentient_orchestrator.llm import router as router_module
from sentient_orchestrator.llm.exceptions import BudgetExceeded
from sentient_orchestrator.llm.openrouter import OpenRouterResponse
from sentient_orchestrator.llm.router import LLMRouter, _RoleConfig, _TenantConfig

TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")


def _role_cfg() -> _RoleConfig:
    return _RoleConfig(
        primary_model="model-a",
        fallback_chain=[],
        max_tokens=512,
        temperature=0.0,
        timeout_seconds=30,
        enabled=True,
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


def _ok_response() -> OpenRouterResponse:
    return OpenRouterResponse(
        content='{"severity": "low"}',
        model_used="model-a",
        generation_id="gen",
        input_tokens=10,
        output_tokens=5,
        cached_tokens=0,
        cost_usd=Decimal("0.001"),
        latency_ms=20,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "budget,token_cap",
    [
        (Decimal("0"), None),
        (None, 0),
        (Decimal("0"), 0),
    ],
    ids=["usd_zero", "tokens_zero", "both_zero"],
)
async def test_cap_zero_means_disabled_no_raise(
    monkeypatch: pytest.MonkeyPatch,
    budget: Decimal | None,
    token_cap: int | None,
) -> None:
    """0 on either cap is "disabled" — running calls (even at non-zero cost)
    must NOT raise. Mirrors the NULL semantic. Outer gate skips _check_budget
    entirely; no SELECT against investigations."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_TenantConfig(
            api_key="k",
            region_constraint=None,
            langsmith_enabled=True,
            per_investigation_budget_usd=budget,
            per_investigation_token_cap=token_cap,
        ),
        role_cfg=_role_cfg(),
    )

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)

    conn = MagicMock()
    router = LLMRouter(TENANT_ID, conn)
    # Must not raise — caps are "disabled" semantically.
    result = await router.call(role="triage", messages=[], investigation_id=uuid4())
    assert result.attempt_num == 1

    # Outer gate short-circuited: no SELECT against investigations should
    # have been issued from the cap-gate path.
    gate_selects = [
        c for c in conn.execute.call_args_list if c.args and "FROM investigations" in str(c.args[0])
    ]
    assert gate_selects == []


@pytest.mark.asyncio
async def test_cap_active_with_overshoot_still_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: a positive cap with totals over still raises — only the
    "0 means disabled" semantic is widened, the >0 cap behavior is intact."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_TenantConfig(
            api_key="k",
            region_constraint=None,
            langsmith_enabled=True,
            per_investigation_budget_usd=Decimal("0.50"),
            per_investigation_token_cap=None,
        ),
        role_cfg=_role_cfg(),
    )

    conn = MagicMock()
    conn.execute.return_value.first.return_value = (100, 50, Decimal("0.55"))

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, conn)
    with pytest.raises(BudgetExceeded):
        await router.call(role="triage", messages=[], investigation_id=uuid4())
