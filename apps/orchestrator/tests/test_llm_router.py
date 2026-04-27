"""Unit tests for LLMRouter — fallback loop, sovereignty, schema retry."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import BaseModel, Field, ValidationError

from sentient_orchestrator.llm import router as router_module
from sentient_orchestrator.llm.exceptions import (
    BudgetExceeded,
    FallbackChainExhausted,
)
from sentient_orchestrator.llm.openrouter import OpenRouterResponse, OpenRouterToolCall
from sentient_orchestrator.llm.router import LLMRouter, _RoleConfig, _TenantConfig

TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")


class _Out(BaseModel):
    severity: str = Field(...)


def _ok_response(*, model: str = "google/gemini-3-flash-preview") -> OpenRouterResponse:
    return OpenRouterResponse(
        content='{"severity": "low"}',
        model_used=model,
        generation_id="gen-1",
        input_tokens=10,
        output_tokens=5,
        cached_tokens=0,
        cost_usd=0.0001,
        latency_ms=42,
    )


def _bad_json_response() -> OpenRouterResponse:
    return OpenRouterResponse(
        content="not-json",
        model_used="m",
        generation_id="gen-bad",
        input_tokens=1,
        output_tokens=1,
        cached_tokens=0,
        cost_usd=None,
        latency_ms=10,
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


@pytest.fixture
def usage_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture every log_usage_attempt() invocation for assertion."""
    calls: list[dict[str, Any]] = []

    def _capture(_conn: object, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(router_module, "log_usage_attempt", _capture)
    return calls


@pytest.fixture
def accumulator_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture every update_investigation_totals() invocation."""
    calls: list[dict[str, Any]] = []

    def _capture(_conn: object, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(router_module, "update_investigation_totals", _capture)
    return calls


def _tenant_cfg(
    *,
    langsmith_enabled: bool = True,
    region: str | None = None,
    budget_usd: object = None,
    token_cap: int | None = None,
) -> _TenantConfig:
    from decimal import Decimal

    budget_decimal: Decimal | None
    if budget_usd is None:
        budget_decimal = None
    elif isinstance(budget_usd, Decimal):
        budget_decimal = budget_usd
    else:
        budget_decimal = Decimal(str(budget_usd))
    return _TenantConfig(
        api_key="sk-test",
        region_constraint=region,
        langsmith_enabled=langsmith_enabled,
        per_investigation_budget_usd=budget_decimal,
        per_investigation_token_cap=token_cap,
    )


def _role_cfg(
    *,
    primary: str = "model-a",
    fallback: list[str] | None = None,
    enabled: bool = True,
) -> _RoleConfig:
    return _RoleConfig(
        primary_model=primary,
        fallback_chain=list(fallback or []),
        max_tokens=512,
        temperature=0.0,
        timeout_seconds=30,
        enabled=enabled,
    )


# ---------------------------------------------------------------- happy path


@pytest.mark.asyncio
async def test_call_success_logs_one_usage_row(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(primary="model-a"))

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)

    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(role="triage", messages=[], investigation_id=uuid4())

    assert result.attempt_num == 1
    assert result.model_requested == "model-a"
    assert result.input_tokens == 10
    assert len(usage_calls) == 1
    assert usage_calls[0]["status"] == "success"
    assert usage_calls[0]["attempt_num"] == 1
    assert usage_calls[0]["model_requested"] == "model-a"


@pytest.mark.asyncio
async def test_call_unknown_role_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg())
    router = LLMRouter(TENANT_ID, MagicMock())
    with pytest.raises(ValueError, match="unknown LLM role"):
        await router.call(role="bogus", messages=[])


@pytest.mark.asyncio
async def test_disabled_role_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(enabled=False))
    router = LLMRouter(TENANT_ID, MagicMock())
    with pytest.raises(RuntimeError, match="disabled"):
        await router.call(role="summarize", messages=[])


# ---------------------------------------------------------------- fallback chain


@pytest.mark.asyncio
async def test_fallback_after_5xx(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )
    call_count = {"n": 0}

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        call_count["n"] += 1
        if model == "model-a":
            req = httpx.Request("POST", "http://x")
            raise httpx.HTTPStatusError(
                "boom",
                request=req,
                response=httpx.Response(503, request=req),
            )
        return _ok_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(role="triage", messages=[])

    assert call_count["n"] == 2
    assert result.model_requested == "model-b"
    assert result.attempt_num == 2
    assert [c["status"] for c in usage_calls] == ["5xx", "success"]
    assert [c["attempt_num"] for c in usage_calls] == [1, 2]


@pytest.mark.asyncio
async def test_fallback_after_timeout(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        if model == "model-a":
            raise httpx.TimeoutException("timeout")
        return _ok_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(role="triage", messages=[])

    assert result.model_requested == "model-b"
    assert [c["status"] for c in usage_calls] == ["timeout", "success"]


@pytest.mark.asyncio
async def test_fallback_after_429(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        if model == "model-a":
            req = httpx.Request("POST", "http://x")
            raise httpx.HTTPStatusError(
                "rate", request=req, response=httpx.Response(429, request=req)
            )
        return _ok_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    await router.call(role="triage", messages=[])

    assert usage_calls[0]["status"] == "rate_limited"


@pytest.mark.asyncio
async def test_auth_error_does_not_retry(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    """401/403 propagates without writing a usage row (infra error, not LLM ledger)."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )
    call_count = {"n": 0}

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        call_count["n"] += 1
        req = httpx.Request("POST", "http://x")
        raise httpx.HTTPStatusError(
            "unauthorized",
            request=req,
            response=httpx.Response(401, request=req),
        )

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    with pytest.raises(httpx.HTTPStatusError):
        await router.call(role="triage", messages=[])

    # Auth failures don't write a misleading 'validation_fail' row.
    assert usage_calls == []
    # Chain NOT exercised — fallback model never tried.
    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_fallback_exhausted_raises(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        raise httpx.TimeoutException("nope")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    with pytest.raises(FallbackChainExhausted) as exc_info:
        await router.call(role="triage", messages=[])

    assert exc_info.value.role == "triage"
    assert exc_info.value.attempts == ["model-a", "model-b"]
    assert [c["status"] for c in usage_calls] == ["timeout", "timeout"]


# ---------------------------------------------------------------- schema retry


@pytest.mark.asyncio
async def test_schema_retry_succeeds_within_attempt(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(primary="model-a"))
    calls = {"n": 0}

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        calls["n"] += 1
        if calls["n"] == 1:
            return _bad_json_response()
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(role="triage", messages=[], response_schema=_Out)

    assert calls["n"] == 2  # initial + 1 retry
    assert isinstance(result.parsed, _Out)
    assert result.attempt_num == 1  # retry didn't increment
    assert len(usage_calls) == 1
    assert usage_calls[0]["status"] == "success"


@pytest.mark.asyncio
async def test_schema_retry_fails_marks_validation_fail(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        if model == "model-a":
            return _bad_json_response()
        return _ok_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(role="triage", messages=[], response_schema=_Out)

    assert result.model_requested == "model-b"
    assert [c["status"] for c in usage_calls] == ["validation_fail", "success"]


# ---------------------------------------------------------------- sovereignty


@pytest.mark.asyncio
async def test_region_constraint_threaded_through(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(region="au-southeast"),
        role_cfg=_role_cfg(),
    )
    captured: dict[str, Any] = {}

    async def fake_call(**kwargs: Any) -> OpenRouterResponse:
        captured.update(kwargs)
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    await router.call(role="triage", messages=[])

    assert captured["region_constraint"] == "au-southeast"


@pytest.mark.asyncio
async def test_master_key_falls_back_to_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No BYO key → use env OPENROUTER_API_KEY."""
    from sentient_orchestrator.llm.router import _resolve_api_key

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-master-12345")
    assert _resolve_api_key(None) == "sk-master-12345"


def test_byo_key_decrypts_via_fernet(monkeypatch: pytest.MonkeyPatch) -> None:
    """BYO encrypted bytes → Fernet decrypt → return plaintext, ignore env."""
    from cryptography.fernet import Fernet

    from sentient_common.crypto import encrypt
    from sentient_orchestrator.llm.router import _resolve_api_key

    # Generate a Fernet key for the test, set in env so encrypt/decrypt agree.
    monkeypatch.setenv("TENANT_SECRET_KEY", Fernet.generate_key().decode())
    # Master env key set to a sentinel that should NOT be returned.
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-master-NEVER-USED")
    encrypted = encrypt("sk-byo-tenant-12345")
    assert _resolve_api_key(encrypted) == "sk-byo-tenant-12345"


def test_resolve_api_key_rejects_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentient_orchestrator.llm.router import _resolve_api_key

    monkeypatch.setenv("OPENROUTER_API_KEY", "CHANGEME_openrouter")
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        _resolve_api_key(None)


# ---------------------------------------------------------------- sovereignty


def test_langsmith_enabled_returns_traceable_wrap() -> None:
    """`langsmith_enabled=True` produces a wrapped callable distinct from the raw fn."""
    from sentient_orchestrator.llm.openrouter import call_chat_completion
    from sentient_orchestrator.llm.router import _build_traced_call

    wrapped = _build_traced_call(True)
    raw = _build_traced_call(False)
    assert raw is call_chat_completion
    # Wrapped is NOT the raw — langsmith.traceable replaces the function ref.
    assert wrapped is not call_chat_completion


def test_langsmith_disabled_returns_raw_function() -> None:
    """`langsmith_enabled=False` returns the raw call_chat_completion (no wrapper)."""
    from sentient_orchestrator.llm.openrouter import call_chat_completion
    from sentient_orchestrator.llm.router import _build_traced_call

    assert _build_traced_call(False) is call_chat_completion


# ---------------------------------------------------------------- network errors


@pytest.mark.asyncio
async def test_connect_error_falls_back(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    """`httpx.ConnectError` (DNS / connection refused) is bucketed as 5xx + retried."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        if model == "model-a":
            raise httpx.ConnectError("upstream unreachable")
        return _ok_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(role="triage", messages=[])

    assert result.model_requested == "model-b"
    assert [c["status"] for c in usage_calls] == ["5xx", "success"]


def test_validation_error_summary_strips_input_value() -> None:
    """Schema-retry corrective message must NOT echo the raw model output back.

    Defends against prompt injection from Splunk-controlled fields landing in
    the prompt and the model's first response.
    """
    from sentient_orchestrator.llm.router import _summarize_validation_errors
    from sentient_orchestrator.triage.schemas import TriageOutput

    bad_json = (
        '{"severity": "<<<INJECTED PROMPT>>>", "confidence": 50, '
        '"mitre_guesses": [], "entities_to_investigate": [], "reasoning": "x"}'
    )
    summary: str | None = None
    try:
        TriageOutput.model_validate_json(bad_json)
    except ValidationError as exc:
        summary = _summarize_validation_errors(exc)
    assert summary is not None
    assert "INJECTED PROMPT" not in summary
    assert "severity" in summary  # field path retained for the model's debugging


def test_classify_http_status() -> None:
    from sentient_orchestrator.llm.router import _classify_http_status

    assert _classify_http_status(500) == "5xx"
    assert _classify_http_status(503) == "5xx"
    assert _classify_http_status(429) == "rate_limited"
    assert _classify_http_status(400) == "validation_fail"
    assert _classify_http_status(404) == "validation_fail"


def test_schema_to_response_format() -> None:
    from sentient_orchestrator.llm.router import _schema_to_response_format

    assert _schema_to_response_format(None) is None
    fmt = _schema_to_response_format(_Out)
    assert fmt is not None
    assert fmt["type"] == "json_schema"
    assert fmt["json_schema"]["name"] == "_Out"
    assert fmt["json_schema"]["strict"] is True
    assert "schema" in fmt["json_schema"]


def test_pydantic_validation_independent() -> None:
    """Sanity: _Out validates correctly so router schema-retry tests are meaningful."""
    _Out.model_validate_json('{"severity": "low"}')
    with pytest.raises(ValidationError):
        _Out.model_validate_json("not-json")


# ---------------------------------------------------------------- tools


def _tool_call_response(
    *,
    model: str = "model-a",
    tool_calls: list[OpenRouterToolCall] | None = None,
) -> OpenRouterResponse:
    return OpenRouterResponse(
        content="",
        model_used=model,
        generation_id="gen-tool",
        input_tokens=20,
        output_tokens=10,
        cached_tokens=0,
        cost_usd=0.0002,
        latency_ms=50,
        tool_calls=tool_calls or [],
    )


@pytest.mark.asyncio
async def test_tools_passthrough_to_call_chat_completion(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(primary="model-a"))
    captured: dict[str, Any] = {}

    async def fake_call(**kwargs: Any) -> OpenRouterResponse:
        captured.update(kwargs)
        return _tool_call_response(
            tool_calls=[
                OpenRouterToolCall(id="call_1", name="siem_query", arguments={"spl": "index=main"})
            ]
        )

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    tools = [{"type": "function", "function": {"name": "siem_query", "parameters": {}}}]
    result = await router.call(
        role="investigation",
        messages=[{"role": "user", "content": "investigate"}],
        tools=tools,
        tool_choice="auto",
    )

    assert captured["tools"] == tools
    assert captured["tool_choice"] == "auto"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "siem_query"
    assert result.tool_calls[0].arguments == {"spl": "index=main"}
    assert usage_calls[0]["status"] == "success"


@pytest.mark.asyncio
async def test_no_tools_keeps_kwargs_unset(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    """No tools supplied → call_chat_completion receives tools=None, tool_choice=None."""
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(primary="model-a"))
    captured: dict[str, Any] = {}

    async def fake_call(**kwargs: Any) -> OpenRouterResponse:
        captured.update(kwargs)
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(role="triage", messages=[])

    assert captured["tools"] is None
    assert captured["tool_choice"] is None
    assert result.tool_calls == ()


@pytest.mark.asyncio
async def test_tools_and_response_schema_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg())
    router = LLMRouter(TENANT_ID, MagicMock())
    with pytest.raises(ValueError, match="mutually exclusive"):
        await router.call(
            role="triage",
            messages=[],
            tools=[{"type": "function", "function": {"name": "x", "parameters": {}}}],
            response_schema=_Out,
        )


@pytest.mark.asyncio
async def test_malformed_tool_args_falls_back_to_next_model(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    """ValueError from `_parse_response` (malformed tool args) → validation_fail → next model."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        if model == "model-a":
            msg = "tool_call 'siem_query' has malformed JSON arguments: ..."
            raise ValueError(msg)
        return _tool_call_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(
        role="investigation",
        messages=[],
        tools=[{"type": "function", "function": {"name": "x", "parameters": {}}}],
    )

    assert result.model_requested == "model-b"
    assert [c["status"] for c in usage_calls] == ["validation_fail", "success"]


@pytest.mark.asyncio
async def test_no_tool_calls_in_response_returns_empty(
    monkeypatch: pytest.MonkeyPatch, usage_calls: list[dict[str, Any]]
) -> None:
    """Model emits text content (no tool_calls) → LLMResult.tool_calls is empty."""
    _patch_loaders(monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(primary="model-a"))

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _tool_call_response(tool_calls=[])  # explicit empty

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    result = await router.call(
        role="investigation",
        messages=[],
        tools=[{"type": "function", "function": {"name": "x", "parameters": {}}}],
    )
    assert result.tool_calls == ()


# --------------------------------------------------------------- wk-7 budget cap


def _conn_with_totals(*, in_tok: int, out_tok: int, cost_usd: object | None) -> MagicMock:
    """MagicMock conn whose `.execute(...).first()` returns running totals."""
    conn = MagicMock()
    conn.execute.return_value.first.return_value = (in_tok, out_tok, cost_usd)
    return conn


@pytest.mark.asyncio
async def test_budget_cap_pre_call_usd_exceeded_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """USD cap reached BEFORE call → BudgetExceeded; no LLM call attempted."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(budget_usd="0.50"),
        role_cfg=_role_cfg(primary="model-a"),
    )

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        msg = "should not be called when budget exceeded"
        raise AssertionError(msg)

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    conn = _conn_with_totals(in_tok=100, out_tok=50, cost_usd="0.55")
    router = LLMRouter(TENANT_ID, conn)
    inv_id = uuid4()

    with pytest.raises(BudgetExceeded) as info:
        await router.call(role="triage", messages=[], investigation_id=inv_id)

    assert info.value.role == "triage"
    assert info.value.cap_usd is not None
    assert info.value.total_cost_usd == "0.55"


@pytest.mark.asyncio
async def test_budget_cap_pre_call_token_exceeded_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Token cap reached BEFORE call → BudgetExceeded."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(token_cap=100),
        role_cfg=_role_cfg(primary="model-a"),
    )
    conn = _conn_with_totals(in_tok=70, out_tok=40, cost_usd="0.10")
    router = LLMRouter(TENANT_ID, conn)

    with pytest.raises(BudgetExceeded) as info:
        await router.call(role="triage", messages=[], investigation_id=uuid4())

    assert info.value.total_tokens == 110
    assert info.value.token_cap == 100


@pytest.mark.asyncio
async def test_budget_cap_under_cap_proceeds(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Totals < cap → call proceeds + accumulator UPDATE fires after success."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(budget_usd="1.00", token_cap=10000),
        role_cfg=_role_cfg(primary="model-a"),
    )

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    conn = _conn_with_totals(in_tok=10, out_tok=5, cost_usd="0.05")
    router = LLMRouter(TENANT_ID, conn)
    inv_id = uuid4()

    result = await router.call(role="triage", messages=[], investigation_id=inv_id)
    assert result.attempt_num == 1
    assert len(usage_calls) == 1
    assert len(accumulator_calls) == 1
    assert accumulator_calls[0]["investigation_id"] == inv_id
    assert accumulator_calls[0]["input_tokens"] == 10
    assert accumulator_calls[0]["output_tokens"] == 5


@pytest.mark.asyncio
async def test_budget_cap_null_cost_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """total_cost_usd NULL on the row must not raise — gate ignores NULL."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(budget_usd="1.00"),
        role_cfg=_role_cfg(primary="model-a"),
    )

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    conn = _conn_with_totals(in_tok=0, out_tok=0, cost_usd=None)
    router = LLMRouter(TENANT_ID, conn)

    result = await router.call(role="triage", messages=[], investigation_id=uuid4())
    assert result.attempt_num == 1


@pytest.mark.asyncio
async def test_budget_cap_disabled_skips_select(
    monkeypatch: pytest.MonkeyPatch,
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Both caps NULL → no SELECT against investigations + accumulator still fires."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),  # caps default to None
        role_cfg=_role_cfg(primary="model-a"),
    )

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    conn = MagicMock()
    router = LLMRouter(TENANT_ID, conn)
    inv_id = uuid4()
    await router.call(role="triage", messages=[], investigation_id=inv_id)

    # No SELECT against investigations should have been issued from the gate.
    select_calls = [
        c for c in conn.execute.call_args_list if "FROM investigations" in str(c.args[0]) if c.args
    ]
    assert select_calls == []
    # Accumulator still runs (independent of the gate).
    assert len(accumulator_calls) == 1


@pytest.mark.asyncio
async def test_failed_attempt_with_response_accumulates_tokens(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Wk-7 fix #2. A schema-validation-fail attempt that DID reach OpenRouter
    consumed tokens — the cap accumulator must capture them, not just the
    final success."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        if model == "model-a":
            return _bad_json_response()  # token-counted response, fails schema
        return _ok_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    inv_id = uuid4()
    await router.call(
        role="triage",
        messages=[],
        response_schema=_Out,
        investigation_id=inv_id,
    )
    # Both attempts accumulate: first (validation_fail with response) + success.
    assert len(accumulator_calls) == 2
    # First call had token counts from `_bad_json_response`.
    assert accumulator_calls[0]["input_tokens"] == 1
    assert accumulator_calls[0]["output_tokens"] == 1
    assert accumulator_calls[0]["cost_usd"] is None  # _bad_json_response has cost=None
    # Second was the successful call.
    assert accumulator_calls[1]["input_tokens"] == 10
    assert accumulator_calls[1]["output_tokens"] == 5


@pytest.mark.asyncio
async def test_pure_transport_failure_does_not_accumulate(
    monkeypatch: pytest.MonkeyPatch,
    usage_calls: list[dict[str, Any]],
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Timeout / network errors have no OpenRouterResponse — nothing to
    accumulate. Only the eventual success bumps the counter."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a", fallback=["model-b"]),
    )

    async def fake_call(*, model: str, **_kwargs: Any) -> OpenRouterResponse:
        if model == "model-a":
            raise httpx.TimeoutException("timeout")
        return _ok_response(model="model-b")

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    await router.call(role="triage", messages=[], investigation_id=uuid4())
    # Only the success accumulates.
    assert len(accumulator_calls) == 1
    assert [c["status"] for c in usage_calls] == ["timeout", "success"]


@pytest.mark.asyncio
async def test_no_investigation_id_skips_budget_and_accumulator(
    monkeypatch: pytest.MonkeyPatch,
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Calls without investigation_id (e.g. ad-hoc verify) skip the cap + accumulator."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(budget_usd="0.0001"),  # impossibly tight
        role_cfg=_role_cfg(primary="model-a"),
    )

    async def fake_call(**_kwargs: Any) -> OpenRouterResponse:
        return _ok_response()

    monkeypatch.setattr(router_module, "call_chat_completion", fake_call)
    router = LLMRouter(TENANT_ID, MagicMock())
    # No investigation_id = no per-investigation gate.
    result = await router.call(role="triage", messages=[])
    assert result.attempt_num == 1
    assert accumulator_calls == []


# --------------------------------------------------------- wk-7 round-2 R-3


def test_update_investigation_totals_sql_clamps_negatives() -> None:
    """Wk-7 round-2 R-3. The accumulator UPDATE must use GREATEST(:val, 0) so
    a Byzantine OpenRouter response with negative token counts cannot
    decrement the running total + defeat the cap gate. Cheap unit check —
    integration covers the actual UPDATE behavior on a real DB."""
    from sentient_orchestrator.llm.usage import update_investigation_totals

    captured: list[str] = []

    class _Conn:
        def execute(self, stmt: object, _params: object = None) -> object:
            captured.append(str(getattr(stmt, "text", stmt)))
            return MagicMock()

    update_investigation_totals(
        _Conn(),  # type: ignore[arg-type]
        investigation_id=uuid4(),
        input_tokens=-1000,  # Byzantine — must clamp.
        output_tokens=42,
        cost_usd=-1.5,  # Byzantine — must clamp.
    )
    sql = captured[0]
    # Three GREATEST clamps — one per accumulator column.
    assert sql.count("GREATEST(") == 3, sql
    # COALESCE still wraps for NULL safety.
    assert sql.count("COALESCE(") == 3, sql


# --------------------------------------------------------- wk-7 round-2 R-5


@pytest.mark.asyncio
async def test_log_failure_with_response_kwarg_accumulates(
    monkeypatch: pytest.MonkeyPatch,
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Wk-7 round-2 R-5. Direct unit test of `_log_failure(response=...)` —
    when a token-counted response is supplied, the accumulator UPDATE fires
    with that response's tokens. Defends against future regressions where a
    new failure callsite adds `response=` and silently bypasses the cap."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a"),
    )
    monkeypatch.setattr(router_module, "log_usage_attempt", lambda *_a, **_kw: None)

    router = LLMRouter(TENANT_ID, MagicMock())
    inv_id = uuid4()
    fake_response = OpenRouterResponse(
        content="bad",
        model_used="model-a",
        generation_id="gen-x",
        input_tokens=77,
        output_tokens=33,
        cached_tokens=0,
        cost_usd=0.0042,
        latency_ms=120,
    )

    router._log_failure(
        attempt_num=1,
        model_requested="model-a",
        role="triage",
        investigation_id=inv_id,
        status="validation_fail",
        response=fake_response,
    )

    assert len(accumulator_calls) == 1
    assert accumulator_calls[0]["investigation_id"] == inv_id
    assert accumulator_calls[0]["input_tokens"] == 77
    assert accumulator_calls[0]["output_tokens"] == 33
    assert accumulator_calls[0]["cost_usd"] == pytest.approx(0.0042)


@pytest.mark.asyncio
async def test_log_failure_without_response_skips_accumulator(
    monkeypatch: pytest.MonkeyPatch,
    accumulator_calls: list[dict[str, Any]],
) -> None:
    """Pure transport failure (timeout / network) → response=None → no accumulator.
    Locks the contract symmetric to the with-response case."""
    _patch_loaders(
        monkeypatch,
        tenant_cfg=_tenant_cfg(),
        role_cfg=_role_cfg(primary="model-a"),
    )
    monkeypatch.setattr(router_module, "log_usage_attempt", lambda *_a, **_kw: None)

    router = LLMRouter(TENANT_ID, MagicMock())
    router._log_failure(
        attempt_num=1,
        model_requested="model-a",
        role="triage",
        investigation_id=uuid4(),
        status="timeout",
        response=None,
    )
    assert accumulator_calls == []
