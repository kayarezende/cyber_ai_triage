"""Unit tests for LLMRouter — fallback loop, sovereignty, schema retry."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import BaseModel, Field, ValidationError

from sentient_orchestrator.llm import router as router_module
from sentient_orchestrator.llm.exceptions import FallbackChainExhausted
from sentient_orchestrator.llm.openrouter import OpenRouterResponse
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


def _tenant_cfg(*, langsmith_enabled: bool = True, region: str | None = None) -> _TenantConfig:
    return _TenantConfig(
        api_key="sk-test",
        region_constraint=region,
        langsmith_enabled=langsmith_enabled,
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
    _patch_loaders(
        monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(primary="model-a")
    )

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
    _patch_loaders(
        monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(enabled=False)
    )
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
    _patch_loaders(
        monkeypatch, tenant_cfg=_tenant_cfg(), role_cfg=_role_cfg(primary="model-a")
    )
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
