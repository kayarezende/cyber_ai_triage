"""Unit tests for the direct httpx → OpenRouter chat-completion client."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from sentient_orchestrator.llm.openrouter import (
    HTTP_REFERER,
    OPENROUTER_URL,
    X_TITLE,
    call_chat_completion,
)


def _ok_payload() -> dict[str, Any]:
    return {
        "id": "gen-abc-123",
        "model": "google/gemini-3-flash-preview",
        "choices": [
            {
                "message": {"role": "assistant", "content": '{"ok": true}'},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 7,
            "total_tokens": 19,
            "cost": 0.000123,
            "prompt_tokens_details": {"cached_tokens": 4},
        },
    }


def _make_client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_request_shape_basic() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_ok_payload())

    async with _make_client(handler) as client:
        response = await call_chat_completion(
            client=client,
            api_key="sk-test-12345",
            model="google/gemini-3-flash-preview",
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=100,
            temperature=0.0,
            timeout=10.0,
        )

    assert captured["url"] == OPENROUTER_URL
    assert captured["headers"]["authorization"] == "Bearer sk-test-12345"
    assert captured["headers"]["http-referer"] == HTTP_REFERER
    assert captured["headers"]["x-title"] == X_TITLE
    body = captured["body"]
    assert body["model"] == "google/gemini-3-flash-preview"
    assert body["messages"] == [{"role": "user", "content": "ping"}]
    assert body["max_tokens"] == 100
    assert body["temperature"] == 0.0
    assert body["usage"] == {"include": True}
    assert "response_format" not in body
    assert "provider" not in body
    assert response.content == '{"ok": true}'


@pytest.mark.asyncio
async def test_response_format_passed_through() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_ok_payload())

    schema = {"type": "object", "properties": {"x": {"type": "string"}}}
    fmt = {"type": "json_schema", "json_schema": {"name": "X", "schema": schema}}
    async with _make_client(handler) as client:
        await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
            response_format=fmt,
        )
    assert captured["body"]["response_format"] == fmt


@pytest.mark.asyncio
async def test_region_constraint_emits_data_collection_deny() -> None:
    """Region constraint set → emit `provider.data_collection: deny` only.

    OpenRouter's `provider` filter has no `region` key today; ADR-0016
    sovereign-mode routing arrives post-MVP. Until then, region-set tenants
    at minimum get the no-retention guarantee.
    """
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_ok_payload())

    async with _make_client(handler) as client:
        await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
            region_constraint="au-southeast",
        )
    provider = captured["body"]["provider"]
    assert provider["data_collection"] == "deny"
    assert "region" not in provider


@pytest.mark.asyncio
async def test_response_parses_usage_fields() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok_payload())

    async with _make_client(handler) as client:
        response = await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
        )
    assert response.input_tokens == 12
    assert response.output_tokens == 7
    assert response.cached_tokens == 4
    assert response.cost_usd == pytest.approx(0.000123)
    assert response.generation_id == "gen-abc-123"
    assert response.model_used == "google/gemini-3-flash-preview"
    assert response.latency_ms >= 0


@pytest.mark.asyncio
async def test_response_handles_missing_cost() -> None:
    payload = _ok_payload()
    payload["usage"].pop("cost")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with _make_client(handler) as client:
        response = await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
        )
    assert response.cost_usd is None


@pytest.mark.asyncio
async def test_response_handles_missing_cached_tokens() -> None:
    payload = _ok_payload()
    payload["usage"].pop("prompt_tokens_details")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with _make_client(handler) as client:
        response = await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
        )
    assert response.cached_tokens == 0


@pytest.mark.asyncio
async def test_5xx_raises_http_status_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "upstream"})

    async with _make_client(handler) as client:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await call_chat_completion(
                client=client,
                api_key="k",
                model="m",
                messages=[],
                max_tokens=1,
                temperature=0.0,
                timeout=1.0,
            )
    assert exc_info.value.response.status_code == 503


@pytest.mark.asyncio
async def test_429_raises_http_status_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "rate_limited"})

    async with _make_client(handler) as client:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await call_chat_completion(
                client=client,
                api_key="k",
                model="m",
                messages=[],
                max_tokens=1,
                temperature=0.0,
                timeout=1.0,
            )
    assert exc_info.value.response.status_code == 429


@pytest.mark.asyncio
async def test_4xx_raises_http_status_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "bad model"})

    async with _make_client(handler) as client:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await call_chat_completion(
                client=client,
                api_key="k",
                model="m",
                messages=[],
                max_tokens=1,
                temperature=0.0,
                timeout=1.0,
            )
    assert exc_info.value.response.status_code == 400


@pytest.mark.asyncio
async def test_no_choices_raises_value_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "x", "model": "m", "choices": []})

    async with _make_client(handler) as client:
        with pytest.raises(ValueError, match="no choices"):
            await call_chat_completion(
                client=client,
                api_key="k",
                model="m",
                messages=[],
                max_tokens=1,
                temperature=0.0,
                timeout=1.0,
            )
