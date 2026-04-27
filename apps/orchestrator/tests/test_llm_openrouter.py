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
    OpenRouterToolCall,
    _apply_cache_markers,
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


# ---------------------------------------------------------------- tools


def _tool_payload(*, tool_calls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Response with tool_calls in the assistant message."""
    return {
        "id": "gen-tool",
        "model": "google/gemini-3-flash-preview",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": tool_calls or [],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 20, "cost": 0.0001},
    }


@pytest.mark.asyncio
async def test_tools_passthrough_in_request_body() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_tool_payload())

    tools = [
        {
            "type": "function",
            "function": {
                "name": "siem_query",
                "description": "Run an SPL query.",
                "parameters": {
                    "type": "object",
                    "properties": {"spl": {"type": "string"}},
                    "required": ["spl"],
                },
            },
        }
    ]
    async with _make_client(handler) as client:
        await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
            tools=tools,
            tool_choice="auto",
        )
    assert captured["body"]["tools"] == tools
    assert captured["body"]["tool_choice"] == "auto"


@pytest.mark.asyncio
async def test_no_tools_no_tools_in_body() -> None:
    """When `tools` is not supplied, body must not include `tools`/`tool_choice` keys."""
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
        )
    assert "tools" not in captured["body"]
    assert "tool_choice" not in captured["body"]


@pytest.mark.asyncio
async def test_tool_choice_only_emitted_when_specified() -> None:
    """`tools` set but `tool_choice` omitted → body has tools but no tool_choice."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_tool_payload())

    async with _make_client(handler) as client:
        await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
            tools=[{"type": "function", "function": {"name": "x", "parameters": {}}}],
        )
    assert "tools" in captured["body"]
    assert "tool_choice" not in captured["body"]


@pytest.mark.asyncio
async def test_response_parses_tool_calls() -> None:
    payload = _tool_payload(
        tool_calls=[
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "siem_query",
                    "arguments": '{"spl": "index=main", "earliest": "-1h"}',
                },
            }
        ]
    )

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
    assert len(response.tool_calls) == 1
    tc = response.tool_calls[0]
    assert isinstance(tc, OpenRouterToolCall)
    assert tc.id == "call_1"
    assert tc.name == "siem_query"
    assert tc.arguments == {"spl": "index=main", "earliest": "-1h"}


@pytest.mark.asyncio
async def test_response_parses_multiple_tool_calls() -> None:
    payload = _tool_payload(
        tool_calls=[
            {
                "id": "call_a",
                "type": "function",
                "function": {"name": "siem_query", "arguments": '{"spl": "x"}'},
            },
            {
                "id": "call_b",
                "type": "function",
                "function": {
                    "name": "siem_get_notable",
                    "arguments": '{"notable_id": "abc"}',
                },
            },
        ]
    )

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
    assert [tc.name for tc in response.tool_calls] == ["siem_query", "siem_get_notable"]


@pytest.mark.asyncio
async def test_response_no_tool_calls_returns_empty_tuple() -> None:
    """Plain content response: tool_calls=[]."""

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
    assert response.tool_calls == []


@pytest.mark.asyncio
async def test_malformed_tool_arguments_raises_value_error() -> None:
    payload = _tool_payload(
        tool_calls=[
            {
                "id": "call_x",
                "type": "function",
                "function": {"name": "siem_query", "arguments": "{not valid json"},
            }
        ]
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with _make_client(handler) as client:
        with pytest.raises(ValueError, match="malformed JSON arguments"):
            await call_chat_completion(
                client=client,
                api_key="k",
                model="m",
                messages=[],
                max_tokens=1,
                temperature=0.0,
                timeout=1.0,
            )


@pytest.mark.asyncio
async def test_tool_arguments_can_be_dict() -> None:
    """Some providers pre-parse `arguments` to a dict; tolerated."""
    payload = _tool_payload(
        tool_calls=[
            {
                "id": "call_d",
                "type": "function",
                "function": {"name": "siem_query", "arguments": {"spl": "x"}},
            }
        ]
    )

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
    assert response.tool_calls[0].arguments == {"spl": "x"}


@pytest.mark.asyncio
async def test_tool_arguments_empty_string_treated_as_empty_dict() -> None:
    payload = _tool_payload(
        tool_calls=[
            {
                "id": "call_e",
                "type": "function",
                "function": {"name": "noop", "arguments": ""},
            }
        ]
    )

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
    assert response.tool_calls[0].arguments == {}


# --------------------------------------------------------------- wk-7 cache markers


def test_apply_cache_markers_string_to_block_array() -> None:
    """cacheable=True + string content → 1-block content array with cache_control."""
    rewritten = _apply_cache_markers(
        [
            {"role": "system", "content": "long stable system prompt", "cacheable": True},
            {"role": "user", "content": "incident facts", "cacheable": True},
        ]
    )
    assert len(rewritten) == 2
    assert "cacheable" not in rewritten[0]
    assert rewritten[0]["content"] == [
        {
            "type": "text",
            "text": "long stable system prompt",
            "cache_control": {"type": "ephemeral"},
        }
    ]
    assert rewritten[1]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert rewritten[0]["role"] == "system"


def test_apply_cache_markers_skips_unflagged() -> None:
    """Unflagged messages pass through unchanged (sans cacheable key)."""
    rewritten = _apply_cache_markers(
        [
            {"role": "system", "content": "x", "cacheable": True},
            {"role": "user", "content": "y"},  # no cacheable
            {"role": "assistant", "content": "z"},
        ]
    )
    assert isinstance(rewritten[0]["content"], list)
    assert rewritten[1] == {"role": "user", "content": "y"}
    assert rewritten[2] == {"role": "assistant", "content": "z"}


def test_apply_cache_markers_strips_flag_when_false() -> None:
    """cacheable=False is also stripped — leaves no leak."""
    rewritten = _apply_cache_markers([{"role": "user", "content": "hi", "cacheable": False}])
    assert "cacheable" not in rewritten[0]
    assert rewritten[0]["content"] == "hi"  # unchanged


def test_apply_cache_markers_existing_block_array() -> None:
    """Caller-supplied block-array content gets cache_control on LAST text block."""
    rewritten = _apply_cache_markers(
        [
            {
                "role": "system",
                "content": [
                    {"type": "text", "text": "preamble"},
                    {"type": "text", "text": "main"},
                ],
                "cacheable": True,
            }
        ]
    )
    blocks = rewritten[0]["content"]
    assert "cache_control" not in blocks[0]
    assert blocks[1]["cache_control"] == {"type": "ephemeral"}


def test_apply_cache_markers_does_not_mutate_caller() -> None:
    """Defensive copy: caller's message dict must not gain cache_control."""
    original = {"role": "system", "content": "x", "cacheable": True}
    _apply_cache_markers([original])
    assert original == {"role": "system", "content": "x", "cacheable": True}


def test_apply_cache_markers_assistant_with_tool_calls_passthrough() -> None:
    """Assistant messages typically aren't flagged; if not flagged, pass through."""
    msg = {
        "role": "assistant",
        "content": "calling tool",
        "tool_calls": [{"id": "x", "type": "function", "function": {}}],
    }
    rewritten = _apply_cache_markers([msg])
    assert rewritten[0] == msg


@pytest.mark.asyncio
async def test_call_chat_completion_strips_cacheable_field_on_wire() -> None:
    """End-to-end: the `cacheable` key must NOT be present in the body sent."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_ok_payload())

    async with _make_client(handler) as client:
        await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[
                {"role": "system", "content": "sys", "cacheable": True},
                {"role": "user", "content": "u"},
            ],
            max_tokens=1,
            temperature=0.0,
            timeout=1.0,
        )

    sent = captured["body"]["messages"]
    assert "cacheable" not in sent[0]
    assert sent[0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert sent[1] == {"role": "user", "content": "u"}
