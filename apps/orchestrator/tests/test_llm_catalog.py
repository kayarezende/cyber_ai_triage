"""Unit tests for the multi-provider capability catalog + client gating."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from sentient_orchestrator.llm import catalog
from sentient_orchestrator.llm.openrouter import call_chat_completion


def test_parse_model_ref_bare_defaults_openrouter() -> None:
    assert catalog.parse_model_ref("google/gemini-3-flash-preview") == (
        "openrouter",
        "google/gemini-3-flash-preview",
    )


def test_parse_model_ref_recognised_prefix() -> None:
    assert catalog.parse_model_ref("groq:openai/gpt-oss-120b") == (
        "groq",
        "openai/gpt-oss-120b",
    )


def test_parse_model_ref_unknown_prefix_is_openrouter_slug() -> None:
    # `anthropic/claude-...` uses `/`, not a `:` provider prefix.
    assert catalog.parse_model_ref("anthropic/claude-opus-4-7") == (
        "openrouter",
        "anthropic/claude-opus-4-7",
    )


def test_resolve_known_groq_strict_model() -> None:
    spec, cap, bare = catalog.resolve("groq:openai/gpt-oss-120b")
    assert spec.name == "groq"
    assert bare == "openai/gpt-oss-120b"
    assert cap.structured_output == "json_schema_strict"
    assert spec.send_usage_param is False


def test_resolve_groq_default_is_json_object() -> None:
    _spec, cap, _bare = catalog.resolve("groq:llama-3.3-70b-versatile")
    assert cap.structured_output == "json_object"


def test_resolve_anthropic_is_none_capability() -> None:
    _spec, cap, _bare = catalog.resolve("anthropic:claude-sonnet-4-6")
    assert cap.structured_output == "none"


def test_resolve_unknown_prefix_is_lenient_openrouter() -> None:
    # Runtime is lenient — unknown prefixes fall through to OpenRouter (the
    # admin API rejects them at config time). The whole ref stays the model.
    spec, _cap, bare = catalog.resolve("grok:whatever")
    assert spec.name == "openrouter"
    assert bare == "grok:whatever"


@pytest.mark.asyncio
async def test_openrouter_sends_usage_param() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "g1",
                "model": "m",
                "choices": [{"message": {"content": "{}"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        await call_chat_completion(
            client=client,
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=10,
            temperature=0.0,
            timeout=5.0,
            spec=catalog.PROVIDERS["openrouter"],
        )
    assert captured["url"] == catalog.PROVIDERS["openrouter"].base_url
    assert captured["body"]["usage"] == {"include": True}


@pytest.mark.asyncio
async def test_groq_omits_usage_param_and_uses_base_url() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "g1",
                "model": "m",
                "choices": [{"message": {"content": "{}"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        await call_chat_completion(
            client=client,
            api_key="k",
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=10,
            temperature=0.0,
            timeout=5.0,
            spec=catalog.PROVIDERS["groq"],
        )
    assert captured["url"] == catalog.PROVIDERS["groq"].base_url
    assert "usage" not in captured["body"]
    # No OpenRouter ranking headers leaked to Groq.
    assert catalog.PROVIDERS["groq"].extra_headers == {}
