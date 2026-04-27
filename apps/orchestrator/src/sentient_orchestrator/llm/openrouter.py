"""Direct httpx → OpenRouter chat-completion client.

ADR-0015: bypass `langchain-openai` (which warns against `base_url` redirects
to non-OpenAI providers and silently drops non-standard fields). Single-model
calls only — `models[]` array fallback is gone, replaced by the app-side loop
in `router.py`.

Returns a typed `OpenRouterResponse` so the router doesn't have to crawl raw
JSON. Cost comes from `usage.cost` when OpenRouter returns it (we send
`usage: {include: true}`); falls back to None if absent (don't fabricate).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
HTTP_REFERER = "https://sentientlayer.ai"
X_TITLE = "Sentient Layer Triage"


@dataclass(frozen=True)
class OpenRouterResponse:
    """Parsed chat-completion response."""

    content: str
    model_used: str
    generation_id: str | None
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost_usd: float | None
    latency_ms: int


async def call_chat_completion(
    *,
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    messages: list[dict[str, Any]],
    max_tokens: int,
    temperature: float,
    timeout: float,
    response_format: dict[str, Any] | None = None,
    region_constraint: str | None = None,
) -> OpenRouterResponse:
    """POST /chat/completions; raise httpx errors; return parsed response.

    Caller (the router) catches `httpx.TimeoutException` + `httpx.HTTPStatusError`
    and classifies them into the `usage.status` enum. This function does no
    classification of its own — it just talks HTTP.
    """
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "usage": {"include": True},
    }
    if response_format is not None:
        body["response_format"] = response_format
    if region_constraint:
        # ADR-0016: dormant in MVP. OpenRouter's `provider` filter has no
        # `region` key today — region routing post-MVP requires a
        # constraint→provider-list resolver (e.g. AU-southeast → Bedrock-syd
        # / Azure-AU). For now, when ANY region constraint is set we at
        # least force `data_collection: deny` so payloads aren't retained
        # by intermediary providers.
        body["provider"] = {"data_collection": "deny"}

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": HTTP_REFERER,
        "X-Title": X_TITLE,
    }

    start = time.monotonic()
    response = await client.post(
        OPENROUTER_URL,
        headers=headers,
        json=body,
        timeout=timeout,
    )
    latency_ms = int((time.monotonic() - start) * 1000)
    response.raise_for_status()
    payload: dict[str, Any] = response.json()

    return _parse_response(payload, latency_ms=latency_ms)


def _parse_response(payload: dict[str, Any], *, latency_ms: int) -> OpenRouterResponse:
    """Extract the fields the router + usage logger need."""
    choices = payload.get("choices") or []
    if not choices:
        msg = "openrouter response had no choices"
        raise ValueError(msg)
    message = choices[0].get("message") or {}
    content = message.get("content") or ""

    usage = payload.get("usage") or {}
    input_tokens = int(usage.get("prompt_tokens", 0) or 0)
    output_tokens = int(usage.get("completion_tokens", 0) or 0)
    # OpenRouter exposes cached_tokens via `prompt_tokens_details.cached_tokens`
    # (OpenAI-style) for Anthropic + some other providers. Fall back to 0.
    cached = 0
    details = usage.get("prompt_tokens_details") or {}
    if isinstance(details, dict):
        cached = int(details.get("cached_tokens", 0) or 0)
    cost = usage.get("cost")
    cost_usd: float | None = float(cost) if cost is not None else None

    return OpenRouterResponse(
        content=str(content),
        model_used=str(payload.get("model") or ""),
        generation_id=payload.get("id"),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached,
        cost_usd=cost_usd,
        latency_ms=latency_ms,
    )


__all__ = ["OpenRouterResponse", "call_chat_completion", "OPENROUTER_URL"]
