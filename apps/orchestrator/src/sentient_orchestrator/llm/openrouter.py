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

import json
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

import httpx

from sentient_common.logging import get_logger
from sentient_orchestrator.llm.catalog import (
    HTTP_REFERER,
    PROVIDERS,
    X_TITLE,
    ProviderSpec,
)

#: Back-compat alias — moved to the OpenRouter ``ProviderSpec`` but re-exported
#: here (with HTTP_REFERER / X_TITLE via __all__) so existing imports keep working.
OPENROUTER_URL = PROVIDERS["openrouter"].base_url

log = get_logger(__name__)


@dataclass(frozen=True)
class OpenRouterToolCall:
    """One parsed tool-call from `choices[0].message.tool_calls`.

    OpenRouter mirrors the OpenAI shape:
        {"id": "...", "type": "function",
         "function": {"name": "...", "arguments": "<json string>"}}

    `arguments` is a JSON string on the wire; we parse to a dict here so callers
    don't have to. Malformed JSON raises `ValueError` from `_parse_response` —
    classified by the router as `validation_fail` (model output is broken, try
    next model in the chain).
    """

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class OpenRouterResponse:
    """Parsed chat-completion response.

    ``cost_usd`` is ``Decimal`` (cluster C / HIGH-8) — the boundary cast from
    the JSON ``usage.cost`` float happens once here in ``_parse_response``
    via ``Decimal(str(...))`` to avoid binary-float drift before binding to
    NUMERIC(14,6) columns. Stays Decimal end-to-end inside the orchestrator;
    only the JSON evidence manifest casts back to float at emission.
    """

    content: str
    model_used: str
    generation_id: str | None
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost_usd: Decimal | None
    latency_ms: int
    tool_calls: list[OpenRouterToolCall] = field(default_factory=list)


async def call_chat_completion(
    *,
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    messages: list[dict[str, Any]],
    max_tokens: int,
    temperature: float,
    timeout: float,
    spec: ProviderSpec | None = None,
    response_format: dict[str, Any] | None = None,
    region_constraint: str | None = None,
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | dict[str, Any] | None = None,
) -> OpenRouterResponse:
    """POST /chat/completions; raise httpx errors; return parsed response.

    Caller (the router) catches `httpx.TimeoutException` + `httpx.HTTPStatusError`
    and classifies them into the `usage.status` enum. This function does no
    classification of its own — it just talks HTTP.

    `tools` + `tool_choice` are OpenAI-format pass-through. `tools` is a list of
    `{"type": "function", "function": {"name", "description", "parameters"}}`
    dicts. `tool_choice` is `"auto" | "none" | "required" | {"type":"function",
    "function":{"name":"..."}}`. Default `tool_choice="auto"` is sent only when
    `tools` is supplied; absent otherwise (matches OpenAI spec).

    Mutually exclusive at the call site: do not combine `tools` with
    `response_format=json_schema` — most providers reject the combination.
    The router enforces this; we don't double-check here.
    """
    if spec is None:
        spec = PROVIDERS["openrouter"]

    wire_messages = _apply_cache_markers(messages)
    body: dict[str, Any] = {
        "model": model,
        "messages": wire_messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if spec.send_usage_param:
        # OpenRouter opt-in to cost reporting. Other providers reject unknown
        # params (e.g. Groq 400s), so this key is omitted for them.
        body["usage"] = {"include": True}
    if response_format is not None:
        body["response_format"] = response_format
    if tools:
        body["tools"] = tools
        # OpenRouter / OpenAI default is `auto` when tools are present.
        # Pass through explicit choice when caller specified it.
        if tool_choice is not None:
            body["tool_choice"] = tool_choice
    if region_constraint and spec.supports_provider_field:
        # ADR-0016: dormant in MVP. OpenRouter's `provider` filter has no
        # `region` key today — region routing post-MVP requires a
        # constraint→provider-list resolver (e.g. AU-southeast → Bedrock-syd
        # / Azure-AU). For now, when ANY region constraint is set we at
        # least force `data_collection: deny` so payloads aren't retained
        # by intermediary providers. Only OpenRouter honours this field.
        body["provider"] = {"data_collection": "deny"}

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **spec.extra_headers,
    }

    start = time.monotonic()
    response = await client.post(
        spec.base_url,
        headers=headers,
        json=body,
        timeout=timeout,
    )
    latency_ms = int((time.monotonic() - start) * 1000)
    response.raise_for_status()
    payload: dict[str, Any] = response.json()

    return _parse_response(payload, latency_ms=latency_ms)


def _apply_cache_markers(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rewrite messages flagged `cacheable=True` into Anthropic cache-block form.

    Wk-7. Caller (the investigation prompt builders) flags long, stable blocks
    with ``"cacheable": True``. This pre-wire transform converts a string
    ``content`` into a 1-element content-block array carrying
    ``cache_control: {"type": "ephemeral"}`` — the wire shape Anthropic
    honors for prompt caching when proxied through OpenRouter.

    The flag is stripped before the request leaves the process. Non-Anthropic
    backends (Gemini, OpenAI) ignore unknown ``cache_control`` metadata
    gracefully — extra fields on text blocks pass through. Gemini's implicit
    caching path doesn't need markers; this is a no-op for it.

    Anthropic enforces a max of 4 cache breakpoints per request — that's a
    caller-side budget (system + finding + MITRE = 3 today; tool-results
    block is the wk-8 candidate for the 4th). Not enforced here.
    """
    out: list[dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict) or not msg.get("cacheable"):
            # Not flagged — pass through verbatim. Defensive copy to avoid
            # mutating the caller's history (LangGraph state may be shared).
            out.append({k: v for k, v in msg.items() if k != "cacheable"})
            continue
        rewritten = {k: v for k, v in msg.items() if k != "cacheable"}
        content = rewritten.get("content")
        if isinstance(content, str) and content:
            rewritten["content"] = [
                {
                    "type": "text",
                    "text": content,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        elif isinstance(content, list) and content:
            # Already block-array — add cache_control to the LAST text block
            # (the breakpoint sits at the end of the cached prefix).
            new_blocks = [dict(b) if isinstance(b, dict) else b for b in content]
            for block in reversed(new_blocks):
                if isinstance(block, dict) and block.get("type") == "text":
                    block["cache_control"] = {"type": "ephemeral"}
                    break
            rewritten["content"] = new_blocks
        # else: empty / unsupported content — leave alone, just strip the flag.
        out.append(rewritten)
    return out


def _parse_response(payload: dict[str, Any], *, latency_ms: int) -> OpenRouterResponse:
    """Extract the fields the router + usage logger need."""
    choices = payload.get("choices") or []
    if not choices:
        msg = "openrouter response had no choices"
        raise ValueError(msg)
    message = choices[0].get("message") or {}
    content = message.get("content") or ""
    tool_calls = _parse_tool_calls(message.get("tool_calls"))

    usage = payload.get("usage") or {}
    input_tokens = int(usage.get("prompt_tokens", 0) or 0)
    output_tokens = int(usage.get("completion_tokens", 0) or 0)
    # OpenRouter exposes cached_tokens via `prompt_tokens_details.cached_tokens`
    # (OpenAI-style) for Anthropic + some other providers. Fall back to 0.
    # Cluster E MED-12: a misbehaving provider returning a non-numeric value
    # (string "n/a", nested dict, etc) must NOT convert a successful HTTP
    # call into a `validation_fail` via parse error. Default to 0 + warn.
    cached = 0
    details = usage.get("prompt_tokens_details") or {}
    if isinstance(details, dict):
        try:
            cached = int(details.get("cached_tokens", 0) or 0)
        except (ValueError, TypeError):
            log.warning(
                "cached_tokens unparseable; defaulting to 0",
                raw_repr=repr(details.get("cached_tokens"))[:80],
            )
            cached = 0
    # Cluster C / HIGH-8: route via Decimal(str(...)) to avoid binary-float
    # drift on NUMERIC binds. `cost` arrives as int / float / str depending
    # on provider — str() coercion handles all three uniformly.
    raw_cost = usage.get("cost")
    cost_usd: Decimal | None = Decimal(str(raw_cost)) if raw_cost is not None else None

    return OpenRouterResponse(
        content=str(content),
        model_used=str(payload.get("model") or ""),
        generation_id=payload.get("id"),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached,
        cost_usd=cost_usd,
        latency_ms=latency_ms,
        tool_calls=tool_calls,
    )


def _parse_tool_calls(raw: Any) -> list[OpenRouterToolCall]:
    """Parse `choices[0].message.tool_calls` → list[OpenRouterToolCall].

    Returns `[]` when absent / null / empty. Malformed JSON in `arguments`
    raises `ValueError` so the router buckets the attempt as `validation_fail`
    — same policy as a JSON-schema response that fails Pydantic validation.
    """
    if not raw:
        return []
    if not isinstance(raw, list):
        return []
    parsed: list[OpenRouterToolCall] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        function = item.get("function") or {}
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        if not name:
            continue
        args_raw = function.get("arguments")
        # OpenAI/OpenRouter wire format: `arguments` is a JSON string.
        # A dict is also tolerated (some providers pre-parse).
        if isinstance(args_raw, str):
            try:
                arguments = json.loads(args_raw) if args_raw else {}
            except json.JSONDecodeError as exc:
                msg = f"tool_call {name!r} has malformed JSON arguments: {exc}"
                raise ValueError(msg) from exc
        elif isinstance(args_raw, dict):
            arguments = args_raw
        elif args_raw is None:
            arguments = {}
        else:
            msg = f"tool_call {name!r} has unexpected arguments type {type(args_raw).__name__}"
            raise ValueError(msg)
        if not isinstance(arguments, dict):
            msg = f"tool_call {name!r} arguments must be an object"
            raise ValueError(msg)
        parsed.append(
            OpenRouterToolCall(
                id=str(item.get("id") or ""),
                name=name,
                arguments=arguments,
            )
        )
    return parsed


__all__ = [
    "HTTP_REFERER",
    "OPENROUTER_URL",
    "X_TITLE",
    "OpenRouterResponse",
    "OpenRouterToolCall",
    "call_chat_completion",
]
