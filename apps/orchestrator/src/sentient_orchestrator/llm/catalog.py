"""Provider/model capability catalog — the multi-provider switchboard.

ADR-0004 routed everything through OpenRouter. This module generalises that to
direct provider access (Groq, Gemini, Anthropic) while keeping the single
direct-httpx client (ADR-0015). Provider is encoded as a prefix on the model
ref stored in `llm_role_config` (e.g. ``groq:openai/gpt-oss-120b``); a bare slug
(no recognised prefix before the first ``:``) defaults to OpenRouter, so existing
seeded rows like ``google/gemini-3-flash-preview`` keep working unchanged.

Two declarative tables drive behaviour:

* ``PROVIDERS`` — per-provider wire facts (base URL, key env var, and the
  OpenRouter-specific body quirks that must NOT be sent to other providers).
* ``_CATALOG`` / ``_PROVIDER_DEFAULTS`` — per-model capabilities, chiefly
  ``structured_output`` (can the model produce strict schema-conforming JSON?).
  This is what lets config-time validation block an incapable model from a
  structured role, and what lets the router pick the right ``response_format``
  dialect at call time.

Kept as code constants for now; the shape (dict keyed by canonical ref) is
designed to move behind a DB-backed loader later without touching call sites.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel

HTTP_REFERER = "https://sentientlayer.ai"
X_TITLE = "Sentient Layer Triage"

#: How a model accepts a structured-output request.
#: - ``json_schema_strict``: OpenAI-style ``response_format: json_schema`` with
#:   ``strict: true`` (guaranteed conformance, e.g. constrained decoding).
#: - ``json_object``: only ``{"type": "json_object"}`` (valid JSON, no schema
#:   enforcement) — the schema is injected into the prompt and the router's
#:   validate-and-retry loop is the safety net.
#: - ``none``: ``response_format`` is ignored by the provider (e.g. Anthropic's
#:   OpenAI-compat layer) — schema goes in the prompt only.
StructuredMode = Literal["json_schema_strict", "json_object", "none"]


@dataclass(frozen=True)
class ProviderSpec:
    """Per-provider wire facts. All four expose an OpenAI-compatible
    ``/chat/completions``; the flags capture where they diverge."""

    name: str
    base_url: str
    #: Env var holding the API key when no DB-stored credential exists (legacy
    #: fallback; the secure path is the `provider_credentials` table).
    key_env: str
    #: OpenRouter accepts ``usage: {include: true}`` to opt into cost reporting.
    #: Groq/Gemini/Anthropic reject unknown params, so it must be omitted.
    send_usage_param: bool
    #: Only OpenRouter honours the top-level ``provider`` body field.
    supports_provider_field: bool
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelCapability:
    """What a given model can do, for routing + config-time validation."""

    provider: str
    structured_output: StructuredMode
    supports_tools: bool
    #: Whether the provider returns per-call cost (only OpenRouter does today).
    returns_cost: bool


PROVIDERS: dict[str, ProviderSpec] = {
    "openrouter": ProviderSpec(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1/chat/completions",
        key_env="OPENROUTER_API_KEY",
        send_usage_param=True,
        supports_provider_field=True,
        extra_headers={"HTTP-Referer": HTTP_REFERER, "X-Title": X_TITLE},
    ),
    "groq": ProviderSpec(
        name="groq",
        base_url="https://api.groq.com/openai/v1/chat/completions",
        key_env="GROQ_API_KEY",
        send_usage_param=False,
        supports_provider_field=False,
    ),
    "gemini": ProviderSpec(
        name="gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        key_env="GEMINI_API_KEY",
        send_usage_param=False,
        supports_provider_field=False,
    ),
    "anthropic": ProviderSpec(
        name="anthropic",
        base_url="https://api.anthropic.com/v1/chat/completions",
        key_env="ANTHROPIC_API_KEY",
        send_usage_param=False,
        supports_provider_field=False,
    ),
}

DEFAULT_PROVIDER = "openrouter"
ALLOWED_PROVIDERS = frozenset(PROVIDERS)

#: Per-model overrides, keyed by canonical ``provider:model`` ref. Only entries
#: that differ from the provider default need listing. Verified against vendor
#: docs (2026-05): Groq strict json_schema is limited to the gpt-oss family
#: (constrained decoding); llama-3.3 / llama-4 do json_object only.
_CATALOG: dict[str, ModelCapability] = {
    "groq:openai/gpt-oss-120b": ModelCapability("groq", "json_schema_strict", True, False),
    "groq:openai/gpt-oss-20b": ModelCapability("groq", "json_schema_strict", True, False),
    "groq:llama-3.3-70b-versatile": ModelCapability("groq", "json_object", True, False),
    "groq:meta-llama/llama-4-scout-17b-16e-instruct": ModelCapability(
        "groq", "json_object", True, False
    ),
}

#: Fallback capability when a model is not explicitly catalogued. Conservative
#: per provider so an unknown model never over-promises structured output.
_PROVIDER_DEFAULTS: dict[str, ModelCapability] = {
    # OpenRouter: preserve the pre-existing always-strict behaviour.
    "openrouter": ModelCapability("openrouter", "json_schema_strict", True, True),
    # Groq: assume json_object unless a model is known to support strict.
    "groq": ModelCapability("groq", "json_object", True, False),
    # Gemini 2.x supports json_schema via the OpenAI-compat layer.
    "gemini": ModelCapability("gemini", "json_schema_strict", True, False),
    # Anthropic's OpenAI-compat endpoint IGNORES response_format entirely.
    "anthropic": ModelCapability("anthropic", "none", True, False),
}

#: Roles whose runtime contract requires schema-conforming JSON. A model whose
#: capability is ``none`` cannot serve these (validation blocks it).
STRUCTURED_ROLES = frozenset({"triage", "investigation", "review"})


def parse_model_ref(raw: str) -> tuple[str, str]:
    """Split a stored model ref into ``(provider, model)``.

    A recognised provider prefix before the first ``:`` selects that provider;
    anything else (including OpenRouter org-prefixed slugs like
    ``anthropic/claude-...`` that use ``/``) defaults to OpenRouter.
    """
    head, sep, tail = raw.partition(":")
    if sep and head in PROVIDERS:
        return head, tail
    return DEFAULT_PROVIDER, raw


def resolve(model_ref: str) -> tuple[ProviderSpec, ModelCapability, str]:
    """Resolve a stored model ref to ``(spec, capability, bare_model)``.

    Lenient at runtime: an unrecognised prefix is treated as an OpenRouter
    slug (it will 400 at OpenRouter if invalid). Strict rejection of unknown
    provider prefixes is enforced earlier, at the admin API config layer.
    """
    provider, model = parse_model_ref(model_ref)
    spec = PROVIDERS[provider]
    capability = _CATALOG.get(f"{provider}:{model}") or _PROVIDER_DEFAULTS[provider]
    return spec, capability, model


def capability_for(model_ref: str) -> ModelCapability:
    """Capability lookup without raising on bare slugs — for validation paths."""
    return resolve(model_ref)[1]


def build_response_format(
    capability: ModelCapability,
    schema: type[BaseModel] | None,
) -> tuple[dict[str, Any] | None, bool]:
    """Map a capability + target schema to ``(response_format, inject_prompt)``.

    ``inject_prompt`` signals the router to add a schema instruction to the
    messages (for json_object / none modes the provider won't enforce shape).
    """
    if schema is None:
        return None, False
    if capability.structured_output == "json_schema_strict":
        return (
            {
                "type": "json_schema",
                "json_schema": {
                    "name": schema.__name__,
                    "strict": True,
                    "schema": schema.model_json_schema(),
                },
            },
            False,
        )
    if capability.structured_output == "json_object":
        return {"type": "json_object"}, True
    # none: provider ignores response_format; rely on prompt + validate/retry.
    return None, True


def schema_instruction(schema: type[BaseModel]) -> str:
    """A system-message body instructing JSON-only output matching ``schema``.

    Used when the provider can't enforce the schema natively (json_object /
    none modes). Mirrors the corrective-message style in the router's retry.
    """
    import json

    return (
        "You must respond with ONLY a single JSON object conforming to this "
        "JSON Schema. No prose, no markdown, no code fences.\n"
        f"{json.dumps(schema.model_json_schema())}"
    )


__all__ = [
    "ALLOWED_PROVIDERS",
    "DEFAULT_PROVIDER",
    "PROVIDERS",
    "STRUCTURED_ROLES",
    "ModelCapability",
    "ProviderSpec",
    "StructuredMode",
    "build_response_format",
    "capability_for",
    "parse_model_ref",
    "resolve",
    "schema_instruction",
]
