# 0004: OpenRouter as unified LLM routing

Date: 2026-04-15
Status: Accepted

## Context

Need an LLM routing layer that:
- Supports multiple model vendors (Anthropic, Google, open-weight, future) without binding our code to one provider.
- Handles model fallback natively (if primary model fails, try next).
- Gives per-request cost/usage metadata so we can bill per tenant.
- Keeps the door open for sovereign on-prem models later (Llama, Qwen, DeepSeek) via the same code path.

## Decision

**OpenRouter** for all LLM compute in MVP (cloud-hosted deployment model). Founder's master OpenRouter API key. Per-tenant usage tracked for chargeback in `usage` table.

**Per-role configuration** (see ADR 0010) — each role (`triage`, `investigation`, `review`) has a primary model + fallback chain, both admin-panel configurable.

**OpenRouter native fallback** — we pass `"models": [primary, *fallback_chain]` and `"route": "fallback"` in the request body; OpenRouter tries them in order. Zero fallback logic in our code.

**MVP dev default model:** `google/gemini-3-flash-preview` for speed + cost during testing. **Production intent:** Claude Opus 4.6 (investigation) + Haiku 4.5 (triage) once admin-configurable.

## Alternatives considered

- **Anthropic direct API only** — simpler single-provider but locks out on-prem / sovereign model story.
- **Hybrid (Anthropic direct for Tier 2 + OpenRouter for Tier 1)** — was our position earlier when Claude Agent SDK was planned (SDK required Anthropic direct). Obsolete once LangGraph was chosen.
- **LangChain `with_fallbacks()`** — fallback logic lives in our code; more control but more moving parts. Rejected in favor of OpenRouter native for MVP simplicity.
- **Bedrock Sydney direct** — solves AU sovereignty but adds AWS dep + harder billing model for MVP. Deferred as a config-flag upgrade path post-MVP.

## Consequences

**Gain:**
- Single vendor/billing relationship for all LLM calls.
- Model swap is admin-panel config, not a code change.
- Clear path to on-prem (Ollama/vLLM exposed via OpenAI-compat endpoint registered as a "provider" in our config).
- OpenRouter native fallback = reliability without custom code.

**Accept:**
- OpenRouter is a dependency — if their service degrades, all tenants affected.
- Anthropic-specific features (prompt caching `cache_control`, extended thinking, computer use) are supported via passthrough but feature parity is not guaranteed. Verify aggressively in wk 5-7.
- Loses some sovereignty purity (cloud-hosted MVP routes through OpenRouter infrastructure). Mitigation: on-prem deployment model uses customer's own keys.
- Prompt caching passthrough through OpenRouter has historically been inconsistent; must measure cache hit rate wk 7 and fall back to provider-direct if needed.

## Related

- ADR 0010 — Per-role LLM configuration (the mechanics).
- `docs/context/stack-locks.md` — LLM routing lock.
