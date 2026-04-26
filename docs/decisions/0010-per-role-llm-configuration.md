# 0010: Per-role LLM configuration

Date: 2026-04-15
Status: Accepted (fallback mechanism superseded by ADR-0015 on 2026-04-27 — the per-role config table stays; the OpenRouter native fallback in §3 is replaced by an app-side loop)

## Context

The agent makes multiple kinds of LLM calls that have very different cost/quality profiles:
- **Triage** — one-shot classification of incoming notable. Cheap, fast.
- **Investigation** — multi-turn agent loop with MCP tools. Expensive, strong reasoning.
- **Review** — critic model passes over draft verdict before HITL. Cheap, catches hallucinations.
- Future: `summarize`, `entity_extraction`, specialist agents.

Using one model for all tiers wastes money on triage/summary/review calls that don't need Opus-class reasoning. Using hard-coded model choices per tier loses tenant flexibility and makes model updates a code change.

Founder requirement: admin-panel configurability of "what model does what" + per-role fallback chains.

## Decision

**Per-role LLM configuration.** One row per `(tenant_id, role)` in `llm_role_config`:

```sql
CREATE TABLE llm_role_config (
  id UUID PRIMARY KEY,
  tenant_id UUID,
  role TEXT CHECK (role IN ('triage','investigation','review','summarize','entity_extraction')),
  primary_model TEXT NOT NULL,
  fallback_chain TEXT[] DEFAULT '{}',
  max_tokens INT DEFAULT 4096,
  temperature NUMERIC(3,2) DEFAULT 0.2,
  timeout_seconds INT DEFAULT 30,
  enabled BOOLEAN DEFAULT TRUE,
  UNIQUE(tenant_id, role)
);
```

**MVP active roles:** `triage`, `investigation`, **`review`** (critic).
**MVP defined-but-disabled roles:** `summarize`, `entity_extraction` (schema + admin UI rows present, `enabled=false`).

**OpenRouter native fallback** — when invoking, we pass `{"models": [primary, *fallback_chain], "route": "fallback"}`. OpenRouter tries in order. The actual model used is returned in the response for usage logging.

**Usage tracking** logs each attempt separately (model, tokens, cost, success/failure reason) in `usage` table.

**MVP dev defaults** for all active roles: `google/gemini-3-flash-preview` (cost/speed for testing).
**Production defaults** (admin-configurable, not hard-coded): investigation = Opus; triage + review = Haiku or Sonnet.

## Alternatives considered

- **Single global model** — simpler but wastes money on triage/review + loses quality on investigation. Rejected.
- **Two-tier only (triage + investigation)** — addresses cost but doesn't support review as a first-class quality gate and doesn't scale to future `summarize` / specialist roles. Rejected in favor of extensible per-role schema.
- **Hard-coded model per tier in code** — loses admin flexibility. Rejected.
- **LangChain `with_fallbacks()` for fallback** — more code in our app; rejected in favor of OpenRouter native.

## Consequences

**Gain:**
- Tenant-level model tuning without code deploys.
- Cost/quality trade-off tunable per role.
- Adding `summarize` / specialist agent roles post-MVP is a row insert + enable toggle, not a schema migration.
- Fallback resilience without fallback logic in our codebase.

**Accept:**
- Admin panel UI complexity — 5 rows of config per tenant (MVP shows all; only 3 enabled).
- Different models have different prompt format quirks (system prompt length, tool use format). Prompts may need per-role variants or defensive parsing.
- OpenRouter fallback passthrough for features like `cache_control` is not guaranteed identical across models. Measure cache hit rates per role in wk 7.

## Related

- ADR 0004 — OpenRouter as unified LLM routing (the mechanism).
- ADR 0003 — LangGraph graph has a `review` node between draft_verdict and await_approval.
- `docs/context/stack-locks.md` — LLM routing lock.
