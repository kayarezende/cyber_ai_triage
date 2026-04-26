# 0015: App-side LLM fallback loop

Date: 2026-04-27
Status: Accepted

## Context

ADR-0004 specified OpenRouter **native** fallback — passing `"models": [primary, *fallback_chain]` (and historically a `"route": "fallback"` field, since deprecated) and letting OpenRouter handle retries internally. The `usage` table schema (`attempt_num`, `model_requested`, `model_used`, status enum including `timeout`/`5xx`/`rate_limited`) was designed to log each attempt as a separate row.

This is a contradiction. OpenRouter native fallback returns a single response indicating only the model that ultimately succeeded — the failed-attempt chain is not exposed in the response body or via the `/generation` endpoint. Per the OpenRouter docs (verified 2026-04-27 via Context7): _"Requests are priced based on the model that was ultimately used. This model will be indicated in the `model` attribute of the response body."_ There is no per-failed-model attempt history.

If we keep native fallback, the `attempt_num` column is permanently NULL or always `1` and the failure-status enum values (`timeout`, `5xx`, `rate_limited`) are unreachable in practice. The schema lies.

For an MSSP-targeting product with compliance posture (E8 ML2, APRA CPS 234, future SOC2 + IRAP), a verifiable per-attempt audit ledger is more valuable than the simplicity of native fallback. An auditor asking "did this investigation use your declared primary model, or did it silently fall back?" needs a defensible answer.

## Decision

**App-side fallback loop.** Implement retry logic in our own code at `apps/orchestrator/src/llm/router.py` (file lands wk 5 with Tier 1 triage). Drop OpenRouter `models[]` array from request bodies — make explicit single-model calls.

```python
class LLMRouter:
    async def call(self, messages, tenant_id, investigation_id) -> LLMResponse:
        models_to_try = [self.role_config.primary_model, *self.role_config.fallback_chain]
        for attempt_num, model in enumerate(models_to_try, start=1):
            start = time.monotonic()
            try:
                response = await self._call_openrouter(model, messages, tenant_id)
                self.usage_logger.log(..., status='success', ...)
                return response
            except (asyncio.TimeoutError, httpx.TimeoutException):
                self.usage_logger.log(..., status='timeout', ...)
            except httpx.HTTPStatusError as e:
                status = '5xx' if e.response.status_code >= 500 \
                    else 'rate_limited' if e.response.status_code == 429 \
                    else 'validation_fail'
                self.usage_logger.log(..., status=status, ...)
            # continue to next model
        raise FallbackChainExhausted(role=self.role_config.role, attempts=models_to_try)
```

Contract requirements:
- **Each attempt logs a row immediately** (not batched). Failure mid-loop still leaves an audit trail.
- `FallbackChainExhausted` propagates to the LangGraph `draft_verdict` node; the investigation is marked `inconclusive`, `inconclusive_reason` is populated, and the dashboard card surfaces the attempt history.
- Per-tenant sovereignty hooks: if `tenants.byo_openrouter_key_encrypted` is set, use that key. If `tenants.llm_region_constraint` is set, pass it through OpenRouter's `provider` filter. If `tenants.langsmith_enabled = false`, skip the `@traceable` wrapper. (See ADR-0016.)

## Alternatives considered

- **Keep OpenRouter native fallback + drop `attempt_num`/failure-status columns** — simpler schema, less code. Rejected: loses per-attempt audit, weakens compliance pitch.
- **Native fallback + best-effort detection** (compare `model_requested` vs `model_used` in response, log mismatch as evidence-of-fallback) — partial information. Rejected: still can't answer "what error was the primary model returning?"
- **LangChain `with_fallbacks()`** — fallback in app code via LangChain abstraction. Rejected: we already chose to bypass `langchain-anthropic` for direct OpenRouter calls; adding `with_fallbacks` re-introduces a layer we removed.

## Consequences

**Gain:**
- Per-attempt audit ledger. `usage` table tells the full story of what happened.
- Schema and runtime agree.
- Provider failure visibility (track OpenRouter SLA against our `usage` data).
- Sovereignty hooks integrate cleanly into one wrapper.

**Accept:**
- ~30 lines of Python in the wrapper. Need timeout/retry tuning per-error-class.
- Lose OpenRouter's native fallback heuristics (e.g., model availability awareness). Mitigation: `fallback_chain` config can be tuned per role.
- Cache hit-rate test scenarios more complex (cache may attach to specific model in chain).

## Related

- Supersedes ADR-0004 §4 ("OpenRouter native fallback") — other decisions in 0004 stand.
- ADR-0010 — Per-role LLM configuration (the table this consumes).
- ADR-0016 — Sovereignty hybrid hooks consumed by this wrapper.
- `usage` table schema in `db/migrations/versions/81e2d43b3ec0_initial_schema.py:143-160` — already supports per-attempt rows.
