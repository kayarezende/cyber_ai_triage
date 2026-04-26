# 0016: Sovereignty hybrid surface — drop MVP claim, prepare DB

Date: 2026-04-27
Status: Accepted

## Context

The Plan (`docs/PLAN.md` pre-rewrite) and the original positioning marketed the product as sovereign: _"never leaving sovereign infrastructure"_, _"no cross-border inference"_. The actual stack contradicts both:

- **OpenRouter** routes all LLM calls through OpenRouter's US-based infrastructure regardless of which model is selected. ADR-0004.
- **LangSmith** tracing (ADR-0013) is a US-based SaaS. Trace payloads include LLM inputs + outputs.

A multi-agent review flagged this as a P1 — for any sovereignty-sensitive AU buyer (gov-adjacent, financial services, regulated industries), the marketing claim is false against the implementation. Ship with that mismatch and the first IRAP-curious customer will catch it.

Two clean options were considered:

1. Build a sovereign-mode tier now (Bedrock Sydney / Azure AU East routing, LangSmith disabled, customer-supplied LLM keys, region-constraint validation). Big lift — adds wks 9-10 of engineering — but lets MVP claim sovereignty truthfully.
2. Drop sovereignty from MVP marketing entirely. Reposition as "Australian-built, sovereignty-roadmapped." Sovereign-mode becomes a paid post-MVP tier.

Option 2 fits the bootstrap timeline. But it leaves the question: what about the buyer who walks in month 4 and asks for sovereign-mode? If we have to do a schema migration to support BYO keys + region constraints + LangSmith toggle, we lose that buyer.

## Decision

**Hybrid.** Drop the sovereignty claim from MVP marketing. Reframe positioning as "Australian-built AI SOC analyst — Splunk-first, OCSF-native, audit-complete." Add the **DB surface** for sovereign-mode now, in the wk-2 cleanup migration, so that activation post-MVP is a feature flag + admin UI surface rather than a schema migration.

DB columns added to `tenants` table (dormant in MVP, activated when sovereign-mode tier ships):

- `byo_openrouter_key_encrypted BYTEA` — if set, used instead of master key.
- `byo_anthropic_key_encrypted BYTEA` — for direct Anthropic API routing post-MVP if Anthropic adds AU residency.
- `llm_region_constraint TEXT` — `'au-southeast'` / `'us-east'` / NULL=any. Passed through OpenRouter `provider` filter on every call.
- `langsmith_enabled BOOLEAN DEFAULT TRUE` — sovereign-mode tenants set FALSE.

The `LLMRouter` wrapper (ADR-0015) consumes these on every call:
- Picks the BYO key over master if set.
- Adds region constraint to request if set.
- Skips `@traceable` LangSmith wrapper if `langsmith_enabled = false`.

Sovereign-mode runtime additions (post-MVP, when first sovereign-mode design partner signs):
- Bedrock Sydney provider route in `LLMRouter`.
- Azure AU East provider route in `LLMRouter`.
- Admin UI to expose the toggle columns.
- Region-constraint validation enforced at call time (reject if response provider doesn't match constraint).
- Sovereign-mode tier pricing (premium % over standard tenant pricing; defer until first conversation).

## Alternatives considered

- **Build sovereign-mode in MVP.** ~2 weeks engineering during a 13-week solo build. Rejected: founder wedge wins on "Australian-built, compliance-native" without sovereignty in MVP. Premature build risks scoping out ship gate features.
- **Drop sovereignty entirely; no DB surface.** Cheapest. Rejected: schema migration when the first sovereign-mode buyer arrives is a worse problem than 4 dormant columns now. Migration fear pushes design.
- **External feature flag (LaunchDarkly etc.) instead of DB columns.** Rejected: feature flag gives binary on/off; we need per-tenant per-key data which is stateful, not flag-shaped.

## Consequences

**Gain:**
- MVP claim matches MVP reality. No false sovereignty pitch.
- Post-MVP activation is a runtime feature, not a migration. First sovereign-mode buyer can be onboarded in a week, not a month.
- Sovereign-mode is a clean upsell path with separate pricing.

**Accept:**
- 4 columns sit dormant on `tenants` table for several months. Cheap.
- Marketing has to commit to "Australian-built, sovereignty-roadmapped" framing without overclaiming.
- If a sovereignty-sensitive buyer walks in month 2, we have to decline or accelerate sovereign-mode. Acceptable risk — bootstrap economics don't support pre-building speculative features.
- Buyers who hear "sovereignty post-MVP" may walk to a competitor offering it now. None exist in AU AI SOC at the moment, but track this.

## Related

- ADR-0004 — OpenRouter as unified LLM routing (the contradiction that made this necessary).
- ADR-0013 — LangSmith observability (the other half of the contradiction).
- ADR-0015 — App-side LLM fallback (the wrapper that consumes these flags).
- `tenants` table schema — Phase 2 migration adds the four columns.
